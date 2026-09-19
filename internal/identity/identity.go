// Package identity is the control-plane store for users, credentials,
// sessions, and RBAC grant loading (SECURITY.md §3-5, PRD §5).
//
// Design rules:
//
//   - Tokens are never stored in plaintext; only their SHA-256 digest lives in
//     the database, so a database read cannot be replayed as a live session.
//   - Brute-force state and lockout transitions are single UPDATE statements
//     with arithmetic done in SQL, so two concurrent failed logins both count
//     (DATABASE.md §16: do not rely on in-process state).
//   - The store performs NO authorization decisions. It loads grants; the
//     internal/rbac evaluator decides. Keeping the two apart means "what does
//     this user hold?" and "is this request allowed?" stay independently
//     testable.
package identity

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/password"
	"github.com/bukansembarangkong/jawaker-panel/internal/secureid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors. Handlers map these onto stable API codes; the raw cause is
// logged but never serialized (API.md §8).
var (
	// ErrNotFound is returned when the requested user or session does not
	// exist. It deliberately does not distinguish "unknown email" from
	// "unknown id" at the HTTP boundary; login flows must not enumerate users.
	ErrNotFound = errors.New("identity: not found")
	// ErrAlreadyExists is returned when a unique constraint rejects a create.
	ErrAlreadyExists = errors.New("identity: already exists")
	// ErrSessionExpired is returned for a session past its idle or absolute
	// expiry.
	ErrSessionExpired = errors.New("identity: session expired")
	// ErrSessionRevoked is returned for a session revoked by policy or user.
	ErrSessionRevoked = errors.New("identity: session revoked")
	// ErrUserNotActive is returned when the account is suspended, pending
	// deletion, or deleted.
	ErrUserNotActive = errors.New("identity: user is not active")
)

// Queryer is the minimal read surface. pgx.Tx and *pgxpool.Pool both satisfy
// it, so every read works inside or outside a caller transaction.
type Queryer interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Execer adds writes to Queryer.
type Execer interface {
	Queryer
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// Querier is the transaction-opening surface: a pool satisfies it, and the
// store uses it for operations that must span multiple statements atomically.
type Querier interface {
	Execer
	Begin(ctx context.Context) (pgx.Tx, error)
}

// User is one account row.
type User struct {
	ID               string
	Email            string
	DisplayName      string
	State            string
	AccountType      string
	IsOwner          bool
	FailedLoginCount int
	LockedUntil      *time.Time
	LastLoginAt      *time.Time
}

// Active reports whether the account may authenticate.
func (u User) Active() bool { return u.State == "active" }

// Locked reports whether the account is currently inside a lockout window.
func (u User) Locked(now time.Time) bool {
	return u.LockedUntil != nil && u.LockedUntil.After(now)
}

// LoginCandidate bundles the columns the login path needs in one round trip.
type LoginCandidate struct {
	User
	// PasswordHash is the argon2id encoded string of the ACTIVE credential, or
	// empty when the user has no password credential.
	PasswordHash string
	// HasConfirmedTOTP reports whether a usable TOTP enrollment exists, which
	// determines whether the second factor is required.
	HasConfirmedTOTP bool
}

// userColumns is the canonical column list so every user read scans the same
// shape and cannot drift from scanUser.
const userColumns = `u.id, u.email, u.display_name, u.state, u.account_type,
	u.is_owner, u.failed_login_count, u.locked_until, u.last_login_at`

const selectLoginCandidate = `
SELECT ` + userColumns + `,
       COALESCE(pc.password_hash, ''),
       EXISTS (SELECT 1 FROM totp_credentials tc
                WHERE tc.user_id = u.id AND tc.confirmed_at IS NOT NULL
                  AND tc.disabled_at IS NULL)
FROM users u
LEFT JOIN LATERAL (
    SELECT password_hash FROM password_credentials
    WHERE user_id = u.id AND superseded_at IS NULL
    ORDER BY created_at DESC LIMIT 1
) pc ON true
WHERE u.email = $1`

// GetLoginCandidate loads a user plus their active credential by email.
// Email comparison is case-insensitive because the column is citext.
func GetLoginCandidate(ctx context.Context, db Queryer, email string) (LoginCandidate, error) {
	var c LoginCandidate
	err := db.QueryRow(ctx, selectLoginCandidate, email).Scan(
		&c.ID, &c.Email, &c.DisplayName, &c.State, &c.AccountType, &c.IsOwner,
		&c.FailedLoginCount, &c.LockedUntil, &c.LastLoginAt,
		&c.PasswordHash, &c.HasConfirmedTOTP)
	if errors.Is(err, pgx.ErrNoRows) {
		return LoginCandidate{}, ErrNotFound
	}
	if err != nil {
		return LoginCandidate{}, fmt.Errorf("identity: load login candidate: %w", err)
	}
	return c, nil
}

// GetUserByID loads a user row by id.
func GetUserByID(ctx context.Context, db Queryer, id string) (User, error) {
	var u User
	err := db.QueryRow(ctx, `
		SELECT `+userColumns+` FROM users u WHERE u.id = $1`, id).Scan(
		&u.ID, &u.Email, &u.DisplayName, &u.State, &u.AccountType, &u.IsOwner,
		&u.FailedLoginCount, &u.LockedUntil, &u.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("identity: load user: %w", err)
	}
	return u, nil
}

// BootstrapParams describes the initial platform owner.
type BootstrapParams struct {
	Email       string
	DisplayName string
	Password    string
	// RequestID correlates the bootstrap audit event with the HTTP request.
	RequestID string
}

// Bootstrap creates the single platform owner with its first credential and
// the global platform_owner role binding, in ONE transaction together with its
// audit event.
//
// Concurrent bootstrap attempts are serialized by the database: the partial
// unique index on users(is_owner) makes the second attempt fail with
// ErrAlreadyExists rather than creating two owners.
func Bootstrap(ctx context.Context, db Querier, p BootstrapParams, params password.Params) (string, error) {
	hash, err := password.Hash(p.Password, params)
	if err != nil {
		return "", fmt.Errorf("identity: hash bootstrap password: %w", err)
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("identity: begin bootstrap: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after commit

	var userID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO users (email, display_name, account_type, is_owner)
		VALUES ($1, $2, 'platform_owner', true)
		RETURNING id`,
		p.Email, p.DisplayName).Scan(&userID); err != nil {
		return "", fmt.Errorf("identity: create owner: %w",
			mapUniqueViolation(err, "a platform owner already exists"))
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO password_credentials (user_id, password_hash) VALUES ($1, $2)`,
		userID, hash); err != nil {
		return "", fmt.Errorf("identity: create owner credential: %w", err)
	}

	// Explicit global binding to the built-in role. Authority is queryable,
	// never a code-level superuser flag.
	if _, err := tx.Exec(ctx, `
		INSERT INTO role_bindings (user_id, role_id, scope_type)
		SELECT $1, r.id, 'global' FROM roles r WHERE r.key = 'platform_owner'`,
		userID); err != nil {
		return "", fmt.Errorf("identity: bind platform_owner role: %w", err)
	}

	if err := audit.Record(ctx, tx, audit.Event{
		ActorType:    audit.ActorSystem,
		Action:       "identity.bootstrap",
		ResourceType: "user",
		ResourceID:   userID,
		RequestID:    p.RequestID,
		Result:       audit.ResultSuccess,
		Context:      map[string]any{"email": p.Email, "account_type": "platform_owner"},
	}); err != nil {
		return "", err
	}

	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("identity: commit bootstrap: %w", err)
	}
	return userID, nil
}

// HasAnyUser reports whether the installation already has accounts. The
// bootstrap endpoint uses this to refuse running twice with a clean 409 rather
// than surfacing a constraint error.
func HasAnyUser(ctx context.Context, db Queryer) (bool, error) {
	var exists bool
	if err := db.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM users)`).Scan(&exists); err != nil {
		return false, fmt.Errorf("identity: check users: %w", err)
	}
	return exists, nil
}

// CreateUserParams describes an account created by an administrator.
type CreateUserParams struct {
	Email       string
	DisplayName string
	Password    string
	AccountType string
}

// CreateUser creates an account with its first password credential in one
// transaction. The caller is responsible for authorization; this function
// refuses to create owners — that path is Bootstrap only.
func CreateUser(ctx context.Context, db Querier, p CreateUserParams, params password.Params) (string, error) {
	if p.AccountType == "platform_owner" {
		return "", errors.New("identity: platform owner is created by bootstrap only")
	}
	hash, err := password.Hash(p.Password, params)
	if err != nil {
		return "", fmt.Errorf("identity: hash password: %w", err)
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return "", fmt.Errorf("identity: begin create user: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO users (email, display_name, account_type)
		VALUES ($1, $2, $3) RETURNING id`,
		p.Email, p.DisplayName, p.AccountType).Scan(&userID); err != nil {
		return "", fmt.Errorf("identity: create user: %w",
			mapUniqueViolation(err, "that email is already registered"))
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO password_credentials (user_id, password_hash) VALUES ($1, $2)`,
		userID, hash); err != nil {
		return "", fmt.Errorf("identity: create credential: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return "", fmt.Errorf("identity: commit create user: %w", err)
	}
	return userID, nil
}

// VerifyPassword checks a plaintext password against a stored argon2id hash
// and reports whether a transparent rehash is due.
//
// A wrong password is an EXPECTED outcome, not a fault: it returns
// ok=false with a nil error so handlers can count a failed attempt without
// special-casing an error value or turning a bad login into a 500. A non-nil
// error means the stored hash itself is unusable (malformed, wrong algorithm,
// unbounded parameters) — an operator-visible fault.
func VerifyPassword(storedHash, plaintext string, current password.Params) (ok, needsRehash bool, err error) {
	if storedHash == "" {
		// No credential on file. Reported as a plain mismatch so an account
		// without a password cannot authenticate, and so callers cannot
		// distinguish "no credential" from "wrong credential" — the same
		// reason the login endpoint does not reveal which emails exist.
		return false, false, nil
	}
	ok, needsRehash, err = password.Verify(plaintext, storedHash, current)
	if errors.Is(err, password.ErrMismatch) {
		return false, false, nil
	}
	return ok, needsRehash, err
}

// RecordLoginFailure increments the brute-force counter and, at the threshold,
// arms the lockout. All arithmetic is in SQL so concurrent failures both count.
// Returns the resulting lockout deadline (nil when the threshold was not
// reached).
func RecordLoginFailure(ctx context.Context, db Execer, userID string, threshold int, lockout time.Duration, now time.Time) (*time.Time, error) {
	if threshold <= 0 {
		return nil, errors.New("identity: failure threshold must be positive")
	}
	if lockout <= 0 {
		return nil, errors.New("identity: lockout duration must be positive")
	}

	var lockedUntil *time.Time
	err := db.QueryRow(ctx, `
		UPDATE users SET
		    failed_login_count = failed_login_count + 1,
		    locked_until = CASE
		        WHEN failed_login_count + 1 >= $2
		        THEN $3::timestamptz ELSE locked_until END,
		    updated_at = now()
		WHERE id = $1
		RETURNING locked_until`,
		userID, threshold, now.Add(lockout)).Scan(&lockedUntil)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("identity: record login failure: %w", err)
	}
	return lockedUntil, nil
}

// RecordLoginSuccess clears brute-force state and stamps the login time.
func RecordLoginSuccess(ctx context.Context, db Execer, userID string) error {
	tag, err := db.Exec(ctx, `
		UPDATE users SET failed_login_count = 0, locked_until = NULL,
		                 last_login_at = now(), updated_at = now()
		WHERE id = $1`, userID)
	if err != nil {
		return fmt.Errorf("identity: record login success: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RotatePassword supersedes the active credential and installs a new one in
// one transaction. The superseded row is retained so credential rotation stays
// auditable and an interrupted rotation is diagnosable.
func RotatePassword(ctx context.Context, db Querier, userID, newPassword string, params password.Params) error {
	hash, err := password.Hash(newPassword, params)
	if err != nil {
		return fmt.Errorf("identity: hash password: %w", err)
	}

	tx, err := db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("identity: begin rotate: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, `
		UPDATE password_credentials SET superseded_at = now()
		WHERE user_id = $1 AND superseded_at IS NULL`, userID); err != nil {
		return fmt.Errorf("identity: supersede credential: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO password_credentials (user_id, password_hash) VALUES ($1, $2)`,
		userID, hash); err != nil {
		return fmt.Errorf("identity: insert rotated credential: %w", err)
	}
	return tx.Commit(ctx)
}

// SessionPolicy bounds session lifetime. Absolute expiry caps total lifetime
// regardless of activity; idle expiry caps inactivity.
type SessionPolicy struct {
	IdleTimeout     time.Duration
	AbsoluteTimeout time.Duration
}

// DefaultSessionPolicy matches SECURITY.md §4 defaults for browser sessions.
func DefaultSessionPolicy() SessionPolicy {
	return SessionPolicy{
		IdleTimeout:     30 * time.Minute,
		AbsoluteTimeout: 12 * time.Hour,
	}
}

func (p SessionPolicy) validate() error {
	if p.IdleTimeout <= 0 {
		return errors.New("identity: idle timeout must be positive")
	}
	if p.AbsoluteTimeout <= 0 {
		return errors.New("identity: absolute timeout must be positive")
	}
	if p.IdleTimeout > p.AbsoluteTimeout {
		return errors.New("identity: idle timeout cannot exceed absolute timeout")
	}
	return nil
}

// SessionMetadata describes the device creating the session (inventory).
type SessionMetadata struct {
	UserAgent string
	ClientIP  netip.Addr
}

// Session is a stored session row. Token is set only by the creating
// functions — the database never returns it.
type Session struct {
	ID              string
	UserID          string
	PreviousID      string
	UserAgent       string
	ClientIP        string
	ElevatedUntil   *time.Time
	AbsoluteExpires time.Time
	IdleExpires     time.Time
	CreatedAt       time.Time
	LastSeenAt      time.Time
	// Token is the plaintext session token, returned exactly once at creation.
	Token string
}

const sessionInsert = `
INSERT INTO sessions (user_id, token_hash, previous_session_id, user_agent,
                      client_ip, absolute_expires_at, idle_expires_at)
VALUES ($1, $2, NULLIF($3, '')::uuid, NULLIF($4, ''), NULLIF($5, '')::inet, $6, $7)
RETURNING id, user_id, COALESCE(previous_session_id::text, ''),
          COALESCE(user_agent, ''), COALESCE(host(client_ip), ''),
          elevated_until, absolute_expires_at, idle_expires_at,
          created_at, last_seen_at`

func scanSession(row pgx.Row) (Session, error) {
	var s Session
	err := row.Scan(&s.ID, &s.UserID, &s.PreviousID, &s.UserAgent, &s.ClientIP,
		&s.ElevatedUntil, &s.AbsoluteExpires, &s.IdleExpires,
		&s.CreatedAt, &s.LastSeenAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, fmt.Errorf("identity: scan session: %w", err)
	}
	return s, nil
}

// CreateSession issues a new opaque token, stores only its SHA-256 digest, and
// returns the plaintext token to the caller (which puts it in the cookie).
func CreateSession(ctx context.Context, db Execer, userID string, meta SessionMetadata, policy SessionPolicy, now time.Time) (Session, error) {
	if err := policy.validate(); err != nil {
		return Session{}, err
	}
	token, tokenHash, err := secureid.SessionToken()
	if err != nil {
		return Session{}, err
	}

	s, err := scanSession(db.QueryRow(ctx, sessionInsert,
		userID, tokenHash, "", meta.UserAgent, clientIPString(meta.ClientIP),
		now.Add(policy.AbsoluteTimeout), now.Add(policy.IdleTimeout)))
	if err != nil {
		return Session{}, fmt.Errorf("identity: create session: %w", err)
	}
	s.Token = token
	return s, nil
}

// ResolveSession validates a presented token digest and returns the session
// plus its user, sliding the idle window on success.
//
// Checks in order: existence, expiry, revocation, then user state. Expired
// rows are deleted (they hold no value and would grow the table forever);
// revoked rows are retained for the device inventory but never usable.
func ResolveSession(ctx context.Context, db Execer, tokenHash []byte, policy SessionPolicy, now time.Time) (Session, User, error) {
	if err := policy.validate(); err != nil {
		return Session{}, User{}, err
	}

	var s Session
	var u User
	var revokedAt *time.Time
	err := db.QueryRow(ctx, `
		SELECT s.id, s.user_id, COALESCE(s.previous_session_id::text, ''),
		       COALESCE(s.user_agent, ''), COALESCE(host(s.client_ip), ''),
		       s.elevated_until, s.absolute_expires_at, s.idle_expires_at,
		       s.created_at, s.last_seen_at, s.revoked_at,
		       `+userColumns+`
		FROM sessions s JOIN users u ON u.id = s.user_id
		WHERE s.token_hash = $1`, tokenHash).
		Scan(&s.ID, &s.UserID, &s.PreviousID, &s.UserAgent, &s.ClientIP,
			&s.ElevatedUntil, &s.AbsoluteExpires, &s.IdleExpires,
			&s.CreatedAt, &s.LastSeenAt, &revokedAt,
			&u.ID, &u.Email, &u.DisplayName, &u.State, &u.AccountType, &u.IsOwner,
			&u.FailedLoginCount, &u.LockedUntil, &u.LastLoginAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, User{}, ErrNotFound
	}
	if err != nil {
		return Session{}, User{}, fmt.Errorf("identity: resolve session: %w", err)
	}

	// Revocation is checked before expiry: a deliberately killed session
	// reports revocation, which is the more actionable fact for the operator
	// and the more informative audit outcome.
	if revokedAt != nil {
		return Session{}, User{}, ErrSessionRevoked
	}

	if now.After(s.IdleExpires) || now.After(s.AbsoluteExpires) {
		// Deleting an expired row is housekeeping; its failure must not turn a
		// clean expiry into a server error.
		_, _ = db.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, s.ID)
		return Session{}, User{}, ErrSessionExpired
	}

	if !u.Active() {
		return Session{}, u, ErrUserNotActive
	}

	// Slide the idle window from NOW, capped by the absolute deadline so
	// activity can never extend a session past its absolute expiry.
	idleExpires := now.Add(policy.IdleTimeout)
	if idleExpires.After(s.AbsoluteExpires) {
		idleExpires = s.AbsoluteExpires
	}
	if _, err := db.Exec(ctx, `
		UPDATE sessions SET last_seen_at = $2, idle_expires_at = $3 WHERE id = $1`,
		s.ID, now, idleExpires); err != nil {
		return Session{}, User{}, fmt.Errorf("identity: touch session: %w", err)
	}
	s.LastSeenAt = now
	s.IdleExpires = idleExpires
	return s, u, nil
}

// RevokeSession marks one session revoked. Already-revoked sessions return nil
// (idempotent); the row is retained for the device inventory.
func RevokeSession(ctx context.Context, db Execer, sessionID, reason string) error {
	tag, err := db.Exec(ctx, `
		UPDATE sessions SET revoked_at = now(), revoke_reason = NULLIF($2, '')
		WHERE id = $1 AND revoked_at IS NULL`, sessionID, reason)
	if err != nil {
		return fmt.Errorf("identity: revoke session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either unknown or already revoked; distinguish so "revoke my other
		// sessions" can report honestly.
		var exists bool
		if err := db.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM sessions WHERE id = $1)`, sessionID).Scan(&exists); err != nil {
			return fmt.Errorf("identity: check session existence: %w", err)
		}
		if !exists {
			return ErrNotFound
		}
	}
	return nil
}

// RevokeAllUserSessions revokes every live session for a user (global kill
// switch: password change, role change, compromise response). Returns the
// number of sessions revoked.
func RevokeAllUserSessions(ctx context.Context, db Execer, userID, reason string) (int64, error) {
	tag, err := db.Exec(ctx, `
		UPDATE sessions SET revoked_at = now(), revoke_reason = NULLIF($2, '')
		WHERE user_id = $1 AND revoked_at IS NULL`, userID, reason)
	if err != nil {
		return 0, fmt.Errorf("identity: revoke user sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// RotateSession supersedes the current session with a new one: the old row is
// revoked with reason "rotated" and a new row links back via
// previous_session_id, so the rotation chain stays auditable. Rotation happens
// after authentication and after privilege changes (SECURITY.md §4).
func RotateSession(ctx context.Context, db Querier, current Session, meta SessionMetadata, policy SessionPolicy, now time.Time) (Session, error) {
	if err := policy.validate(); err != nil {
		return Session{}, err
	}
	tx, err := db.Begin(ctx)
	if err != nil {
		return Session{}, fmt.Errorf("identity: begin rotate session: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if revokeErr := RevokeSession(ctx, tx, current.ID, "rotated"); revokeErr != nil {
		return Session{}, revokeErr
	}

	token, tokenHash, err := secureid.SessionToken()
	if err != nil {
		return Session{}, err
	}
	s, err := scanSession(tx.QueryRow(ctx, sessionInsert,
		current.UserID, tokenHash, current.ID, meta.UserAgent,
		clientIPString(meta.ClientIP),
		now.Add(policy.AbsoluteTimeout), now.Add(policy.IdleTimeout)))
	if err != nil {
		return Session{}, fmt.Errorf("identity: insert rotated session: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Session{}, fmt.Errorf("identity: commit rotate session: %w", err)
	}
	s.Token = token
	return s, nil
}

// Grant is one resolved role binding, shaped for the rbac evaluator.
type Grant struct {
	Permission     string
	ScopeType      string
	ScopeID        string
	ExpiresAt      *time.Time
	RevokedAt      *time.Time
	AllowedCIDRs   []string
	RequiresStepUp bool
}

// LoadGrants resolves the effective permission set for a user: every unrevoked
// binding, joined to its role's permissions. Expiry, IP matching, and step-up
// enforcement happen in the rbac evaluator, which owns the clock and the
// request context.
func LoadGrants(ctx context.Context, db Queryer, userID string) ([]Grant, error) {
	rows, err := db.Query(ctx, `
		SELECT rp.permission_key, rb.scope_type, COALESCE(rb.scope_id::text, ''),
		       rb.expires_at, rb.revoked_at,
		       ARRAY(SELECT host(c) FROM unnest(rb.allowed_cidrs) AS c),
		       p.requires_step_up
		FROM role_bindings rb
		JOIN roles r ON r.id = rb.role_id
		JOIN role_permissions rp ON rp.role_id = r.id
		JOIN permissions p ON p.key = rp.permission_key
		WHERE rb.user_id = $1 AND rb.revoked_at IS NULL
		ORDER BY rp.permission_key`, userID)
	if err != nil {
		return nil, fmt.Errorf("identity: load grants: %w", err)
	}
	defer rows.Close()

	var grants []Grant
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.Permission, &g.ScopeType, &g.ScopeID,
			&g.ExpiresAt, &g.RevokedAt, &g.AllowedCIDRs, &g.RequiresStepUp); err != nil {
			return nil, fmt.Errorf("identity: scan grant: %w", err)
		}
		grants = append(grants, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("identity: iterate grants: %w", err)
	}
	return grants, nil
}

// BindRole grants a role to a user within a scope. scopeID is required for
// non-global scope types; the database CHECK enforces the same rule, so a
// mismatch between the two is impossible.
func BindRole(ctx context.Context, db Execer, userID, roleKey, scopeType, scopeID, grantedBy string, expiresAt *time.Time) error {
	tag, err := db.Exec(ctx, `
		INSERT INTO role_bindings (user_id, role_id, scope_type, scope_id, granted_by, expires_at)
		SELECT $1, r.id, $3, NULLIF($4, '')::uuid, NULLIF($5, '')::uuid, $6
		FROM roles r WHERE r.key = $2`,
		userID, roleKey, scopeType, scopeID, grantedBy, expiresAt)
	if err != nil {
		return fmt.Errorf("identity: bind role %q: %w", roleKey,
			mapUniqueViolation(err, "that role is already bound in this scope"))
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("identity: bind role %q: %w", roleKey, ErrNotFound)
	}
	return nil
}

// UnbindRole revokes a binding. Rows are retained (revoked_at) so the history
// of who held what, and when, survives.
func UnbindRole(ctx context.Context, db Execer, bindingID string) error {
	tag, err := db.Exec(ctx, `
		UPDATE role_bindings SET revoked_at = now()
		WHERE id = $1 AND revoked_at IS NULL`, bindingID)
	if err != nil {
		return fmt.Errorf("identity: unbind role: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- helpers -----------------------------------------------------------------

// mapUniqueViolation converts a PostgreSQL unique-violation into
// ErrAlreadyExists so handlers answer 409 instead of 500. Everything else
// passes through unchanged.
func mapUniqueViolation(err error, what string) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return fmt.Errorf("%w: %s", ErrAlreadyExists, what)
	}
	return err
}

func clientIPString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

// NormalizeEmail trims surrounding whitespace. Casing is preserved: the column
// is citext, so uniqueness and lookup are already case-insensitive and
// rewriting the user's chosen casing would be a gratuitous change to their
// data.
func NormalizeEmail(email string) string { return strings.TrimSpace(email) }

// Compile-time proof that the interfaces match what callers pass.
var (
	_ Querier = (*pgxpool.Pool)(nil)
	_ Execer  = (pgx.Tx)(nil)
)
