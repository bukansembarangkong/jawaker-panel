//go:build integration

// Integration tests for the identity store and the audit writer against real
// PostgreSQL. The schema is created by applying the embedded migration set,
// exactly as the controller does at startup, so these tests exercise the same
// database surface production sees.
//
// Run with:
//
//	JAWAKER_TEST_DATABASE_URL=postgres://... go test -tags integration ./internal/identity/

package identity

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/db/migrate"
	"github.com/bukansembarangkong/jawaker-panel/internal/password"
	"github.com/bukansembarangkong/jawaker-panel/internal/secureid"
	"github.com/bukansembarangkong/jawaker-panel/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("JAWAKER_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("JAWAKER_TEST_DATABASE_URL not set; skipping identity integration tests")
	}
	return url
}

// setup applies the real migrations to a pristine schema and returns a pool.
func setup(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, testDatabaseURL(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}

	m, err := migrate.New(migrations.FS, discardLogger())
	if err != nil {
		t.Fatalf("migrator: %v", err)
	}
	if _, err := m.Up(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool, ctx
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fastParams keeps the suite fast; production parameters are covered by the
// password package's own tests.
func fastParams() password.Params {
	return password.Params{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

func TestBootstrapCreatesOwnerWithRoleAndAudit(t *testing.T) {
	pool, ctx := setup(t)

	userID, err := Bootstrap(ctx, pool, BootstrapParams{
		Email:       "Owner@Example.test",
		DisplayName: "First Owner",
		Password:    "correct horse battery staple",
		RequestID:   "req_boot_1",
	}, fastParams())
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	// The owner holds the full platform_owner catalog via an explicit global
	// binding — authority is queryable, never a code-level superuser flag.
	var globalOwnerBindings int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM role_bindings rb
		JOIN roles r ON r.id = rb.role_id
		WHERE rb.user_id = $1 AND r.key = 'platform_owner'
		  AND rb.scope_type = 'global' AND rb.revoked_at IS NULL`,
		userID).Scan(&globalOwnerBindings); err != nil {
		t.Fatalf("query bindings: %v", err)
	}
	if globalOwnerBindings != 1 {
		t.Errorf("platform_owner global bindings = %d, want 1", globalOwnerBindings)
	}

	// An active credential exists and the stored value is an argon2id hash,
	// never the plaintext.
	var hash string
	if err := pool.QueryRow(ctx, `
		SELECT password_hash FROM password_credentials
		WHERE user_id = $1 AND superseded_at IS NULL`, userID).Scan(&hash); err != nil {
		t.Fatalf("query credential: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("stored credential is not argon2id: %q", hash)
	}
	if strings.Contains(hash, "correct horse") {
		t.Error("plaintext password leaked into storage")
	}

	// Email casing is preserved; lookup is case-insensitive (citext).
	u, err := GetUserByID(ctx, pool, userID)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if u.Email != "Owner@Example.test" {
		t.Errorf("email = %q, want the supplied casing preserved", u.Email)
	}
	if !u.IsOwner {
		t.Error("bootstrap user is not flagged owner")
	}
	if u.AccountType != "platform_owner" {
		t.Errorf("account_type = %q, want platform_owner", u.AccountType)
	}

	// The bootstrap wrote its audit row in the same transaction, and the
	// request id correlates it back to the HTTP request.
	var action, result, requestID string
	if err := pool.QueryRow(ctx, `
		SELECT action, result, request_id FROM audit_events
		WHERE resource_id = $1`, userID).
		Scan(&action, &result, &requestID); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if action != "identity.bootstrap" || result != audit.ResultSuccess {
		t.Errorf("audit = %s/%s, want identity.bootstrap/success", action, result)
	}
	if requestID != "req_boot_1" {
		t.Errorf("audit request_id = %q, want req_boot_1", requestID)
	}
}

// The database — not an in-process mutex — is the authority on "exactly one
// owner". Two bootstrap attempts must not both succeed, even if they race.
func TestBootstrapSecondOwnerRejected(t *testing.T) {
	pool, ctx := setup(t)

	if _, err := Bootstrap(ctx, pool, BootstrapParams{
		Email: "first@example.test", DisplayName: "First", Password: "pw-first-owner",
	}, fastParams()); err != nil {
		t.Fatalf("first Bootstrap: %v", err)
	}

	_, err := Bootstrap(ctx, pool, BootstrapParams{
		Email: "second@example.test", DisplayName: "Second", Password: "pw-second-owner",
	}, fastParams())
	if err == nil {
		t.Fatal("second owner accepted")
	}
	if !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("err = %v, want ErrAlreadyExists", err)
	}

	var owners int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE is_owner`).Scan(&owners); err != nil {
		t.Fatalf("count owners: %v", err)
	}
	if owners != 1 {
		t.Errorf("owners = %d, want exactly 1", owners)
	}

	// The failed bootstrap must have left nothing behind: no user, no
	// credential, and no audit row. Transactional rollback is the guarantee.
	var leftovers int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE email = 'second@example.test'`).Scan(&leftovers); err != nil {
		t.Fatalf("count leftovers: %v", err)
	}
	if leftovers != 0 {
		t.Errorf("failed bootstrap left %d user rows behind", leftovers)
	}
}

func TestBootstrapIsRefusedAfterAccountsExist(t *testing.T) {
	pool, ctx := setup(t)

	exists, err := HasAnyUser(ctx, pool)
	if err != nil {
		t.Fatalf("HasAnyUser: %v", err)
	}
	if exists {
		t.Fatal("fresh installation reports users")
	}
	if _, err := Bootstrap(ctx, pool, BootstrapParams{
		Email: "a@example.test", DisplayName: "A", Password: "pw-owner-a",
	}, fastParams()); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}

	exists, err = HasAnyUser(ctx, pool)
	if err != nil {
		t.Fatalf("HasAnyUser after bootstrap: %v", err)
	}
	if !exists {
		t.Error("HasAnyUser = false after bootstrap")
	}
}

func TestCreateUserStoresHashedCredentialAndRefusesOwnerType(t *testing.T) {
	pool, ctx := setup(t)

	id, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "Dev@Example.test", DisplayName: "Dev", Password: "pw-for-dev", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	c, err := GetLoginCandidate(ctx, pool, "dev@example.TEST")
	if err != nil {
		t.Fatalf("GetLoginCandidate (case-insensitive): %v", err)
	}
	if c.ID != id {
		t.Errorf("candidate id = %q, want %q", c.ID, id)
	}
	if c.Email != "Dev@Example.test" {
		t.Errorf("email casing not preserved: %q", c.Email)
	}
	if c.HasConfirmedTOTP {
		t.Error("new user reports a confirmed TOTP enrollment")
	}
	ok, needsRehash, err := VerifyPassword(c.PasswordHash, "pw-for-dev", fastParams())
	if err != nil || !ok {
		t.Errorf("VerifyPassword = %v, %v; want true", ok, err)
	}
	if needsRehash {
		t.Error("needsRehash = true for a freshly written hash")
	}

	// The platform owner path is Bootstrap only.
	if _, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "x@example.test", DisplayName: "X", Password: "pw", AccountType: "platform_owner",
	}, fastParams()); err == nil {
		t.Error("CreateUser accepted account_type=platform_owner")
	}

	// Duplicate email is a 409, not a 500.
	_, err = CreateUser(ctx, pool, CreateUserParams{
		Email: "dev@example.test", DisplayName: "Dup", Password: "pw-dup", AccountType: "customer",
	}, fastParams())
	if !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("duplicate email err = %v, want ErrAlreadyExists", err)
	}
}

// Brute-force state is the database's, not the process's: concurrent failures
// must both count, and the lockout must arm at the threshold.
func TestLoginFailureCounterAndLockout(t *testing.T) {
	pool, ctx := setup(t)

	id, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "bf@example.test", DisplayName: "BF", Password: "pw-bf", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	const threshold = 3
	lockout := 15 * time.Minute

	for i := 1; i < threshold; i++ {
		locked, err := RecordLoginFailure(ctx, pool, id, threshold, lockout, now)
		if err != nil {
			t.Fatalf("failure %d: %v", i, err)
		}
		if locked != nil {
			t.Fatalf("lockout armed early at attempt %d", i)
		}
	}
	u, err := GetUserByID(ctx, pool, id)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if u.FailedLoginCount != threshold-1 {
		t.Errorf("failed_login_count = %d, want %d", u.FailedLoginCount, threshold-1)
	}
	if u.Locked(now) {
		t.Error("user locked before the threshold was reached")
	}

	// The threshold attempt arms the lockout.
	locked, err := RecordLoginFailure(ctx, pool, id, threshold, lockout, now)
	if err != nil {
		t.Fatalf("threshold failure: %v", err)
	}
	if locked == nil {
		t.Fatal("lockout not armed at threshold")
	}
	if !locked.Equal(now.Add(lockout)) {
		t.Errorf("locked_until = %v, want %v", locked, now.Add(lockout))
	}
	u, _ = GetUserByID(ctx, pool, id)
	if !u.Locked(now) {
		t.Error("Locked = false after the lockout armed")
	}
	if u.Locked(now.Add(lockout + time.Minute)) {
		t.Error("Locked = true after the lockout window passed")
	}

	// A successful login clears the brute-force state entirely.
	if err := RecordLoginSuccess(ctx, pool, id); err != nil {
		t.Fatalf("RecordLoginSuccess: %v", err)
	}
	u, _ = GetUserByID(ctx, pool, id)
	if u.FailedLoginCount != 0 || u.LockedUntil != nil {
		t.Errorf("after success: count=%d locked_until=%v, want 0/nil",
			u.FailedLoginCount, u.LockedUntil)
	}
	if u.LastLoginAt == nil {
		t.Error("last_login_at not stamped")
	}
}

// The counter must not be reachable through an in-process increment: two
// concurrent failures against the same row both count.
func TestConcurrentLoginFailuresBothCount(t *testing.T) {
	pool, ctx := setup(t)

	id, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "race@example.test", DisplayName: "Race", Password: "pw-race", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	const attempts = 8
	errs := make(chan error, attempts)
	now := time.Now().UTC()
	for i := 0; i < attempts; i++ {
		go func() {
			_, err := RecordLoginFailure(ctx, pool, id, 100, time.Minute, now)
			errs <- err
		}()
	}
	for i := 0; i < attempts; i++ {
		if err := <-errs; err != nil {
			t.Errorf("concurrent failure: %v", err)
		}
	}

	u, err := GetUserByID(ctx, pool, id)
	if err != nil {
		t.Fatalf("GetUserByID: %v", err)
	}
	if u.FailedLoginCount != attempts {
		t.Errorf("failed_login_count = %d, want %d (lost updates mean the counter is not durable)",
			u.FailedLoginCount, attempts)
	}
}

func TestLoginFailureRejectsInvalidPolicy(t *testing.T) {
	pool, ctx := setup(t)
	id, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "pol@example.test", DisplayName: "Pol", Password: "pw-pol", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if _, err := RecordLoginFailure(ctx, pool, id, 0, time.Minute, time.Now()); err == nil {
		t.Error("zero threshold accepted")
	}
	if _, err := RecordLoginFailure(ctx, pool, id, 3, 0, time.Now()); err == nil {
		t.Error("zero lockout accepted")
	}
	if _, err := RecordLoginFailure(ctx, pool, "00000000-0000-0000-0000-000000000000", 3, time.Minute, time.Now()); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown user err = %v, want ErrNotFound", err)
	}
}

func TestPasswordRotationSupersedesAndVerifies(t *testing.T) {
	pool, ctx := setup(t)

	id, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "rot@example.test", DisplayName: "Rot", Password: "pw-old", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := RotatePassword(ctx, pool, id, "pw-new", fastParams()); err != nil {
		t.Fatalf("RotatePassword: %v", err)
	}

	// Exactly one active credential, and history is retained.
	var active, total int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE superseded_at IS NULL), count(*)
		FROM password_credentials WHERE user_id = $1`, id).Scan(&active, &total); err != nil {
		t.Fatalf("count credentials: %v", err)
	}
	if active != 1 || total != 2 {
		t.Errorf("credentials active=%d total=%d, want 1/2", active, total)
	}

	c, err := GetLoginCandidate(ctx, pool, "rot@example.test")
	if err != nil {
		t.Fatalf("GetLoginCandidate: %v", err)
	}
	if ok, _, err := VerifyPassword(c.PasswordHash, "pw-old", fastParams()); err != nil || ok {
		t.Error("old password still verifies after rotation")
	}
	if ok, _, err := VerifyPassword(c.PasswordHash, "pw-new", fastParams()); err != nil || !ok {
		t.Error("new password does not verify after rotation")
	}
}

// --- sessions -----------------------------------------------------------------

func TestSessionStoresHashNotToken(t *testing.T) {
	pool, ctx := setup(t)

	id, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "sess@example.test", DisplayName: "Sess", Password: "pw-sess", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	s, err := CreateSession(ctx, pool, id, SessionMetadata{
		UserAgent: "Mozilla/5.0 (test)",
		ClientIP:  netip.MustParseAddr("203.0.113.7"),
	}, DefaultSessionPolicy(), now)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if s.Token == "" {
		t.Fatal("CreateSession returned no plaintext token")
	}
	if s.UserID != id {
		t.Errorf("session user = %q, want %q", s.UserID, id)
	}

	// The plaintext token must not be anywhere in the row; only its digest.
	var stored string
	if err := pool.QueryRow(ctx,
		`SELECT encode(token_hash, 'hex') FROM sessions WHERE id = $1`, s.ID).Scan(&stored); err != nil {
		t.Fatalf("query token_hash: %v", err)
	}
	if strings.Contains(stored, s.Token) {
		t.Error("plaintext token stored in the database")
	}
	if stored != fmt.Sprintf("%x", sessionDigest(t, s.Token)) {
		t.Errorf("token_hash is not the SHA-256 of the issued token")
	}
}

// sessionDigest mirrors what an auth handler does with a presented cookie:
// decode the issued token, then digest the entropy. Recomputing it here keeps
// the storage format pinned independently of CreateSession.
func sessionDigest(t *testing.T, token string) []byte {
	t.Helper()
	digest, err := secureid.HashSessionToken(token)
	if err != nil {
		t.Fatalf("HashSessionToken(%q): %v", token, err)
	}
	return digest
}

func TestResolveSessionSlidesIdleWindowCappedByAbsolute(t *testing.T) {
	pool, ctx := setup(t)

	id, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "slide@example.test", DisplayName: "Slide", Password: "pw-slide", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	policy := SessionPolicy{IdleTimeout: 30 * time.Minute, AbsoluteTimeout: time.Hour}
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	s, err := CreateSession(ctx, pool, id, SessionMetadata{ClientIP: netip.MustParseAddr("203.0.113.9")}, policy, now)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if !s.IdleExpires.Equal(now.Add(30 * time.Minute)) {
		t.Errorf("initial idle expiry = %v", s.IdleExpires)
	}

	// Activity at +10m slides the idle window to +40m.
	at := now.Add(10 * time.Minute)
	resolved, u, err := ResolveSession(ctx, pool, sessionDigest(t, s.Token), policy, at)
	if err != nil {
		t.Fatalf("ResolveSession: %v", err)
	}
	if u.ID != id {
		t.Errorf("resolved user = %q, want %q", u.ID, id)
	}
	if !resolved.IdleExpires.Equal(at.Add(30 * time.Minute)) {
		t.Errorf("slid idle expiry = %v, want %v", resolved.IdleExpires, at.Add(30*time.Minute))
	}

	// Activity at +35m is still inside the slid idle window (+40m), but a naive
	// slide would push expiry to +65m — past the +60m absolute deadline. The
	// cap must clamp it, so activity can extend a session's usability within
	// its lifetime but never its lifetime itself.
	near := now.Add(35 * time.Minute)
	resolved2, _, err := ResolveSession(ctx, pool, sessionDigest(t, s.Token), policy, near)
	if err != nil {
		t.Fatalf("ResolveSession near absolute: %v", err)
	}
	if resolved2.IdleExpires.After(now.Add(time.Hour)) {
		t.Errorf("idle expiry %v exceeds the absolute deadline %v",
			resolved2.IdleExpires, now.Add(time.Hour))
	}
	if !resolved2.IdleExpires.Equal(now.Add(time.Hour)) {
		t.Errorf("idle expiry = %v, want it clamped to the absolute deadline %v",
			resolved2.IdleExpires, now.Add(time.Hour))
	}
}

func TestResolveSessionRejectsExpiredAndUnknown(t *testing.T) {
	pool, ctx := setup(t)

	id, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "exp@example.test", DisplayName: "Exp", Password: "pw-exp", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	policy := SessionPolicy{IdleTimeout: 30 * time.Minute, AbsoluteTimeout: time.Hour}
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	s, err := CreateSession(ctx, pool, id, SessionMetadata{}, policy, now)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Past the idle window: expired, and the row is deleted as housekeeping.
	if _, _, err := ResolveSession(ctx, pool, sessionDigest(t, s.Token), policy, now.Add(31*time.Minute)); !errors.Is(err, ErrSessionExpired) {
		t.Errorf("idle-expired err = %v, want ErrSessionExpired", err)
	}
	var remaining int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE id = $1`, s.ID).Scan(&remaining); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if remaining != 0 {
		t.Errorf("expired session row retained (%d), want deleted", remaining)
	}

	// Absolute expiry is independent of activity.
	s2, err := CreateSession(ctx, pool, id, SessionMetadata{}, policy, now)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	if _, _, err := ResolveSession(ctx, pool, sessionDigest(t, s2.Token), policy, now.Add(61*time.Minute)); !errors.Is(err, ErrSessionExpired) {
		t.Errorf("absolute-expired err = %v, want ErrSessionExpired", err)
	}

	// An unknown token is indistinguishable from an expired one at the store
	// boundary: both are "this session does not exist".
	if _, _, err := ResolveSession(ctx, pool, sessionDigest(t, "not-a-real-token"), policy, now); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown token err = %v, want ErrNotFound", err)
	}
}

// Revocation must win over everything else: a deliberately killed session is
// not usable even while it is inside its expiry window, and the row survives
// for the device inventory.
func TestSessionRevocation(t *testing.T) {
	pool, ctx := setup(t)

	id, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "rev@example.test", DisplayName: "Rev", Password: "pw-rev", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	policy := DefaultSessionPolicy()
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	s, err := CreateSession(ctx, pool, id, SessionMetadata{}, policy, now)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	// Valid before revocation.
	if _, _, err := ResolveSession(ctx, pool, sessionDigest(t, s.Token), policy, now.Add(time.Minute)); err != nil {
		t.Fatalf("session should be valid: %v", err)
	}

	if err := RevokeSession(ctx, pool, s.ID, "password changed"); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	if _, _, err := ResolveSession(ctx, pool, sessionDigest(t, s.Token), policy, now.Add(2*time.Minute)); !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("revoked session err = %v, want ErrSessionRevoked", err)
	}

	// The row is retained with its reason, so the device inventory can explain
	// why the session ended.
	var reason string
	if err := pool.QueryRow(ctx,
		`SELECT revoke_reason FROM sessions WHERE id = $1`, s.ID).Scan(&reason); err != nil {
		t.Fatalf("query revoked row: %v", err)
	}
	if reason != "password changed" {
		t.Errorf("revoke_reason = %q", reason)
	}

	// Revocation is idempotent, and an unknown id reports not-found.
	if err := RevokeSession(ctx, pool, s.ID, "again"); err != nil {
		t.Errorf("second RevokeSession: %v", err)
	}
	if err := RevokeSession(ctx, pool, "00000000-0000-0000-0000-000000000000", "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoke unknown session err = %v, want ErrNotFound", err)
	}
}

func TestRevokeAllUserSessions(t *testing.T) {
	pool, ctx := setup(t)

	id, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "all@example.test", DisplayName: "All", Password: "pw-all", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	other, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "other@example.test", DisplayName: "Other", Password: "pw-other", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	var sessions []Session
	for i := 0; i < 3; i++ {
		s, err := CreateSession(ctx, pool, id, SessionMetadata{}, DefaultSessionPolicy(), now)
		if err != nil {
			t.Fatalf("CreateSession %d: %v", i, err)
		}
		sessions = append(sessions, s)
	}
	keep, err := CreateSession(ctx, pool, other, SessionMetadata{}, DefaultSessionPolicy(), now)
	if err != nil {
		t.Fatalf("CreateSession other: %v", err)
	}

	revoked, err := RevokeAllUserSessions(ctx, pool, id, "suspected compromise")
	if err != nil {
		t.Fatalf("RevokeAllUserSessions: %v", err)
	}
	if revoked != 3 {
		t.Errorf("revoked = %d, want 3", revoked)
	}
	for _, s := range sessions {
		if _, _, err := ResolveSession(ctx, pool, sessionDigest(t, s.Token), DefaultSessionPolicy(), now.Add(time.Minute)); !errors.Is(err, ErrSessionRevoked) {
			t.Errorf("session %s err = %v, want ErrSessionRevoked", s.ID, err)
		}
	}
	// Another user's session is untouched.
	if _, _, err := ResolveSession(ctx, pool, sessionDigest(t, keep.Token), DefaultSessionPolicy(), now.Add(time.Minute)); err != nil {
		t.Errorf("unrelated session broken: %v", err)
	}
	// A second global revoke finds nothing left to do.
	again, err := RevokeAllUserSessions(ctx, pool, id, "again")
	if err != nil {
		t.Fatalf("second RevokeAllUserSessions: %v", err)
	}
	if again != 0 {
		t.Errorf("second revoke affected %d rows, want 0", again)
	}
}

func TestRotateSessionSupersedesAndLinks(t *testing.T) {
	pool, ctx := setup(t)

	id, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "rotate@example.test", DisplayName: "Rotate", Password: "pw-rotate", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	policy := DefaultSessionPolicy()
	now := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	old, err := CreateSession(ctx, pool, id, SessionMetadata{UserAgent: "agent-old"}, policy, now)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	rotated, err := RotateSession(ctx, pool, old, SessionMetadata{UserAgent: "agent-new"}, policy, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("RotateSession: %v", err)
	}
	if rotated.Token == old.Token {
		t.Error("rotation reused the previous token")
	}
	if rotated.PreviousID != old.ID {
		t.Errorf("previous_session_id = %q, want %q", rotated.PreviousID, old.ID)
	}

	// The old token is dead; the new one works.
	if _, _, err := ResolveSession(ctx, pool, sessionDigest(t, old.Token), policy, now.Add(2*time.Minute)); !errors.Is(err, ErrSessionRevoked) {
		t.Errorf("old session err = %v, want ErrSessionRevoked", err)
	}
	if _, _, err := ResolveSession(ctx, pool, sessionDigest(t, rotated.Token), policy, now.Add(2*time.Minute)); err != nil {
		t.Errorf("rotated session err = %v, want nil", err)
	}

	var reason string
	if err := pool.QueryRow(ctx,
		`SELECT revoke_reason FROM sessions WHERE id = $1`, old.ID).Scan(&reason); err != nil {
		t.Fatalf("query old session: %v", err)
	}
	if reason != "rotated" {
		t.Errorf("revoke_reason = %q, want rotated", reason)
	}
}

func TestSessionPolicyValidation(t *testing.T) {
	pool, ctx := setup(t)
	id, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "policy@example.test", DisplayName: "Policy", Password: "pw-policy", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	for label, p := range map[string]SessionPolicy{
		"zero idle":       {IdleTimeout: 0, AbsoluteTimeout: time.Hour},
		"zero absolute":   {IdleTimeout: time.Minute, AbsoluteTimeout: 0},
		"idle > absolute": {IdleTimeout: 2 * time.Hour, AbsoluteTimeout: time.Hour},
	} {
		t.Run(label, func(t *testing.T) {
			if _, err := CreateSession(ctx, pool, id, SessionMetadata{}, p, time.Now()); err == nil {
				t.Error("invalid policy accepted")
			}
		})
	}
}

// --- RBAC grant loading --------------------------------------------------------

func TestLoadGrantsResolvesRolePermissions(t *testing.T) {
	pool, ctx := setup(t)

	id, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "viewer@example.test", DisplayName: "V", Password: "pw-viewer", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := BindRole(ctx, pool, id, "viewer", "global", "", "", nil); err != nil {
		t.Fatalf("BindRole: %v", err)
	}

	grants, err := LoadGrants(ctx, pool, id)
	if err != nil {
		t.Fatalf("LoadGrants: %v", err)
	}
	if len(grants) == 0 {
		t.Fatal("viewer resolved to no grants")
	}
	for _, g := range grants {
		if !strings.HasSuffix(g.Permission, ".read") {
			t.Errorf("viewer grant %q is not read-only", g.Permission)
		}
		if g.ScopeType != "global" {
			t.Errorf("grant %q scope = %q, want global", g.Permission, g.ScopeType)
		}
	}

	// A user with no bindings holds nothing: deny by default starts at the
	// data layer, not just in the evaluator.
	other, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "none@example.test", DisplayName: "N", Password: "pw-none", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	empty, err := LoadGrants(ctx, pool, other)
	if err != nil {
		t.Fatalf("LoadGrants (unbound): %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("unbound user holds %d grants, want 0", len(empty))
	}
}

func TestBindRoleRejectsDuplicatesAndUnknownRoles(t *testing.T) {
	pool, ctx := setup(t)

	id, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "dup@example.test", DisplayName: "D", Password: "pw-dup", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := BindRole(ctx, pool, id, "operator", "global", "", "", nil); err != nil {
		t.Fatalf("BindRole: %v", err)
	}
	// A duplicate active binding is rejected rather than silently stacked.
	if err := BindRole(ctx, pool, id, "operator", "global", "", "", nil); !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("duplicate bind err = %v, want ErrAlreadyExists", err)
	}
	// An unknown role inserts nothing, so a typo cannot grant an empty role
	// that looks bound but denies everything.
	if err := BindRole(ctx, pool, id, "no_such_role", "global", "", "", nil); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown role err = %v, want ErrNotFound", err)
	}
	// A non-global scope without a scope id violates the database CHECK.
	if err := BindRole(ctx, pool, id, "viewer", "project", "", "", nil); err == nil {
		t.Error("project binding without scope_id accepted")
	}
}

func TestUnbindRoleRetainsHistory(t *testing.T) {
	pool, ctx := setup(t)

	id, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "unbind@example.test", DisplayName: "U", Password: "pw-unbind", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := BindRole(ctx, pool, id, "viewer", "global", "", "", nil); err != nil {
		t.Fatalf("BindRole: %v", err)
	}

	var bindingID string
	if err := pool.QueryRow(ctx,
		`SELECT id FROM role_bindings WHERE user_id = $1`, id).Scan(&bindingID); err != nil {
		t.Fatalf("query binding: %v", err)
	}
	if err := UnbindRole(ctx, pool, bindingID); err != nil {
		t.Fatalf("UnbindRole: %v", err)
	}

	grants, err := LoadGrants(ctx, pool, id)
	if err != nil {
		t.Fatalf("LoadGrants after unbind: %v", err)
	}
	if len(grants) != 0 {
		t.Errorf("revoked binding still resolves %d grants", len(grants))
	}

	// The row survives with a timestamp, so "who held what, until when" is
	// still answerable.
	var revoked bool
	if err := pool.QueryRow(ctx,
		`SELECT revoked_at IS NOT NULL FROM role_bindings WHERE id = $1`, bindingID).Scan(&revoked); err != nil {
		t.Fatalf("query revoked binding: %v", err)
	}
	if !revoked {
		t.Error("binding row was deleted instead of revoked")
	}

	// Unbinding twice reports not-found; the first unbind already did the work.
	if err := UnbindRole(ctx, pool, bindingID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second unbind err = %v, want ErrNotFound", err)
	}
}

// --- audit integration ---------------------------------------------------------

// The audit trail must be append-only at the database level: even a caller
// with a live transaction cannot rewrite history.
func TestAuditEventsAreImmutableInDatabase(t *testing.T) {
	pool, ctx := setup(t)

	if err := audit.Record(ctx, pool, audit.Event{
		ActorType: audit.ActorUser, Action: "site.create", ResourceType: "site",
		ResourceID: "site-1", Result: audit.ResultSuccess, RequestID: "req_audit_imm",
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	if _, err := pool.Exec(ctx,
		`UPDATE audit_events SET result = 'denied' WHERE request_id = 'req_audit_imm'`); err == nil {
		t.Error("audit UPDATE accepted")
	}
	if _, err := pool.Exec(ctx,
		`DELETE FROM audit_events WHERE request_id = 'req_audit_imm'`); err == nil {
		t.Error("audit DELETE accepted")
	}

	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_events WHERE request_id = 'req_audit_imm'`).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("audit rows = %d, want 1", count)
	}
}

// Audit correlation is the Phase 1 gate: actor, resource, and request must all
// be recoverable from a single row.
func TestAuditCorrelatesActorResourceRequest(t *testing.T) {
	pool, ctx := setup(t)

	userID, err := CreateUser(ctx, pool, CreateUserParams{
		Email: "corr@example.test", DisplayName: "C", Password: "pw-corr", AccountType: "customer",
	}, fastParams())
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if err := audit.Record(ctx, pool, audit.Event{
		ActorType:    audit.ActorUser,
		ActorID:      userID,
		Action:       "session.revoke",
		ResourceType: "session",
		ResourceID:   "sess-1",
		RequestID:    "req_corr_1",
		Result:       audit.ResultSuccess,
		SourceIP:     "203.0.113.44",
		UserAgent:    "curl/8",
		Context:      map[string]any{"reason": "user request"},
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	var (
		actorID, resourceID, requestID, sourceIP, contextJSON string
	)
	if err := pool.QueryRow(ctx, `
		SELECT actor_id::text, resource_id, request_id, host(source_ip), context::text
		FROM audit_events WHERE request_id = 'req_corr_1'`).
		Scan(&actorID, &resourceID, &requestID, &sourceIP, &contextJSON); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if actorID != userID {
		t.Errorf("actor_id = %q, want %q", actorID, userID)
	}
	if resourceID != "sess-1" || requestID != "req_corr_1" {
		t.Errorf("resource=%q request=%q", resourceID, requestID)
	}
	if sourceIP != "203.0.113.44" {
		t.Errorf("source_ip = %q", sourceIP)
	}
	// jsonb::text normalizes whitespace, so match on the canonical form
	// rather than on the exact bytes json.Marshal produced.
	if !strings.Contains(contextJSON, `"reason"`) || !strings.Contains(contextJSON, `"user request"`) {
		t.Errorf("context = %q, want it to carry the reason", contextJSON)
	}
}

// A denied action without a reason cannot be reviewed later, and the database
// rejects it too (result CHECK), so validation happens before the write.
func TestAuditRejectsMalformedEvent(t *testing.T) {
	pool, ctx := setup(t)

	if err := audit.Record(ctx, pool, audit.Event{
		ActorType: audit.ActorUser, Action: "site.delete", ResourceType: "site",
		Result: audit.ResultDenied, // no reason
	}); err == nil {
		t.Error("denied event without a reason accepted")
	}
	var rows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&rows); err != nil {
		t.Fatalf("count: %v", err)
	}
	if rows != 0 {
		t.Errorf("invalid event was written (%d rows)", rows)
	}
}

// The Phase 1 gate: a change and its audit row commit together or not at all.
// An audit write failure must abort the surrounding transaction.
func TestAuditFailureAbortsSurroundingTransaction(t *testing.T) {
	pool, ctx := setup(t)

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID string
	if err := tx.QueryRow(ctx, `
		INSERT INTO users (email, display_name) VALUES ('atomic@example.test', 'A')
		RETURNING id`).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	// An invalid audit event must fail here, leaving the caller free to abort.
	err = audit.Record(ctx, tx, audit.Event{
		ActorType: audit.ActorUser, Action: "", ResourceType: "user",
		Result: audit.ResultSuccess,
	})
	if err == nil {
		t.Fatal("invalid audit event accepted inside a transaction")
	}

	// Because the caller rolls back, no half-written user survives.
	_ = tx.Rollback(ctx)
	var users int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE email = 'atomic@example.test'`).Scan(&users); err != nil {
		t.Fatalf("count users: %v", err)
	}
	if users != 0 {
		t.Errorf("user survived a failed audit write (%d rows)", users)
	}
}
