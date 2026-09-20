package nodes

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
	"github.com/bukansembarangkong/jawaker-panel/internal/secureid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is the server inventory and enrollment store.
//
// It holds no authority of its own: issuance is the Authority's job, so a Store
// can be constructed and used for reads in tests and in code paths that must not
// be able to mint certificates.
type Store struct {
	pool  *pgxpool.Pool
	clock func() time.Time
}

// NewStore builds a store over a pool.
func NewStore(pool *pgxpool.Pool, now func() time.Time) *Store {
	clock := now
	if clock == nil {
		clock = time.Now
	}
	return &Store{pool: pool, clock: clock}
}

// Server is one managed server.
type Server struct {
	ID           string
	Name         string
	Description  string
	Address      string
	Status       string
	CertStatus   string
	OSFamily     string
	OSVersion    string
	AgentVersion string
	LastSeenAt   *time.Time
	EnrolledAt   *time.Time
	CreatedAt    time.Time
	DeletedAt    *time.Time
}

// Live reports whether the server is not tombstoned.
func (s Server) Live() bool { return s.DeletedAt == nil }

// serverColumns is the shared select list so a scanned Server is always the same
// shape no matter which query produced it.
const serverColumns = `id, name, description, address, status, cert_status,
	os_family, os_version, agent_version, last_seen_at, enrolled_at, created_at, deleted_at`

func scanServer(row pgx.Row) (Server, error) {
	var s Server
	err := row.Scan(&s.ID, &s.Name, &s.Description, &s.Address, &s.Status, &s.CertStatus,
		&s.OSFamily, &s.OSVersion, &s.AgentVersion, &s.LastSeenAt, &s.EnrolledAt,
		&s.CreatedAt, &s.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Server{}, ErrNotFound
	}
	if err != nil {
		return Server{}, fmt.Errorf("nodes: scan server: %w", err)
	}
	return s, nil
}

// --- enrollment tokens --------------------------------------------------------

// TokenLifetime is the default validity of an enrollment token.
//
// Fifteen minutes is long enough to copy a token into an install command and
// short enough that a token leaked into a shell history or a log is stale before
// anyone finds it. SECURITY.md §6 requires "short-lived"; this is the judgement
// call on how short.
const TokenLifetime = 15 * time.Minute

// maxTokenLifetime bounds what an operator may ask for. A token valid for a week
// would satisfy "expires eventually" while being as risky as a standing
// credential, so the ceiling is enforced here rather than left to discipline.
const maxTokenLifetime = 24 * time.Hour

// EnrollmentToken describes a minted token.
type EnrollmentToken struct {
	ID        string
	NodeName  string
	ExpiresAt time.Time
	CreatedBy string
	CreatedAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
}

// CreateTokenParams configures token creation.
type CreateTokenParams struct {
	// NodeName is the intended server name.
	NodeName string
	// CreatedBy is the actor's user id, for the audit trail.
	CreatedBy string
	// Lifetime overrides the default. Zero means TokenLifetime.
	Lifetime time.Duration
}

// CreateToken mints a one-time enrollment token.
//
// The PLAINTEXT is returned exactly once and never stored: only its SHA-256
// digest goes into the database, so no read of this table — including a dump —
// yields a usable token (PRD.md §6.2: "never retained as plaintext after
// exchange").
func (s *Store) CreateToken(ctx context.Context, controllerID string, p CreateTokenParams) (token EnrollmentToken, plaintext string, err error) {
	name := strings.TrimSpace(p.NodeName)
	if !validServerName(name) {
		return token, "", fmt.Errorf("%w: node_name %q is not a valid server name", ErrInvalid, p.NodeName)
	}
	lifetime := p.Lifetime
	if lifetime == 0 {
		lifetime = TokenLifetime
	}
	if lifetime <= 0 || lifetime > maxTokenLifetime {
		return token, "", fmt.Errorf("%w: lifetime must be between 1s and %s", ErrInvalid, maxTokenLifetime)
	}
	if strings.TrimSpace(controllerID) == "" {
		return token, "", errors.New("nodes: controller id is required")
	}

	plaintextToken, digest, err := secureid.EnrollmentToken()
	if err != nil {
		return token, "", fmt.Errorf("nodes: generate token: %w", err)
	}
	// BOTH timestamps come from this process's clock.
	//
	// created_at has a database default, and relying on it would mix two clocks
	// in one row: expires_at computed here, created_at computed by PostgreSQL.
	// The schema's expiry-after-creation check then fails whenever the
	// application clock runs behind the database clock, which is an ordinary
	// NTP drift, not a misconfiguration. Reading the failure back would say
	// "constraint violated" and point at nothing the operator did.
	createdAt := s.clock().UTC()
	expiresAt := createdAt.Add(lifetime)

	err = s.pool.QueryRow(ctx, `
		INSERT INTO enrollment_tokens (token_hash, controller_id, node_name, expires_at, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, node_name, expires_at, created_at`,
		digest, controllerID, name, expiresAt, createdAt, nullableUUID(p.CreatedBy)).
		Scan(&token.ID, &token.NodeName, &token.ExpiresAt, &token.CreatedAt)
	if err != nil {
		return token, "", fmt.Errorf("nodes: create enrollment token: %w", err)
	}
	token.CreatedBy = p.CreatedBy
	return token, plaintextToken, nil
}

// ListTokens returns live and recently-spent tokens for the UI.
//
// Plaintexts are absent by construction: they were never stored. The list shows
// enough to recognize a token (name, expiry, whether it was used) without
// revealing anything usable.
func (s *Store) ListTokens(ctx context.Context, limit int) ([]EnrollmentToken, error) {
	if limit <= 0 || limit > 200 {
		return nil, fmt.Errorf("%w: limit must be between 1 and 200", ErrInvalid)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, node_name, expires_at, created_at, used_at, revoked_at
		FROM enrollment_tokens
		ORDER BY created_at DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("nodes: list enrollment tokens: %w", err)
	}
	defer rows.Close()

	out := make([]EnrollmentToken, 0, limit)
	for rows.Next() {
		var t EnrollmentToken
		if err := rows.Scan(&t.ID, &t.NodeName, &t.ExpiresAt, &t.CreatedAt, &t.UsedAt, &t.RevokedAt); err != nil {
			return nil, fmt.Errorf("nodes: scan enrollment token: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("nodes: iterate enrollment tokens: %w", err)
	}
	return out, nil
}

// RevokeToken invalidates a token that was never used.
//
// Revoking a spent token is refused: the states are mutually exclusive in the
// schema, and a caller trying it is either confused or probing.
func (s *Store) RevokeToken(ctx context.Context, tokenID, actorID string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE enrollment_tokens
		   SET revoked_at = $1
		 WHERE id = $2 AND used_at IS NULL AND revoked_at IS NULL`,
		s.clock().UTC(), tokenID)
	if err != nil {
		if isCheckViolation(err) {
			return fmt.Errorf("%w: token was already used", ErrStatus)
		}
		return fmt.Errorf("nodes: revoke enrollment token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	_ = actorID // attribution is recorded by the caller in the audit trail
	return nil
}

// --- server inventory ---------------------------------------------------------

// ListServers returns live servers, newest first, with a total for pagination.
//
// Tombstoned servers are excluded: the fleet view answers "what am I managing
// now?", and mixing in deleted rows makes that question ambiguous. The status
// filter is an explicit allowlist — an arbitrary value would either silently
// return nothing or, if interpolated, become an injection surface.
func (s *Store) ListServers(ctx context.Context, limit, offset int, status string) ([]Server, int, error) {
	if limit <= 0 || limit > 200 {
		return nil, 0, fmt.Errorf("%w: limit must be between 1 and 200", ErrInvalid)
	}
	if offset < 0 {
		return nil, 0, fmt.Errorf("%w: offset cannot be negative", ErrInvalid)
	}
	// A NULL filter means "any live status", so one predicate serves both cases
	// and the count can never disagree with the page it accompanies.
	var filter any
	switch status {
	case "":
		filter = nil
	case "pending", "active", "suspended":
		filter = status
	default:
		return nil, 0, fmt.Errorf("%w: unknown status filter %q", ErrInvalid, status)
	}

	var total int
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM servers
		WHERE deleted_at IS NULL AND ($1::text IS NULL OR status = $1)`, filter).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("nodes: count servers: %w", err)
	}

	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM servers
		WHERE deleted_at IS NULL AND ($3::text IS NULL OR status = $3)
		ORDER BY created_at DESC, id
		LIMIT $1 OFFSET $2`, serverColumns), limit, offset, filter)
	if err != nil {
		return nil, 0, fmt.Errorf("nodes: list servers: %w", err)
	}
	defer rows.Close()

	out := make([]Server, 0, limit)
	for rows.Next() {
		srv, err := scanServer(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, srv)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("nodes: iterate servers: %w", err)
	}
	return out, total, nil
}

// GetServer returns one live server by id.
func (s *Store) GetServer(ctx context.Context, id string) (Server, error) {
	query := fmt.Sprintf(`SELECT %s FROM servers WHERE id = $1 AND deleted_at IS NULL`, serverColumns)
	return scanServer(s.pool.QueryRow(ctx, query, id))
}

// --- enrollment ---------------------------------------------------------------

// EnrollmentResult is what a successful enrollment produces.
//
// It contains NO PRIVATE KEY. The node generated its own key pair and sent only
// the public half, so the controller has nothing secret to hold: a compromise of
// the control plane can issue identities but cannot authenticate as an already
// enrolled node. This is why the field set here is certificate material only.
type EnrollmentResult struct {
	Server      Server
	NodeURI     string
	CertPEM     []byte
	Serial      string
	Fingerprint string
	NotBefore   time.Time
	NotAfter    time.Time
}

// RedeemRequest carries everything a node presents during enrollment.
//
// It is a struct rather than a growing parameter list because enrollment has
// several independent facts and positional arguments for them would let a caller
// pass an OS family where a version belongs without the compiler objecting.
type RedeemRequest struct {
	// Token is the presented one-time enrollment token.
	Token string
	// PublicKey is the node's OWN public key. The controller signs it and never
	// sees the matching private half, so a controller compromise can mint
	// identities but cannot authenticate as an already-enrolled node.
	PublicKey crypto.PublicKey
	// NodeAddress is the host:port the controller dials for agent operations.
	NodeAddress string
	// AgentVersion, OSFamily and OSVersion are the facts the agent reports about
	// itself. They are recorded at enrollment rather than waiting for the first
	// heartbeat, so a server row is never "active" with no idea what is running
	// on it.
	AgentVersion string
	OSFamily     string
	OSVersion    string
}

// Redeem exchanges a one-time token for a long-lived node identity.
//
// Everything happens in ONE transaction. See the package comment for why: a
// partial enrollment is an installation that can neither retry nor proceed.
//
// The first statement claims the token with a conditional UPDATE, so two
// concurrent redemptions of one token cannot both succeed.
func (s *Store) Redeem(ctx context.Context, auth *Authority, req RedeemRequest) (EnrollmentResult, error) {
	if auth == nil {
		return EnrollmentResult{}, errors.New("nodes: authority is required")
	}
	if req.PublicKey == nil {
		return EnrollmentResult{}, fmt.Errorf("%w: a node public key is required", ErrInvalid)
	}
	address, err := validNodeAddress(req.NodeAddress)
	if err != nil {
		return EnrollmentResult{}, err
	}
	osFamily, err := boundedHostFact("os_family", req.OSFamily, 32)
	if err != nil {
		return EnrollmentResult{}, err
	}
	osVersion, err := boundedHostFact("os_version", req.OSVersion, 64)
	if err != nil {
		return EnrollmentResult{}, err
	}
	agentVersion, err := boundedHostFact("agent_version", req.AgentVersion, 64)
	if err != nil {
		return EnrollmentResult{}, err
	}
	digest, err := tokenDigest(req.Token)
	if err != nil {
		return EnrollmentResult{}, ErrTokenInvalid
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("nodes: begin enrollment: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Step 1: claim the token. This is the single-use gate, and it is a
	// database row lock rather than an application check.
	//
	// The returned controller_id and node_name are the binding: a token minted
	// by another installation fails the equality test below and is refused.
	var (
		tokenID      string
		controllerID string
		nodeName     string
	)
	err = tx.QueryRow(ctx, `
		UPDATE enrollment_tokens
		   SET used_at = $1
		 WHERE token_hash = $2
		   AND used_at IS NULL
		   AND revoked_at IS NULL
		   AND expires_at > $1
		RETURNING id, controller_id, node_name`,
		s.clock().UTC(), digest).Scan(&tokenID, &controllerID, &nodeName)
	if errors.Is(err, pgx.ErrNoRows) {
		// One error for every refusal reason. Distinguishing "expired" from
		// "unknown" from "already used" would tell a caller holding a guessed
		// token whether the guess was structurally valid.
		return EnrollmentResult{}, ErrTokenInvalid
	}
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("nodes: claim enrollment token: %w", err)
	}
	// The token is bound to the controller that minted it. A token that is valid
	// on another installation must not enroll here.
	if controllerID != auth.ControllerID() {
		return EnrollmentResult{}, ErrTokenInvalid
	}

	// Step 2: create the server. The NAME comes from the token, not from the
	// caller, so an attacker holding a token cannot pick a name that collides
	// with an existing server or impersonate one. The address and host facts come
	// from the caller, because only the node knows where it listens and what it
	// runs — they are descriptive, not identity-bearing, and are validated above.
	//
	// enrolled_at is set here rather than by a follow-up UPDATE so the row is
	// never briefly "active but not enrolled", which a concurrent list would
	// render as a server with no enrollment time.
	var server Server
	now := s.clock().UTC()
	err = tx.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO servers (name, address, os_family, os_version, agent_version,
		                     status, enrolled_at, created_by)
		VALUES ($1, $2, $3, $4, $5, 'active', $6,
		        (SELECT created_by FROM enrollment_tokens WHERE id = $7))
		RETURNING %s`, serverColumns),
		nodeName, address, osFamily, osVersion, agentVersion, now, tokenID).Scan(
		&server.ID, &server.Name, &server.Description, &server.Address, &server.Status,
		&server.CertStatus, &server.OSFamily, &server.OSVersion, &server.AgentVersion,
		&server.LastSeenAt, &server.EnrolledAt, &server.CreatedAt, &server.DeletedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return EnrollmentResult{}, ErrNameTaken
		}
		return EnrollmentResult{}, fmt.Errorf("nodes: create server: %w", err)
	}

	// Step 3: issue the node certificate for the key the NODE generated. The
	// returned Leaf deliberately carries no private key material: the controller
	// never had it. See pki.CA.IssueLeafForKey for why that distinction is a
	// security property and not a tidiness preference.
	leaf, err := auth.IssueNodeLeafForKey(server.ID, req.PublicKey)
	if err != nil {
		return EnrollmentResult{}, err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO node_identities (server_id, controller_id, node_uri)
		VALUES ($1, $2, $3)`,
		server.ID, controllerID, NodeIdentity(server.ID).String())
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("nodes: record node identity: %w", err)
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO node_certificates (serial, server_id, fingerprint, not_before, not_after)
		VALUES ($1, $2, $3, $4, $5)`,
		leaf.SerialHex(), server.ID, leaf.Fingerprint(), leaf.Cert().NotBefore, leaf.Cert().NotAfter)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("nodes: record node certificate: %w", err)
	}
	_, err = tx.Exec(ctx, `
		UPDATE servers SET cert_status = 'active' WHERE id = $1`, server.ID)
	if err != nil {
		return EnrollmentResult{}, fmt.Errorf("nodes: mark certificate active: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return EnrollmentResult{}, fmt.Errorf("nodes: commit enrollment: %w", err)
	}
	server.CertStatus = "active"
	return EnrollmentResult{
		Server:      server,
		NodeURI:     NodeIdentity(server.ID).String(),
		CertPEM:     leaf.CertPEM(),
		Serial:      leaf.SerialHex(),
		Fingerprint: leaf.Fingerprint(),
		NotBefore:   leaf.Cert().NotBefore,
		NotAfter:    leaf.Cert().NotAfter,
	}, nil
}

// validNodeAddress checks the address the controller will dial.
//
// It must be a literal host:port and must be bounded. The value is later handed
// to net.Dial, so an unvalidated string is a request-forgery primitive: an agent
// could register an address pointing at the controller's own database port, and
// a subsequent "restart service" would open a connection somewhere unexpected.
// SplitHostPort also refuses the forms that are ambiguous about where the port
// begins, which is the check that matters most here.
func validNodeAddress(raw string) (string, error) {
	address := strings.TrimSpace(raw)
	if address == "" {
		return "", fmt.Errorf("%w: a node address is required", ErrInvalid)
	}
	if len(address) > 255 {
		return "", fmt.Errorf("%w: node address is too long", ErrInvalid)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("%w: node address must be host:port: %v", ErrInvalid, err)
	}
	if host == "" || port == "" {
		return "", fmt.Errorf("%w: node address needs both a host and a port", ErrInvalid)
	}
	return address, nil
}

// boundedHostFact trims and bounds a self-reported host fact.
//
// These are agent-supplied and end up in a list view, so they are length-bounded
// rather than trusted. An empty value is allowed: a platform that cannot report
// its OS version should still be able to enroll, and an empty cell is honest
// where a fabricated one is not.
func boundedHostFact(field, raw string, max int) (string, error) {
	v := strings.TrimSpace(raw)
	if len(v) > max {
		return "", fmt.Errorf("%w: %s exceeds %d characters", ErrInvalid, field, max)
	}
	return v, nil
}

// tokenDigest computes the stored digest for a presented token.
//
// The computation lives in secureid, beside the generator, so the canonical form
// cannot drift between minting and lookup. This wrapper only maps a malformed
// value onto the same opaque ErrTokenInvalid as a well-formed-but-unknown one,
// so the shape of a presented token reveals nothing to the caller.
func tokenDigest(presented string) ([]byte, error) {
	digest, err := secureid.HashEnrollmentToken(presented)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenInvalid, err)
	}
	return digest, nil
}

// --- certificate revocation ---------------------------------------------------

// RevokeCertificate marks a certificate revoked and updates the server's
// rollup. The reason is required by the schema: a revocation without one is an
// audit gap.
//
// Revocation takes effect at the next connection because the listener checks the
// serial against this table; there is no CRL to distribute, and no window during
// which a revoked node keeps working because the fleet has not been told yet.
func (s *Store) RevokeCertificate(ctx context.Context, serverID, serial, reason string) error {
	if strings.TrimSpace(reason) == "" {
		return fmt.Errorf("%w: a revocation reason is required", ErrInvalid)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("nodes: begin revocation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		UPDATE node_certificates
		   SET revoked_at = $1, revoke_reason = $2
		 WHERE serial = $3 AND server_id = $4 AND revoked_at IS NULL`,
		s.clock().UTC(), strings.TrimSpace(reason), serial, serverID)
	if err != nil {
		return fmt.Errorf("nodes: revoke certificate: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if _, err := tx.Exec(ctx, `
		UPDATE servers SET cert_status = 'revoked', updated_at = $1 WHERE id = $2`,
		s.clock().UTC(), serverID); err != nil {
		return fmt.Errorf("nodes: update server certificate status: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("nodes: commit revocation: %w", err)
	}
	return nil
}

// IsRevoked reports whether a serial has been revoked.
//
// This is the query the mTLS listener runs per connection. It is deliberately
// small and indexed: a handshake that does a table scan would make every
// connection expensive.
func (s *Store) IsRevoked(ctx context.Context, serial string) (bool, error) {
	var revoked bool
	err := s.pool.QueryRow(ctx, `
		SELECT revoked_at IS NOT NULL FROM node_certificates WHERE serial = $1`, serial).
		Scan(&revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		// A serial we never issued is not "revoked", it is unknown. Refusing it
		// is the caller's job, and it does so by chain validation, not by this
		// query. Returning false here keeps the two concerns separate.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("nodes: check revocation: %w", err)
	}
	return revoked, nil
}

// RecordHeartbeat appends one observation and rolls it up onto the server.
//
// Both happen in ONE transaction, and that is not tidiness: last_seen_at is a
// projection of the observation stream, and a crash between the two writes would
// leave a server that looks offline while a heartbeat row says it reported. The
// list view would then contradict the time series, and the operator would have to
// decide which of the two to believe.
//
// The status is NOT changed here. A heartbeat is an observation, not a state
// transition: a node that reports while suspended must not silently reactivate
// itself, or "suspend" would be a hint rather than a control.
func (s *Store) RecordHeartbeat(ctx context.Context, serverID string, report nodewire.HeartbeatInput) error {
	if strings.TrimSpace(serverID) == "" {
		return fmt.Errorf("%w: a server id is required", ErrInvalid)
	}
	// Validated with the SHARED rules, so an impossible reading is refused with
	// the same message on both ends rather than stored as plausible numbers.
	if err := report.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if report.ObservedAt.IsZero() {
		return fmt.Errorf("%w: observed_at is required", ErrInvalid)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("nodes: begin heartbeat: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO node_heartbeats (server_id, observed_at, received_at,
		                             uptime_seconds, load1_milli,
		                             mem_total_bytes, mem_used_bytes, workload_count)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		serverID, report.ObservedAt.UTC(), s.clock().UTC(),
		report.UptimeSeconds, report.Load1Milli,
		report.MemTotalBytes, report.MemUsedBytes, report.WorkloadCount)
	if err != nil {
		if isForeignKeyViolation(err) {
			// The certificate was valid but the server row is gone: a tombstoned
			// server whose node is still beating. Unknown, not a fault.
			return ErrNotFound
		}
		return fmt.Errorf("nodes: record heartbeat: %w", err)
	}

	// last_seen_at moves forward only. A node with a clock behind the controller
	// would otherwise walk its own last-seen time backwards, making a live server
	// look like it stopped reporting.
	tag, err := tx.Exec(ctx, `
		UPDATE servers
		   SET last_seen_at = GREATEST(coalesce(last_seen_at, $1), $1),
		       updated_at = $2
		 WHERE id = $3 AND deleted_at IS NULL`,
		report.ObservedAt.UTC(), s.clock().UTC(), serverID)
	if err != nil {
		return fmt.Errorf("nodes: update last seen: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("nodes: commit heartbeat: %w", err)
	}
	return nil
}

// RecordCapabilities replaces a server's capability inventory.
//
// Replace-in-place rather than merge: the report is the node's CURRENT truth, and
// merging would keep a capability the node no longer has — a node that lost
// PostgreSQL would still advertise it forever, and the panel would offer work the
// node cannot do.
//
// Delete-then-insert inside one transaction, because the intermediate state of a
// merge-by-upsert is a table that briefly claims capabilities the node just
// disowned, and a concurrent list would read exactly that.
func (s *Store) RecordCapabilities(ctx context.Context, serverID string, result nodewire.CapabilitiesResult) error {
	if strings.TrimSpace(serverID) == "" {
		return fmt.Errorf("%w: a server id is required", ErrInvalid)
	}
	for _, c := range result.Capabilities {
		if strings.TrimSpace(c.Kind) == "" || strings.TrimSpace(c.Name) == "" {
			return fmt.Errorf("%w: a capability needs a kind and a name", ErrInvalid)
		}
		switch c.State {
		case nodewire.CapabilityAvailable, nodewire.CapabilityDegraded, nodewire.CapabilityUnsupported:
		default:
			return fmt.Errorf("%w: unknown capability state %q", ErrInvalid, c.State)
		}
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("nodes: begin capability update: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err = tx.Exec(ctx, `DELETE FROM node_capabilities WHERE server_id = $1`, serverID); err != nil {
		return fmt.Errorf("nodes: clear capabilities: %w", err)
	}
	observedAt := result.ObservedAt.UTC()
	if observedAt.IsZero() {
		observedAt = s.clock().UTC()
	}
	for _, c := range result.Capabilities {
		detail, marshalErr := json.Marshal(detailOrEmpty(c.Detail))
		if marshalErr != nil {
			return fmt.Errorf("nodes: encode capability detail: %w", marshalErr)
		}
		if _, err = tx.Exec(ctx, `
			INSERT INTO node_capabilities (server_id, kind, name, version, state, detail, observed_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			serverID, c.Kind, c.Name, c.Version, c.State, detail, observedAt); err != nil {
			if isForeignKeyViolation(err) {
				return ErrNotFound
			}
			return fmt.Errorf("nodes: record capability %s/%s: %w", c.Kind, c.Name, err)
		}
	}
	tag, err := tx.Exec(ctx, `
		UPDATE servers
		   SET capabilities_observed_at = $1,
		       os_family = coalesce(nullif($2, ''), os_family),
		       os_version = coalesce(nullif($3, ''), os_version),
		       agent_version = coalesce(nullif($4, ''), agent_version),
		       updated_at = $5
		 WHERE id = $6 AND deleted_at IS NULL`,
		observedAt, result.OSFamily, result.OSVersion, result.AgentVersion, s.clock().UTC(), serverID)
	if err != nil {
		return fmt.Errorf("nodes: update server capabilities rollup: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("nodes: commit capability update: %w", err)
	}
	return nil
}

// detailOrEmpty keeps a nil detail map out of the JSON encoder, which would
// produce the literal "null" and violate the column's NOT NULL default.
func detailOrEmpty(detail map[string]any) map[string]any {
	if detail == nil {
		return map[string]any{}
	}
	return detail
}

// ActiveCertificate returns the newest unrevoked certificate for a server.
func (s *Store) ActiveCertificate(ctx context.Context, serverID string) (serial string, fingerprint string, notAfter time.Time, err error) {
	err = s.pool.QueryRow(ctx, `
		SELECT serial, fingerprint, not_after FROM node_certificates
		WHERE server_id = $1 AND revoked_at IS NULL
		ORDER BY not_after DESC
		LIMIT 1`, serverID).Scan(&serial, &fingerprint, &notAfter)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", time.Time{}, ErrNotFound
	}
	if err != nil {
		return "", "", time.Time{}, fmt.Errorf("nodes: read active certificate: %w", err)
	}
	return serial, fingerprint, notAfter, nil
}

// --- status transitions -------------------------------------------------------

// SetStatus transitions a live server's status.
//
// Deleting is the only transition that also stamps deleted_at, because the schema
// ties the two together: allowing 'deleted' with a null timestamp would make
// "when was this removed?" unanswerable, and allowing a timestamp on a live
// server would make the list filter lie.
//
// A tombstoned server cannot be brought back by this function. That is
// deliberate: resurrecting a row whose certificates have been revoked and whose
// name may already be reused by a new server would produce two servers claiming
// one identity. Re-enrollment is the supported path, and it mints a fresh
// identity.
func (s *Store) SetStatus(ctx context.Context, id, status string) error {
	switch status {
	case "active", "suspended", "pending", "deleted":
	default:
		return fmt.Errorf("%w: unknown status %q", ErrInvalid, status)
	}
	// One statement rather than two variants. Two variants meant the 'deleted'
	// branch never referenced the status parameter while still receiving it, and
	// PostgreSQL could not infer the type of an unused placeholder — so every
	// deletion failed with "could not determine data type of parameter $1".
	//
	// The timestamptz cast is required, not decorative: a parameter inside a CASE
	// branch has no column to take its type from, and without the cast PostgreSQL
	// infers text and rejects the assignment. This is the same class of failure
	// as the unused-placeholder one above, so both are spelled out explicitly
	// rather than left to inference.
	tag, err := s.pool.Exec(ctx, `
		UPDATE servers
		   SET status = $1,
		       deleted_at = CASE WHEN $1::text = 'deleted' THEN $2::timestamptz END,
		       updated_at = $2::timestamptz
		 WHERE id = $3 AND deleted_at IS NULL`,
		status, s.clock().UTC(), id)
	if err != nil {
		return fmt.Errorf("nodes: update server status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// --- helpers ------------------------------------------------------------------

// validServerName constrains a server name.
//
// A name is operator-facing text, so it is more permissive than a unit name, but
// it still has to be a single line of bounded length: an unbounded or multiline
// value would be pasted into a list view and could carry markup or a spoofed
// second row.
func validServerName(name string) bool {
	if name == "" || len(name) > 100 {
		return false
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '.', r == '_':
		default:
			return false
		}
	}
	return true
}

// ValidServerName is the exported form, for the HTTP layer to validate input at
// its own boundary and return a clear 400 rather than a constraint error.
func ValidServerName(name string) bool { return validServerName(strings.TrimSpace(name)) }

// ErrInvalid marks a caller error: bad input, not a fault.
var ErrInvalid = errors.New("nodes: invalid argument")

// nullableUUID turns an empty string into a SQL NULL so an optional actor id
// does not fail the uuid type.
func nullableUUID(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

// isUniqueViolation reports a PostgreSQL unique-constraint breach (23505).
func isUniqueViolation(err error) bool { return pgCode(err) == "23505" }

// isCheckViolation reports a CHECK constraint breach (23514).
func isCheckViolation(err error) bool { return pgCode(err) == "23514" }

// isForeignKeyViolation reports a foreign-key breach (23503), which in this
// package means the referenced server row is gone.
func isForeignKeyViolation(err error) bool { return pgCode(err) == "23503" }

func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// IdentityOf returns the pki identity a server authenticates with. It is a
// convenience over NodeIdentity so callers do not have to import pki for this.
func IdentityOf(serverID string) pki.Identity { return NodeIdentity(serverID) }
