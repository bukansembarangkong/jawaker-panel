// Package certs owns the certificate inventory and the hostname-to-certificate
// binding state machine.
//
// Invariant enforced by this package and the schema (migrations/0014):
//
//   - CERTIFICATES TABLE HOLDS NO KEY MATERIAL, EVER (SECURITY.md §8,
//     DATABASE.md §12). The private key lives in secret_values (internal/secret)
//     under a secret:// reference; this table holds only metadata and the public
//     chain PEM. A query over this table cannot leak a private key.
//
//   - Safe renewal binding (PRD.md §15.4): "retain the previous valid certificate
//     until the new certificate proves healthy." The binding join table
//     domain_certificates keeps historical activations; activating a new
//     certificate deactivates the previous one in ONE transaction, so rollback
//     always has a row to return to and the partial unique index guarantees
//     exactly one current certificate per domain at any commit boundary.
package certs

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors. Callers branch on these.
var (
	ErrInvalid   = errors.New("certs: invalid argument")
	ErrNotFound  = errors.New("certs: not found")
	ErrState     = errors.New("certs: invalid state transition")
	ErrNotActive = errors.New("certs: certificate is not active")
)

// Lifecycle states (migrations/0014 L320-322).
const (
	StateActive     = "active"
	StateExpiring   = "expiring"
	StateExpired    = "expired"
	StateRevoked    = "revoked"
	StateSuperseded = "superseded"
)

// DefaultRenewalWindow is how far before not_after a certificate is considered
// due for renewal. 30 days matches PRD.md conventions.
const DefaultRenewalWindow = 30 * 24 * time.Hour

// Certificate is one certificate inventory row. It carries public material
// only; PrivateKey lives in the secret subsystem.
type Certificate struct {
	ID            string
	ProjectID     string
	IssuedAt      time.Time
	NotAfter      time.Time
	Identifiers   []string
	Issuer        string
	DirectoryURL  string
	SerialHex     string
	SecretRef     string
	ChainPEM      string
	State         string
	IssuedByJobID *string
	ReplacesID    *string
	RevokedAt     *time.Time
	RevokeReason  string
	CreatedAt     time.Time
	DeletedAt     *time.Time
}

// Live reports whether the certificate is not tombstoned.
func (c Certificate) Live() bool { return c.DeletedAt == nil }

// Usable reports whether the certificate may be bound to serve traffic.
func (c Certificate) Usable() bool {
	return c.Live() && (c.State == StateActive || c.State == StateExpiring)
}

const certColumns = `id, project_id, issued_at, not_after, identifiers,
	issuer, directory_url, serial_hex, secret_ref, chain_pem,
	state, issued_by_job_id, replaces_id, revoked_at, revoke_reason,
	created_at, deleted_at`

func scanCert(row pgx.Row) (Certificate, error) {
	var c Certificate
	err := row.Scan(&c.ID, &c.ProjectID, &c.IssuedAt, &c.NotAfter, &c.Identifiers,
		&c.Issuer, &c.DirectoryURL, &c.SerialHex, &c.SecretRef, &c.ChainPEM,
		&c.State, &c.IssuedByJobID, &c.ReplacesID, &c.RevokedAt, &c.RevokeReason,
		&c.CreatedAt, &c.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Certificate{}, ErrNotFound
	}
	if err != nil {
		return Certificate{}, fmt.Errorf("certs: scan cert: %w", err)
	}
	return c, nil
}

// Store reads and writes certificates and their domain bindings.
type Store struct {
	pool    *pgxpool.Pool
	secrets *secret.Store
	clock   func() time.Time
}

// NewStore builds a certs store. secrets may be nil if private-key operations
// are not needed (e.g. read-only inventory queries).
func NewStore(pool *pgxpool.Pool, secrets *secret.Store, now func() time.Time) *Store {
	clock := now
	if clock == nil {
		clock = time.Now
	}
	return &Store{pool: pool, secrets: secrets, clock: clock}
}

// RecordParams configures certificate recording.
type RecordParams struct {
	ProjectID    string
	IssuedAt     time.Time
	NotAfter     time.Time
	Identifiers  []string
	Issuer       string
	DirectoryURL string
	SerialHex    string
	// PrivateKeyPEM is sealed into the secret subsystem; the row stores only
	// the resulting reference. Never stored plaintext.
	PrivateKeyPEM string
	ChainPEM      string
	IssuedByJobID string
	ReplacesID    string
}

// Record seals the private key into the secret store, then inserts the
// certificate inventory row. Both are written so a certificate cannot exist
// without its key reference.
func (s *Store) Record(ctx context.Context, p RecordParams) (Certificate, error) {
	projectID := strings.TrimSpace(p.ProjectID)
	if projectID == "" {
		return Certificate{}, fmt.Errorf("%w: project_id is required", ErrInvalid)
	}
	if len(p.Identifiers) == 0 || len(p.Identifiers) > 100 {
		return Certificate{}, fmt.Errorf("%w: identifiers must contain between 1 and 100 hostnames", ErrInvalid)
	}
	if !p.NotAfter.After(p.IssuedAt) {
		return Certificate{}, fmt.Errorf("%w: not_after must be after issued_at", ErrInvalid)
	}
	if strings.TrimSpace(p.PrivateKeyPEM) == "" {
		return Certificate{}, fmt.Errorf("%w: private_key_pem is required", ErrInvalid)
	}
	if strings.TrimSpace(p.ChainPEM) == "" {
		return Certificate{}, fmt.Errorf("%w: chain_pem is required", ErrInvalid)
	}
	if s.secrets == nil {
		return Certificate{}, errors.New("certs: secret store is required to record a certificate")
	}

	// Reference format: secret://certificates/<uuid>/key
	// Pre-generate the ref via the pool so the secret row and cert row share it.
	var certID string
	if err := s.pool.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&certID); err != nil {
		return Certificate{}, fmt.Errorf("certs: generate id: %w", err)
	}
	ref := fmt.Sprintf("secret://certificates/%s/key", certID)

	if err := s.secrets.Create(ctx, ref, p.PrivateKeyPEM, fmt.Sprintf("TLS private key for certificate %s", certID)); err != nil {
		return Certificate{}, fmt.Errorf("certs: seal private key: %w", err)
	}

	var replacesID any
	if v := strings.TrimSpace(p.ReplacesID); v != "" {
		replacesID = v
	}
	var jobID any
	if v := strings.TrimSpace(p.IssuedByJobID); v != "" {
		jobID = v
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO certificates (
			id, project_id, issued_at, not_after, identifiers,
			issuer, directory_url, serial_hex, secret_ref, chain_pem,
			state, issued_by_job_id, replaces_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'active', $11, $12)
		RETURNING %s`, certColumns),
		certID, projectID, p.IssuedAt, p.NotAfter, p.Identifiers,
		p.Issuer, p.DirectoryURL, p.SerialHex, ref, p.ChainPEM,
		jobID, replacesID)

	cert, err := scanCert(row)
	if err != nil {
		// Clean up the sealed key on insert failure so orphan ciphertext does
		// not accumulate.
		_ = s.secrets.Delete(ctx, ref)
		if isForeignKeyViolation(err) {
			return Certificate{}, fmt.Errorf("%w: the project does not exist", ErrInvalid)
		}
		return Certificate{}, err
	}
	return cert, nil
}

// Get returns one certificate by id.
func (s *Store) Get(ctx context.Context, id string) (Certificate, error) {
	if strings.TrimSpace(id) == "" {
		return Certificate{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT %s FROM certificates WHERE id = $1 AND deleted_at IS NULL`, certColumns), id)
	return scanCert(row)
}

// OpenKey retrieves and decrypts the private key for a certificate from the
// secret subsystem. This is reachable only through an explicit call and is never
// returned by ordinary inventory queries.
func (s *Store) OpenKey(ctx context.Context, cert Certificate) (string, error) {
	if s.secrets == nil {
		return "", errors.New("certs: secret store is not configured")
	}
	if cert.SecretRef == "" {
		return "", errors.New("certs: certificate has no secret reference")
	}
	return s.secrets.Open(ctx, cert.SecretRef)
}

// Bind activates a certificate for a domain in ONE transaction, deactivating the
// previously current certificate.
//
// This is PRD.md §15.4's safe-renewal invariant in code:
//
//   - The previous binding is kept with deactivated_at = now(); it is NOT
//     deleted, so rollback always has the previous binding to revert to.
//
//   - The deactivate-then-activate pair runs inside one transaction, so the
//     partial unique index domain_certificates_current_unique_idx sees at most
//     one current certificate for the domain at any commit boundary.
//
//   - The candidate certificate MUST be usable (active or expiring); binding a
//     revoked or expired certificate is refused.
func (s *Store) Bind(ctx context.Context, domainID, certID string) error {
	if strings.TrimSpace(domainID) == "" || strings.TrimSpace(certID) == "" {
		return fmt.Errorf("%w: domain_id and cert_id are required", ErrInvalid)
	}

	cert, err := s.Get(ctx, certID)
	if err != nil {
		return err
	}
	if !cert.Usable() {
		return fmt.Errorf("%w: certificate %s is %s", ErrNotActive, certID, cert.State)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("certs: begin bind: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	now := s.clock()

	// Deactivate current binding if any.
	if _, err := tx.Exec(ctx, `
		UPDATE domain_certificates
		   SET is_current = false, deactivated_at = $2
		 WHERE site_domain_id = $1 AND is_current = true`,
		domainID, now); err != nil {
		return fmt.Errorf("certs: deactivate current: %w", err)
	}

	// Insert new current binding.
	if _, err := tx.Exec(ctx, `
		INSERT INTO domain_certificates (site_domain_id, certificate_id, is_current, activated_at)
		VALUES ($1, $2, true, $3)`,
		domainID, certID, now); err != nil {
		return fmt.Errorf("certs: insert binding: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("certs: commit bind: %w", err)
	}
	return nil
}

// CurrentForDomain returns the certificate currently serving a domain, or
// ErrNotFound when no certificate is currently bound.
func (s *Store) CurrentForDomain(ctx context.Context, domainID string) (Certificate, error) {
	if strings.TrimSpace(domainID) == "" {
		return Certificate{}, fmt.Errorf("%w: domain_id is required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT %s FROM certificates c
		  JOIN domain_certificates dc ON dc.certificate_id = c.id
		 WHERE dc.site_domain_id = $1
		   AND dc.is_current = true
		   AND c.deleted_at IS NULL`, certColumnsWithPrefix("c")), domainID)
	return scanCert(row)
}

// ListExpiring returns active certificates whose not_after is within window from
// now. This is the expiry monitor's query; it uses the certificates_expiry_idx
// index.
func (s *Store) ListExpiring(ctx context.Context, window time.Duration) ([]Certificate, error) {
	if window <= 0 {
		window = DefaultRenewalWindow
	}
	cutoff := s.clock().Add(window)
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM certificates
		 WHERE state IN ('active', 'expiring')
		   AND not_after <= $1
		   AND deleted_at IS NULL
		 ORDER BY not_after ASC`, certColumns), cutoff)
	if err != nil {
		return nil, fmt.Errorf("certs: list expiring: %w", err)
	}
	defer rows.Close()

	var out []Certificate
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("certs: iterate expiring: %w", err)
	}
	return out, nil
}

// Revoke marks a certificate as revoked. It does NOT automatically unbind it:
// unbinding and deploying a replacement is an operator decision, and revoking a
// certificate that is serving should be visible as an alert, not a silent outage.
func (s *Store) Revoke(ctx context.Context, id, reason string) (Certificate, error) {
	if strings.TrimSpace(id) == "" {
		return Certificate{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	now := s.clock()
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE certificates
		   SET state = 'revoked', revoked_at = $2, revoke_reason = $3
		 WHERE id = $1
		   AND state <> 'revoked'
		   AND deleted_at IS NULL
		RETURNING %s`, certColumns), id, now, reason)
	cert, err := scanCert(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Certificate{}, fmt.Errorf("%w: cannot revoke", ErrState)
		}
		return Certificate{}, err
	}
	return cert, nil
}

func certColumnsWithPrefix(prefix string) string {
	cols := []string{
		"id", "project_id", "issued_at", "not_after", "identifiers",
		"issuer", "directory_url", "serial_hex", "secret_ref", "chain_pem",
		"state", "issued_by_job_id", "replaces_id", "revoked_at", "revoke_reason",
		"created_at", "deleted_at",
	}
	out := make([]string, len(cols))
	for i, c := range cols {
		out[i] = prefix + "." + c
	}
	return strings.Join(out, ", ")
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}
