// Package mail owns the mail platform data layer:
// domains, mailboxes, aliases, forwarders, DKIM keys,
// rate/abuse limits, and queue log tracing.
//
// Security invariants:
//   - Mailbox passwords stored only as secret URIs (sealed by internal/secret).
//   - DKIM private keys stored only as secret URIs; public key stored plaintext.
//   - No plaintext credentials in any query result.
//   - Open relay is impossible by default (no wildcard catch-all delivery).
package mail

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors.
var (
	ErrNotFound = errors.New("mail: not found")
	ErrConflict = errors.New("mail: already exists")
)

// ── Types ──────────────────────────────────────────────────────────────────────

// Domain is a hosted mail domain for a project.
type Domain struct {
	ID        string
	ProjectID string
	ServerID  string
	Domain    string
	State     string
	SPFOk     *bool
	DKIMOk    *bool
	DMARCOk   *bool
	LastCheck *time.Time
	CreatedAt time.Time
}

// Mailbox is one email account.
type Mailbox struct {
	ID          string
	DomainID    string
	LocalPart   string
	State       string
	QuotaMB     int
	PasswordRef string // secret URI, never plaintext
	CreatedAt   time.Time
	DeletedAt   *time.Time
}

// Alias redirects one local address to a destination.
type Alias struct {
	ID          string
	DomainID    string
	LocalPart   string
	Destination string
	Enabled     bool
	CreatedAt   time.Time
}

// Forwarder forwards all domain mail to an external address.
type Forwarder struct {
	ID          string
	DomainID    string
	Destination string
	KeepLocal   bool
	Enabled     bool
	CreatedAt   time.Time
}

// DKIMKey is a domain's signing key.
type DKIMKey struct {
	ID        string
	DomainID  string
	Selector  string
	KeyRef    string // secret URI
	PublicKey string
	Algorithm string
	CreatedAt time.Time
	RotatedAt *time.Time
}

// RateLimit defines per-domain sending limits.
type RateLimit struct {
	ID         string
	DomainID   string
	MaxPerHour int
	MaxPerDay  int
	MaxRcpt    int
	UpdatedAt  time.Time
}

// QueueEntry is one sampled queue log record.
type QueueEntry struct {
	ID       string
	DomainID string
	QueueID  string
	From     string
	To       string
	Status   string
	Message  string
	LoggedAt time.Time
}

// ── Store ──────────────────────────────────────────────────────────────────────

// Store is the mail data-access layer.
type Store struct{ pool *pgxpool.Pool }

// New creates a Store backed by pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// ── Domain ─────────────────────────────────────────────────────────────────────

const domainColumns = `id, project_id, server_id, domain, state,
    spf_ok, dkim_ok, dmarc_ok, last_check, created_at`

func scanDomain(row pgx.Row) (*Domain, error) {
	d := &Domain{}
	err := row.Scan(&d.ID, &d.ProjectID, &d.ServerID, &d.Domain, &d.State,
		&d.SPFOk, &d.DKIMOk, &d.DMARCOk, &d.LastCheck, &d.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return d, err
}

// CreateDomain adds a mail domain to a project.
func (s *Store) CreateDomain(ctx context.Context, projectID, serverID, domain string) (*Domain, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO mail_domains (project_id, server_id, domain)
		VALUES ($1,$2,$3)
		RETURNING `+domainColumns,
		projectID, serverID, domain)
	d, err := scanDomain(row)
	if err != nil && err.Error() != "mail: not found" && isUniqueViolation(err) {
		return nil, ErrConflict
	}
	return d, err
}

// GetDomain fetches one domain by ID.
func (s *Store) GetDomain(ctx context.Context, id string) (*Domain, error) {
	return scanDomain(s.pool.QueryRow(ctx,
		`SELECT `+domainColumns+` FROM mail_domains WHERE id=$1`, id))
}

// ListDomains returns domains for a project.
func (s *Store) ListDomains(ctx context.Context, projectID string) ([]*Domain, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+domainColumns+`
		 FROM mail_domains WHERE project_id=$1 AND state != 'deleted'
		 ORDER BY domain`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Domain
	for rows.Next() {
		d := &Domain{}
		if err := rows.Scan(&d.ID, &d.ProjectID, &d.ServerID, &d.Domain, &d.State,
			&d.SPFOk, &d.DKIMOk, &d.DMARCOk, &d.LastCheck, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// UpdateDomainState transitions a domain's state.
func (s *Store) UpdateDomainState(ctx context.Context, id, state string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE mail_domains SET state=$1 WHERE id=$2`, state, id)
	return err
}

// UpdateReadiness records DNS readiness check results.
func (s *Store) UpdateReadiness(ctx context.Context, id string, spfOk, dkimOk, dmarcOk bool) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE mail_domains
		SET spf_ok=$1, dkim_ok=$2, dmarc_ok=$3, last_check=NOW()
		WHERE id=$4`, spfOk, dkimOk, dmarcOk, id)
	return err
}

// DeleteDomain soft-deletes a domain (state='disabled').
func (s *Store) DeleteDomain(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE mail_domains SET state='disabled' WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Mailbox ────────────────────────────────────────────────────────────────────

// CreateMailbox creates a new mailbox. passwordRef is a sealed secret URI.
func (s *Store) CreateMailbox(ctx context.Context, domainID, localPart, passwordRef string, quotaMB int) (*Mailbox, error) {
	mb := &Mailbox{}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO mailboxes (domain_id, local_part, password_ref, quota_mb)
		VALUES ($1,$2,$3,$4)
		RETURNING id, domain_id, local_part, state, quota_mb, password_ref, created_at, deleted_at`,
		domainID, localPart, passwordRef, quotaMB).
		Scan(&mb.ID, &mb.DomainID, &mb.LocalPart, &mb.State, &mb.QuotaMB,
			&mb.PasswordRef, &mb.CreatedAt, &mb.DeletedAt)
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	return mb, err
}

// ListMailboxes returns active mailboxes for a domain.
func (s *Store) ListMailboxes(ctx context.Context, domainID string) ([]*Mailbox, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, domain_id, local_part, state, quota_mb, password_ref, created_at, deleted_at
		FROM mailboxes
		WHERE domain_id=$1 AND state != 'deleted'
		ORDER BY local_part`, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Mailbox
	for rows.Next() {
		mb := &Mailbox{}
		if err := rows.Scan(&mb.ID, &mb.DomainID, &mb.LocalPart, &mb.State, &mb.QuotaMB,
			&mb.PasswordRef, &mb.CreatedAt, &mb.DeletedAt); err != nil {
			return nil, err
		}
		out = append(out, mb)
	}
	return out, rows.Err()
}

// DeleteMailbox soft-deletes a mailbox.
func (s *Store) DeleteMailbox(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE mailboxes SET state='deleted', deleted_at=NOW() WHERE id=$1 AND state != 'deleted'`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Alias ──────────────────────────────────────────────────────────────────────

// CreateAlias creates a new mail alias.
func (s *Store) CreateAlias(ctx context.Context, domainID, localPart, destination string) (*Alias, error) {
	a := &Alias{}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO mail_aliases (domain_id, local_part, destination)
		VALUES ($1,$2,$3)
		RETURNING id, domain_id, local_part, destination, enabled, created_at`,
		domainID, localPart, destination).
		Scan(&a.ID, &a.DomainID, &a.LocalPart, &a.Destination, &a.Enabled, &a.CreatedAt)
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	return a, err
}

// ListAliases returns aliases for a domain.
func (s *Store) ListAliases(ctx context.Context, domainID string) ([]*Alias, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, domain_id, local_part, destination, enabled, created_at
		FROM mail_aliases WHERE domain_id=$1 ORDER BY local_part`, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Alias
	for rows.Next() {
		a := &Alias{}
		if err := rows.Scan(&a.ID, &a.DomainID, &a.LocalPart, &a.Destination, &a.Enabled, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAlias removes an alias.
func (s *Store) DeleteAlias(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM mail_aliases WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── DKIM ───────────────────────────────────────────────────────────────────────

// UpsertDKIMKey inserts or updates a DKIM key for a domain+selector.
func (s *Store) UpsertDKIMKey(ctx context.Context, domainID, selector, keyRef, publicKey, algorithm string) (*DKIMKey, error) {
	k := &DKIMKey{}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO dkim_keys (domain_id, selector, key_ref, public_key, algorithm)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (domain_id, selector) DO UPDATE
		    SET key_ref=EXCLUDED.key_ref, public_key=EXCLUDED.public_key,
		        algorithm=EXCLUDED.algorithm, rotated_at=NOW()
		RETURNING id, domain_id, selector, key_ref, public_key, algorithm, created_at, rotated_at`,
		domainID, selector, keyRef, publicKey, algorithm).
		Scan(&k.ID, &k.DomainID, &k.Selector, &k.KeyRef, &k.PublicKey, &k.Algorithm, &k.CreatedAt, &k.RotatedAt)
	return k, err
}

// GetDKIMKey fetches a DKIM key by domain and selector.
func (s *Store) GetDKIMKey(ctx context.Context, domainID, selector string) (*DKIMKey, error) {
	k := &DKIMKey{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, domain_id, selector, key_ref, public_key, algorithm, created_at, rotated_at
		FROM dkim_keys WHERE domain_id=$1 AND selector=$2`,
		domainID, selector).
		Scan(&k.ID, &k.DomainID, &k.Selector, &k.KeyRef, &k.PublicKey, &k.Algorithm, &k.CreatedAt, &k.RotatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return k, err
}

// ── Rate limits ────────────────────────────────────────────────────────────────

// UpsertRateLimit sets or updates rate limits for a domain.
func (s *Store) UpsertRateLimit(ctx context.Context, domainID string, maxPerHour, maxPerDay, maxRcpt int) (*RateLimit, error) {
	r := &RateLimit{}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO mail_rate_limits (domain_id, max_per_hour, max_per_day, max_rcpt)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (domain_id) DO UPDATE
		    SET max_per_hour=EXCLUDED.max_per_hour, max_per_day=EXCLUDED.max_per_day,
		        max_rcpt=EXCLUDED.max_rcpt, updated_at=NOW()
		RETURNING id, domain_id, max_per_hour, max_per_day, max_rcpt, updated_at`,
		domainID, maxPerHour, maxPerDay, maxRcpt).
		Scan(&r.ID, &r.DomainID, &r.MaxPerHour, &r.MaxPerDay, &r.MaxRcpt, &r.UpdatedAt)
	return r, err
}

// GetRateLimit returns rate limits for a domain.
func (s *Store) GetRateLimit(ctx context.Context, domainID string) (*RateLimit, error) {
	r := &RateLimit{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, domain_id, max_per_hour, max_per_day, max_rcpt, updated_at
		FROM mail_rate_limits WHERE domain_id=$1`, domainID).
		Scan(&r.ID, &r.DomainID, &r.MaxPerHour, &r.MaxPerDay, &r.MaxRcpt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// ── Queue log ──────────────────────────────────────────────────────────────────

// RecordQueueEntry inserts a sampled queue log record.
func (s *Store) RecordQueueEntry(ctx context.Context, domainID, queueID, from, to, status, message string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO mail_queue_log (domain_id, queue_id, from_addr, to_addr, status, message)
		VALUES ($1,$2,$3,$4,$5,NULLIF($6,''))`,
		domainID, queueID, from, to, status, message)
	return err
}

// ListQueueLog returns recent queue log entries for a domain.
func (s *Store) ListQueueLog(ctx context.Context, domainID string, limit int) ([]*QueueEntry, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, domain_id, queue_id, from_addr, to_addr, status, COALESCE(message,''), logged_at
		FROM mail_queue_log WHERE domain_id=$1
		ORDER BY logged_at DESC LIMIT $2`, domainID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*QueueEntry
	for rows.Next() {
		e := &QueueEntry{}
		if err := rows.Scan(&e.ID, &e.DomainID, &e.QueueID, &e.From, &e.To,
			&e.Status, &e.Message, &e.LoggedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ── helpers ────────────────────────────────────────────────────────────────────

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, pgx.ErrNoRows) || // pgx doesn't expose pgconn.PgError directly
		(err != nil && len(err.Error()) > 0 && (containsCode(err, "23505")))
}

func containsCode(err error, code string) bool {
	return err != nil && len(err.Error()) > 4 &&
		(err.Error()[:4] == code[:4] || err.Error() == "mail: already exists")
}
