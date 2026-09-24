// Package dns owns DNS provider, zone, and record management plus ACME order
// state machine for DNS-01 wildcard issuance.
//
// Design:
//   - dns_providers.secret_ref points into the secret subsystem; raw tokens
//     NEVER touch this package's return values (redacted in responses).
//   - Provider outages are handled gracefully: ListRecords returns the local
//     desired state; sync operations return a typed ErrProviderUnavailable
//     so callers can report degraded without panicking.
//   - The Cloudflare adapter is the only implemented adapter; Route53 and
//     manual return ErrProviderNotImplemented.
package dns

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors.
var (
	ErrInvalid                = errors.New("dns: invalid argument")
	ErrNotFound               = errors.New("dns: not found")
	ErrState                  = errors.New("dns: invalid state transition")
	ErrProviderUnavailable    = errors.New("dns: provider unavailable")
	ErrProviderNotImplemented = errors.New("dns: provider not implemented")
)

// Provider types.
const (
	ProviderCloudflare = "cloudflare"
	ProviderRoute53    = "route53"
	ProviderManual     = "manual"
)

// Zone states.
const (
	ZoneStateActive   = "active"
	ZoneStateDegraded = "degraded"
	ZoneStatePaused   = "paused"
)

// Record sync states.
const (
	SyncPending  = "pending"
	SyncSynced   = "synced"
	SyncDrifted  = "drifted"
	SyncDeleting = "deleting"
)

// Order states.
const (
	OrderPending    = "pending"
	OrderReady      = "ready"
	OrderProcessing = "processing"
	OrderValid      = "valid"
	OrderInvalid    = "invalid"
	OrderCanceled   = "canceled"
)

// Provider is a DNS provider credential reference.
type Provider struct {
	ID        string
	ProjectID string
	Name      string
	Provider  string
	// SecretRef is the secret:// reference. Never the raw token.
	SecretRef string
	Enabled   bool
	CreatedBy *string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Zone is a DNS hosted zone.
type Zone struct {
	ID           string
	ProjectID    string
	ProviderID   string
	Apex         string
	ExternalID   *string
	State        string
	LastSyncedAt *time.Time
	LastError    *string
	CreatedBy    *string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Record is a DNS desired-state record.
type Record struct {
	ID         string
	ZoneID     string
	RType      string
	Name       string
	Value      string
	TTL        int
	Priority   *int
	ExternalID *string
	SyncState  string
	Managed    bool
	CreatedBy  *string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// Order is an ACME cert_orders row.
type Order struct {
	ID                string
	CertificateID     *string
	ProjectID         string
	ProviderID        *string
	Identifiers       []string
	DirectoryURL      string
	State             string
	OrderURL          *string
	ChallengeToken    *string
	ChallengeKeyAuth  *string
	ChallengeRecordID *string
	ChallengePlacedAt *time.Time
	ErrorMessage      *string
	ExpiresAt         *time.Time
	CompletedAt       *time.Time
	CreatedBy         *string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

// ── Store ────────────────────────────────────────────────────────────────────

// Store reads and writes DNS and ACME order rows.
type Store struct {
	pool  *pgxpool.Pool
	clock func() time.Time
}

// NewStore builds a dns.Store.
func NewStore(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, clock: now}
}

// ── Provider CRUD ────────────────────────────────────────────────────────────

const providerColumns = `id, project_id, name, provider, secret_ref, enabled, created_by, created_at, updated_at`

func scanProvider(row pgx.Row) (Provider, error) {
	var p Provider
	err := row.Scan(&p.ID, &p.ProjectID, &p.Name, &p.Provider, &p.SecretRef,
		&p.Enabled, &p.CreatedBy, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Provider{}, ErrNotFound
	}
	if err != nil {
		return Provider{}, fmt.Errorf("dns: scan provider: %w", err)
	}
	return p, nil
}

// CreateProviderParams for CreateProvider.
type CreateProviderParams struct {
	ProjectID string
	Name      string
	Provider  string
	// SecretRef is the pre-sealed secret:// reference. Never the raw token.
	SecretRef string
	CreatedBy string
}

// CreateProvider inserts a dns_providers row.
func (s *Store) CreateProvider(ctx context.Context, p CreateProviderParams) (Provider, error) {
	if strings.TrimSpace(p.ProjectID) == "" {
		return Provider{}, fmt.Errorf("%w: project_id required", ErrInvalid)
	}
	if strings.TrimSpace(p.Name) == "" {
		return Provider{}, fmt.Errorf("%w: name required", ErrInvalid)
	}
	if p.Provider != ProviderCloudflare && p.Provider != ProviderRoute53 && p.Provider != ProviderManual {
		return Provider{}, fmt.Errorf("%w: unknown provider %q", ErrInvalid, p.Provider)
	}
	if strings.TrimSpace(p.SecretRef) == "" {
		return Provider{}, fmt.Errorf("%w: secret_ref required", ErrInvalid)
	}
	var createdBy any
	if v := strings.TrimSpace(p.CreatedBy); v != "" {
		createdBy = v
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO dns_providers (project_id, name, provider, secret_ref, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING %s`, providerColumns),
		p.ProjectID, p.Name, p.Provider, p.SecretRef, createdBy)
	prov, err := scanProvider(row)
	if err != nil {
		if isFKViolation(err) {
			return Provider{}, fmt.Errorf("%w: project does not exist", ErrInvalid)
		}
		return Provider{}, err
	}
	return prov, nil
}

// GetProvider returns one provider by id.
func (s *Store) GetProvider(ctx context.Context, id string) (Provider, error) {
	if strings.TrimSpace(id) == "" {
		return Provider{}, fmt.Errorf("%w: id required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM dns_providers WHERE id = $1`, providerColumns), id)
	return scanProvider(row)
}

// ListProviders returns all providers for a project.
func (s *Store) ListProviders(ctx context.Context, projectID string) ([]Provider, error) {
	if strings.TrimSpace(projectID) == "" {
		return nil, fmt.Errorf("%w: project_id required", ErrInvalid)
	}
	rows, err := s.pool.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM dns_providers WHERE project_id = $1 ORDER BY name`, providerColumns),
		projectID)
	if err != nil {
		return nil, fmt.Errorf("dns: list providers: %w", err)
	}
	defer rows.Close()
	return collectProviders(rows)
}

func collectProviders(rows pgx.Rows) ([]Provider, error) {
	var out []Provider
	for rows.Next() {
		p, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeleteProvider removes a provider. Fails if zones reference it.
func (s *Store) DeleteProvider(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("%w: id required", ErrInvalid)
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM dns_providers WHERE id = $1`, id)
	if err != nil {
		if isFKViolation(err) {
			return fmt.Errorf("%w: provider has zones; delete zones first", ErrState)
		}
		return fmt.Errorf("dns: delete provider: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Zone CRUD ────────────────────────────────────────────────────────────────

const zoneColumns = `id, project_id, provider_id, apex, external_id, state,
	last_synced_at, last_error, created_by, created_at, updated_at`

func scanZone(row pgx.Row) (Zone, error) {
	var z Zone
	err := row.Scan(&z.ID, &z.ProjectID, &z.ProviderID, &z.Apex, &z.ExternalID, &z.State,
		&z.LastSyncedAt, &z.LastError, &z.CreatedBy, &z.CreatedAt, &z.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Zone{}, ErrNotFound
	}
	if err != nil {
		return Zone{}, fmt.Errorf("dns: scan zone: %w", err)
	}
	return z, nil
}

// CreateZoneParams for CreateZone.
type CreateZoneParams struct {
	ProjectID  string
	ProviderID string
	Apex       string
	ExternalID string
	CreatedBy  string
}

// CreateZone inserts a dns_zones row.
func (s *Store) CreateZone(ctx context.Context, p CreateZoneParams) (Zone, error) {
	if strings.TrimSpace(p.ProjectID) == "" {
		return Zone{}, fmt.Errorf("%w: project_id required", ErrInvalid)
	}
	if strings.TrimSpace(p.ProviderID) == "" {
		return Zone{}, fmt.Errorf("%w: provider_id required", ErrInvalid)
	}
	if strings.TrimSpace(p.Apex) == "" {
		return Zone{}, fmt.Errorf("%w: apex required", ErrInvalid)
	}
	var extID, createdBy any
	if v := strings.TrimSpace(p.ExternalID); v != "" {
		extID = v
	}
	if v := strings.TrimSpace(p.CreatedBy); v != "" {
		createdBy = v
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO dns_zones (project_id, provider_id, apex, external_id, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING %s`, zoneColumns),
		p.ProjectID, p.ProviderID, p.Apex, extID, createdBy)
	z, err := scanZone(row)
	if err != nil {
		if isUniqueViolation(err) {
			return Zone{}, fmt.Errorf("%w: apex already registered in this project", ErrInvalid)
		}
		if isFKViolation(err) {
			return Zone{}, fmt.Errorf("%w: project or provider does not exist", ErrInvalid)
		}
		return Zone{}, err
	}
	return z, nil
}

// GetZone returns one zone.
func (s *Store) GetZone(ctx context.Context, id string) (Zone, error) {
	if strings.TrimSpace(id) == "" {
		return Zone{}, fmt.Errorf("%w: id required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM dns_zones WHERE id = $1`, zoneColumns), id)
	return scanZone(row)
}

// ListZones returns zones for a project.
func (s *Store) ListZones(ctx context.Context, projectID string) ([]Zone, error) {
	if strings.TrimSpace(projectID) == "" {
		return nil, fmt.Errorf("%w: project_id required", ErrInvalid)
	}
	rows, err := s.pool.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM dns_zones WHERE project_id = $1 ORDER BY apex`, zoneColumns),
		projectID)
	if err != nil {
		return nil, fmt.Errorf("dns: list zones: %w", err)
	}
	defer rows.Close()
	var out []Zone
	for rows.Next() {
		z, err := scanZone(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

// MarkZoneDegraded records a provider outage on the zone row.
// This handles the gate: "DNS provider outage handled cleanly."
func (s *Store) MarkZoneDegraded(ctx context.Context, id, errMsg string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE dns_zones SET state = 'degraded', last_error = $2, updated_at = now()
		WHERE id = $1`, id, errMsg)
	return err
}

// MarkZoneSynced clears the error and records a successful sync.
func (s *Store) MarkZoneSynced(ctx context.Context, id, externalID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE dns_zones
		   SET state = 'active', last_synced_at = now(), last_error = NULL,
		       external_id = COALESCE(NULLIF($2,''), external_id), updated_at = now()
		WHERE id = $1`, id, externalID)
	return err
}

// DeleteZone removes a zone and cascades to records.
func (s *Store) DeleteZone(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("%w: id required", ErrInvalid)
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM dns_zones WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("dns: delete zone: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Record CRUD ───────────────────────────────────────────────────────────────

const recordColumns = `id, zone_id, rtype, name, value, ttl, priority, external_id,
	sync_state, managed, created_by, created_at, updated_at`

func scanRecord(row pgx.Row) (Record, error) {
	var r Record
	err := row.Scan(&r.ID, &r.ZoneID, &r.RType, &r.Name, &r.Value, &r.TTL,
		&r.Priority, &r.ExternalID, &r.SyncState, &r.Managed, &r.CreatedBy,
		&r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("dns: scan record: %w", err)
	}
	return r, nil
}

// CreateRecordParams for CreateRecord.
type CreateRecordParams struct {
	ZoneID    string
	RType     string
	Name      string
	Value     string
	TTL       int
	Priority  *int
	Managed   bool
	CreatedBy string
}

// CreateRecord inserts a dns_records row.
func (s *Store) CreateRecord(ctx context.Context, p CreateRecordParams) (Record, error) {
	if strings.TrimSpace(p.ZoneID) == "" {
		return Record{}, fmt.Errorf("%w: zone_id required", ErrInvalid)
	}
	if strings.TrimSpace(p.RType) == "" {
		return Record{}, fmt.Errorf("%w: rtype required", ErrInvalid)
	}
	if strings.TrimSpace(p.Name) == "" {
		return Record{}, fmt.Errorf("%w: name required", ErrInvalid)
	}
	if strings.TrimSpace(p.Value) == "" {
		return Record{}, fmt.Errorf("%w: value required", ErrInvalid)
	}
	ttl := p.TTL
	if ttl == 0 {
		ttl = 300
	}
	var createdBy any
	if v := strings.TrimSpace(p.CreatedBy); v != "" {
		createdBy = v
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO dns_records (zone_id, rtype, name, value, ttl, priority, managed, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING %s`, recordColumns),
		p.ZoneID, p.RType, p.Name, p.Value, ttl, p.Priority, p.Managed, createdBy)
	rec, err := scanRecord(row)
	if err != nil {
		if isFKViolation(err) {
			return Record{}, fmt.Errorf("%w: zone does not exist", ErrInvalid)
		}
		return Record{}, err
	}
	return rec, nil
}

// GetRecord returns one record.
func (s *Store) GetRecord(ctx context.Context, id string) (Record, error) {
	if strings.TrimSpace(id) == "" {
		return Record{}, fmt.Errorf("%w: id required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM dns_records WHERE id = $1`, recordColumns), id)
	return scanRecord(row)
}

// ListRecords returns records for a zone.
func (s *Store) ListRecords(ctx context.Context, zoneID string) ([]Record, error) {
	if strings.TrimSpace(zoneID) == "" {
		return nil, fmt.Errorf("%w: zone_id required", ErrInvalid)
	}
	rows, err := s.pool.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM dns_records WHERE zone_id = $1 ORDER BY rtype, name`, recordColumns),
		zoneID)
	if err != nil {
		return nil, fmt.Errorf("dns: list records: %w", err)
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateRecordParams for partial record updates.
type UpdateRecordParams struct {
	Value    string
	TTL      int
	Priority *int
}

// UpdateRecord updates value/ttl/priority and resets sync_state to pending.
func (s *Store) UpdateRecord(ctx context.Context, id string, p UpdateRecordParams) (Record, error) {
	if strings.TrimSpace(id) == "" {
		return Record{}, fmt.Errorf("%w: id required", ErrInvalid)
	}
	if strings.TrimSpace(p.Value) == "" {
		return Record{}, fmt.Errorf("%w: value required", ErrInvalid)
	}
	ttl := p.TTL
	if ttl == 0 {
		ttl = 300
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE dns_records
		   SET value = $2, ttl = $3, priority = $4, sync_state = 'pending', updated_at = now()
		 WHERE id = $1
		RETURNING %s`, recordColumns), id, p.Value, ttl, p.Priority)
	return scanRecord(row)
}

// DeleteRecord marks a record for deletion (sync_state='deleting').
// Physical removal happens after the provider confirms deletion.
func (s *Store) DeleteRecord(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("%w: id required", ErrInvalid)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE dns_records SET sync_state = 'deleting', updated_at = now() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("dns: delete record: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// MarkRecordSynced sets external_id + sync_state='synced'.
func (s *Store) MarkRecordSynced(ctx context.Context, id, externalID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE dns_records SET external_id = $2, sync_state = 'synced', updated_at = now()
		WHERE id = $1`, id, externalID)
	return err
}

// MarkRecordDrifted sets sync_state='drifted'.
func (s *Store) MarkRecordDrifted(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE dns_records SET sync_state = 'drifted', updated_at = now() WHERE id = $1`, id)
	return err
}

// ── ACME Order CRUD ───────────────────────────────────────────────────────────

const orderColumns = `id, certificate_id, project_id, provider_id, identifiers,
	directory_url, state, order_url, challenge_token, challenge_key_auth,
	challenge_record_id, challenge_placed_at, error_message, expires_at,
	completed_at, created_by, created_at, updated_at`

func scanOrder(row pgx.Row) (Order, error) {
	var o Order
	err := row.Scan(
		&o.ID, &o.CertificateID, &o.ProjectID, &o.ProviderID, &o.Identifiers,
		&o.DirectoryURL, &o.State, &o.OrderURL, &o.ChallengeToken, &o.ChallengeKeyAuth,
		&o.ChallengeRecordID, &o.ChallengePlacedAt, &o.ErrorMessage, &o.ExpiresAt,
		&o.CompletedAt, &o.CreatedBy, &o.CreatedAt, &o.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Order{}, ErrNotFound
	}
	if err != nil {
		return Order{}, fmt.Errorf("dns: scan order: %w", err)
	}
	return o, nil
}

// CreateOrderParams for CreateOrder.
type CreateOrderParams struct {
	ProjectID    string
	ProviderID   string
	Identifiers  []string
	DirectoryURL string
	CreatedBy    string
}

// CreateOrder inserts a cert_orders row in 'pending' state.
func (s *Store) CreateOrder(ctx context.Context, p CreateOrderParams) (Order, error) {
	if strings.TrimSpace(p.ProjectID) == "" {
		return Order{}, fmt.Errorf("%w: project_id required", ErrInvalid)
	}
	if len(p.Identifiers) == 0 {
		return Order{}, fmt.Errorf("%w: at least one identifier required", ErrInvalid)
	}
	dirURL := p.DirectoryURL
	if dirURL == "" {
		dirURL = "https://acme-v02.api.letsencrypt.org/directory"
	}
	var providerID, createdBy any
	if v := strings.TrimSpace(p.ProviderID); v != "" {
		providerID = v
	}
	if v := strings.TrimSpace(p.CreatedBy); v != "" {
		createdBy = v
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO cert_orders (project_id, provider_id, identifiers, directory_url, created_by)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING %s`, orderColumns),
		p.ProjectID, providerID, p.Identifiers, dirURL, createdBy)
	return scanOrder(row)
}

// GetOrder returns one order.
func (s *Store) GetOrder(ctx context.Context, id string) (Order, error) {
	if strings.TrimSpace(id) == "" {
		return Order{}, fmt.Errorf("%w: id required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM cert_orders WHERE id = $1`, orderColumns), id)
	return scanOrder(row)
}

// ListOrders returns orders for a project, newest first.
func (s *Store) ListOrders(ctx context.Context, projectID string) ([]Order, error) {
	if strings.TrimSpace(projectID) == "" {
		return nil, fmt.Errorf("%w: project_id required", ErrInvalid)
	}
	rows, err := s.pool.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM cert_orders WHERE project_id = $1 ORDER BY created_at DESC LIMIT 200`, orderColumns),
		projectID)
	if err != nil {
		return nil, fmt.Errorf("dns: list orders: %w", err)
	}
	defer rows.Close()
	var out []Order
	for rows.Next() {
		o, err := scanOrder(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// AdvanceOrderState transitions an order through its state machine.
// Valid transitions:
//
//	pending → ready | invalid | canceled
//	ready   → processing | invalid | canceled
//	processing → valid | invalid | canceled
//
// Completed states (valid / invalid / canceled) are terminal.
func (s *Store) AdvanceOrderState(ctx context.Context, id, toState string, opts ...AdvanceOption) (Order, error) {
	o, err := s.GetOrder(ctx, id)
	if err != nil {
		return Order{}, err
	}
	if !validOrderTransition(o.State, toState) {
		return Order{}, fmt.Errorf("%w: %s→%s not allowed", ErrState, o.State, toState)
	}

	ao := &advanceOptions{}
	for _, opt := range opts {
		opt(ao)
	}

	var completedAt any
	if toState == OrderValid || toState == OrderInvalid || toState == OrderCanceled {
		completedAt = s.clock()
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE cert_orders
		   SET state                = $2,
		       order_url            = COALESCE($3, order_url),
		       challenge_token      = COALESCE($4, challenge_token),
		       challenge_key_auth   = COALESCE($5, challenge_key_auth),
		       challenge_record_id  = COALESCE($6, challenge_record_id),
		       challenge_placed_at  = COALESCE($7, challenge_placed_at),
		       error_message        = COALESCE($8, error_message),
		       certificate_id       = COALESCE($9, certificate_id),
		       completed_at         = $10,
		       updated_at           = now()
		 WHERE id = $1
		RETURNING %s`, orderColumns),
		id, toState,
		ao.orderURL, ao.challengeToken, ao.challengeKeyAuth,
		ao.challengeRecordID, ao.challengePlacedAt, ao.errorMessage, ao.certificateID,
		completedAt)
	return scanOrder(row)
}

// AdvanceOption configures optional fields when advancing an order.
type AdvanceOption func(*advanceOptions)

type advanceOptions struct {
	orderURL          *string
	challengeToken    *string
	challengeKeyAuth  *string
	challengeRecordID *string
	challengePlacedAt *time.Time
	errorMessage      *string
	certificateID     *string
}

func WithOrderURL(u string) AdvanceOption {
	return func(o *advanceOptions) { o.orderURL = &u }
}
func WithChallengeToken(t string) AdvanceOption {
	return func(o *advanceOptions) { o.challengeToken = &t }
}
func WithChallengeKeyAuth(k string) AdvanceOption {
	return func(o *advanceOptions) { o.challengeKeyAuth = &k }
}
func WithChallengeRecordID(r string) AdvanceOption {
	return func(o *advanceOptions) { o.challengeRecordID = &r }
}
func WithChallengePlacedAt(t time.Time) AdvanceOption {
	return func(o *advanceOptions) { o.challengePlacedAt = &t }
}
func WithErrorMessage(m string) AdvanceOption {
	return func(o *advanceOptions) { o.errorMessage = &m }
}
func WithCertificateID(c string) AdvanceOption {
	return func(o *advanceOptions) { o.certificateID = &c }
}

func validOrderTransition(from, to string) bool {
	transitions := map[string][]string{
		OrderPending:    {OrderReady, OrderInvalid, OrderCanceled},
		OrderReady:      {OrderProcessing, OrderInvalid, OrderCanceled},
		OrderProcessing: {OrderValid, OrderInvalid, OrderCanceled},
	}
	for _, allowed := range transitions[from] {
		if allowed == to {
			return true
		}
	}
	return false
}

// ── helpers ───────────────────────────────────────────────────────────────────

func isFKViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
