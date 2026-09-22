// Package observe owns the Phase 7 observability rows: bounded metric
// samples, alert rules, alert incidents with one-open-per-condition dedup,
// and scheduled report summaries.
//
// Design notes:
//   - metric_samples is the ONLY table the retention sweeper may delete from.
//     The storage pressure guard is a schema fact: pruning touches nothing else.
//   - Incidents dedup via a partial unique index on (dedup_key) WHERE
//     state='open', so two evaluators racing produce one incident.
//   - Recovery notifications are the caller's job (notify.Publish); this store
//     only records state transitions.
package observe

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors.
var (
	ErrInvalid  = errors.New("observe: invalid input")
	ErrNotFound = errors.New("observe: not found")
	ErrState    = errors.New("observe: invalid state transition")
)

// Metric names. Kept in sync with the metric_samples/alert_rules CHECK
// constraints (migration 0019).
const (
	MetricCPUPct  = "cpu_pct"
	MetricMemPct  = "mem_pct"
	MetricDiskPct = "disk_pct"
	MetricLoad1   = "load1"
)

// AllMetrics is the closed set of baseline metrics.
var AllMetrics = []string{MetricCPUPct, MetricMemPct, MetricDiskPct, MetricLoad1}

// Comparators.
const (
	ComparatorGT = "gt"
	ComparatorLT = "lt"
)

// Severities mirror notify severities.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Incident states.
const (
	IncidentOpen     = "open"
	IncidentResolved = "resolved"
)

// Report cadences.
const (
	CadenceDaily   = "daily"
	CadenceWeekly  = "weekly"
	CadenceMonthly = "monthly"
)

const maxListLimit = 500

// Store is the observability data access.
type Store struct {
	pool  *pgxpool.Pool
	clock func() time.Time
}

// NewStore builds a Store. now supplies the clock (tests inject one).
func NewStore(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &Store{pool: pool, clock: now}
}

// ─── metric samples ──────────────────────────────────────────────────────────

// Sample is one metric observation.
type Sample struct {
	ServerID   string
	Metric     string
	Value      float64
	ObservedAt time.Time
}

// RecordSamples inserts a batch of samples in one statement.
func (s *Store) RecordSamples(ctx context.Context, samples []Sample) error {
	if len(samples) == 0 {
		return nil
	}
	for _, sm := range samples {
		if sm.ServerID == "" || !validMetric(sm.Metric) || sm.Value < 0 {
			return fmt.Errorf("%w: sample %+v", ErrInvalid, sm)
		}
	}
	batch := &pgx.Batch{}
	for _, sm := range samples {
		batch.Queue(`INSERT INTO metric_samples (server_id, metric, value, observed_at)
			VALUES ($1, $2, $3, $4)`,
			sm.ServerID, sm.Metric, sm.Value, sm.ObservedAt)
	}
	if err := s.pool.SendBatch(ctx, batch).Close(); err != nil {
		return fmt.Errorf("observe: record samples: %w", err)
	}
	return nil
}

// QuerySamples returns samples for one server+metric since cutoff, newest
// first, bounded by limit.
func (s *Store) QuerySamples(ctx context.Context, serverID, metric string, since time.Time, limit int) ([]Sample, error) {
	if limit <= 0 || limit > maxListLimit {
		limit = 240
	}
	rows, err := s.pool.Query(ctx, `
		SELECT server_id::text, metric, value, observed_at FROM metric_samples
		WHERE server_id = $1::uuid AND metric = $2 AND observed_at >= $3
		ORDER BY observed_at DESC LIMIT $4`,
		serverID, metric, since, limit)
	if err != nil {
		return nil, fmt.Errorf("observe: query samples: %w", err)
	}
	defer rows.Close()
	var out []Sample
	for rows.Next() {
		var sm Sample
		if err := rows.Scan(&sm.ServerID, &sm.Metric, &sm.Value, &sm.ObservedAt); err != nil {
			return nil, fmt.Errorf("observe: scan sample: %w", err)
		}
		out = append(out, sm)
	}
	return out, rows.Err()
}

// SamplesSince returns all samples for one server+metric within a window,
// oldest first. The evaluator uses this to check "condition held for N".
func (s *Store) SamplesSince(ctx context.Context, serverID, metric string, since time.Time) ([]Sample, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT server_id::text, metric, value, observed_at FROM metric_samples
		WHERE server_id = $1::uuid AND metric = $2 AND observed_at >= $3
		ORDER BY observed_at ASC LIMIT $4`,
		serverID, metric, since, maxListLimit)
	if err != nil {
		return nil, fmt.Errorf("observe: samples since: %w", err)
	}
	defer rows.Close()
	var out []Sample
	for rows.Next() {
		var sm Sample
		if err := rows.Scan(&sm.ServerID, &sm.Metric, &sm.Value, &sm.ObservedAt); err != nil {
			return nil, fmt.Errorf("observe: scan sample: %w", err)
		}
		out = append(out, sm)
	}
	return out, rows.Err()
}

// PruneSamples deletes samples older than cutoff. When maxRows > 0 and the
// table still exceeds it afterwards, the oldest rows are deleted until it
// fits. Returns the number of rows deleted. This is the storage pressure
// guard: it only ever touches metric_samples (Gate: retention bounded).
func (s *Store) PruneSamples(ctx context.Context, cutoff time.Time, maxRows int) (int64, error) {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM metric_samples WHERE observed_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("observe: prune samples: %w", err)
	}
	deleted := tag.RowsAffected()
	if maxRows <= 0 {
		return deleted, nil
	}
	tag, err = s.pool.Exec(ctx, `
		DELETE FROM metric_samples WHERE id IN (
			SELECT id FROM metric_samples ORDER BY observed_at ASC
			OFFSET $1
		)`, maxRows)
	if err != nil {
		return deleted, fmt.Errorf("observe: prune overflow: %w", err)
	}
	return deleted + tag.RowsAffected(), nil
}

// ─── alert rules ─────────────────────────────────────────────────────────────

// AlertRule is one threshold condition.
type AlertRule struct {
	ID              string
	ServerID        string
	Name            string
	Metric          string
	Comparator      string
	Threshold       float64
	DurationSeconds int
	Severity        string
	Enabled         bool
	State           string
	CreatedBy       *string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

const ruleColumns = `id::text, server_id::text, name, metric, comparator, threshold,
	duration_seconds, severity, enabled, state, created_by::text, created_at, updated_at`

func scanRule(row pgx.Row) (AlertRule, error) {
	var r AlertRule
	err := row.Scan(&r.ID, &r.ServerID, &r.Name, &r.Metric, &r.Comparator, &r.Threshold,
		&r.DurationSeconds, &r.Severity, &r.Enabled, &r.State, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return AlertRule{}, ErrNotFound
	}
	if err != nil {
		return AlertRule{}, fmt.Errorf("observe: scan rule: %w", err)
	}
	return r, nil
}

// CreateRuleParams is the input for CreateRule.
type CreateRuleParams struct {
	ServerID        string
	Name            string
	Metric          string
	Comparator      string
	Threshold       float64
	DurationSeconds int
	Severity        string
	CreatedBy       string
}

// CreateRule inserts a new alert rule.
func (s *Store) CreateRule(ctx context.Context, p CreateRuleParams) (AlertRule, error) {
	if p.Severity == "" {
		p.Severity = SeverityWarning
	}
	if err := p.validate(); err != nil {
		return AlertRule{}, err
	}
	rule, err := scanRule(s.pool.QueryRow(ctx, `
		INSERT INTO alert_rules (server_id, name, metric, comparator, threshold,
			duration_seconds, severity, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, '')::uuid)
		RETURNING `+ruleColumns,
		p.ServerID, strings.TrimSpace(p.Name), p.Metric, p.Comparator, p.Threshold,
		p.DurationSeconds, p.Severity, p.CreatedBy))
	if err != nil {
		return AlertRule{}, err
	}
	return rule, nil
}

func (p CreateRuleParams) validate() error {
	var errs []error
	if p.ServerID == "" {
		errs = append(errs, errors.New("server_id is required"))
	}
	if strings.TrimSpace(p.Name) == "" {
		errs = append(errs, errors.New("name is required"))
	}
	if !validMetric(p.Metric) {
		errs = append(errs, fmt.Errorf("metric %q is not a baseline metric", p.Metric))
	}
	if p.Comparator != ComparatorGT && p.Comparator != ComparatorLT {
		errs = append(errs, fmt.Errorf("comparator %q must be gt or lt", p.Comparator))
	}
	if p.DurationSeconds < 60 || p.DurationSeconds > 86400 {
		errs = append(errs, errors.New("duration_seconds must be between 60 and 86400"))
	}
	switch p.Severity {
	case SeverityInfo, SeverityWarning, SeverityCritical:
	default:
		errs = append(errs, fmt.Errorf("severity %q is not valid", p.Severity))
	}
	if len(errs) > 0 {
		return errors.Join(append([]error{ErrInvalid}, errs...)...)
	}
	return nil
}

// GetRule loads one rule by id.
func (s *Store) GetRule(ctx context.Context, id string) (AlertRule, error) {
	return scanRule(s.pool.QueryRow(ctx,
		`SELECT `+ruleColumns+` FROM alert_rules WHERE id = $1::uuid`, id))
}

// ListRules lists rules, optionally filtered by server.
func (s *Store) ListRules(ctx context.Context, serverID string, limit, offset int) ([]AlertRule, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+ruleColumns+` FROM alert_rules
		WHERE ($1::uuid IS NULL OR server_id = $1::uuid)
		ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		nullIfEmpty(serverID), limit, offset)
	if err != nil {
		return nil, fmt.Errorf("observe: list rules: %w", err)
	}
	defer rows.Close()
	var out []AlertRule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// EnabledRules returns every enabled active rule, ordered by server.
func (s *Store) EnabledRules(ctx context.Context) ([]AlertRule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+ruleColumns+` FROM alert_rules
		WHERE enabled AND state = 'active' ORDER BY server_id`)
	if err != nil {
		return nil, fmt.Errorf("observe: enabled rules: %w", err)
	}
	defer rows.Close()
	var out []AlertRule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateRuleParams carries the mutable rule fields; nil means unchanged.
type UpdateRuleParams struct {
	Name            *string
	Threshold       *float64
	DurationSeconds *int
	Severity        *string
	Enabled         *bool
	State           *string
}

// UpdateRule patches a rule.
func (s *Store) UpdateRule(ctx context.Context, id string, p UpdateRuleParams) (AlertRule, error) {
	rule, err := scanRule(s.pool.QueryRow(ctx, `
		UPDATE alert_rules SET
			name = COALESCE($2, name),
			threshold = COALESCE($3, threshold),
			duration_seconds = COALESCE($4, duration_seconds),
			severity = COALESCE($5, severity),
			enabled = COALESCE($6, enabled),
			state = COALESCE($7, state),
			updated_at = now()
		WHERE id = $1::uuid
		RETURNING `+ruleColumns,
		id, p.Name, p.Threshold, p.DurationSeconds, p.Severity, p.Enabled, p.State))
	if err != nil {
		return AlertRule{}, err
	}
	return rule, nil
}

// DeleteRule removes a rule and (via ON DELETE CASCADE) its incidents.
func (s *Store) DeleteRule(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM alert_rules WHERE id = $1::uuid`, id)
	if err != nil {
		return fmt.Errorf("observe: delete rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ─── incidents ───────────────────────────────────────────────────────────────

// Incident is one alert condition episode.
type Incident struct {
	ID         string
	RuleID     string
	ServerID   string
	State      string
	DedupKey   string
	OpenedAt   time.Time
	ResolvedAt *time.Time
	NotifiedAt *time.Time
}

const incidentColumns = `id::text, rule_id::text, server_id::text, state, dedup_key,
	opened_at, resolved_at, notified_at`

func scanIncident(row pgx.Row) (Incident, error) {
	var i Incident
	err := row.Scan(&i.ID, &i.RuleID, &i.ServerID, &i.State, &i.DedupKey,
		&i.OpenedAt, &i.ResolvedAt, &i.NotifiedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Incident{}, ErrNotFound
	}
	if err != nil {
		return Incident{}, fmt.Errorf("observe: scan incident: %w", err)
	}
	return i, nil
}

// OpenIncident opens an incident for dedupKey, or returns the existing open
// one. The partial unique index makes the race impossible: a unique violation
// re-reads the winner.
func (s *Store) OpenIncident(ctx context.Context, ruleID, serverID, dedupKey string) (Incident, bool, error) {
	if ruleID == "" || serverID == "" || dedupKey == "" {
		return Incident{}, false, fmt.Errorf("%w: rule_id, server_id and dedup_key are required", ErrInvalid)
	}
	inc, err := scanIncident(s.pool.QueryRow(ctx, `
		INSERT INTO alert_incidents (rule_id, server_id, dedup_key)
		VALUES ($1::uuid, $2::uuid, $3)
		ON CONFLICT (dedup_key) WHERE state = 'open'
		DO NOTHING
		RETURNING `+incidentColumns,
		ruleID, serverID, dedupKey))
	if err == nil {
		return inc, true, nil // newly opened
	}
	if errors.Is(err, ErrNotFound) {
		// An open incident already exists: return it, created=false.
		existing, findErr := s.GetOpenIncident(ctx, dedupKey)
		if findErr != nil {
			return Incident{}, false, findErr
		}
		return existing, false, nil
	}
	return Incident{}, false, err
}

// GetOpenIncident loads the open incident for a dedup key.
func (s *Store) GetOpenIncident(ctx context.Context, dedupKey string) (Incident, error) {
	return scanIncident(s.pool.QueryRow(ctx,
		`SELECT `+incidentColumns+` FROM alert_incidents
		 WHERE dedup_key = $1 AND state = 'open'`, dedupKey))
}

// MarkIncidentNotified records that the firing notification was published.
func (s *Store) MarkIncidentNotified(ctx context.Context, id string) error {
	now := s.clock().UTC()
	_, err := s.pool.Exec(ctx,
		`UPDATE alert_incidents SET notified_at = $2 WHERE id = $1::uuid`, id, now)
	if err != nil {
		return fmt.Errorf("observe: mark notified: %w", err)
	}
	return nil
}

// ResolveIncident closes an open incident. Returns ErrState when it is
// already resolved (idempotent callers can ignore it).
func (s *Store) ResolveIncident(ctx context.Context, id string) error {
	now := s.clock().UTC()
	tag, err := s.pool.Exec(ctx, `
		UPDATE alert_incidents SET state = 'resolved', resolved_at = $2
		WHERE id = $1::uuid AND state = 'open'`, id, now)
	if err != nil {
		return fmt.Errorf("observe: resolve incident: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrState
	}
	return nil
}

// ResolveOpenByDedup closes the open incident for a dedup key, if any.
// Returns the resolved incident ID, or "" when none was open.
func (s *Store) ResolveOpenByDedup(ctx context.Context, dedupKey string) (string, error) {
	now := s.clock().UTC()
	var id string
	err := s.pool.QueryRow(ctx, `
		UPDATE alert_incidents SET state = 'resolved', resolved_at = $2
		WHERE id = (SELECT id FROM alert_incidents WHERE dedup_key = $1 AND state = 'open')
		RETURNING id::text`, dedupKey, now).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("observe: resolve by dedup: %w", err)
	}
	return id, nil
}

// ListIncidents lists incidents, newest first. state filters when non-empty.
func (s *Store) ListIncidents(ctx context.Context, serverID, state string, limit, offset int) ([]Incident, error) {
	if limit <= 0 || limit > 200 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.pool.Query(ctx, `
		SELECT `+incidentColumns+` FROM alert_incidents
		WHERE ($1::uuid IS NULL OR server_id = $1::uuid)
		  AND ($2 = '' OR state = $2)
		ORDER BY opened_at DESC LIMIT $3 OFFSET $4`,
		nullIfEmpty(serverID), state, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("observe: list incidents: %w", err)
	}
	defer rows.Close()
	var out []Incident
	for rows.Next() {
		i, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// CountOpenIncidents reports how many incidents are open (report summaries).
func (s *Store) CountOpenIncidents(ctx context.Context) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alert_incidents WHERE state = 'open'`).Scan(&n); err != nil {
		return 0, fmt.Errorf("observe: count open incidents: %w", err)
	}
	return n, nil
}

// ─── report schedules ────────────────────────────────────────────────────────

// ReportSchedule is one periodic summary notification.
type ReportSchedule struct {
	ID        string
	Name      string
	Cadence   string
	NextRunAt time.Time
	Enabled   bool
	LastRunAt *time.Time
	CreatedBy *string
	CreatedAt time.Time
}

const scheduleColumns = `id::text, name, cadence, next_run_at, enabled, last_run_at,
	created_by::text, created_at`

func scanSchedule(row pgx.Row) (ReportSchedule, error) {
	var r ReportSchedule
	err := row.Scan(&r.ID, &r.Name, &r.Cadence, &r.NextRunAt, &r.Enabled, &r.LastRunAt,
		&r.CreatedBy, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ReportSchedule{}, ErrNotFound
	}
	if err != nil {
		return ReportSchedule{}, fmt.Errorf("observe: scan schedule: %w", err)
	}
	return r, nil
}

// CreateSchedule inserts a report schedule starting at firstRun.
func (s *Store) CreateSchedule(ctx context.Context, name, cadence string, firstRun time.Time, createdBy string) (ReportSchedule, error) {
	switch cadence {
	case CadenceDaily, CadenceWeekly, CadenceMonthly:
	default:
		return ReportSchedule{}, fmt.Errorf("%w: cadence %q must be daily, weekly, or monthly", ErrInvalid, cadence)
	}
	if strings.TrimSpace(name) == "" {
		return ReportSchedule{}, fmt.Errorf("%w: name is required", ErrInvalid)
	}
	sched, err := scanSchedule(s.pool.QueryRow(ctx, `
		INSERT INTO report_schedules (name, cadence, next_run_at, created_by)
		VALUES ($1, $2, $3, NULLIF($4, '')::uuid)
		RETURNING `+scheduleColumns,
		strings.TrimSpace(name), cadence, firstRun, createdBy))
	if err != nil {
		return ReportSchedule{}, err
	}
	return sched, nil
}

// ListSchedules lists all report schedules.
func (s *Store) ListSchedules(ctx context.Context) ([]ReportSchedule, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+scheduleColumns+` FROM report_schedules ORDER BY created_at`)
	if err != nil {
		return nil, fmt.Errorf("observe: list schedules: %w", err)
	}
	defer rows.Close()
	var out []ReportSchedule
	for rows.Next() {
		r, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DueSchedules returns enabled schedules whose next_run_at has passed.
func (s *Store) DueSchedules(ctx context.Context, now time.Time) ([]ReportSchedule, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT `+scheduleColumns+` FROM report_schedules
		WHERE enabled AND next_run_at <= $1 ORDER BY next_run_at LIMIT 50`, now)
	if err != nil {
		return nil, fmt.Errorf("observe: due schedules: %w", err)
	}
	defer rows.Close()
	var out []ReportSchedule
	for rows.Next() {
		r, err := scanSchedule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AdvanceSchedule records a run and sets the next one for the cadence.
func (s *Store) AdvanceSchedule(ctx context.Context, id string, ranAt, next time.Time) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE report_schedules SET last_run_at = $2, next_run_at = $3
		WHERE id = $1::uuid`, id, ranAt, next)
	if err != nil {
		return fmt.Errorf("observe: advance schedule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteSchedule removes a schedule.
func (s *Store) DeleteSchedule(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM report_schedules WHERE id = $1::uuid`, id)
	if err != nil {
		return fmt.Errorf("observe: delete schedule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func validMetric(m string) bool {
	for _, ok := range AllMetrics {
		if m == ok {
			return true
		}
	}
	return false
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
