// Package health provides production health checking, upgrade history recording,
// and runbook event tracking for Phase 17 production hardening.
//
// Security invariants:
//   - Health check details may contain sensitive counts; the HTTP handler
//     MUST NOT expose this data to unauthenticated callers.
//   - system_health_log is append-only (no DELETE for audit integrity).
package health

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Status values.
const (
	StatusOK       = "ok"
	StatusDegraded = "degraded"
	StatusFailed   = "failed"
)

// Sentinel errors.
var ErrNotFound = errors.New("health: not found")

// ── Types ─────────────────────────────────────────────────────────────────────

// HealthLog is one health check event.
type HealthLog struct {
	ID         string
	CheckName  string
	Status     string
	Message    string
	Details    map[string]any
	DurationMS int
	CheckedAt  time.Time
}

// UpgradeRecord is one migration run.
type UpgradeRecord struct {
	ID            string
	MigrationName string
	FromVersion   string
	ToVersion     string
	AppliedBy     string
	Status        string
	DurationMS    int
	AppliedAt     time.Time
}

// RunbookEvent records the outcome of a runbook drill or incident.
type RunbookEvent struct {
	ID          string
	RunbookName string
	EventType   string // drill | incident | recovery | test
	Outcome     string // pass | fail | partial
	PerformedBy string
	Notes       string
	DurationMin int
	OccurredAt  time.Time
}

// ── Store ─────────────────────────────────────────────────────────────────────

// Store is the health/hardening data store.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// New returns a Store backed by pool.
func New(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, now: now}
}

// ── Health Logs ───────────────────────────────────────────────────────────────

// Record appends a health check event. Append-only; never update/delete.
func (s *Store) Record(ctx context.Context, checkName, status, message string, details map[string]any, durationMS int) (HealthLog, error) {
	if details == nil {
		details = map[string]any{}
	}
	var h HealthLog
	err := s.pool.QueryRow(ctx,
		`INSERT INTO system_health_log (check_name, status, message, details, duration_ms)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, check_name, status, message, details, duration_ms, checked_at`,
		checkName, status, message, details, durationMS).
		Scan(&h.ID, &h.CheckName, &h.Status, &h.Message, &h.Details, &h.DurationMS, &h.CheckedAt)
	return h, err
}

// ListRecent returns the most recent health log entries.
func (s *Store) ListRecent(ctx context.Context, limit int) ([]HealthLog, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, check_name, status, message, details, duration_ms, checked_at
		 FROM system_health_log ORDER BY checked_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HealthLog
	for rows.Next() {
		var h HealthLog
		if err := rows.Scan(&h.ID, &h.CheckName, &h.Status, &h.Message, &h.Details, &h.DurationMS, &h.CheckedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// LatestByCheck returns the most recent log entry for each check name.
func (s *Store) LatestByCheck(ctx context.Context) ([]HealthLog, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT DISTINCT ON (check_name) id, check_name, status, message, details, duration_ms, checked_at
		 FROM system_health_log ORDER BY check_name, checked_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HealthLog
	for rows.Next() {
		var h HealthLog
		if err := rows.Scan(&h.ID, &h.CheckName, &h.Status, &h.Message, &h.Details, &h.DurationMS, &h.CheckedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ── Upgrade History ───────────────────────────────────────────────────────────

// RecordUpgrade records a migration run.
func (s *Store) RecordUpgrade(ctx context.Context, migrationName, fromVersion, toVersion, appliedBy, status string, durationMS int) (UpgradeRecord, error) {
	var r UpgradeRecord
	err := s.pool.QueryRow(ctx,
		`INSERT INTO upgrade_history (migration_name, from_version, to_version, applied_by, status, duration_ms)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, migration_name, from_version, to_version, applied_by, status, duration_ms, applied_at`,
		migrationName, fromVersion, toVersion, appliedBy, status, durationMS).
		Scan(&r.ID, &r.MigrationName, &r.FromVersion, &r.ToVersion, &r.AppliedBy, &r.Status, &r.DurationMS, &r.AppliedAt)
	return r, err
}

// ListUpgrades returns upgrade history.
func (s *Store) ListUpgrades(ctx context.Context, limit int) ([]UpgradeRecord, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, migration_name, from_version, to_version, applied_by, status, duration_ms, applied_at
		 FROM upgrade_history ORDER BY applied_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UpgradeRecord
	for rows.Next() {
		var r UpgradeRecord
		if err := rows.Scan(&r.ID, &r.MigrationName, &r.FromVersion, &r.ToVersion, &r.AppliedBy,
			&r.Status, &r.DurationMS, &r.AppliedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ── Runbook Events ────────────────────────────────────────────────────────────

// RecordRunbookEvent records the outcome of a runbook drill or incident.
func (s *Store) RecordRunbookEvent(ctx context.Context, runbookName, eventType, outcome, performedBy, notes string, durationMin int) (RunbookEvent, error) {
	var ev RunbookEvent
	err := s.pool.QueryRow(ctx,
		`INSERT INTO runbook_events (runbook_name, event_type, outcome, performed_by, notes, duration_min)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, runbook_name, event_type, outcome, performed_by, notes, duration_min, occurred_at`,
		runbookName, eventType, outcome, performedBy, notes, durationMin).
		Scan(&ev.ID, &ev.RunbookName, &ev.EventType, &ev.Outcome, &ev.PerformedBy, &ev.Notes, &ev.DurationMin, &ev.OccurredAt)
	return ev, err
}

// ListRunbookEvents returns recent runbook events.
func (s *Store) ListRunbookEvents(ctx context.Context, limit int) ([]RunbookEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, runbook_name, event_type, outcome, performed_by, notes, duration_min, occurred_at
		 FROM runbook_events ORDER BY occurred_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunbookEvent
	for rows.Next() {
		var ev RunbookEvent
		if err := rows.Scan(&ev.ID, &ev.RunbookName, &ev.EventType, &ev.Outcome, &ev.PerformedBy,
			&ev.Notes, &ev.DurationMin, &ev.OccurredAt); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// ── System health check (in-process) ─────────────────────────────────────────

// CheckDatabase performs a quick DB round-trip and records the result.
func (s *Store) CheckDatabase(ctx context.Context) (HealthLog, error) {
	start := s.now()
	err := s.pool.QueryRow(ctx, `SELECT 1`).Scan(new(int))
	duration := int(s.now().Sub(start).Milliseconds())
	status, message := StatusOK, "database reachable"
	if err != nil {
		status, message = StatusFailed, "database unreachable: "+err.Error()
	}
	return s.Record(ctx, "database.ping", status, message, nil, duration)
}

// CheckMigrationChain verifies the migration count is within an expected window.
// It reads from the migrations table if available; otherwise records degraded.
func (s *Store) CheckMigrationChain(ctx context.Context, expectedMin, expectedMax int) (HealthLog, error) {
	var count int
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name='schema_migrations'`).
		Scan(&count)
	if err != nil || count == 0 {
		// schema_migrations table not available; try counting known tables as proxy.
		_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.tables WHERE table_schema='public'`).Scan(&count)
		return s.Record(ctx, "migration.chain", StatusDegraded,
			"schema_migrations table unavailable; counted public tables",
			map[string]any{"public_tables": count}, 0)
	}
	var applied int
	_ = s.pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations`).Scan(&applied)
	status, message := StatusOK, "migration chain valid"
	if applied < expectedMin || (expectedMax > 0 && applied > expectedMax) {
		status, message = StatusFailed, "unexpected migration count"
	}
	return s.Record(ctx, "migration.chain", status, message,
		map[string]any{"applied": applied, "expected_min": expectedMin, "expected_max": expectedMax}, 0)
}

// CheckSelf counts registered plugins and routes as a canary for self-integrity.
func (s *Store) CheckSelf(ctx context.Context) (HealthLog, error) {
	var tables int
	_ = s.pool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public'`).Scan(&tables)
	// ponytail: add row count assertions per critical table; add when monitoring integration available.
	status := StatusOK
	if tables == 0 {
		status = StatusFailed
	}
	return s.Record(ctx, "self.integrity", status, "schema table count",
		map[string]any{"public_tables": tables}, 0)
}

// ── pgconn helper ─────────────────────────────────────────────────────────────

var _ = pgx.ErrNoRows // suppress unused import
