// Package backups owns the backup plan lifecycle, run records, and expiring
// download links (Phase 6, BACKUP_RECOVERY.md §4-§11).
//
// This package is the ONLY writer of the backup tables; state transitions are
// enforced here so no caller can assemble its own UPDATE that violates the
// lifecycle invariants.
//
// It holds no authorization logic — RBAC decides whether a caller may act;
// this package decides what acting means.
//
// Encryption keys and destination credentials are NEVER stored here: only
// opaque secret:// URIs pointing at internal/secret.
package backups

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors. Callers branch on these to choose an HTTP status.
var (
	// ErrInvalid is returned for a caller-supplied value that cannot be stored.
	ErrInvalid = errors.New("backups: invalid argument")
	// ErrNotFound is returned when the resource does not exist or is tombstoned.
	// A missing and a deleted row return the SAME error to avoid enumeration oracles.
	ErrNotFound = errors.New("backups: not found")
	// ErrSlugTaken is returned when a live plan in the same project already uses the slug.
	ErrSlugTaken = errors.New("backups: slug already in use in this project")
	// ErrState is returned for a transition the lifecycle does not permit.
	ErrState = errors.New("backups: invalid state transition")
	// ErrConflictActive is returned when a run is already queued or running for this plan.
	ErrConflictActive = errors.New("backups: a backup run is already queued or running")
	// ErrLinkExpired is returned when an expiring link is past its deadline or used.
	ErrLinkExpired = errors.New("backups: link expired or already used")
)

// Plan lifecycle states (mirrors apps/sites tombstone pattern).
const (
	StateActive        = "active"
	StateSuspended     = "suspended"
	StatePendingDelete = "pending_delete"
	StateDeleted       = "deleted"
)

// Scope types (BACKUP_RECOVERY.md §2).
const (
	ScopeProject  = "project"
	ScopeSite     = "site"
	ScopeDatabase = "database"
)

// Destination types (BACKUP_RECOVERY.md §3, baseline subset).
const (
	DestLocal = "local"
	DestS3    = "s3"
)

// Run states.
const (
	RunQueued    = "queued"
	RunRunning   = "running"
	RunCompleted = "completed"
	RunFailed    = "failed"
)

// Verification states (BACKUP_RECOVERY.md §6).
const (
	VerifUnverified = "unverified"
	VerifVerified   = "verified"
	VerifFailed     = "failed"
	VerifExpired    = "expired"
)

// Run triggers.
const (
	TriggerManual    = "manual"
	TriggerScheduled = "scheduled"
	TriggerPreChange = "pre_change"
)

const (
	DefaultDeleteGrace = 7 * 24 * time.Hour
	maxDeleteGrace     = 90 * 24 * time.Hour
	maxListLimit       = 200
)

var slugRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9_]*[a-z0-9])?$`)

// Plan is one backup plan definition.
type Plan struct {
	ID                 string
	ProjectID          string
	ServerID           string
	Name               string
	Slug               string
	ScopeType          string
	ScopeID            *string
	DestinationType    string
	DestinationConfig  map[string]any
	DestinationConfRef string
	EncryptionKeyRef   string
	ScheduleCron       string
	NextRunAt          *time.Time
	Enabled            bool
	RetentionCount     int
	RetentionDays      int
	State              string
	CreatedBy          *string
	CreatedAt          time.Time
	UpdatedAt          time.Time
	DeleteAfter        *time.Time
	DeletedAt          *time.Time
}

// Live reports whether the plan is not tombstoned.
func (p Plan) Live() bool { return p.DeletedAt == nil }

const planColumns = `id, project_id, server_id, name, slug, scope_type, scope_id,
	destination_type, destination_config, destination_config_ref, encryption_key_ref,
	schedule_cron, next_run_at, enabled, retention_count, retention_days, state,
	created_by, created_at, updated_at, delete_after, deleted_at`

func scanPlan(row pgx.Row) (Plan, error) {
	var p Plan
	var destJSON []byte
	err := row.Scan(
		&p.ID, &p.ProjectID, &p.ServerID, &p.Name, &p.Slug, &p.ScopeType, &p.ScopeID,
		&p.DestinationType, &destJSON, &p.DestinationConfRef, &p.EncryptionKeyRef,
		&p.ScheduleCron, &p.NextRunAt, &p.Enabled, &p.RetentionCount, &p.RetentionDays, &p.State,
		&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt, &p.DeleteAfter, &p.DeletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Plan{}, ErrNotFound
	}
	if err != nil {
		return Plan{}, fmt.Errorf("backups: scan plan: %w", err)
	}
	if len(destJSON) > 0 {
		if err := json.Unmarshal(destJSON, &p.DestinationConfig); err != nil {
			return Plan{}, fmt.Errorf("backups: unmarshal destination_config: %w", err)
		}
	}
	return p, nil
}

// Run is one backup execution record.
type Run struct {
	ID              string
	PlanID          *string
	ProjectID       string
	ServerID        string
	Trigger         string
	State           string
	ArchivePath     string
	ArchiveSize     int64
	SHA256          string
	EncryptionRef   string
	Manifest        map[string]any
	Verification    string
	JobID           *string
	RequestedByType string
	RequestedByID   string
	IdempotencyKey  *string
	FailedReason    string
	CreatedAt       time.Time
	StartedAt       *time.Time
	CompletedAt     *time.Time
}

const runColumns = `id, plan_id, project_id, server_id, trigger, state, archive_path,
	archive_size_bytes, sha256, encryption_key_ref, manifest, verification_state,
	job_id, requested_by_type, requested_by_id, idempotency_key, failed_reason,
	created_at, started_at, completed_at`

func scanRun(row pgx.Row) (Run, error) {
	var r Run
	var manifestJSON []byte
	err := row.Scan(
		&r.ID, &r.PlanID, &r.ProjectID, &r.ServerID, &r.Trigger, &r.State, &r.ArchivePath,
		&r.ArchiveSize, &r.SHA256, &r.EncryptionRef, &manifestJSON, &r.Verification,
		&r.JobID, &r.RequestedByType, &r.RequestedByID, &r.IdempotencyKey, &r.FailedReason,
		&r.CreatedAt, &r.StartedAt, &r.CompletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Run{}, ErrNotFound
	}
	if err != nil {
		return Run{}, fmt.Errorf("backups: scan run: %w", err)
	}
	if len(manifestJSON) > 0 {
		if err := json.Unmarshal(manifestJSON, &r.Manifest); err != nil {
			return Run{}, fmt.Errorf("backups: unmarshal manifest: %w", err)
		}
	}
	return r, nil
}

// ExpiringLink is one secure, time-limited download token.
type ExpiringLink struct {
	ID        string
	RunID     string
	ProjectID string
	TokenHash string
	ExpiresAt time.Time
	SingleUse bool
	UsedAt    *time.Time
	RevokedAt *time.Time
	CreatedBy *string
	CreatedAt time.Time
}

// Store reads and writes the backup tables.
type Store struct {
	pool  *pgxpool.Pool
	clock func() time.Time
}

// NewStore builds a Store over a pool. now may be nil (defaults to time.Now).
func NewStore(pool *pgxpool.Pool, now func() time.Time) *Store {
	clock := now
	if clock == nil {
		clock = time.Now
	}
	return &Store{pool: pool, clock: clock}
}

// CreatePlanParams is the input for CreatePlan.
type CreatePlanParams struct {
	ProjectID          string
	ServerID           string
	Name               string
	Slug               string
	ScopeType          string
	ScopeID            string // empty when scope is the whole project
	DestinationType    string
	DestinationConfig  map[string]any
	DestinationConfRef string
	EncryptionKeyRef   string
	ScheduleCron       string
	NextRunAt          *time.Time
	RetentionCount     int
	RetentionDays      int
	CreatedBy          string
}

// CreatePlan inserts one plan.
func (s *Store) CreatePlan(ctx context.Context, p CreatePlanParams) (Plan, error) {
	if err := p.validate(); err != nil {
		return Plan{}, err
	}
	destJSON, err := json.Marshal(orEmptyMap(p.DestinationConfig))
	if err != nil {
		return Plan{}, fmt.Errorf("backups: marshal destination_config: %w", err)
	}
	retentionCount := p.RetentionCount
	if retentionCount <= 0 {
		retentionCount = 7
	}
	retentionDays := p.RetentionDays
	if retentionDays <= 0 {
		retentionDays = 30
	}
	var plan Plan
	err = s.pool.QueryRow(ctx, `
		INSERT INTO backup_plans (
			project_id, server_id, name, slug, scope_type, scope_id,
			destination_type, destination_config, destination_config_ref, encryption_key_ref,
			schedule_cron, next_run_at, retention_count, retention_days, created_by
		) VALUES (
			$1::uuid, $2::uuid, $3, $4, $5, NULLIF($6, '')::uuid,
			$7, $8, $9, $10,
			$11, $12, $13, $14, NULLIF($15, '')::uuid
		) RETURNING `+planColumns,
		p.ProjectID, p.ServerID, p.Name, p.Slug, p.ScopeType, p.ScopeID,
		p.DestinationType, destJSON, p.DestinationConfRef, p.EncryptionKeyRef,
		p.ScheduleCron, p.NextRunAt, retentionCount, retentionDays, p.CreatedBy,
	).Scan(
		&plan.ID, &plan.ProjectID, &plan.ServerID, &plan.Name, &plan.Slug, &plan.ScopeType, &plan.ScopeID,
		&plan.DestinationType, &destJSON, &plan.DestinationConfRef, &plan.EncryptionKeyRef,
		&plan.ScheduleCron, &plan.NextRunAt, &plan.Enabled, &plan.RetentionCount, &plan.RetentionDays, &plan.State,
		&plan.CreatedBy, &plan.CreatedAt, &plan.UpdatedAt, &plan.DeleteAfter, &plan.DeletedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return Plan{}, ErrSlugTaken
		}
		return Plan{}, fmt.Errorf("backups: insert plan: %w", err)
	}
	if len(destJSON) > 0 {
		if uErr := json.Unmarshal(destJSON, &plan.DestinationConfig); uErr != nil {
			return Plan{}, fmt.Errorf("backups: unmarshal plan destination_config: %w", uErr)
		}
	}
	return plan, nil
}

func (p CreatePlanParams) validate() error {
	var errs []error
	if p.ProjectID == "" || p.ServerID == "" {
		errs = append(errs, errors.New("project_id and server_id are required"))
	}
	if !slugRE.MatchString(p.Slug) || len(p.Slug) < 2 || len(p.Slug) > 48 {
		errs = append(errs, fmt.Errorf("slug %q must match %s (2-48 chars)", p.Slug, slugRE))
	}
	if p.Name == "" {
		errs = append(errs, errors.New("name is required"))
	}
	switch p.ScopeType {
	case ScopeProject, ScopeSite, ScopeDatabase:
	default:
		errs = append(errs, fmt.Errorf("scope_type %q must be project, site, or database", p.ScopeType))
	}
	switch p.DestinationType {
	case DestLocal, DestS3:
	default:
		errs = append(errs, fmt.Errorf("destination_type %q must be local or s3", p.DestinationType))
	}
	if len(errs) > 0 {
		return errors.Join(append([]error{ErrInvalid}, errs...)...)
	}
	return nil
}

// GetPlanInProject loads a live plan scoped to a project. A plan from another
// project returns ErrNotFound (not ErrState): cross-project reads are
// indistinguishable from missing rows, closing the enumeration oracle.
func (s *Store) GetPlanInProject(ctx context.Context, projectID, id string) (Plan, error) {
	return scanPlan(s.pool.QueryRow(ctx,
		`SELECT `+planColumns+` FROM backup_plans
		 WHERE id = $1::uuid AND project_id = $2::uuid AND deleted_at IS NULL`, id, projectID))
}

// ListPlans lists live plans in a project, newest first.
func (s *Store) ListPlans(ctx context.Context, projectID string, limit, offset int) ([]Plan, error) {
	if limit <= 0 || limit > maxListLimit {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+planColumns+` FROM backup_plans
		 WHERE project_id = $1::uuid AND deleted_at IS NULL
		 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, projectID, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("backups: list plans: %w", err)
	}
	defer rows.Close()
	var out []Plan
	for rows.Next() {
		p, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdatePlanParams holds the mutable fields; nil means "leave unchanged".
type UpdatePlanParams struct {
	Name           *string
	ScheduleCron   *string
	NextRunAt      **time.Time
	Enabled        *bool
	RetentionCount *int
	RetentionDays  *int
	State          *string
}

// UpdatePlan applies a partial update, refreshing updated_at.
func (s *Store) UpdatePlan(ctx context.Context, projectID, id string, p UpdatePlanParams) (Plan, error) {
	plan, err := s.GetPlanInProject(ctx, projectID, id)
	if err != nil {
		return Plan{}, err
	}
	name := plan.Name
	if p.Name != nil {
		name = *p.Name
		if name == "" {
			return Plan{}, fmt.Errorf("%w: name must not be empty", ErrInvalid)
		}
	}
	cron := plan.ScheduleCron
	if p.ScheduleCron != nil {
		cron = *p.ScheduleCron
	}
	nextRun := plan.NextRunAt
	if p.NextRunAt != nil && *p.NextRunAt != nil {
		nextRun = *p.NextRunAt
	}
	enabled := plan.Enabled
	if p.Enabled != nil {
		enabled = *p.Enabled
	}
	retCount := plan.RetentionCount
	if p.RetentionCount != nil {
		retCount = *p.RetentionCount
		if retCount < 1 {
			return Plan{}, fmt.Errorf("%w: retention_count must be >= 1", ErrInvalid)
		}
	}
	retDays := plan.RetentionDays
	if p.RetentionDays != nil {
		retDays = *p.RetentionDays
		if retDays < 1 {
			return Plan{}, fmt.Errorf("%w: retention_days must be >= 1", ErrInvalid)
		}
	}
	state := plan.State
	if p.State != nil {
		state = *p.State
		switch state {
		case StateActive, StateSuspended:
			if plan.State == StatePendingDelete || plan.State == StateDeleted {
				return Plan{}, fmt.Errorf("%w: %s -> %s", ErrState, plan.State, state)
			}
		default:
			return Plan{}, fmt.Errorf("%w: state %q not settable here", ErrInvalid, state)
		}
	}
	var updated Plan
	var destJSON []byte
	err = s.pool.QueryRow(ctx, `
		UPDATE backup_plans SET
			name = $3, schedule_cron = $4, next_run_at = $5, enabled = $6,
			retention_count = $7, retention_days = $8, state = $9, updated_at = $10
		WHERE id = $1::uuid AND project_id = $2::uuid AND deleted_at IS NULL
		RETURNING `+planColumns,
		id, projectID, name, cron, nextRun, enabled, retCount, retDays, state, s.clock().UTC(),
	).Scan(
		&updated.ID, &updated.ProjectID, &updated.ServerID, &updated.Name, &updated.Slug, &updated.ScopeType, &updated.ScopeID,
		&updated.DestinationType, &destJSON, &updated.DestinationConfRef, &updated.EncryptionKeyRef,
		&updated.ScheduleCron, &updated.NextRunAt, &updated.Enabled, &updated.RetentionCount, &updated.RetentionDays, &updated.State,
		&updated.CreatedBy, &updated.CreatedAt, &updated.UpdatedAt, &updated.DeleteAfter, &updated.DeletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Plan{}, ErrNotFound
	}
	if err != nil {
		return Plan{}, fmt.Errorf("backups: update plan: %w", err)
	}
	if err := finalizePlanScan(&updated, destJSON); err != nil {
		return Plan{}, err
	}
	return updated, nil
}

// finalizePlanScan unmarshals the destination_config after a plan Scan.
func finalizePlanScan(p *Plan, destJSON []byte) error {
	if len(destJSON) > 0 {
		if err := json.Unmarshal(destJSON, &p.DestinationConfig); err != nil {
			return fmt.Errorf("backups: unmarshal updated destination_config: %w", err)
		}
	}
	return nil
}

// MarkPendingDelete moves a plan to pending_delete with a grace window.
func (s *Store) MarkPendingDelete(ctx context.Context, projectID, id string, grace time.Duration) (Plan, error) {
	if grace <= 0 {
		grace = DefaultDeleteGrace
	}
	if grace > maxDeleteGrace {
		grace = maxDeleteGrace
	}
	now := s.clock().UTC()
	deleteAfter := now.Add(grace)
	var plan Plan
	var destJSON []byte
	err := s.pool.QueryRow(ctx, `
		UPDATE backup_plans SET state = 'pending_delete', delete_after = $3, updated_at = $4
		WHERE id = $1::uuid AND project_id = $2::uuid AND deleted_at IS NULL
		  AND state IN ('active', 'suspended')
		RETURNING `+planColumns, id, projectID, deleteAfter, now,
	).Scan(
		&plan.ID, &plan.ProjectID, &plan.ServerID, &plan.Name, &plan.Slug, &plan.ScopeType, &plan.ScopeID,
		&plan.DestinationType, &destJSON, &plan.DestinationConfRef, &plan.EncryptionKeyRef,
		&plan.ScheduleCron, &plan.NextRunAt, &plan.Enabled, &plan.RetentionCount, &plan.RetentionDays, &plan.State,
		&plan.CreatedBy, &plan.CreatedAt, &plan.UpdatedAt, &plan.DeleteAfter, &plan.DeletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Plan{}, ErrNotFound
	}
	if err != nil {
		return Plan{}, fmt.Errorf("backups: mark pending delete: %w", err)
	}
	if err := finalizePlanScan(&plan, destJSON); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

// FinalizeDelete tombstones a plan whose grace period has elapsed.
func (s *Store) FinalizeDelete(ctx context.Context, id string) error {
	now := s.clock().UTC()
	tag, err := s.pool.Exec(ctx, `
		UPDATE backup_plans SET state = 'deleted', deleted_at = $2, delete_after = NULL, updated_at = $2
		WHERE id = $1::uuid AND state = 'pending_delete' AND delete_after <= $2`, id, now)
	if err != nil {
		return fmt.Errorf("backups: finalize delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateRunParams is the input for CreateRun.
type CreateRunParams struct {
	PlanID          string
	ProjectID       string
	ServerID        string
	Trigger         string
	RequestedByType string
	RequestedByID   string
	IdempotencyKey  string
}

// CreateRun inserts a queued run. An active (queued/running) run for the same
// plan refuses a second one with ErrConflictActive.
func (s *Store) CreateRun(ctx context.Context, p CreateRunParams) (Run, error) {
	if err := p.validate(); err != nil {
		return Run{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Run{}, fmt.Errorf("backups: begin create run: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if p.PlanID != "" {
		var activeExists bool
		checkErr := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM backup_runs
				WHERE plan_id = $1::uuid AND state IN ('queued', 'running')
			)`, p.PlanID).Scan(&activeExists)
		if checkErr != nil {
			return Run{}, fmt.Errorf("backups: check active run: %w", checkErr)
		}
		if activeExists {
			return Run{}, ErrConflictActive
		}
	}

	var run Run
	var manifestJSON []byte
	err = tx.QueryRow(ctx, `
		INSERT INTO backup_runs (
			plan_id, project_id, server_id, trigger, requested_by_type, requested_by_id, idempotency_key
		) VALUES (
			NULLIF($1, '')::uuid, $2::uuid, $3::uuid, $4, $5, $6, NULLIF($7, '')
		) RETURNING `+runColumns,
		p.PlanID, p.ProjectID, p.ServerID, p.Trigger, p.RequestedByType, p.RequestedByID, p.IdempotencyKey,
	).Scan(
		&run.ID, &run.PlanID, &run.ProjectID, &run.ServerID, &run.Trigger, &run.State, &run.ArchivePath,
		&run.ArchiveSize, &run.SHA256, &run.EncryptionRef, &manifestJSON, &run.Verification,
		&run.JobID, &run.RequestedByType, &run.RequestedByID, &run.IdempotencyKey, &run.FailedReason,
		&run.CreatedAt, &run.StartedAt, &run.CompletedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			// Idempotency duplicate: return the existing run.
			_ = tx.Rollback(ctx)
			return s.GetRunByIdempotencyKey(ctx, p.ProjectID, p.IdempotencyKey)
		}
		return Run{}, fmt.Errorf("backups: insert run: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return Run{}, fmt.Errorf("backups: commit create run: %w", err)
	}
	run.RequestedByType = p.RequestedByType
	run.RequestedByID = p.RequestedByID
	return run, nil
}

func (p CreateRunParams) validate() error {
	var errs []error
	if p.ProjectID == "" || p.ServerID == "" {
		errs = append(errs, errors.New("project_id and server_id are required"))
	}
	switch p.Trigger {
	case TriggerManual, TriggerScheduled, TriggerPreChange:
	default:
		errs = append(errs, fmt.Errorf("trigger %q must be manual, scheduled, or pre_change", p.Trigger))
	}
	switch p.RequestedByType {
	case "user", "system":
	default:
		errs = append(errs, fmt.Errorf("requested_by_type %q must be user or system", p.RequestedByType))
	}
	if len(errs) > 0 {
		return errors.Join(append([]error{ErrInvalid}, errs...)...)
	}
	return nil
}

// GetRun loads one run scoped to a project.
func (s *Store) GetRun(ctx context.Context, projectID, id string) (Run, error) {
	return scanRun(s.pool.QueryRow(ctx,
		`SELECT `+runColumns+` FROM backup_runs
		 WHERE id = $1::uuid AND project_id = $2::uuid`, id, projectID))
}

// GetRunByIdempotencyKey loads a run by its idempotency key.
func (s *Store) GetRunByIdempotencyKey(ctx context.Context, projectID, key string) (Run, error) {
	return scanRun(s.pool.QueryRow(ctx,
		`SELECT `+runColumns+` FROM backup_runs
		 WHERE project_id = $1::uuid AND idempotency_key = $2`, projectID, key))
}

// ListRuns lists runs in a project, newest first.
func (s *Store) ListRuns(ctx context.Context, projectID string, planID string, limit, offset int) ([]Run, error) {
	if limit <= 0 || limit > maxListLimit {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}
	rows, err := s.pool.Query(ctx,
		`SELECT `+runColumns+` FROM backup_runs
		 WHERE project_id = $1::uuid AND ($2::uuid IS NULL OR plan_id = $2::uuid)
		 ORDER BY created_at DESC LIMIT $3 OFFSET $4`,
		projectID, nullIfEmpty(planID), limit, offset)
	if err != nil {
		return nil, fmt.Errorf("backups: list runs: %w", err)
	}
	defer rows.Close()
	var out []Run
	for rows.Next() {
		r, err := scanRun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MarkRunRunning transitions queued -> running.
func (s *Store) MarkRunRunning(ctx context.Context, id string) error {
	now := s.clock().UTC()
	tag, err := s.pool.Exec(ctx, `
		UPDATE backup_runs SET state = 'running', started_at = $2 WHERE id = $1::uuid AND state = 'queued'`,
		id, now)
	if err != nil {
		return fmt.Errorf("backups: mark run running: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrState
	}
	return nil
}

// CompleteRunParams holds the artifact facts recorded when a run completes.
type CompleteRunParams struct {
	ID            string
	ArchivePath   string
	ArchiveSize   int64
	SHA256        string
	Manifest      map[string]any
	EncryptionRef string
}

// MarkRunCompleted transitions running -> completed with artifact metadata.
func (s *Store) MarkRunCompleted(ctx context.Context, p CompleteRunParams) error {
	manifestJSON, err := json.Marshal(orEmptyMap(p.Manifest))
	if err != nil {
		return fmt.Errorf("backups: marshal manifest: %w", err)
	}
	now := s.clock().UTC()
	tag, err := s.pool.Exec(ctx, `
		UPDATE backup_runs SET
			state = 'completed', archive_path = $2, archive_size_bytes = $3,
			sha256 = $4, manifest = $5, encryption_key_ref = $6, completed_at = $7
		WHERE id = $1::uuid AND state = 'running'`,
		p.ID, p.ArchivePath, p.ArchiveSize, p.SHA256, manifestJSON, p.EncryptionRef, now)
	if err != nil {
		return fmt.Errorf("backups: mark run completed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrState
	}
	return nil
}

// MarkRunFailed transitions queued|running -> failed with a reason.
func (s *Store) MarkRunFailed(ctx context.Context, id, reason string) error {
	now := s.clock().UTC()
	tag, err := s.pool.Exec(ctx, `
		UPDATE backup_runs SET state = 'failed', failed_reason = $2, completed_at = $3
		WHERE id = $1::uuid AND state IN ('queued', 'running')`, id, reason, now)
	if err != nil {
		return fmt.Errorf("backups: mark run failed: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrState
	}
	return nil
}

// UpdateRunVerification records the outcome of a verification pass.
func (s *Store) UpdateRunVerification(ctx context.Context, id, state string) error {
	switch state {
	case VerifUnverified, VerifVerified, VerifFailed, VerifExpired:
	default:
		return fmt.Errorf("%w: verification_state %q is not valid", ErrInvalid, state)
	}
	tag, err := s.pool.Exec(ctx, `
		UPDATE backup_runs SET verification_state = $2 WHERE id = $1::uuid`, id, state)
	if err != nil {
		return fmt.Errorf("backups: update verification: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetRunJob links a job to a run.
func (s *Store) SetRunJob(ctx context.Context, runID, jobID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE backup_runs SET job_id = $2::uuid WHERE id = $1::uuid`, runID, jobID)
	if err != nil {
		return fmt.Errorf("backups: set run job: %w", err)
	}
	return nil
}

// DuePlans returns enabled active plans whose next_run_at has passed.
// The scheduler calls this once per tick.
func (s *Store) DuePlans(ctx context.Context, now time.Time) ([]Plan, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+planColumns+` FROM backup_plans
		 WHERE enabled AND state = 'active' AND deleted_at IS NULL
		   AND next_run_at IS NOT NULL AND next_run_at <= $1
		 ORDER BY next_run_at LIMIT 50`, now)
	if err != nil {
		return nil, fmt.Errorf("backups: due plans: %w", err)
	}
	defer rows.Close()
	var out []Plan
	for rows.Next() {
		p, err := scanPlan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// AdvanceNextRun sets a plan's next_run_at after the scheduler enqueues a run.
func (s *Store) AdvanceNextRun(ctx context.Context, planID string, next time.Time) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE backup_plans SET next_run_at = $2, updated_at = $2
		WHERE id = $1::uuid AND enabled AND state = 'active' AND deleted_at IS NULL`,
		planID, next)
	if err != nil {
		return fmt.Errorf("backups: advance next run: %w", err)
	}
	return nil
}

// ExpireOldRuns enforces retention: marks completed runs beyond the plan's
// retention window as verification-expired so the retention worker can delete
// their artifacts. Returns the run IDs to purge.
func (s *Store) ExpireOldRuns(ctx context.Context, planID string, keepCount int, olderThan time.Time) ([]string, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE backup_runs SET verification_state = 'expired'
		WHERE id IN (
			SELECT id FROM backup_runs
			WHERE plan_id = $1::uuid AND state = 'completed'
			  AND verification_state <> 'expired'
			  AND created_at < $3
			ORDER BY created_at DESC
			OFFSET $2
		)
		RETURNING id::text`, planID, keepCount, olderThan)
	if err != nil {
		return nil, fmt.Errorf("backups: expire old runs: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("backups: scan expired run: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// CreateExpiringLinkParams is the input for CreateExpiringLink.
type CreateExpiringLinkParams struct {
	RunID     string
	ProjectID string
	TokenHash string
	TTL       time.Duration
	SingleUse bool
	CreatedBy string
}

// CreateExpiringLink inserts one download token record.
func (s *Store) CreateExpiringLink(ctx context.Context, p CreateExpiringLinkParams) (ExpiringLink, error) {
	if p.TokenHash == "" || p.RunID == "" || p.ProjectID == "" {
		return ExpiringLink{}, fmt.Errorf("%w: run_id, project_id, and token_hash are required", ErrInvalid)
	}
	if p.TTL <= 0 || p.TTL > 24*time.Hour {
		return ExpiringLink{}, fmt.Errorf("%w: ttl must be between 1s and 24h", ErrInvalid)
	}
	now := s.clock().UTC()
	var l ExpiringLink
	err := s.pool.QueryRow(ctx, `
		INSERT INTO backup_expiring_links (run_id, project_id, token_hash, expires_at, single_use, created_by)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, NULLIF($6, '')::uuid)
		RETURNING id::text, run_id::text, project_id::text, token_hash, expires_at, single_use,
		          used_at, revoked_at, created_by::text, created_at`,
		p.RunID, p.ProjectID, p.TokenHash, now.Add(p.TTL), p.SingleUse, p.CreatedBy,
	).Scan(&l.ID, &l.RunID, &l.ProjectID, &l.TokenHash, &l.ExpiresAt, &l.SingleUse,
		&l.UsedAt, &l.RevokedAt, &l.CreatedBy, &l.CreatedAt)
	if err != nil {
		if isUniqueViolation(err) {
			return ExpiringLink{}, fmt.Errorf("%w: token collision, regenerate", ErrInvalid)
		}
		return ExpiringLink{}, fmt.Errorf("backups: insert expiring link: %w", err)
	}
	return l, nil
}

// RedeemExpiringLink atomically validates and (for single-use links) consumes a
// token. Returns the run ID the token authorizes. Any of: unknown, revoked,
// expired, or already-used returns ErrLinkExpired — indistinguishable, so the
// endpoint is not an oracle for which tokens exist.
func (s *Store) RedeemExpiringLink(ctx context.Context, tokenHash string) (string, error) {
	now := s.clock().UTC()
	var runID string
	err := s.pool.QueryRow(ctx, `
		UPDATE backup_expiring_links SET
			used_at = CASE WHEN single_use THEN $2 ELSE used_at END
		WHERE token_hash = $1
		  AND revoked_at IS NULL
		  AND used_at IS NULL
		  AND expires_at > $2
		RETURNING run_id::text`, tokenHash, now).Scan(&runID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrLinkExpired
	}
	if err != nil {
		return "", fmt.Errorf("backups: redeem expiring link: %w", err)
	}
	return runID, nil
}

// RevokeExpiringLink cancels an outstanding link.
func (s *Store) RevokeExpiringLink(ctx context.Context, projectID, id string) error {
	now := s.clock().UTC()
	tag, err := s.pool.Exec(ctx, `
		UPDATE backup_expiring_links SET revoked_at = $3
		WHERE id = $1::uuid AND project_id = $2::uuid AND revoked_at IS NULL`, id, projectID, now)
	if err != nil {
		return fmt.Errorf("backups: revoke expiring link: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func orEmptyMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// isUniqueViolation reports the PostgreSQL unique-violation code (23505).
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
