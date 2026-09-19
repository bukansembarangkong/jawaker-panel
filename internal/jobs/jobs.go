// Package jobs is the durable job engine (ARCHITECTURE.md §3.5, PRD §32.4).
//
// It uses PostgreSQL tables, row locks, and LISTEN/NOTIFY with a polling
// fallback — no external broker, so a small installation stays lightweight
// (ADR-029). A dedicated broker can be added later as an optional scale module
// without changing this API.
//
// The six properties a durable engine has to satisfy, and how each is met here:
//
//   - persisted steps with independent status: job_steps, one row per step;
//   - leases with expiry so a crashed worker's job is RECOVERED, not lost:
//     lease_owner/lease_expires_at, reaped by ReclaimExpiredLeases;
//   - bounded retry with backoff: attempt_count/max_attempts/next_attempt_at;
//   - cancellation a running worker observes: cancel_requested_at, checked at
//     step boundaries;
//   - idempotent enqueue: the caller-supplied key hits jobs_idempotency_idx, so
//     concurrent retries cannot both insert;
//   - per-resource exclusion: job_resource_locks, so two jobs cannot mutate one
//     resource at once.
//
// All mutual exclusion is enforced in the database. An in-process mutex would be
// wrong: controllers run as several replicas during a rolling upgrade, and the
// whole point of the lease is to survive one of them dying.
package jobs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors.
var (
	// ErrNotFound means the job does not exist.
	ErrNotFound = errors.New("jobs: not found")
	// ErrLeaseLost means this worker no longer owns the job: another worker
	// reclaimed it after the lease expired. The caller must stop immediately,
	// because continuing would double-execute work.
	ErrLeaseLost = errors.New("jobs: lease lost")
	// ErrAlreadyTerminal means the job reached a final state.
	ErrAlreadyTerminal = errors.New("jobs: already terminal")
	// ErrDuplicate means the idempotency key was already used. The returned job
	// is the one that won.
	ErrDuplicate = errors.New("jobs: duplicate idempotency key")
	// ErrCanceled means cooperative cancellation was requested and observed.
	ErrCanceled = errors.New("jobs: canceled")
	// ErrNoStep means a step transition referenced an unknown step index.
	ErrNoStep = errors.New("jobs: no such step")
)

// States. Kept in sync with the jobs.state CHECK constraint (migration 0005).
const (
	StateQueued     = "queued"
	StateLeased     = "leased"
	StateRunning    = "running"
	StateSucceeded  = "succeeded"
	StateFailed     = "failed"
	StateCanceled   = "canceled"
	StateDeadLetter = "dead_letter"
)

// Step states. Kept in sync with job_steps.state.
const (
	StepPending   = "pending"
	StepRunning   = "running"
	StepSucceeded = "succeeded"
	StepFailed    = "failed"
	StepSkipped   = "skipped"
	StepCanceled  = "canceled"
)

// Attempt outcomes. Kept in sync with job_attempts.outcome.
const (
	OutcomeLeased    = "leased"
	OutcomeSucceeded = "succeeded"
	OutcomeFailed    = "failed"
	OutcomeLostLease = "lost_lease"
	OutcomeCanceled  = "canceled"
)

// DefaultPriority is the queue default. Higher runs first among jobs contending
// for the same resource.
const DefaultPriority = 100

// notifyChannel is the LISTEN/NOTIFY channel used to wake workers immediately
// rather than waiting for the next poll. Polling remains as a fallback, so a
// missed NOTIFY costs latency and never correctness.
const notifyChannel = "jobs_wakeup"

// Requested describes a job to enqueue.
type Requested struct {
	// Type is the job type key, e.g. "site.create". Required.
	Type string
	// ServerID/ProjectID scope the job. Both empty for installation-wide work
	// such as "panel.update".
	ServerID  string
	ProjectID string
	// IdempotencyKey scopes duplicate suppression. Empty means no suppression
	// (internal/scheduled work).
	IdempotencyKey string
	// IdempotencyScope qualifies the key, e.g. "user:<id>". The unique index
	// covers the pair, so the same key under different scopes is different work.
	IdempotencyScope string
	// Priority. Zero means DefaultPriority.
	Priority int
	// MaxAttempts bounds retries. Zero means 3.
	MaxAttempts int
	// RequestedByType/RequestByID attribute the request for audit and
	// notification routing.
	RequestedByType string
	RequestedByID   string
	// Payload is arbitrary job input, serialized as jsonb.
	Payload map[string]any
	// Steps declares the step plan up front, so the UI can render progress
	// before the job runs.
	Steps []StepPlan
	// RequestID correlates with the HTTP request that enqueued the job.
	RequestID string
	// LockKeys are resources the job needs exclusively, e.g. "site:<id>".
	LockKeys []string
}

// StepPlan is one declared step.
type StepPlan struct {
	// Name identifies the step for humans and logs.
	Name string
}

func (r Requested) withDefaults() Requested {
	if r.Priority == 0 {
		r.Priority = DefaultPriority
	}
	if r.MaxAttempts == 0 {
		r.MaxAttempts = 3
	}
	if r.RequestedByType == "" {
		r.RequestedByType = "system"
	}
	return r
}

func (r Requested) validate() error {
	var errs []error
	if r.Type == "" {
		errs = append(errs, errors.New("jobs: type is required"))
	}
	if r.Priority < 0 {
		errs = append(errs, errors.New("jobs: priority must not be negative"))
	}
	if r.MaxAttempts <= 0 {
		errs = append(errs, errors.New("jobs: max_attempts must be positive"))
	}
	if r.MaxAttempts > 20 {
		// Bounded so a permanently failing job cannot retry forever and hide
		// itself among healthy ones.
		errs = append(errs, errors.New("jobs: max_attempts must not exceed 20"))
	}
	switch r.RequestedByType {
	case "user", "api_token", "service", "system", "ai":
	default:
		errs = append(errs, fmt.Errorf("jobs: requested_by_type %q is not valid", r.RequestedByType))
	}
	if r.IdempotencyKey != "" && r.IdempotencyScope == "" {
		errs = append(errs, errors.New("jobs: idempotency_scope is required with an idempotency_key"))
	}
	return errors.Join(errs...)
}

// Job is a job row.
type Job struct {
	ID            string
	Type          string
	ServerID      string
	ProjectID     string
	State         string
	Priority      int
	Progress      Progress
	AttemptCount  int
	MaxAttempts   int
	NextAttemptAt time.Time
	LeaseOwner    string
	LeaseExpires  *time.Time
	CancelReq     *time.Time
	ErrorCode     string
	ErrorSummary  string
	RequestID     string
	CreatedAt     time.Time
	StartedAt     *time.Time
	FinishedAt    *time.Time
	// Payload is the job input.
	Payload map[string]any
	// LockKeys are the resources the job currently holds.
	LockKeys []string
}

// Progress is the durable progress report the UI renders (DESIGN_SYSTEM.md §15).
type Progress struct {
	Current     int
	Total       int
	CurrentStep string
}

// Terminal reports whether the job reached a final state.
func (j Job) Terminal() bool {
	switch j.State {
	case StateSucceeded, StateFailed, StateCanceled, StateDeadLetter:
		return true
	default:
		return false
	}
}

// Enqueue creates a job and its declared steps in one transaction.
//
// When an idempotency key is supplied, a concurrent duplicate does NOT create a
// second job: the unique index makes one insert lose, and the existing job is
// returned with ErrDuplicate so the caller can treat both outcomes as success.
// This is what lets a retried HTTP request be safe (API.md §9).
func Enqueue(ctx context.Context, pool *pgxpool.Pool, req Requested) (Job, error) {
	req = req.withDefaults()
	if err := req.validate(); err != nil {
		return Job{}, err
	}
	if pool == nil {
		return Job{}, errors.New("jobs: database is required")
	}

	encodedPayload, err := encodePayload(req.Payload)
	if err != nil {
		return Job{}, err
	}

	lockKeys := req.LockKeys
	if lockKeys == nil {
		// The column is NOT NULL; an explicit empty array is the honest value.
		lockKeys = []string{}
	}
	for _, key := range lockKeys {
		if key == "" {
			return Job{}, errors.New("jobs: lock key must not be empty")
		}
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return Job{}, fmt.Errorf("jobs: begin enqueue: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var job Job
	err = tx.QueryRow(ctx, `
		INSERT INTO jobs (type, server_id, project_id, idempotency_key, idempotency_scope,
		                  priority, max_attempts, requested_by_type, requested_by_id,
		                  payload, request_id, lock_keys)
		VALUES ($1, NULLIF($2, '')::uuid, NULLIF($3, '')::uuid, NULLIF($4, ''), NULLIF($5, ''),
		        $6, $7, $8, NULLIF($9, '')::uuid, $10::jsonb, NULLIF($11, ''), $12::text[])
		RETURNING id, type, COALESCE(server_id::text, ''), COALESCE(project_id::text, ''),
		          state, priority, progress_current, COALESCE(progress_total, 0),
		          COALESCE(current_step, ''), attempt_count, max_attempts, next_attempt_at,
		          created_at, COALESCE(request_id, '')`,
		req.Type, req.ServerID, req.ProjectID, req.IdempotencyKey, req.IdempotencyScope,
		req.Priority, req.MaxAttempts, req.RequestedByType, req.RequestedByID,
		encodedPayload, req.RequestID, lockKeys).
		Scan(&job.ID, &job.Type, &job.ServerID, &job.ProjectID, &job.State,
			&job.Priority, &job.Progress.Current, &job.Progress.Total,
			&job.Progress.CurrentStep, &job.AttemptCount, &job.MaxAttempts,
			&job.NextAttemptAt, &job.CreatedAt, &job.RequestID)
	if err != nil {
		if isUniqueViolation(err) {
			// The losing side of an idempotency race. Return the job that won so
			// the caller has something to report.
			//
			// The lookup MUST NOT use tx: a unique violation aborts the whole
			// transaction, so every later statement on it fails with 25P02
			// ("current transaction is aborted"). Roll back and read through the
			// pool, which is already committed by the winner.
			_ = tx.Rollback(ctx)
			existing, lookupErr := GetByIdempotencyKey(ctx, pool, req.IdempotencyScope, req.IdempotencyKey)
			if lookupErr != nil {
				return Job{}, fmt.Errorf("jobs: duplicate lookup: %w", lookupErr)
			}
			return existing, fmt.Errorf("%w: %s/%s", ErrDuplicate,
				req.IdempotencyScope, req.IdempotencyKey)
		}
		return Job{}, fmt.Errorf("jobs: insert: %w", err)
	}
	job.LockKeys = req.LockKeys
	job.Payload, err = decodePayload(encodedPayload)
	if err != nil {
		return Job{}, fmt.Errorf("jobs: decode inserted payload: %w", err)
	}

	// Declared steps are inserted up front so progress is renderable before the
	// job runs, and so the plan is durable even if the process dies first.
	for i, step := range req.Steps {
		if step.Name == "" {
			return Job{}, fmt.Errorf("jobs: step %d has no name", i)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO job_steps (job_id, step_index, name) VALUES ($1, $2, $3)`,
			job.ID, i, step.Name); err != nil {
			return Job{}, fmt.Errorf("jobs: insert step %d: %w", i, err)
		}
	}
	job.Progress.Total = len(req.Steps)
	if job.Progress.Total > 0 {
		if _, err := tx.Exec(ctx,
			`UPDATE jobs SET progress_total = $2 WHERE id = $1`, job.ID, job.Progress.Total); err != nil {
			return Job{}, fmt.Errorf("jobs: record step count: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return Job{}, fmt.Errorf("jobs: commit enqueue: %w", err)
	}

	// NOTIFY outside the transaction: a notification sent before the insert is
	// visible would wake a worker that then finds nothing. Deliberately not
	// returned as an error either — the job is already committed, and failing the
	// call here would tell the caller their job does not exist when it does. A
	// worker's polling loop finds the job regardless, so a lost notify costs
	// latency and never correctness.
	_, _ = pool.Exec(ctx, `SELECT pg_notify($1, $2)`, notifyChannel, job.ID)

	return job, nil
}

// GetByID loads a job.
func GetByID(ctx context.Context, q Queryer, id string) (Job, error) {
	job, err := scanJob(q.QueryRow(ctx, `
		SELECT id, type, COALESCE(server_id::text, ''), COALESCE(project_id::text, ''),
		       state, priority, progress_current, COALESCE(progress_total, 0),
		       COALESCE(current_step, ''), attempt_count, max_attempts, next_attempt_at,
		       COALESCE(lease_owner, ''), lease_expires_at, cancel_requested_at,
		       COALESCE(error_code, ''), COALESCE(error_summary, ''),
		       created_at, started_at, finished_at, COALESCE(request_id, ''), payload
		FROM jobs WHERE id = $1`, id))
	if err != nil {
		return Job{}, err
	}
	locks, err := HeldLocks(ctx, q, id)
	if err != nil {
		return Job{}, err
	}
	job.LockKeys = locks
	return job, nil
}

// Step is one durable step row.
type Step struct {
	Index        int
	Name         string
	State        string
	Output       map[string]any
	ErrorCode    string
	ErrorSummary string
	Attempt      int
	StartedAt    *time.Time
	FinishedAt   *time.Time
}

// ListSteps returns a job's steps in execution order. Progress rendering and
// resumability both depend on this being the authoritative plan, so it reads
// the table rather than any in-memory copy.
func ListSteps(ctx context.Context, q Queryer, jobID string) ([]Step, error) {
	rows, err := q.Query(ctx, `
		SELECT step_index, name, state, output, COALESCE(error_code, ''),
		       COALESCE(error_summary, ''), attempt, started_at, finished_at
		FROM job_steps WHERE job_id = $1 ORDER BY step_index`, jobID)
	if err != nil {
		return nil, fmt.Errorf("jobs: list steps: %w", err)
	}
	defer rows.Close()

	var steps []Step
	for rows.Next() {
		var s Step
		var output []byte
		if err := rows.Scan(&s.Index, &s.Name, &s.State, &output, &s.ErrorCode,
			&s.ErrorSummary, &s.Attempt, &s.StartedAt, &s.FinishedAt); err != nil {
			return nil, fmt.Errorf("jobs: scan step: %w", err)
		}
		decoded, err := decodePayload(output)
		if err != nil {
			return nil, fmt.Errorf("jobs: decode step output: %w", err)
		}
		s.Output = decoded
		steps = append(steps, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("jobs: iterate steps: %w", err)
	}
	return steps, nil
}

// HeldLocks returns the resource lock keys a job currently holds.
func HeldLocks(ctx context.Context, q Queryer, jobID string) ([]string, error) {
	rows, err := q.Query(ctx,
		`SELECT lock_key FROM job_resource_locks WHERE job_id = $1 ORDER BY lock_key`, jobID)
	if err != nil {
		return nil, fmt.Errorf("jobs: list held locks: %w", err)
	}
	defer rows.Close()
	var keys []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, fmt.Errorf("jobs: scan held lock: %w", err)
		}
		keys = append(keys, key)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("jobs: iterate held locks: %w", err)
	}
	return keys, nil
}

// GetByIdempotencyKey resolves the job created for a scope/key pair.
func GetByIdempotencyKey(ctx context.Context, q Queryer, scope, key string) (Job, error) {
	return scanJob(q.QueryRow(ctx, `
		SELECT id, type, COALESCE(server_id::text, ''), COALESCE(project_id::text, ''),
		       state, priority, progress_current, COALESCE(progress_total, 0),
		       COALESCE(current_step, ''), attempt_count, max_attempts, next_attempt_at,
		       COALESCE(lease_owner, ''), lease_expires_at, cancel_requested_at,
		       COALESCE(error_code, ''), COALESCE(error_summary, ''),
		       created_at, started_at, finished_at, COALESCE(request_id, ''), payload
		FROM jobs WHERE idempotency_scope = $1 AND idempotency_key = $2`, scope, key))
}

// Queryer is the read surface. pgx.Tx and *pgxpool.Pool both satisfy it.
type Queryer interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Execer adds writes.
type Execer interface {
	Queryer
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

func scanJob(row pgx.Row) (Job, error) {
	var j Job
	var payload []byte
	err := row.Scan(&j.ID, &j.Type, &j.ServerID, &j.ProjectID, &j.State, &j.Priority,
		&j.Progress.Current, &j.Progress.Total, &j.Progress.CurrentStep,
		&j.AttemptCount, &j.MaxAttempts, &j.NextAttemptAt,
		&j.LeaseOwner, &j.LeaseExpires, &j.CancelReq,
		&j.ErrorCode, &j.ErrorSummary,
		&j.CreatedAt, &j.StartedAt, &j.FinishedAt, &j.RequestID, &payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	if err != nil {
		return Job{}, fmt.Errorf("jobs: scan: %w", err)
	}
	decoded, err := decodePayload(payload)
	if err != nil {
		return Job{}, fmt.Errorf("jobs: decode payload: %w", err)
	}
	j.Payload = decoded
	return j, nil
}

// isUniqueViolation reports the PostgreSQL unique-violation code.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// encodePayload serializes a job payload to jsonb text. A nil or empty payload
// becomes "{}", matching the column default, so an absent input is not
// distinguishable from an empty one. An unmarshalable value is an error rather
// than a silent "{}" — a job that loses its input is worse than one that
// refuses to enqueue.
func encodePayload(payload map[string]any) ([]byte, error) {
	if len(payload) == 0 {
		return []byte("{}"), nil
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("jobs: encode payload: %w", err)
	}
	return encoded, nil
}

// decodePayload parses a jsonb document into a map. It returns an empty map for
// an empty document rather than nil, so callers can always index the result.
func decodePayload(data []byte) (map[string]any, error) {
	if len(data) == 0 {
		return map[string]any{}, nil
	}
	decoded := map[string]any{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, err
	}
	return decoded, nil
}
