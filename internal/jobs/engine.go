package jobs

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Lease tuning. A worker renews at half the TTL so a single missed heartbeat
// (GC pause, brief network blip) does not forfeit the job; two consecutive
// misses do, which is the intended crash-detection latency.
const (
	// DefaultLeaseTTL is how long a claim is valid before another worker may
	// reclaim it.
	DefaultLeaseTTL = 60 * time.Second
	// DefaultPollInterval bounds how long a worker waits between claim attempts
	// when no NOTIFY arrives. NOTIFY makes the common case immediate; polling is
	// the correctness fallback so a lost notification costs latency, never a job.
	DefaultPollInterval = 5 * time.Second
	// retryBaseDelay and retryMaxDelay bound exponential backoff. Deterministic
	// (no jitter) so tests can assert the schedule; a large fleet that needs
	// jitter to avoid thundering-herd retries is a later, opt-in concern.
	retryBaseDelay = 5 * time.Second
	retryMaxDelay  = 5 * time.Minute
)

// BackoffDelay returns the delay before the next attempt for a job that has
// already failed `attempt` times. Exponential from retryBaseDelay, capped at
// retryMaxDelay.
func BackoffDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return retryBaseDelay
	}
	// Guard the shift: attempt is bounded by max_attempts (<= 20), but an
	// unvalidated caller must not be able to overflow the exponent.
	if attempt > 30 {
		return retryMaxDelay
	}
	d := time.Duration(math.Pow(2, float64(attempt-1))) * retryBaseDelay
	if d <= 0 || d > retryMaxDelay { // overflow or beyond cap
		return retryMaxDelay
	}
	return d
}

// ClaimOptions selects which jobs a worker may claim.
type ClaimOptions struct {
	// Owner identifies this worker in lease_owner and job_attempts. Required;
	// it must be unique per process (hostname+pid+random) so a restarted process
	// never mistakes a dead predecessor's lease for its own.
	Owner string
	// LeaseTTL bounds how long the claim is held. Zero means DefaultLeaseTTL.
	LeaseTTL time.Duration
	// Types restricts the worker to specific job types. Empty means any type.
	Types []string
	// Now overrides the clock; tests use it to control lease expiry and backoff.
	// Zero means the database clock (now()), which is what production uses.
	Now time.Time
}

func (o ClaimOptions) withDefaults() (ClaimOptions, error) {
	if o.Owner == "" {
		return o, errors.New("jobs: claim owner is required")
	}
	if o.LeaseTTL == 0 {
		o.LeaseTTL = DefaultLeaseTTL
	}
	if o.LeaseTTL < time.Second {
		return o, errors.New("jobs: lease TTL must be at least 1s")
	}
	return o, nil
}

// Claim atomically takes the next runnable job for this worker.
//
// It returns (Job{}, nil) when nothing is claimable right now — that is the
// normal idle case, not an error. Mutual exclusion is enforced entirely in the
// database:
//
//   - FOR UPDATE SKIP LOCKED means two workers never claim the same row and
//     never block each other waiting for it;
//   - the NOT EXISTS check skips any job whose declared lock_keys collide with a
//     lock another job currently holds, giving per-resource exclusion;
//   - the resource locks are inserted in the SAME transaction as the lease, so a
//     job is never running without holding the locks it declared.
//
// A lost race on a resource lock (two workers pass the NOT EXISTS check before
// either inserts) is resolved by the PRIMARY KEY on lock_key: the loser's insert
// fails, the whole claim transaction rolls back, and the job stays queued for
// the next poll. No partial state escapes.
func Claim(ctx context.Context, pool *pgxpool.Pool, opts ClaimOptions) (Job, error) {
	opts, err := opts.withDefaults()
	if err != nil {
		return Job{}, err
	}
	if pool == nil {
		return Job{}, errors.New("jobs: database is required")
	}

	leaseSeconds := opts.LeaseTTL.Seconds()

	tx, err := pool.Begin(ctx)
	if err != nil {
		return Job{}, fmt.Errorf("jobs: begin claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// A nil slice would be sent as SQL NULL, and cardinality(NULL) is NULL, not
	// 0 — which made the type predicate unknown and excluded every candidate.
	// Normalizing here keeps the query's meaning independent of driver encoding.
	types := opts.Types
	if types == nil {
		types = []string{}
	}

	// Candidate selection. An empty Types filter matches every type.
	// next_attempt_at gates retry backoff.
	//
	// COALESCE on both arrays is load-bearing: `x = ANY(NULL)` yields unknown
	// rather than false, so an unguarded comparison would silently disqualify
	// every job that declares no locks — the common case.
	row := tx.QueryRow(ctx, `
		SELECT id
		FROM jobs
		WHERE state = 'queued'
		  AND next_attempt_at <= now()
		  AND (cardinality(COALESCE($1::text[], '{}')) = 0 OR type = ANY($1::text[]))
		  AND NOT EXISTS (
		      SELECT 1 FROM job_resource_locks held
		      WHERE held.lock_key = ANY(COALESCE(jobs.lock_keys, '{}'))
		  )
		ORDER BY priority DESC, next_attempt_at ASC, id ASC
		FOR UPDATE SKIP LOCKED
		LIMIT 1`, types)

	var id string
	if scanErr := row.Scan(&id); scanErr != nil {
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return Job{}, nil // idle: nothing to claim
		}
		return Job{}, fmt.Errorf("jobs: select candidate: %w", scanErr)
	}

	// Take the lease and bump the attempt counter. started_at is set once, on
	// the first attempt, so retries do not reset the wall-clock start.
	var job Job
	var payload []byte
	var lockKeys []string
	err = tx.QueryRow(ctx, `
		UPDATE jobs
		SET state = 'leased',
		    lease_owner = $2,
		    lease_expires_at = now() + make_interval(secs => $3),
		    attempt_count = attempt_count + 1,
		    started_at = COALESCE(started_at, now())
		WHERE id = $1
		RETURNING id, type, COALESCE(server_id::text, ''), COALESCE(project_id::text, ''),
		          state, priority, progress_current, COALESCE(progress_total, 0),
		          COALESCE(current_step, ''), attempt_count, max_attempts, next_attempt_at,
		          COALESCE(lease_owner, ''), lease_expires_at, cancel_requested_at,
		          COALESCE(error_code, ''), COALESCE(error_summary, ''),
		          created_at, started_at, finished_at, COALESCE(request_id, ''),
		          payload, COALESCE(lock_keys, '{}')`,
		id, opts.Owner, leaseSeconds).
		Scan(&job.ID, &job.Type, &job.ServerID, &job.ProjectID, &job.State, &job.Priority,
			&job.Progress.Current, &job.Progress.Total, &job.Progress.CurrentStep,
			&job.AttemptCount, &job.MaxAttempts, &job.NextAttemptAt,
			&job.LeaseOwner, &job.LeaseExpires, &job.CancelReq,
			&job.ErrorCode, &job.ErrorSummary,
			&job.CreatedAt, &job.StartedAt, &job.FinishedAt, &job.RequestID,
			&payload, &lockKeys)
	if err != nil {
		return Job{}, fmt.Errorf("jobs: lease: %w", err)
	}
	decoded, err := decodePayload(payload)
	if err != nil {
		return Job{}, fmt.Errorf("jobs: decode claimed payload: %w", err)
	}
	job.Payload = decoded
	job.LockKeys = lockKeys

	// Acquire the declared resource locks in this same transaction. A conflict
	// means another worker won the race; roll back so the job stays queued.
	for _, key := range lockKeys {
		if _, err := tx.Exec(ctx,
			`INSERT INTO job_resource_locks (lock_key, job_id) VALUES ($1, $2)`,
			key, job.ID); err != nil {
			if isUniqueViolation(err) {
				return Job{}, nil // lost the lock race; retry on next poll
			}
			return Job{}, fmt.Errorf("jobs: acquire lock %q: %w", key, err)
		}
	}

	// Record the attempt. Outcome starts as 'leased' and is finalized by
	// Complete/Fail/Cancel; the row exists even if the worker dies mid-job,
	// which is what makes flapping detectable.
	if _, err := tx.Exec(ctx, `
		INSERT INTO job_attempts (job_id, attempt, worker, outcome)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (job_id, attempt) DO UPDATE
		SET worker = EXCLUDED.worker, outcome = EXCLUDED.outcome, started_at = now()`,
		job.ID, job.AttemptCount, opts.Owner, OutcomeLeased); err != nil {
		return Job{}, fmt.Errorf("jobs: record attempt: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Job{}, fmt.Errorf("jobs: commit claim: %w", err)
	}
	return job, nil
}

// A Lease is a claimed job plus the identity needed to renew and finish it.
// Every state transition goes through the Lease so a worker that has lost its
// lease cannot mutate a job another worker reclaimed.
type Lease struct {
	pool  *pgxpool.Pool
	job   Job
	owner string
	ttl   time.Duration
	// lost is set by the heartbeat when a renewal finds the lease gone. Reads
	// are atomic so the handler goroutine and the heartbeat goroutine share it
	// without a mutex.
	lost atomic.Bool
}

// Job returns the claimed job.
func (l *Lease) Job() Job { return l.job }

// Owner returns the lease owner identity.
func (l *Lease) Owner() string { return l.owner }

// Lost reports whether the lease has been forfeited.
func (l *Lease) Lost() bool { return l.lost.Load() }

// Renew extends the lease. It returns ErrLeaseLost if this worker no longer
// owns the job, which is the signal to abort immediately.
func (l *Lease) Renew(ctx context.Context) error {
	tag, err := l.pool.Exec(ctx, `
		UPDATE jobs
		SET lease_expires_at = now() + make_interval(secs => $3)
		WHERE id = $1 AND lease_owner = $2 AND state IN ('leased', 'running')`,
		l.job.ID, l.owner, l.ttl.Seconds())
	if err != nil {
		return fmt.Errorf("jobs: renew lease: %w", err)
	}
	if tag.RowsAffected() == 0 {
		l.lost.Store(true)
		return ErrLeaseLost
	}
	return nil
}

// Checkpoint renews the lease and reports whether cancellation was requested.
// Call it at every step boundary: it is the single place a running worker
// discovers that it lost the job (ErrLeaseLost) or that a user canceled it
// (returns canceled=true). Doing both in one round trip keeps the hot path
// cheap.
func (l *Lease) Checkpoint(ctx context.Context) (canceled bool, err error) {
	if l.lost.Load() {
		return false, ErrLeaseLost
	}
	var cancelRequested bool
	row := l.pool.QueryRow(ctx, `
		UPDATE jobs
		SET lease_expires_at = now() + make_interval(secs => $3)
		WHERE id = $1 AND lease_owner = $2 AND state IN ('leased', 'running')
		RETURNING cancel_requested_at IS NOT NULL`,
		l.job.ID, l.owner, l.ttl.Seconds())
	if err := row.Scan(&cancelRequested); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			l.lost.Store(true)
			return false, ErrLeaseLost
		}
		return false, fmt.Errorf("jobs: checkpoint: %w", err)
	}
	return cancelRequested, nil
}

// MarkRunning transitions a leased job to running. Idempotent: re-claiming a
// job after a crash finds it already running and this is a no-op.
func (l *Lease) MarkRunning(ctx context.Context) error {
	_, err := l.pool.Exec(ctx, `
		UPDATE jobs SET state = 'running'
		WHERE id = $1 AND lease_owner = $2 AND state = 'leased'`,
		l.job.ID, l.owner)
	if err != nil {
		return fmt.Errorf("jobs: mark running: %w", err)
	}
	return nil
}

// StartStep marks a step running and advances the durable progress the UI reads.
func (l *Lease) StartStep(ctx context.Context, index int, name string) error {
	tag, err := l.pool.Exec(ctx, `
		UPDATE job_steps
		SET state = 'running', started_at = now(), finished_at = NULL,
		    error_code = NULL, error_summary = NULL
		WHERE job_id = $1 AND step_index = $2
		  AND EXISTS (SELECT 1 FROM jobs
		              WHERE id = $1 AND lease_owner = $3 AND state IN ('leased','running'))`,
		l.job.ID, index, l.owner)
	if err != nil {
		return fmt.Errorf("jobs: start step %d: %w", index, err)
	}
	if tag.RowsAffected() == 0 {
		return l.stepGuardMiss(ctx, index)
	}
	if _, err := l.pool.Exec(ctx, `
		UPDATE jobs SET progress_current = $2, current_step = $3
		WHERE id = $1 AND lease_owner = $4`,
		l.job.ID, index+1, name, l.owner); err != nil {
		return fmt.Errorf("jobs: advance progress: %w", err)
	}
	return nil
}

// CompleteStep marks a step succeeded and records bounded structured output.
func (l *Lease) CompleteStep(ctx context.Context, index int, output map[string]any) error {
	encoded, err := encodePayload(output)
	if err != nil {
		return err
	}
	tag, err := l.pool.Exec(ctx, `
		UPDATE job_steps
		SET state = 'succeeded', finished_at = now(), output = $3::jsonb,
		    error_code = NULL, error_summary = NULL
		WHERE job_id = $1 AND step_index = $2
		  AND EXISTS (SELECT 1 FROM jobs
		              WHERE id = $1 AND lease_owner = $4 AND state IN ('leased','running'))`,
		l.job.ID, index, encoded, l.owner)
	if err != nil {
		return fmt.Errorf("jobs: complete step %d: %w", index, err)
	}
	if tag.RowsAffected() == 0 {
		return l.stepGuardMiss(ctx, index)
	}
	return nil
}

// FailStep marks a step failed with a code and a short summary.
func (l *Lease) FailStep(ctx context.Context, index int, code, summary string) error {
	tag, err := l.pool.Exec(ctx, `
		UPDATE job_steps
		SET state = 'failed', finished_at = now(), error_code = $3, error_summary = $4
		WHERE job_id = $1 AND step_index = $2
		  AND EXISTS (SELECT 1 FROM jobs
		              WHERE id = $1 AND lease_owner = $5 AND state IN ('leased','running'))`,
		l.job.ID, index, code, summary, l.owner)
	if err != nil {
		return fmt.Errorf("jobs: fail step %d: %w", index, err)
	}
	if tag.RowsAffected() == 0 {
		return l.stepGuardMiss(ctx, index)
	}
	return nil
}

// SkipStep marks a step skipped (a later branch made it unnecessary).
func (l *Lease) SkipStep(ctx context.Context, index int) error {
	tag, err := l.pool.Exec(ctx, `
		UPDATE job_steps
		SET state = 'skipped', finished_at = now()
		WHERE job_id = $1 AND step_index = $2
		  AND EXISTS (SELECT 1 FROM jobs
		              WHERE id = $1 AND lease_owner = $3 AND state IN ('leased','running'))`,
		l.job.ID, index, l.owner)
	if err != nil {
		return fmt.Errorf("jobs: skip step %d: %w", index, err)
	}
	if tag.RowsAffected() == 0 {
		return l.stepGuardMiss(ctx, index)
	}
	return nil
}

// stepGuardMiss distinguishes "lease lost" from "unknown step index" when a
// guarded step update touched no rows. The distinction matters: a lost lease
// must abort the worker, a bad index is a programming error.
func (l *Lease) stepGuardMiss(ctx context.Context, index int) error {
	var owned bool
	err := l.pool.QueryRow(ctx, `
		SELECT lease_owner = $2 AND state IN ('leased','running')
		FROM jobs WHERE id = $1`, l.job.ID, l.owner).Scan(&owned)
	if errors.Is(err, pgx.ErrNoRows) {
		l.lost.Store(true)
		return ErrLeaseLost
	}
	if err != nil {
		return fmt.Errorf("jobs: verify lease after step miss: %w", err)
	}
	if !owned {
		l.lost.Store(true)
		return ErrLeaseLost
	}
	return fmt.Errorf("%w: index %d", ErrNoStep, index)
}

// Complete finishes the job successfully: releases resource locks, records the
// attempt outcome, and clears the lease.
func (l *Lease) Complete(ctx context.Context) error {
	return l.finish(ctx, StateSucceeded, "", "")
}

// Fail records a failure. If attempts remain the job is re-queued with
// exponential backoff; otherwise it goes to dead_letter. Either way the locks
// are released so the resource is not held by a job that is not running.
func (l *Lease) Fail(ctx context.Context, code, summary string) error {
	if l.job.AttemptCount >= l.job.MaxAttempts {
		return l.finish(ctx, StateDeadLetter, code, summary)
	}
	return l.requeue(ctx, code, summary)
}

// CancelRequested reports whether a cancellation was recorded for this job,
// without renewing the lease. Use it when the worker wants to check intent
// between checkpoints.
func (l *Lease) CancelRequested(ctx context.Context) (bool, error) {
	var requested bool
	err := l.pool.QueryRow(ctx,
		`SELECT cancel_requested_at IS NOT NULL FROM jobs WHERE id = $1`,
		l.job.ID).Scan(&requested)
	if err != nil {
		return false, fmt.Errorf("jobs: read cancel flag: %w", err)
	}
	return requested, nil
}

// Cancel finishes the job as canceled and releases its locks.
func (l *Lease) Cancel(ctx context.Context, summary string) error {
	return l.finish(ctx, StateCanceled, "canceled", summary)
}

// finish writes a terminal state, releases locks, and finalizes the attempt row
// in one transaction so no lock can outlive the job that held it.
func (l *Lease) finish(ctx context.Context, state, code, summary string) error {
	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("jobs: begin finish: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	outcome := outcomeForState(state)
	tag, err := tx.Exec(ctx, `
		UPDATE jobs
		SET state = $2, error_code = NULLIF($3, ''), error_summary = NULLIF($4, ''),
		    finished_at = now(), lease_owner = NULL, lease_expires_at = NULL,
		    dead_lettered_at = CASE WHEN $2 = 'dead_letter' THEN now() ELSE dead_lettered_at END
		WHERE id = $1 AND lease_owner = $5 AND state IN ('leased','running')`,
		l.job.ID, state, code, summary, l.owner)
	if err != nil {
		return fmt.Errorf("jobs: finish update: %w", err)
	}
	if tag.RowsAffected() == 0 {
		l.lost.Store(true)
		return ErrLeaseLost
	}

	if err := releaseLocks(ctx, tx, l.job.ID); err != nil {
		return err
	}
	if err := finalizeAttempt(ctx, tx, l.job.ID, l.job.AttemptCount, l.owner, outcome, code, summary); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("jobs: commit finish: %w", err)
	}
	return nil
}

// requeue puts a failed-but-retryable job back in the queue with backoff.
func (l *Lease) requeue(ctx context.Context, code, summary string) error {
	delaySeconds := BackoffDelay(l.job.AttemptCount).Seconds()

	tx, err := l.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("jobs: begin requeue: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	tag, err := tx.Exec(ctx, `
		UPDATE jobs
		SET state = 'queued', error_code = NULLIF($3, ''), error_summary = NULLIF($4, ''),
		    next_attempt_at = now() + make_interval(secs => $5),
		    lease_owner = NULL, lease_expires_at = NULL
		WHERE id = $1 AND lease_owner = $2 AND state IN ('leased','running')`,
		l.job.ID, l.owner, code, summary, delaySeconds)
	if err != nil {
		return fmt.Errorf("jobs: requeue update: %w", err)
	}
	if tag.RowsAffected() == 0 {
		l.lost.Store(true)
		return ErrLeaseLost
	}

	if err := releaseLocks(ctx, tx, l.job.ID); err != nil {
		return err
	}
	if err := finalizeAttempt(ctx, tx, l.job.ID, l.job.AttemptCount, l.owner, OutcomeFailed, code, summary); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("jobs: commit requeue: %w", err)
	}
	return nil
}

func releaseLocks(ctx context.Context, tx pgx.Tx, jobID string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM job_resource_locks WHERE job_id = $1`, jobID); err != nil {
		return fmt.Errorf("jobs: release locks: %w", err)
	}
	return nil
}

func finalizeAttempt(ctx context.Context, tx pgx.Tx, jobID string, attempt int, worker, outcome, code, summary string) error {
	_, err := tx.Exec(ctx, `
		UPDATE job_attempts
		SET outcome = $4, error_code = NULLIF($5, ''), error_summary = NULLIF($6, ''),
		    finished_at = now()
		WHERE job_id = $1 AND attempt = $2 AND worker = $3`,
		jobID, attempt, worker, outcome, code, summary)
	if err != nil {
		return fmt.Errorf("jobs: finalize attempt: %w", err)
	}
	return nil
}

func outcomeForState(state string) string {
	switch state {
	case StateSucceeded:
		return OutcomeSucceeded
	case StateCanceled:
		return OutcomeCanceled
	default: // failed, dead_letter
		return OutcomeFailed
	}
}

// RequestCancel records a cancellation request. It is cooperative: the running
// worker observes it at the next Checkpoint. A queued job that has not been
// claimed is moved straight to canceled, because there is no worker to notify.
func RequestCancel(ctx context.Context, pool *pgxpool.Pool, jobID, byUserID string) error {
	if pool == nil {
		return errors.New("jobs: database is required")
	}
	tag, err := pool.Exec(ctx, `
		UPDATE jobs
		SET cancel_requested_at = now(),
		    cancel_requested_by = NULLIF($2, '')::uuid,
		    state = CASE WHEN state = 'queued' THEN 'canceled' ELSE state END,
		    finished_at = CASE WHEN state = 'queued' THEN now() ELSE finished_at END
		WHERE id = $1 AND state NOT IN ('succeeded','failed','canceled','dead_letter')`,
		jobID, byUserID)
	if err != nil {
		return fmt.Errorf("jobs: request cancel: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either terminal already or never existed; distinguish for the caller.
		var exists bool
		if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM jobs WHERE id=$1)`, jobID).Scan(&exists); err != nil {
			return fmt.Errorf("jobs: check job for cancel: %w", err)
		}
		if !exists {
			return ErrNotFound
		}
		return ErrAlreadyTerminal
	}
	return nil
}

// ReclaimExpiredLeases recovers jobs whose worker died. Any job still marked
// leased/running with an expired lease is returned to the queue (or dead-letter
// if it has exhausted attempts) and its resource locks are released, so a crash
// loses progress on the in-flight attempt but never the job itself. This is the
// mechanism behind the Phase 1 gate: a controller restart does not lose
// queued/running jobs.
//
// It returns the number of jobs reclaimed.
func ReclaimExpiredLeases(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	if pool == nil {
		return 0, errors.New("jobs: database is required")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("jobs: begin reclaim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Lock the expired rows so two reclaimers do not both process the same job.
	rows, err := tx.Query(ctx, `
		SELECT id, attempt_count, max_attempts, lease_owner
		FROM jobs
		WHERE state IN ('leased','running') AND lease_expires_at < now()
		FOR UPDATE SKIP LOCKED`)
	if err != nil {
		return 0, fmt.Errorf("jobs: select expired leases: %w", err)
	}
	type expired struct {
		id           string
		attemptCount int
		maxAttempts  int
		leaseOwner   string
	}
	var found []expired
	for rows.Next() {
		var e expired
		if err := rows.Scan(&e.id, &e.attemptCount, &e.maxAttempts, &e.leaseOwner); err != nil {
			rows.Close()
			return 0, fmt.Errorf("jobs: scan expired lease: %w", err)
		}
		found = append(found, e)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("jobs: iterate expired leases: %w", err)
	}
	rows.Close()

	for _, e := range found {
		// A reclaimed attempt is recorded as lost_lease against the dead owner,
		// so diagnostics show the job was abandoned rather than failed cleanly.
		if err := finalizeAttempt(ctx, tx, e.id, e.attemptCount, e.leaseOwner, OutcomeLostLease, "lease_expired", "worker did not renew its lease"); err != nil {
			return 0, err
		}
		if err := releaseLocks(ctx, tx, e.id); err != nil {
			return 0, err
		}

		if e.attemptCount >= e.maxAttempts {
			// Out of attempts: dead-letter rather than requeue into an infinite
			// crash loop.
			if _, err := tx.Exec(ctx, `
				UPDATE jobs
				SET state = 'dead_letter', error_code = 'lease_expired',
				    error_summary = 'worker died and attempts are exhausted',
				    finished_at = now(), dead_lettered_at = now(),
				    lease_owner = NULL, lease_expires_at = NULL
				WHERE id = $1`, e.id); err != nil {
				return 0, fmt.Errorf("jobs: dead-letter reclaimed: %w", err)
			}
			continue
		}

		if _, err := tx.Exec(ctx, `
			UPDATE jobs
			SET state = 'queued', lease_owner = NULL, lease_expires_at = NULL,
			    next_attempt_at = now() + make_interval(secs => $2)
			WHERE id = $1`, e.id, BackoffDelay(e.attemptCount).Seconds()); err != nil {
			return 0, fmt.Errorf("jobs: requeue reclaimed: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, fmt.Errorf("jobs: commit reclaim: %w", err)
	}
	return len(found), nil
}

// Handler executes one claimed job. It receives a Lease whose Checkpoint method
// must be called at step boundaries so cancellation and lease loss are observed.
// Returning a non-nil error fails the job (retried or dead-lettered per
// attempts); returning ErrCanceled marks it canceled.
type Handler func(ctx context.Context, lease *Lease) error

// Worker claims and runs jobs in a loop until its context is canceled.
type Worker struct {
	pool         *pgxpool.Pool
	logger       *slog.Logger
	owner        string
	leaseTTL     time.Duration
	pollInterval time.Duration
	types        []string
	handlers     map[string]Handler
	// fallback runs when no handler is registered for a job type. If nil, an
	// unknown type fails the job rather than silently succeeding.
	fallback Handler
}

// WorkerConfig builds a Worker.
type WorkerConfig struct {
	Pool         *pgxpool.Pool
	Logger       *slog.Logger
	Owner        string
	LeaseTTL     time.Duration
	PollInterval time.Duration
	Types        []string
	Handlers     map[string]Handler
	Fallback     Handler
}

// NewWorker validates configuration and returns a Worker. Owner is required and
// must be process-unique.
func NewWorker(cfg WorkerConfig) (*Worker, error) {
	if cfg.Pool == nil {
		return nil, errors.New("jobs: worker requires a database pool")
	}
	if cfg.Owner == "" {
		return nil, errors.New("jobs: worker requires a unique owner id")
	}
	leaseTTL := cfg.LeaseTTL
	if leaseTTL == 0 {
		leaseTTL = DefaultLeaseTTL
	}
	if leaseTTL < time.Second {
		return nil, errors.New("jobs: worker lease TTL must be at least 1s")
	}
	poll := cfg.PollInterval
	if poll == 0 {
		poll = DefaultPollInterval
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	handlers := make(map[string]Handler, len(cfg.Handlers))
	for k, v := range cfg.Handlers {
		if v == nil {
			return nil, fmt.Errorf("jobs: nil handler for type %q", k)
		}
		handlers[k] = v
	}
	return &Worker{
		pool:         cfg.Pool,
		logger:       logger,
		owner:        cfg.Owner,
		leaseTTL:     leaseTTL,
		pollInterval: poll,
		types:        cfg.Types,
		handlers:     handlers,
		fallback:     cfg.Fallback,
	}, nil
}

// Run blocks, claiming and executing jobs, until ctx is canceled. It also runs
// the lease reaper on the poll cadence so a single-worker deployment recovers
// its own crashed predecessors without a separate cron. Run returns only on
// context cancellation; transient claim/handler errors are logged, not returned.
func (w *Worker) Run(ctx context.Context) error {
	w.logger.Info("jobs worker started", "owner", w.owner, "lease_ttl", w.leaseTTL.String())
	defer w.logger.Info("jobs worker stopped", "owner", w.owner)

	// NOTIFY wakes the loop immediately on new work; the ticker is the fallback
	// that guarantees progress even if a notification is lost.
	wakeup := make(chan struct{}, 1)
	stopListen, err := w.listen(ctx, wakeup)
	if err != nil {
		// A failed LISTEN is not fatal: polling still drains the queue, just
		// with up to pollInterval of extra latency.
		w.logger.Warn("jobs LISTEN unavailable, relying on polling", "error", err)
	} else {
		defer stopListen()
	}

	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()

	for {
		if ctx.Err() != nil {
			return nil
		}
		claimed := w.drainOnce(ctx)
		// Reap expired leases each idle cycle. Cheap when nothing is expired.
		if n, err := ReclaimExpiredLeases(ctx, w.pool); err != nil {
			if ctx.Err() == nil {
				w.logger.Error("lease reclaim failed", "error", err)
			}
		} else if n > 0 {
			w.logger.Warn("reclaimed expired leases", "count", n)
		}

		if claimed {
			// More work may be waiting; loop immediately without sleeping.
			continue
		}

		select {
		case <-ctx.Done():
			return nil
		case <-wakeup:
			// A NOTIFY arrived; loop and claim.
		case <-ticker.C:
			// Poll fallback.
		}
	}
}

// drainOnce claims and runs jobs until none are claimable. Returns true if it
// ran at least one, so Run knows to keep going without sleeping.
func (w *Worker) drainOnce(ctx context.Context) bool {
	ran := false
	for {
		if ctx.Err() != nil {
			return ran
		}
		job, err := Claim(ctx, w.pool, ClaimOptions{
			Owner:    w.owner,
			LeaseTTL: w.leaseTTL,
			Types:    w.types,
		})
		if err != nil {
			w.logger.Error("claim failed", "error", err)
			return ran
		}
		if job.ID == "" {
			return ran // idle
		}
		ran = true
		w.execute(ctx, job)
	}
}

// execute runs one claimed job under a lease with a background heartbeat.
func (w *Worker) execute(ctx context.Context, job Job) {
	lease := &Lease{pool: w.pool, job: job, owner: w.owner, ttl: w.leaseTTL}

	// Heartbeat renews the lease at half the TTL so a slow-but-alive worker is
	// not reclaimed. On renewal failure it marks the lease lost; the handler
	// observes that at its next Checkpoint and aborts.
	hbCtx, stopHeartbeat := context.WithCancel(ctx)
	defer stopHeartbeat()
	go func() {
		t := time.NewTicker(w.leaseTTL / 2)
		defer t.Stop()
		for {
			select {
			case <-hbCtx.Done():
				return
			case <-t.C:
				if err := lease.Renew(hbCtx); err != nil {
					if !errors.Is(err, ErrLeaseLost) && hbCtx.Err() == nil {
						w.logger.Warn("lease renewal error", "job", job.ID, "error", err)
					}
					return
				}
			}
		}
	}()

	handler, ok := w.handlers[job.Type]
	if !ok {
		handler = w.fallback
	}

	var runErr error
	if handler == nil {
		runErr = fmt.Errorf("jobs: no handler registered for type %q", job.Type)
	} else {
		if err := lease.MarkRunning(ctx); err != nil {
			w.logger.Error("mark running failed", "job", job.ID, "error", err)
		}
		runErr = w.runHandler(ctx, handler, lease)
	}

	// Finalize. A lost lease means another worker owns the job now: do nothing,
	// or we would corrupt its state.
	if lease.Lost() {
		w.logger.Warn("lease lost during execution, abandoning", "job", job.ID)
		return
	}
	switch {
	case errors.Is(runErr, ErrLeaseLost):
		// Another worker owns the job now. Writing anything would corrupt its
		// state, so this worker simply lets go.
		w.logger.Warn("handler reported lease loss, abandoning", "job", job.ID)
	case errors.Is(runErr, ErrCanceled):
		if err := lease.Cancel(ctx, "canceled"); err != nil && !errors.Is(err, ErrLeaseLost) {
			w.logger.Error("cancel finish failed", "job", job.ID, "error", err)
		}
	case runErr != nil:
		code, summary := classifyError(runErr)
		if err := lease.Fail(ctx, code, summary); err != nil && !errors.Is(err, ErrLeaseLost) {
			w.logger.Error("fail finish failed", "job", job.ID, "error", err)
		}
	default:
		if err := lease.Complete(ctx); err != nil && !errors.Is(err, ErrLeaseLost) {
			w.logger.Error("complete finish failed", "job", job.ID, "error", err)
		}
	}
}

// runHandler invokes the handler and converts a cancellation observed via the
// lease into ErrCanceled so the finish path is uniform.
func (w *Worker) runHandler(ctx context.Context, handler Handler, lease *Lease) (err error) {
	defer func() {
		if r := recover(); r != nil {
			// A panicking handler must fail the job, not crash the worker: the
			// whole point of durability is that one bad job cannot take down the
			// process serving the others.
			w.logger.Error("job handler panicked", "job", lease.job.ID, "panic", r)
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	return handler(ctx, lease)
}

// classifyError maps a handler error to a stable code and a bounded summary.
// The summary is truncated so a verbose error cannot bloat the row.
func classifyError(err error) (code, summary string) {
	switch {
	case errors.Is(err, ErrCanceled):
		return "canceled", "canceled"
	case errors.Is(err, context.Canceled):
		return "context_canceled", "context canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded", "context deadline exceeded"
	default:
		return "handler_error", truncate(err.Error(), 500)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// listen subscribes to the wakeup channel and forwards notifications to out.
// It returns a stop function. Uses a dedicated connection (not the pool) because
// LISTEN holds the connection for its lifetime.
func (w *Worker) listen(ctx context.Context, out chan<- struct{}) (func(), error) {
	conn, err := w.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("jobs: acquire listen conn: %w", err)
	}
	if _, err := conn.Exec(ctx, `LISTEN `+notifyChannel); err != nil {
		conn.Release()
		return nil, fmt.Errorf("jobs: LISTEN: %w", err)
	}

	listenCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer conn.Release()
		for {
			notification, err := conn.Conn().WaitForNotification(listenCtx)
			if err != nil {
				if listenCtx.Err() == nil && ctx.Err() == nil {
					w.logger.Debug("jobs listen ended", "error", err)
				}
				return
			}
			if notification.Channel == notifyChannel {
				select {
				case out <- struct{}{}:
				default: // a wake is already pending; coalesce
				}
			}
		}
	}()

	return func() {
		cancel()
		<-done
	}, nil
}
