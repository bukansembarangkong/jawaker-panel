//go:build integration

// Integration tests for the durable job engine against real PostgreSQL.
//
// These pin the six properties the package documents, because each one is a
// correctness claim that only a real database can falsify:
//
//   - a job survives its worker dying (lease expiry + reclaim);
//   - enqueue is idempotent under concurrency (the unique index decides);
//   - per-resource exclusion actually excludes;
//   - cancellation is observed by a running worker;
//   - retries back off and then dead-letter.
//
// A mock would make all five pass while proving nothing, since every guarantee
// here is a database behaviour (row locks, partial indexes, constraint
// conflicts) rather than application logic.

package jobs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/db/migrate"
	"github.com/bukansembarangkong/jawaker-panel/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("JAWAKER_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("JAWAKER_TEST_DATABASE_URL not set; skipping jobs integration tests")
	}
	return url
}

// setup applies the real migrations to a pristine schema and returns a pool.
// The schema is built exactly as the controller builds it at startup, so these
// tests exercise the same database surface production sees.
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

func mustEnqueue(t *testing.T, ctx context.Context, pool *pgxpool.Pool, req Requested) Job {
	t.Helper()
	job, err := Enqueue(ctx, pool, req)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	return job
}

// requireState asserts a job's persisted state, reading it back rather than
// trusting the value a call returned.
func requireState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id, want string) Job {
	t.Helper()
	job, err := GetByID(ctx, pool, id)
	if err != nil {
		t.Fatalf("GetByID(%s): %v", id, err)
	}
	if job.State != want {
		t.Fatalf("job %s state = %q, want %q (error: %s %s)",
			id, job.State, want, job.ErrorCode, job.ErrorSummary)
	}
	return job
}

func TestEnqueuePersistsPayloadAndSteps(t *testing.T) {
	pool, ctx := setup(t)

	job := mustEnqueue(t, ctx, pool, Requested{
		Type:    "site.create",
		Payload: map[string]any{"domain": "example.test", "php": "8.4"},
		Steps:   []StepPlan{{Name: "provision"}, {Name: "configure"}},
	})

	if job.State != StateQueued {
		t.Errorf("state = %q, want queued", job.State)
	}
	if job.Progress.Total != 2 {
		t.Errorf("progress_total = %d, want 2", job.Progress.Total)
	}
	if job.Payload["domain"] != "example.test" {
		t.Errorf("payload domain = %v, want example.test", job.Payload["domain"])
	}

	steps, err := ListSteps(ctx, pool, job.ID)
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	if len(steps) != 2 {
		t.Fatalf("steps = %d, want 2", len(steps))
	}
	if steps[0].Name != "provision" || steps[0].State != StepPending {
		t.Errorf("step 0 = %+v, want provision/pending", steps[0])
	}
}

func TestEnqueueRejectsInvalidRequest(t *testing.T) {
	pool, ctx := setup(t)

	cases := map[string]Requested{
		"no type":           {},
		"negative priority": {Type: "x", Priority: -1},
		"too many attempts": {Type: "x", MaxAttempts: 21},
		"bad requested_by":  {Type: "x", RequestedByType: "wizard"},
		"key without scope": {Type: "x", IdempotencyKey: "k"},
		"empty lock key":    {Type: "x", LockKeys: []string{""}},
	}
	for label, req := range cases {
		t.Run(label, func(t *testing.T) {
			if _, err := Enqueue(ctx, pool, req); err == nil {
				t.Error("invalid request accepted")
			}
		})
	}
}

// The gate that matters most: a worker that dies mid-job must not lose the job.
// Simulated by claiming with a lease that we then let expire, exactly as a
// crashed process would leave it, and confirming a second worker recovers and
// completes it.
func TestCrashedWorkerLeaseIsReclaimedAndJobStillCompletes(t *testing.T) {
	pool, ctx := setup(t)

	job := mustEnqueue(t, ctx, pool, Requested{
		Type:     "backup.run",
		Steps:    []StepPlan{{Name: "dump"}, {Name: "upload"}},
		LockKeys: []string{"server:" + "11111111-1111-1111-1111-111111111111"},
	})

	// Worker A claims the job and then "dies": it never renews and never
	// finishes. The claim must have taken the resource lock.
	claimedByA, err := Claim(ctx, pool, ClaimOptions{Owner: "worker-a", LeaseTTL: time.Minute})
	if err != nil {
		t.Fatalf("Claim A: %v", err)
	}
	if claimedByA.ID != job.ID {
		t.Fatalf("worker A claimed %s, want %s", claimedByA.ID, job.ID)
	}
	if claimedByA.AttemptCount != 1 {
		t.Fatalf("attempt_count = %d, want 1", claimedByA.AttemptCount)
	}
	held, err := HeldLocks(ctx, pool, job.ID)
	if err != nil {
		t.Fatalf("HeldLocks: %v", err)
	}
	if len(held) != 1 || held[0] != "server:11111111-1111-1111-1111-111111111111" {
		t.Fatalf("held locks = %v, want the declared server lock", held)
	}

	// While A holds the lease, worker B must NOT be able to claim it.
	if got, err := Claim(ctx, pool, ClaimOptions{Owner: "worker-b", LeaseTTL: time.Minute}); err != nil {
		t.Fatalf("Claim B: %v", err)
	} else if got.ID != "" {
		t.Fatalf("worker B claimed %s while worker A held a live lease", got.ID)
	}

	// Expire A's lease without touching anything else, exactly as a crash would.
	if _, err := pool.Exec(ctx,
		`UPDATE jobs SET lease_expires_at = now() - interval '1 second' WHERE id = $1`,
		job.ID); err != nil {
		t.Fatalf("expire lease: %v", err)
	}

	reclaimed, err := ReclaimExpiredLeases(ctx, pool)
	if err != nil {
		t.Fatalf("ReclaimExpiredLeases: %v", err)
	}
	if reclaimed != 1 {
		t.Fatalf("reclaimed %d jobs, want 1", reclaimed)
	}

	// The job is queued again, its locks released, and the attempt recorded as
	// lost_lease against the dead worker rather than as a clean failure.
	queued := requireState(t, ctx, pool, job.ID, StateQueued)
	if queued.AttemptCount != 1 {
		t.Errorf("attempt_count = %d, want 1 (a reclaim is not a new attempt until claim)", queued.AttemptCount)
	}
	if locks, err := HeldLocks(ctx, pool, job.ID); err != nil {
		t.Fatalf("HeldLocks after reclaim: %v", err)
	} else if len(locks) != 0 {
		t.Errorf("locks still held after reclaim: %v", locks)
	}
	var outcome string
	if err := pool.QueryRow(ctx,
		`SELECT outcome FROM job_attempts WHERE job_id = $1 AND attempt = 1`, job.ID).Scan(&outcome); err != nil {
		t.Fatalf("read attempt outcome: %v", err)
	}
	if outcome != OutcomeLostLease {
		t.Errorf("attempt outcome = %q, want %q", outcome, OutcomeLostLease)
	}

	// Reclaim deliberately re-queues with backoff so a crash loop cannot spin hot.
	// Make the retry due now; the backoff itself is covered by
	// TestFailureBacksOffThenDeadLetters.
	if _, err := pool.Exec(ctx, `UPDATE jobs SET next_attempt_at = now() WHERE id = $1`, job.ID); err != nil {
		t.Fatalf("force retry due: %v", err)
	}

	// Worker B now claims and finishes it. The job completes despite the crash.
	claimedByB, err := Claim(ctx, pool, ClaimOptions{Owner: "worker-b", LeaseTTL: time.Minute})
	if err != nil {
		t.Fatalf("Claim B after reclaim: %v", err)
	}
	if claimedByB.ID != job.ID {
		t.Fatalf("worker B claimed %s, want %s", claimedByB.ID, job.ID)
	}
	if claimedByB.AttemptCount != 2 {
		t.Errorf("attempt_count = %d, want 2", claimedByB.AttemptCount)
	}

	lease := &Lease{pool: pool, job: claimedByB, owner: "worker-b", ttl: time.Minute}
	if err := lease.MarkRunning(ctx); err != nil {
		t.Fatalf("MarkRunning: %v", err)
	}
	if err := lease.StartStep(ctx, 0, "dump"); err != nil {
		t.Fatalf("StartStep: %v", err)
	}
	if err := lease.CompleteStep(ctx, 0, map[string]any{"bytes": 4096}); err != nil {
		t.Fatalf("CompleteStep: %v", err)
	}
	steps, err := ListSteps(ctx, pool, job.ID)
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	if steps[0].State != StepSucceeded || steps[0].Output["bytes"] != float64(4096) {
		t.Errorf("step 0 = %+v, want succeeded with output", steps[0])
	}
	if err := lease.Complete(ctx); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	final := requireState(t, ctx, pool, job.ID, StateSucceeded)
	if final.FinishedAt == nil {
		t.Error("finished_at not set on a terminal job")
	}
	if locks, err := HeldLocks(ctx, pool, job.ID); err != nil {
		t.Fatalf("HeldLocks after complete: %v", err)
	} else if len(locks) != 0 {
		t.Errorf("locks not released on completion: %v", locks)
	}
}

// Concurrent enqueue under one idempotency key must create exactly one job. The
// database decides the winner; the losers must still get a usable answer rather
// than a confusing error, because a retried HTTP request is a normal event.
func TestConcurrentEnqueueWithOneKeyCreatesExactlyOneJob(t *testing.T) {
	pool, ctx := setup(t)

	const workers = 8
	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		ids      = map[string]int{}
		dupCount int
		errs     []error
	)
	start := make(chan struct{})

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // maximize the overlap
			job, err := Enqueue(ctx, pool, Requested{
				Type:             "site.create",
				IdempotencyScope: "user:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
				IdempotencyKey:   "create-example.test",
			})
			mu.Lock()
			defer mu.Unlock()
			if errors.Is(err, ErrDuplicate) {
				dupCount++
				ids[job.ID]++ // the loser must still report the winning job
				return
			}
			if err != nil {
				errs = append(errs, err)
				return
			}
			ids[job.ID]++
		}()
	}
	close(start)
	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	if len(ids) != 1 {
		t.Fatalf("distinct job ids = %d (%v), want 1", len(ids), ids)
	}
	if dupCount != workers-1 {
		t.Errorf("duplicates reported = %d, want %d", dupCount, workers-1)
	}

	var rows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM jobs WHERE idempotency_key = 'create-example.test'`).Scan(&rows); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	if rows != 1 {
		t.Errorf("jobs rows for the key = %d, want 1", rows)
	}

	// The same key under a different scope is different work.
	if _, err := Enqueue(ctx, pool, Requested{
		Type:             "site.create",
		IdempotencyScope: "user:bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
		IdempotencyKey:   "create-example.test",
	}); err != nil {
		t.Fatalf("Enqueue under a different scope: %v", err)
	}
}

// Two jobs declaring the same resource must not run at once. The second stays
// queued until the first releases, and then runs.
func TestResourceLockExcludesConcurrentJobs(t *testing.T) {
	pool, ctx := setup(t)

	const resource = "site:22222222-2222-2222-2222-222222222222"
	first := mustEnqueue(t, ctx, pool, Requested{Type: "site.deploy", LockKeys: []string{resource}})
	second := mustEnqueue(t, ctx, pool, Requested{Type: "site.deploy", LockKeys: []string{resource}})

	claimedFirst, err := Claim(ctx, pool, ClaimOptions{Owner: "w1", LeaseTTL: time.Minute})
	if err != nil {
		t.Fatalf("Claim first: %v", err)
	}
	if claimedFirst.ID != first.ID {
		t.Fatalf("first claim = %s, want the older job %s", claimedFirst.ID, first.ID)
	}

	// The second job is not blocked at the row level — it is skipped because its
	// declared lock collides with a held one. Claim must return idle, not error.
	idle, err := Claim(ctx, pool, ClaimOptions{Owner: "w2", LeaseTTL: time.Minute})
	if err != nil {
		t.Fatalf("Claim second: %v", err)
	}
	if idle.ID != "" {
		t.Fatalf("claimed %s while its resource was locked", idle.ID)
	}

	lease := &Lease{pool: pool, job: claimedFirst, owner: "w1", ttl: time.Minute}
	if err := lease.Complete(ctx); err != nil {
		t.Fatalf("Complete first: %v", err)
	}

	claimedSecond, err := Claim(ctx, pool, ClaimOptions{Owner: "w2", LeaseTTL: time.Minute})
	if err != nil {
		t.Fatalf("Claim second after release: %v", err)
	}
	if claimedSecond.ID != second.ID {
		t.Fatalf("second claim = %s, want %s", claimedSecond.ID, second.ID)
	}
}

// Cancellation must be observable by a worker that is mid-run, and the job must
// end up canceled rather than failed or succeeded.
func TestRunningWorkerObservesCancellation(t *testing.T) {
	pool, ctx := setup(t)

	job := mustEnqueue(t, ctx, pool, Requested{
		Type:  "site.slow",
		Steps: []StepPlan{{Name: "long"}},
	})

	claimed, err := Claim(ctx, pool, ClaimOptions{Owner: "w1", LeaseTTL: time.Minute})
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	lease := &Lease{pool: pool, job: claimed, owner: "w1", ttl: time.Minute}
	if err := lease.MarkRunning(ctx); err != nil {
		t.Fatalf("MarkRunning: %v", err)
	}

	if err := RequestCancel(ctx, pool, job.ID, ""); err != nil {
		t.Fatalf("RequestCancel: %v", err)
	}

	canceled, err := lease.Checkpoint(ctx)
	if err != nil {
		t.Fatalf("Checkpoint: %v", err)
	}
	if !canceled {
		t.Fatal("a requested cancellation was not observed at the step boundary")
	}
	if err := lease.Cancel(ctx, "user asked to stop"); err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	requireState(t, ctx, pool, job.ID, StateCanceled)

	// Canceling a terminal job is reported, not silently ignored.
	if err := RequestCancel(ctx, pool, job.ID, ""); !errors.Is(err, ErrAlreadyTerminal) {
		t.Errorf("cancel of terminal job = %v, want ErrAlreadyTerminal", err)
	}
	// Canceling an unknown job is a not-found, not a success.
	if err := RequestCancel(ctx, pool, "33333333-3333-3333-3333-333333333333", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("cancel of unknown job = %v, want ErrNotFound", err)
	}
}

// A queued job that has not been claimed can be canceled immediately, because
// there is no worker to observe a cooperative request.
func TestQueuedJobIsCanceledImmediately(t *testing.T) {
	pool, ctx := setup(t)

	job := mustEnqueue(t, ctx, pool, Requested{Type: "site.create"})
	if err := RequestCancel(ctx, pool, job.ID, ""); err != nil {
		t.Fatalf("RequestCancel: %v", err)
	}
	requireState(t, ctx, pool, job.ID, StateCanceled)
}

// Failure must back off and then dead-letter rather than retry forever, and a
// dead-lettered job must release its locks.
func TestFailureBacksOffThenDeadLetters(t *testing.T) {
	pool, ctx := setup(t)

	const resource = "site:44444444-4444-4444-4444-444444444444"
	job := mustEnqueue(t, ctx, pool, Requested{
		Type:        "site.broken",
		MaxAttempts: 2,
		LockKeys:    []string{resource},
	})

	for attempt := 1; attempt <= 2; attempt++ {
		claimed, err := Claim(ctx, pool, ClaimOptions{Owner: fmt.Sprintf("w%d", attempt), LeaseTTL: time.Minute})
		if err != nil {
			t.Fatalf("Claim attempt %d: %v", attempt, err)
		}
		if claimed.ID != job.ID {
			t.Fatalf("attempt %d claimed %s, want %s", attempt, claimed.ID, job.ID)
		}
		lease := &Lease{pool: pool, job: claimed, owner: fmt.Sprintf("w%d", attempt), ttl: time.Minute}
		if err := lease.MarkRunning(ctx); err != nil {
			t.Fatalf("MarkRunning attempt %d: %v", attempt, err)
		}
		if err := lease.Fail(ctx, "boom", "handler exploded"); err != nil {
			t.Fatalf("Fail attempt %d: %v", attempt, err)
		}

		if attempt == 1 {
			// Retryable: queued with a future next_attempt_at.
			job := requireState(t, ctx, pool, job.ID, StateQueued)
			if !job.NextAttemptAt.After(time.Now()) {
				t.Errorf("next_attempt_at = %v, want a future time", job.NextAttemptAt)
			}
			if job.ErrorCode != "boom" {
				t.Errorf("error_code = %q, want boom", job.ErrorCode)
			}
			// Locks are released while the job waits to retry, so the resource
			// is not held by a job that is not running.
			if locks, err := HeldLocks(ctx, pool, job.ID); err != nil {
				t.Fatalf("HeldLocks: %v", err)
			} else if len(locks) != 0 {
				t.Errorf("locks held while waiting to retry: %v", locks)
			}
			// Make the retry due now rather than sleeping through the backoff.
			if _, err := pool.Exec(ctx,
				`UPDATE jobs SET next_attempt_at = now() WHERE id = $1`, job.ID); err != nil {
				t.Fatalf("force retry due: %v", err)
			}
			continue
		}

		// Attempts exhausted: terminal dead_letter, not another retry.
		final := requireState(t, ctx, pool, job.ID, StateDeadLetter)
		if final.FinishedAt == nil {
			t.Error("dead-lettered job has no finished_at")
		}
		if locks, err := HeldLocks(ctx, pool, job.ID); err != nil {
			t.Fatalf("HeldLocks after dead-letter: %v", err)
		} else if len(locks) != 0 {
			t.Errorf("locks held by dead-lettered job: %v", locks)
		}
	}

	// Attempt history records one row per attempt, with the failing outcome.
	rows, err := pool.Query(ctx,
		`SELECT attempt, outcome FROM job_attempts WHERE job_id = $1 ORDER BY attempt`, job.ID)
	if err != nil {
		t.Fatalf("read attempts: %v", err)
	}
	defer rows.Close()
	seen := map[int]string{}
	for rows.Next() {
		var attempt int
		var outcome string
		if err := rows.Scan(&attempt, &outcome); err != nil {
			t.Fatalf("scan attempt: %v", err)
		}
		seen[attempt] = outcome
	}
	if seen[1] != OutcomeFailed || seen[2] != OutcomeFailed {
		t.Errorf("attempt outcomes = %v, want both failed", seen)
	}
}

// The worker end-to-end: it claims, runs steps, and finishes a job with no
// manual lease handling. This is the loop the controller actually runs.
func TestWorkerRunsAJobToCompletion(t *testing.T) {
	pool, ctx := setup(t)

	job := mustEnqueue(t, ctx, pool, Requested{
		Type:  "site.create",
		Steps: []StepPlan{{Name: "provision"}, {Name: "configure"}},
	})

	var mu sync.Mutex
	var ran []string
	handler := func(ctx context.Context, lease *Lease) error {
		for i, name := range []string{"provision", "configure"} {
			canceled, err := lease.Checkpoint(ctx)
			if err != nil {
				return err
			}
			if canceled {
				return ErrCanceled
			}
			if err := lease.StartStep(ctx, i, name); err != nil {
				return err
			}
			mu.Lock()
			ran = append(ran, name)
			mu.Unlock()
			if err := lease.CompleteStep(ctx, i, nil); err != nil {
				return err
			}
		}
		return nil
	}

	worker, err := NewWorker(WorkerConfig{
		Pool:         pool,
		Logger:       discardLogger(),
		Owner:        "worker-e2e",
		LeaseTTL:     30 * time.Second,
		PollInterval: 100 * time.Millisecond,
		Handlers:     map[string]Handler{"site.create": handler},
	})
	if err != nil {
		t.Fatalf("NewWorker: %v", err)
	}

	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := worker.Run(runCtx); err != nil {
			t.Errorf("Run: %v", err)
		}
	}()

	// Wait for the job to reach a terminal state, then stop the worker.
	deadline := time.Now().Add(20 * time.Second)
	for {
		if time.Now().After(deadline) {
			stop()
			<-done
			t.Fatalf("job did not finish; state = %s", currentState(t, ctx, pool, job.ID))
		}
		if currentState(t, ctx, pool, job.ID) == StateSucceeded {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	stop()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(ran) != 2 || ran[0] != "provision" || ran[1] != "configure" {
		t.Fatalf("steps ran = %v, want [provision configure] in order", ran)
	}

	final := requireState(t, ctx, pool, job.ID, StateSucceeded)
	if final.Progress.Current != 2 {
		t.Errorf("progress_current = %d, want 2", final.Progress.Current)
	}
	steps, err := ListSteps(ctx, pool, job.ID)
	if err != nil {
		t.Fatalf("ListSteps: %v", err)
	}
	for _, s := range steps {
		if s.State != StepSucceeded {
			t.Errorf("step %d state = %q, want succeeded", s.Index, s.State)
		}
	}
}

// An unknown job type must fail loudly rather than silently "succeed": a job
// that reports success without doing anything is worse than one that errors.
func TestWorkerFailsUnknownJobType(t *testing.T) {
	pool, ctx := setup(t)

	job := mustEnqueue(t, ctx, pool, Requested{Type: "nobody.listens", MaxAttempts: 1})

	worker, err := NewWorker(WorkerConfig{
		Pool:         pool,
		Logger:       discardLogger(),
		Owner:        "worker-unknown",
		LeaseTTL:     30 * time.Second,
		PollInterval: 100 * time.Millisecond,
		Handlers:     map[string]Handler{},
	})
	if err != nil {
		t.Fatalf("NewWorker: %v", err)
	}

	runCtx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = worker.Run(runCtx)
	}()

	deadline := time.Now().Add(20 * time.Second)
	for {
		if time.Now().After(deadline) {
			stop()
			<-done
			t.Fatalf("job did not reach a terminal state; state = %s", currentState(t, ctx, pool, job.ID))
		}
		if currentState(t, ctx, pool, job.ID) == StateDeadLetter {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	stop()
	<-done

	final := requireState(t, ctx, pool, job.ID, StateDeadLetter)
	if final.ErrorCode != "handler_error" {
		t.Errorf("error_code = %q, want handler_error", final.ErrorCode)
	}
}

func currentState(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id string) string {
	t.Helper()
	job, err := GetByID(ctx, pool, id)
	if err != nil {
		t.Fatalf("GetByID(%s): %v", id, err)
	}
	return job.State
}

func TestBackoffDelayGrowsAndIsCapped(t *testing.T) {
	// Deterministic on purpose; there is no jitter to accommodate.
	if got := BackoffDelay(1); got != retryBaseDelay {
		t.Errorf("BackoffDelay(1) = %v, want %v", got, retryBaseDelay)
	}
	if got := BackoffDelay(2); got != 2*retryBaseDelay {
		t.Errorf("BackoffDelay(2) = %v, want %v", got, 2*retryBaseDelay)
	}
	if got := BackoffDelay(3); got != 4*retryBaseDelay {
		t.Errorf("BackoffDelay(3) = %v, want %v", got, 4*retryBaseDelay)
	}
	// Must not grow without bound or overflow into a negative duration.
	if got := BackoffDelay(1000); got != retryMaxDelay {
		t.Errorf("BackoffDelay(1000) = %v, want %v", got, retryMaxDelay)
	}
	if got := BackoffDelay(0); got <= 0 {
		t.Errorf("BackoffDelay(0) = %v, want a positive delay", got)
	}
}

func TestNewWorkerRejectsBadConfig(t *testing.T) {
	pool, _ := setup(t)
	cases := map[string]WorkerConfig{
		"no pool":     {Owner: "w"},
		"no owner":    {Pool: pool},
		"tiny lease":  {Pool: pool, Owner: "w", LeaseTTL: time.Millisecond},
		"nil handler": {Pool: pool, Owner: "w", Handlers: map[string]Handler{"x": nil}},
	}
	for label, cfg := range cases {
		t.Run(label, func(t *testing.T) {
			if _, err := NewWorker(cfg); err == nil {
				t.Error("invalid worker config accepted")
			}
		})
	}
}

func TestClaimRequiresOwner(t *testing.T) {
	pool, ctx := setup(t)
	if _, err := Claim(ctx, pool, ClaimOptions{}); err == nil {
		t.Error("claim without an owner accepted")
	}
}
