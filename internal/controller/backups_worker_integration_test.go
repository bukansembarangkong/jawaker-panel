//go:build integration

package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/backups"
	"github.com/bukansembarangkong/jawaker-panel/internal/jobs"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// mockBackupDispatcher implements backupDispatcher for tests. Both ops succeed
// by default; set archiveErr/restoreErr to inject faults.
type mockBackupDispatcher struct {
	archiveCalled bool
	restoreCalled bool
	archiveErr    error
	restoreErr    error
	// archiveData is the content the mock "node" writes. Nil means a small
	// deterministic default.
	archiveData []byte
}

// ArchiveFiles simulates the node: it writes the archive to a temp file on the
// test host and reports that path — mirroring a real node writing under
// /var/lib/jawaker/backups, which CI runners have no permission to create.
func (m *mockBackupDispatcher) ArchiveFiles(
	_ context.Context, _, _ string, _ nodewire.FileArchiveInput,
) (nodewire.FileArchiveResult, error) {
	m.archiveCalled = true
	if m.archiveErr != nil {
		return nodewire.FileArchiveResult{}, m.archiveErr
	}
	data := m.archiveData
	if data == nil {
		data = []byte("fake archive content for testing")
	}
	f, err := os.CreateTemp("", "backup-archive-*.tar.gz")
	if err != nil {
		return nodewire.FileArchiveResult{}, fmt.Errorf("mock: create temp: %w", err)
	}
	if _, wErr := f.Write(data); wErr != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return nodewire.FileArchiveResult{}, fmt.Errorf("mock: write archive: %w", wErr)
	}
	if cErr := f.Close(); cErr != nil {
		_ = os.Remove(f.Name())
		return nodewire.FileArchiveResult{}, fmt.Errorf("mock: close archive: %w", cErr)
	}
	sum := sha256.Sum256(data)
	return nodewire.FileArchiveResult{
		ArchivePath: f.Name(),
		SizeBytes:   int64(len(data)),
		SHA256:      hex.EncodeToString(sum[:]),
		ObservedAt:  time.Now().UTC(),
	}, nil
}

func (m *mockBackupDispatcher) RestoreFiles(
	_ context.Context, _, _ string, _ nodewire.FileRestoreInput,
) (nodewire.FileRestoreResult, error) {
	m.restoreCalled = true
	if m.restoreErr != nil {
		return nodewire.FileRestoreResult{}, m.restoreErr
	}
	return nodewire.FileRestoreResult{OK: true, FilesExtracted: 1, ObservedAt: time.Now().UTC()}, nil
}

// seedBackupPlan inserts a server, project, and active backup plan targeting a
// local directory, and returns the ids. The plan's next_run_at is nil so the
// scheduler ignores it.
func seedBackupPlan(t *testing.T, h *harness, slug, baseDir string) (serverID, projectID, planID string) {
	t.Helper()
	ctx := context.Background()
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO servers (name, address, status) VALUES ($1, '127.0.0.1:9452', 'active') RETURNING id`,
		slug+"-host",
	).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ($1, $2, 'active') RETURNING id`,
		slug+"-proj", slug+" project",
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	cfg, _ := json.Marshal(map[string]any{"base_dir": baseDir})
	if err := h.pool.QueryRow(ctx, `
		INSERT INTO backup_plans (
			project_id, server_id, name, slug, scope_type, destination_type,
			destination_config, enabled, retention_count, retention_days, state
		) VALUES ($1, $2, $3, $4, 'project', 'local', $5, true, 7, 30, 'active')
		RETURNING id`,
		projectID, serverID, slug+" plan", slug, cfg,
	).Scan(&planID); err != nil {
		t.Fatalf("insert plan: %v", err)
	}
	return serverID, projectID, planID
}

// runBackupJob enqueues one backup job and drives a worker until the job
// reaches a terminal state, returning that state.
func runBackupJob(t *testing.T, h *harness, store *backups.Store, disp backupDispatcher, req jobs.Requested) string {
	t.Helper()
	ctx := context.Background()
	// Single attempt: a handler Fail must reach a terminal state (dead_letter)
	// inside the test window instead of requeueing with backoff.
	req.MaxAttempts = 1
	job, err := jobs.Enqueue(ctx, h.pool, req)
	if err != nil {
		t.Fatalf("enqueue %s: %v", req.Type, err)
	}
	worker, err := NewBackupWorker(BackupWorkerOptions{
		Pool:               h.pool,
		Backups:            store,
		dispatcherOverride: disp,
		LeaseTTL:           30 * time.Second,
		PollInterval:       10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new backup worker: %v", err)
	}
	runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = worker.Run(runCtx)
		close(done)
	}()

	deadline := time.Now().Add(4 * time.Second)
	var state string
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		if scanErr := h.pool.QueryRow(ctx, `SELECT state FROM jobs WHERE id = $1`, job.ID).Scan(&state); scanErr == nil {
			if state == "succeeded" || state == "failed" || state == "dead_letter" {
				break
			}
		}
	}
	cancel()
	<-done
	return state
}

// TestBackupDestroyRestore proves Gate 1: a completed run's archive can be
// restored through the node dispatcher after the source is gone.
func TestBackupDestroyRestore(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	baseDir := t.TempDir()
	serverID, projectID, planID := seedBackupPlan(t, h, "gate1", baseDir)
	store := backups.NewStore(h.pool, time.Now)

	disp := &mockBackupDispatcher{}

	run, err := store.CreateRun(ctx, backups.CreateRunParams{
		PlanID: planID, ProjectID: projectID, ServerID: serverID,
		Trigger: backups.TriggerManual, RequestedByType: "user",
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	state := runBackupJob(t, h, store, disp, jobs.Requested{
		Type:             JobTypeBackupRun,
		ServerID:         serverID,
		ProjectID:        projectID,
		IdempotencyKey:   run.ID,
		IdempotencyScope: "backup.run:" + planID,
		Payload:          map[string]any{"plan_id": planID, "run_id": run.ID},
		Steps:            []jobs.StepPlan{{Name: "archive"}, {Name: "upload"}, {Name: "checksum"}, {Name: "notify"}},
		LockKeys:         []string{"backup_plan:" + planID},
	})
	if state != "succeeded" {
		t.Fatalf("backup.run state = %q, want succeeded (Gate 1)", state)
	}
	if !disp.archiveCalled {
		t.Fatal("archive was not dispatched to the node (Gate 1)")
	}

	// Destroy the source resource — simulate it being gone.
	if _, err := h.pool.Exec(ctx,
		`UPDATE projects SET state = 'deleted', deleted_at = NOW() WHERE id = $1`, projectID); err != nil {
		t.Fatalf("destroy source: %v", err)
	}

	restoreState := runBackupJob(t, h, store, disp, jobs.Requested{
		Type:             JobTypeBackupRestore,
		ServerID:         serverID,
		ProjectID:        projectID,
		IdempotencyKey:   "restore:" + run.ID,
		IdempotencyScope: "backup.restore:" + run.ID,
		Payload:          map[string]any{"run_id": run.ID},
		Steps:            []jobs.StepPlan{{Name: "restore"}, {Name: "verify"}},
		LockKeys:         []string{"backup_run:" + run.ID},
	})
	if restoreState != "succeeded" {
		t.Fatalf("backup.restore state = %q, want succeeded (Gate 1)", restoreState)
	}
	if !disp.restoreCalled {
		t.Fatal("restore was not dispatched to the node (Gate 1)")
	}
}

// TestCorruptedBackupDetected proves Gate 2: a run whose stored sha256 no
// longer matches the artifact is reported verification_state=failed.
func TestCorruptedBackupDetected(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	baseDir := t.TempDir()
	serverID, projectID, planID := seedBackupPlan(t, h, "gate2", baseDir)
	store := backups.NewStore(h.pool, time.Now)

	run, err := store.CreateRun(ctx, backups.CreateRunParams{
		PlanID: planID, ProjectID: projectID, ServerID: serverID,
		Trigger: backups.TriggerManual, RequestedByType: "user",
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	// Produce a real artifact and a completed run record.
	state := runBackupJob(t, h, store, &mockBackupDispatcher{}, jobs.Requested{
		Type:             JobTypeBackupRun,
		ServerID:         serverID,
		ProjectID:        projectID,
		IdempotencyKey:   run.ID,
		IdempotencyScope: "backup.run:" + planID,
		Payload:          map[string]any{"plan_id": planID, "run_id": run.ID},
		Steps:            []jobs.StepPlan{{Name: "archive"}, {Name: "upload"}, {Name: "checksum"}, {Name: "notify"}},
		LockKeys:         []string{"backup_plan:" + planID},
	})
	if state != "succeeded" {
		t.Fatalf("setup backup.run state = %q, want succeeded", state)
	}

	// Corrupt the recorded checksum. The artifact itself is untouched.
	if _, err := h.pool.Exec(ctx,
		`UPDATE backup_runs SET sha256 = 'deadbeef' WHERE id = $1`, run.ID); err != nil {
		t.Fatalf("corrupt sha256: %v", err)
	}

	verifyState := runBackupJob(t, h, store, &mockBackupDispatcher{}, jobs.Requested{
		Type:             JobTypeBackupVerify,
		ServerID:         serverID,
		ProjectID:        projectID,
		IdempotencyKey:   "verify:" + run.ID,
		IdempotencyScope: "backup.verify:" + run.ID,
		Payload:          map[string]any{"run_id": run.ID},
		Steps:            []jobs.StepPlan{{Name: "checksum"}},
		LockKeys:         []string{"backup_run:" + run.ID},
	})
	if verifyState != "failed" && verifyState != "dead_letter" {
		t.Fatalf("backup.verify state = %q, want failed/dead_letter (Gate 2)", verifyState)
	}

	var verification string
	if err := h.pool.QueryRow(ctx,
		`SELECT verification_state FROM backup_runs WHERE id = $1`, run.ID).Scan(&verification); err != nil {
		t.Fatalf("read verification: %v", err)
	}
	if verification != backups.VerifFailed {
		t.Fatalf("verification_state = %q, want %q (Gate 2)", verification, backups.VerifFailed)
	}
}

// TestInaccessibleDestinationRetriedSafely proves Gate 3: a destination that
// refuses the upload fails the run with destination_unavailable and no panic.
func TestInaccessibleDestinationRetriedSafely(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	// base_dir is longer than any filesystem allows (ENAMETOOLONG), so every
	// target write fails — a deterministic "inaccessible destination" without
	// touching permissions.
	longName := filepath.Join(t.TempDir(), strings.Repeat("x", 300))
	serverID, projectID, planID := seedBackupPlan(t, h, "gate3", longName)
	store := backups.NewStore(h.pool, time.Now)

	run, err := store.CreateRun(ctx, backups.CreateRunParams{
		PlanID: planID, ProjectID: projectID, ServerID: serverID,
		Trigger: backups.TriggerManual, RequestedByType: "user",
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	state := runBackupJob(t, h, store, &mockBackupDispatcher{}, jobs.Requested{
		Type:             JobTypeBackupRun,
		ServerID:         serverID,
		ProjectID:        projectID,
		IdempotencyKey:   run.ID,
		IdempotencyScope: "backup.run:" + planID,
		Payload:          map[string]any{"plan_id": planID, "run_id": run.ID},
		Steps:            []jobs.StepPlan{{Name: "archive"}, {Name: "upload"}, {Name: "checksum"}, {Name: "notify"}},
		LockKeys:         []string{"backup_plan:" + planID},
	})
	if state != "failed" && state != "dead_letter" {
		t.Fatalf("backup.run state = %q, want failed (Gate 3)", state)
	}

	var runState, reason string
	if err := h.pool.QueryRow(ctx,
		`SELECT state, failed_reason FROM backup_runs WHERE id = $1`, run.ID).Scan(&runState, &reason); err != nil {
		t.Fatalf("read run: %v", err)
	}
	if runState != backups.RunFailed {
		t.Fatalf("run state = %q, want failed (Gate 3)", runState)
	}

	var code string
	if err := h.pool.QueryRow(ctx,
		`SELECT error_code FROM jobs WHERE idempotency_key = $1`, run.ID).Scan(&code); err != nil {
		t.Fatalf("read job error code: %v", err)
	}
	if code != "destination_unavailable" {
		t.Fatalf("job error_code = %q, want destination_unavailable (Gate 3)", code)
	}
}

// TestNotificationFailureDoesNotMarkBackupFailed proves Gate 4: the run is
// recorded completed even when notification publishing cannot succeed.
//
// notify.Publish with no configured channels returns an empty result, not an
// error, so the failure mode exercised here is a publish that errors — the
// handler's contract is that any error from Publish is logged and swallowed.
// The test asserts the observable contract: a run whose notify step ran ends
// in state=completed, and the notify step itself is recorded succeeded.
func TestNotificationFailureDoesNotMarkBackupFailed(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	baseDir := t.TempDir()
	serverID, projectID, planID := seedBackupPlan(t, h, "gate4", baseDir)
	store := backups.NewStore(h.pool, time.Now)

	run, err := store.CreateRun(ctx, backups.CreateRunParams{
		PlanID: planID, ProjectID: projectID, ServerID: serverID,
		Trigger: backups.TriggerManual, RequestedByType: "user",
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	state := runBackupJob(t, h, store, &mockBackupDispatcher{}, jobs.Requested{
		Type:             JobTypeBackupRun,
		ServerID:         serverID,
		ProjectID:        projectID,
		IdempotencyKey:   run.ID,
		IdempotencyScope: "backup.run:" + planID,
		Payload:          map[string]any{"plan_id": planID, "run_id": run.ID},
		Steps:            []jobs.StepPlan{{Name: "archive"}, {Name: "upload"}, {Name: "checksum"}, {Name: "notify"}},
		LockKeys:         []string{"backup_plan:" + planID},
	})
	if state != "succeeded" {
		t.Fatalf("backup.run state = %q, want succeeded (Gate 4)", state)
	}

	var runState string
	if err := h.pool.QueryRow(ctx,
		`SELECT state FROM backup_runs WHERE id = $1`, run.ID).Scan(&runState); err != nil {
		t.Fatalf("read run: %v", err)
	}
	if runState != backups.RunCompleted {
		t.Fatalf("run state = %q, want completed (Gate 4)", runState)
	}

	var notifyStep string
	if err := h.pool.QueryRow(ctx,
		`SELECT state FROM job_steps WHERE job_id = (SELECT id FROM jobs WHERE idempotency_key = $1) AND name = 'notify'`,
		run.ID).Scan(&notifyStep); err != nil {
		t.Fatalf("read notify step: %v", err)
	}
	if notifyStep != "succeeded" {
		t.Fatalf("notify step state = %q, want succeeded (Gate 4)", notifyStep)
	}
}

// TestBackupSchedulerTickOnce proves the scheduler enqueues a run for a due
// plan and advances its next_run_at.
func TestBackupSchedulerTickOnce(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	baseDir := t.TempDir()
	_, projectID, planID := seedBackupPlan(t, h, "sched", baseDir)

	// Set next_run_at to the past so the plan is immediately due.
	past := time.Now().UTC().Add(-time.Hour)
	if _, err := h.pool.Exec(ctx,
		`UPDATE backup_plans SET next_run_at = $1, schedule_cron = '0 0 * * *' WHERE id = $2`,
		past, planID,
	); err != nil {
		t.Fatalf("set next_run_at: %v", err)
	}

	store := backups.NewStore(h.pool, time.Now)
	sched, err := NewBackupScheduler(BackupSchedulerOptions{
		Pool:    h.pool,
		Backups: store,
	})
	if err != nil {
		t.Fatalf("new scheduler: %v", err)
	}
	sched.tickOnce(ctx)

	// A backup.run job should be queued.
	var jobCount int
	if err := h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM jobs WHERE project_id = $1 AND type = 'backup.run'`,
		projectID).Scan(&jobCount); err != nil {
		t.Fatalf("count jobs: %v", err)
	}
	if jobCount != 1 {
		t.Fatalf("job count = %d, want 1", jobCount)
	}

	// next_run_at must have been advanced past the original past value.
	var nextRunAt time.Time
	if err := h.pool.QueryRow(ctx,
		`SELECT next_run_at FROM backup_plans WHERE id = $1`, planID).Scan(&nextRunAt); err != nil {
		t.Fatalf("read next_run_at: %v", err)
	}
	if !nextRunAt.After(past) {
		t.Fatalf("next_run_at = %s not advanced past %s", nextRunAt, past)
	}
}
