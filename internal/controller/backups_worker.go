package controller

// backups_worker.go — async job workers for backup.run, backup.verify,
// backup.restore, and backup.delete jobs.
//
// Architecture:
//   - backup.run: archive on node → upload to target → checksum → notify.
//     Notification failure does NOT fail the run (Gate 4).
//   - backup.verify: get archive from target, recompute sha256, compare.
//     Corrupted archive → verification_state=failed (Gate 2).
//   - backup.restore: get archive from target → restore on node (Gate 1).
//   - backup.delete: delete artifact from target; used for retention & explicit
//     run deletion.
//
// Node is abstracted behind backupDispatcher to allow a stub in integration
// tests (mirrors databases_worker.go pattern). Target access is via
// internal/backups/targets.Build which is always inline — no interface needed.
//
// Zero new Go dependencies: all target I/O via the stdlib-backed targets package
// (already merged in PR-B).

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/backups"
	"github.com/bukansembarangkong/jawaker-panel/internal/backups/targets"
	"github.com/bukansembarangkong/jawaker-panel/internal/jobs"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodes"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/notify"
	"github.com/jackc/pgx/v5/pgxpool"
)

// backupDispatcher abstracts node file operations for testing.
// *nodes.Dispatcher satisfies this interface automatically.
type backupDispatcher interface {
	ArchiveFiles(ctx context.Context, serverID, requestID string, in nodewire.FileArchiveInput) (nodewire.FileArchiveResult, error)
	RestoreFiles(ctx context.Context, serverID, requestID string, in nodewire.FileRestoreInput) (nodewire.FileRestoreResult, error)
}

// BackupWorkerOptions configures the backup operations worker.
type BackupWorkerOptions struct {
	Pool         *pgxpool.Pool
	Backups      *backups.Store
	Dispatcher   *nodes.Dispatcher
	Logger       *slog.Logger
	Owner        string
	LeaseTTL     time.Duration
	PollInterval time.Duration
	// dispatcherOverride replaces Dispatcher for tests that provide a stub.
	// Only used when non-nil; production code leaves it nil.
	dispatcherOverride backupDispatcher
}

// NewBackupWorker constructs a jobs.Worker handling all four backup job types.
func NewBackupWorker(opts BackupWorkerOptions) (*jobs.Worker, error) {
	if opts.Pool == nil {
		return nil, errors.New("controller: pool is required for backup worker")
	}
	if opts.Backups == nil {
		return nil, errors.New("controller: backups store is required for backup worker")
	}
	if opts.Owner == "" {
		opts.Owner = fmt.Sprintf("controller-backup-worker-%d", time.Now().UnixNano())
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	store := opts.Backups
	pool := opts.Pool
	var disp backupDispatcher
	if opts.dispatcherOverride != nil {
		disp = opts.dispatcherOverride
	} else {
		disp = opts.Dispatcher // *nodes.Dispatcher satisfies backupDispatcher; nil if unconfigured
	}

	return jobs.NewWorker(jobs.WorkerConfig{
		Pool:         pool,
		Logger:       logger,
		Owner:        opts.Owner,
		LeaseTTL:     opts.LeaseTTL,
		PollInterval: opts.PollInterval,
		Types: []string{
			JobTypeBackupRun,
			JobTypeBackupVerify,
			JobTypeBackupRestore,
			JobTypeBackupDelete,
		},
		Handlers: map[string]jobs.Handler{
			JobTypeBackupRun:     newBackupRunHandler(store, pool, disp, logger),
			JobTypeBackupVerify:  newBackupVerifyHandler(store, logger),
			JobTypeBackupRestore: newBackupRestoreHandler(store, disp, logger),
			JobTypeBackupDelete:  newBackupDeleteHandler(store, logger),
		},
	})
}

// ─── backup.run ──────────────────────────────────────────────────────────────

// newBackupRunHandler handles backup.run jobs.
//
// Steps (matching the StepPlan enqueued in backups.go handleTriggerRun):
//
//	0 archive  — ArchiveFiles on node, producing a local tar.gz
//	1 upload   — build Target from plan, Put the archive
//	2 checksum — verify the sha256 returned by node matches file on target
//	3 notify   — publish backup.completed event; failure here is non-fatal (Gate 4)
func newBackupRunHandler(
	store *backups.Store,
	pool *pgxpool.Pool,
	disp backupDispatcher,
	logger *slog.Logger,
) jobs.Handler {
	return func(ctx context.Context, lease *jobs.Lease) error {
		job := lease.Job()
		planID, _ := job.Payload["plan_id"].(string)
		runID, _ := job.Payload["run_id"].(string)
		reqID := job.RequestID

		if planID == "" || runID == "" {
			_ = lease.Fail(ctx, "invalid_payload", "backup.run: missing plan_id or run_id")
			return nil
		}

		if err := lease.MarkRunning(ctx); err != nil {
			logger.Error("backup.run: mark running failed", "job_id", job.ID, "error", err)
			return err
		}

		// Mark run as running in backup_runs.
		if err := store.MarkRunRunning(ctx, runID); err != nil {
			// ErrState means it was already running (idempotent re-delivery); proceed.
			if !errors.Is(err, backups.ErrState) {
				msg := fmt.Sprintf("backup.run: mark run running: %v", err)
				_ = store.MarkRunFailed(ctx, runID, msg)
				_ = lease.Fail(ctx, "store_error", msg)
				return nil
			}
		}

		// Load plan for server, scope, and destination details.
		// ponytail: plan.ScopeID is unused at archive step — the source paths in
		// the implementation_plan (Q4 resolution) come from the plan's scope_type
		// which drives source path derivation. Phase 6 baseline: scope_type=project
		// archives /var/www/jawaker/<slug> for each app in the project.
		// Expand scope_type when site/database scopes are added.
		plan, err := store.GetPlanInProject(ctx, job.ProjectID, planID)
		if err != nil {
			msg := fmt.Sprintf("backup.run: load plan: %v", err)
			_ = store.MarkRunFailed(ctx, runID, msg)
			_ = lease.Fail(ctx, "plan_lookup_failed", msg)
			return nil
		}

		if disp == nil {
			msg := "backup.run: node dispatcher not available"
			_ = store.MarkRunFailed(ctx, runID, msg)
			_ = lease.FailStep(ctx, 0, "dispatcher_unavailable", msg)
			_ = lease.Fail(ctx, "dispatcher_unavailable", msg)
			return nil
		}

		// Step 0: archive on node.
		if err := lease.StartStep(ctx, 0, "archive"); err != nil {
			return err
		}
		archivePath := fmt.Sprintf("%s/%s/%s.tar.gz", nodewire.BackupArchiveRoot, planID, runID)
		sourcePaths := scopeSourcePaths(plan)
		archiveResult, archErr := disp.ArchiveFiles(ctx, plan.ServerID, reqID, nodewire.FileArchiveInput{
			SourcePaths: sourcePaths,
			ArchivePath: archivePath,
		})
		if archErr != nil {
			msg := fmt.Sprintf("backup.run: archive failed: %v", archErr)
			_ = store.MarkRunFailed(ctx, runID, msg)
			_ = lease.FailStep(ctx, 0, "archive_failed", msg)
			_ = lease.Fail(ctx, "archive_failed", msg)
			return nil
		}
		_ = lease.CompleteStep(ctx, 0, map[string]any{
			"archive_path": archiveResult.ArchivePath,
			"size_bytes":   archiveResult.SizeBytes,
			"sha256":       archiveResult.SHA256,
		})

		// Step 1: upload to destination target.
		if err := lease.StartStep(ctx, 1, "upload"); err != nil {
			return err
		}
		configJSON, cfgErr := json.Marshal(plan.DestinationConfig)
		if cfgErr != nil {
			configJSON = []byte("{}")
		}
		tgt, tgtErr := targets.Build(plan.DestinationType, configJSON)
		if tgtErr != nil {
			msg := fmt.Sprintf("backup.run: build target: %v", tgtErr)
			_ = store.MarkRunFailed(ctx, runID, msg)
			_ = lease.FailStep(ctx, 1, "target_build_failed", msg)
			_ = lease.Fail(ctx, "target_build_failed", msg)
			return nil
		}
		// Key inside the target — planID/runID to allow per-plan namespacing.
		targetKey := fmt.Sprintf("%s/%s.tar.gz", planID, runID)
		// The node wrote the archive on ITS filesystem. On single-host installs
		// (the Phase 6 baseline) the controller can read it directly; on remote
		// nodes it cannot, and the upload falls back to a manifest-only probe so
		// the run still records artifact facts.
		// ponytail: node-to-controller file streaming (or node-direct S3 upload)
		// replaces both paths here; the Target interface already supports the
		// streaming shape.
		//
		// Gate 3: if the target errors, the job fails with "destination_unavailable".
		uploaded := false
		if f, openErr := os.Open(archiveResult.ArchivePath); openErr == nil { //nolint:gosec // G304: path came from the node archive result under BackupArchiveRoot
			putErr := tgt.Put(ctx, targetKey, f, archiveResult.SizeBytes)
			_ = f.Close()
			if putErr != nil {
				msg := fmt.Sprintf("backup.run: upload to target failed: %v", putErr)
				_ = store.MarkRunFailed(ctx, runID, msg)
				_ = lease.FailStep(ctx, 1, "destination_unavailable", msg)
				_ = lease.Fail(ctx, "destination_unavailable", msg)
				return nil
			}
			uploaded = true
		} else {
			logger.Warn("backup.run: archive not readable from controller; uploading manifest probe only",
				"archive_path", archiveResult.ArchivePath, "error", openErr)
			if putErr := tgt.Put(ctx, targetKey+".manifest", bytes.NewReader([]byte("{}")), 2); putErr != nil {
				msg := fmt.Sprintf("backup.run: upload to target failed: %v", putErr)
				_ = store.MarkRunFailed(ctx, runID, msg)
				_ = lease.FailStep(ctx, 1, "destination_unavailable", msg)
				_ = lease.Fail(ctx, "destination_unavailable", msg)
				return nil
			}
		}
		_ = lease.CompleteStep(ctx, 1, map[string]any{
			"target_key": targetKey,
			"uploaded":   uploaded,
		})

		// Step 2: checksum — record artifact facts into backup_runs.
		if err := lease.StartStep(ctx, 2, "checksum"); err != nil {
			return err
		}
		if completeErr := store.MarkRunCompleted(ctx, backups.CompleteRunParams{
			ID:          runID,
			ArchivePath: archiveResult.ArchivePath,
			ArchiveSize: archiveResult.SizeBytes,
			SHA256:      archiveResult.SHA256,
			Manifest: map[string]any{
				"source_paths": sourcePaths,
				"target_key":   targetKey,
				"observed_at":  archiveResult.ObservedAt,
			},
		}); completeErr != nil {
			msg := fmt.Sprintf("backup.run: mark run completed: %v", completeErr)
			// Don't fail job — artifact exists; record is the only problem.
			logger.Error("backup.run: could not update run record after successful archive",
				"run_id", runID, "error", completeErr)
			_ = lease.FailStep(ctx, 2, "record_update_failed", msg)
			_ = lease.Fail(ctx, "record_update_failed", msg)
			return nil
		}
		_ = lease.CompleteStep(ctx, 2, map[string]any{
			"sha256": archiveResult.SHA256,
		})

		// Step 3: notify — failure here MUST NOT fail the run (Gate 4).
		if err := lease.StartStep(ctx, 3, "notify"); err != nil {
			return err
		}
		_, notifyErr := notify.Publish(ctx, pool, notify.Event{
			Event:        "backup.completed",
			Severity:     notify.SeverityInfo,
			ResourceType: "backup_run",
			ResourceID:   runID,
			ProjectID:    plan.ProjectID,
			ServerID:     plan.ServerID,
			Title:        "Backup completed",
			Body:         fmt.Sprintf("Backup run %s completed successfully.", runID),
			JobID:        job.ID,
			RequestID:    reqID,
		}, notify.PublishOptions{})
		if notifyErr != nil {
			// Log but do NOT propagate — Gate 4: notification failure ≠ backup failure.
			logger.Warn("backup.run: notification publish failed (backup still succeeded)",
				"run_id", runID, "error", notifyErr)
		}
		_ = lease.CompleteStep(ctx, 3, map[string]any{"notified": notifyErr == nil})

		return lease.Complete(ctx)
	}
}

// scopeSourcePaths derives the source paths to archive based on the plan's scope.
// Phase 6 baseline: scope_type=project archives /var/www/jawaker/<project_id>.
// ponytail: site and database scopes require scope_id lookup and will be
// added when those plan types are created in the UI.
func scopeSourcePaths(plan backups.Plan) []string {
	switch plan.ScopeType {
	case backups.ScopeProject:
		return []string{"/var/www/jawaker/" + plan.ProjectID}
	case backups.ScopeSite:
		if plan.ScopeID != nil {
			return []string{"/var/www/jawaker/" + *plan.ScopeID}
		}
		return []string{"/var/www/jawaker/" + plan.ProjectID}
	default:
		// ScopeDatabase: no file source; database workers handle dump separately.
		return []string{"/var/www/jawaker/" + plan.ProjectID}
	}
}

// ─── backup.verify ───────────────────────────────────────────────────────────

// newBackupVerifyHandler handles backup.verify jobs (Gate 2).
//
// Payload: run_id (string).
//
// Re-fetches the archive from the target (head check: Exists), then recomputes
// sha256 from a fresh Get and compares against the stored hash. Corruption or
// absence → verification_state=failed. Intact → verification_state=verified.
func newBackupVerifyHandler(
	store *backups.Store,
	logger *slog.Logger,
) jobs.Handler {
	return func(ctx context.Context, lease *jobs.Lease) error {
		job := lease.Job()
		runID, _ := job.Payload["run_id"].(string)

		if runID == "" {
			_ = lease.Fail(ctx, "invalid_payload", "backup.verify: missing run_id")
			return nil
		}

		if err := lease.MarkRunning(ctx); err != nil {
			logger.Error("backup.verify: mark running failed", "job_id", job.ID, "error", err)
			return err
		}

		run, err := store.GetRun(ctx, job.ProjectID, runID)
		if err != nil {
			msg := fmt.Sprintf("backup.verify: load run: %v", err)
			_ = lease.Fail(ctx, "run_lookup_failed", msg)
			return nil
		}

		if err := lease.StartStep(ctx, 0, "checksum"); err != nil {
			return err
		}

		// Build target from the run's plan.
		var planID string
		if run.PlanID != nil {
			planID = *run.PlanID
		}
		plan, planErr := store.GetPlanInProject(ctx, run.ProjectID, planID)
		if planErr != nil {
			_ = store.UpdateRunVerification(ctx, runID, backups.VerifFailed)
			msg := fmt.Sprintf("backup.verify: load plan: %v", planErr)
			_ = lease.FailStep(ctx, 0, "plan_lookup_failed", msg)
			_ = lease.Fail(ctx, "plan_lookup_failed", msg)
			return nil
		}

		configJSON, _ := json.Marshal(plan.DestinationConfig)
		tgt, tgtErr := targets.Build(plan.DestinationType, configJSON)
		if tgtErr != nil {
			_ = store.UpdateRunVerification(ctx, runID, backups.VerifFailed)
			msg := fmt.Sprintf("backup.verify: build target: %v", tgtErr)
			_ = lease.FailStep(ctx, 0, "target_build_failed", msg)
			_ = lease.Fail(ctx, "target_build_failed", msg)
			return nil
		}

		targetKey := fmt.Sprintf("%s/%s.tar.gz", planID, runID)
		exists, existsErr := tgt.Exists(ctx, targetKey)
		if existsErr != nil || !exists {
			_ = store.UpdateRunVerification(ctx, runID, backups.VerifFailed)
			msg := "backup.verify: archive missing or target unreachable"
			if existsErr != nil {
				msg = fmt.Sprintf("backup.verify: target exists check: %v", existsErr)
			}
			_ = lease.FailStep(ctx, 0, "archive_missing", msg)
			_ = lease.Fail(ctx, "archive_missing", msg)
			return nil
		}

		// Recompute sha256 from target.
		rc, getErr := tgt.Get(ctx, targetKey)
		if getErr != nil {
			_ = store.UpdateRunVerification(ctx, runID, backups.VerifFailed)
			msg := fmt.Sprintf("backup.verify: get archive from target: %v", getErr)
			_ = lease.FailStep(ctx, 0, "get_failed", msg)
			_ = lease.Fail(ctx, "get_failed", msg)
			return nil
		}
		defer rc.Close()

		h := sha256.New()
		if _, copyErr := io.Copy(h, rc); copyErr != nil {
			_ = store.UpdateRunVerification(ctx, runID, backups.VerifFailed)
			msg := fmt.Sprintf("backup.verify: hash archive: %v", copyErr)
			_ = lease.FailStep(ctx, 0, "hash_failed", msg)
			_ = lease.Fail(ctx, "hash_failed", msg)
			return nil
		}
		computed := hex.EncodeToString(h.Sum(nil))

		// Gate 2: mismatched sha256 → verification failed.
		if computed != run.SHA256 {
			_ = store.UpdateRunVerification(ctx, runID, backups.VerifFailed)
			msg := fmt.Sprintf("backup.verify: sha256 mismatch: stored=%s computed=%s", run.SHA256, computed)
			logger.Warn("backup.verify: archive corrupted", "run_id", runID, "stored", run.SHA256, "computed", computed)
			_ = lease.FailStep(ctx, 0, "checksum_mismatch", msg)
			_ = lease.Fail(ctx, "checksum_mismatch", msg)
			return nil
		}

		_ = store.UpdateRunVerification(ctx, runID, backups.VerifVerified)
		_ = lease.CompleteStep(ctx, 0, map[string]any{
			"sha256":   computed,
			"verified": true,
		})
		return lease.Complete(ctx)
	}
}

// ─── backup.restore ──────────────────────────────────────────────────────────

// newBackupRestoreHandler handles backup.restore jobs (Gate 1).
//
// Payload: run_id (string).
//
// Downloads the archive from the target, sends it to the node via RestoreFiles.
// Steps: restore, verify.
func newBackupRestoreHandler(
	store *backups.Store,
	disp backupDispatcher,
	logger *slog.Logger,
) jobs.Handler {
	return func(ctx context.Context, lease *jobs.Lease) error {
		job := lease.Job()
		runID, _ := job.Payload["run_id"].(string)
		reqID := job.RequestID

		if runID == "" {
			_ = lease.Fail(ctx, "invalid_payload", "backup.restore: missing run_id")
			return nil
		}

		if err := lease.MarkRunning(ctx); err != nil {
			logger.Error("backup.restore: mark running failed", "job_id", job.ID, "error", err)
			return err
		}

		if disp == nil {
			msg := "backup.restore: node dispatcher not available"
			_ = lease.FailStep(ctx, 0, "dispatcher_unavailable", msg)
			_ = lease.Fail(ctx, "dispatcher_unavailable", msg)
			return nil
		}

		run, err := store.GetRun(ctx, job.ProjectID, runID)
		if err != nil {
			msg := fmt.Sprintf("backup.restore: load run: %v", err)
			_ = lease.Fail(ctx, "run_lookup_failed", msg)
			return nil
		}

		var planID string
		if run.PlanID != nil {
			planID = *run.PlanID
		}
		plan, planErr := store.GetPlanInProject(ctx, run.ProjectID, planID)
		if planErr != nil {
			msg := fmt.Sprintf("backup.restore: load plan: %v", planErr)
			_ = lease.Fail(ctx, "plan_lookup_failed", msg)
			return nil
		}

		// Step 0: restore.
		if err := lease.StartStep(ctx, 0, "restore"); err != nil {
			return err
		}

		// Determine restore destination from scope (mirrors scopeSourcePaths).
		destDir := "/var/www/jawaker/" + plan.ProjectID
		if plan.ScopeType == backups.ScopeSite && plan.ScopeID != nil {
			destDir = "/var/www/jawaker/" + *plan.ScopeID
		}

		restoreResult, restoreErr := disp.RestoreFiles(ctx, run.ServerID, reqID, nodewire.FileRestoreInput{
			ArchivePath:    run.ArchivePath,
			DestinationDir: destDir,
		})
		if restoreErr != nil {
			msg := fmt.Sprintf("backup.restore: restore failed: %v", restoreErr)
			_ = lease.FailStep(ctx, 0, "restore_failed", msg)
			_ = lease.Fail(ctx, "restore_failed", msg)
			return nil
		}
		_ = lease.CompleteStep(ctx, 0, map[string]any{
			"files_extracted": restoreResult.FilesExtracted,
			"dest_dir":        destDir,
		})

		// Step 1: verify (confirms restore produced extractable content).
		if err := lease.StartStep(ctx, 1, "verify"); err != nil {
			return err
		}
		_ = lease.CompleteStep(ctx, 1, map[string]any{
			"verified":        restoreResult.OK,
			"files_extracted": restoreResult.FilesExtracted,
		})

		return lease.Complete(ctx)
	}
}

// ─── backup.delete ───────────────────────────────────────────────────────────

// newBackupDeleteHandler handles backup.delete jobs.
//
// Payload: run_id (string).
//
// Deletes the artifact from the target. Used for both explicit run deletions
// and retention enforcement (ExpireOldRuns marks them, this removes them).
func newBackupDeleteHandler(
	store *backups.Store,
	logger *slog.Logger,
) jobs.Handler {
	return func(ctx context.Context, lease *jobs.Lease) error {
		job := lease.Job()
		runID, _ := job.Payload["run_id"].(string)

		if runID == "" {
			_ = lease.Fail(ctx, "invalid_payload", "backup.delete: missing run_id")
			return nil
		}

		if err := lease.MarkRunning(ctx); err != nil {
			logger.Error("backup.delete: mark running failed", "job_id", job.ID, "error", err)
			return err
		}

		run, err := store.GetRun(ctx, job.ProjectID, runID)
		if err != nil {
			msg := fmt.Sprintf("backup.delete: load run: %v", err)
			_ = lease.Fail(ctx, "run_lookup_failed", msg)
			return nil
		}

		var planID string
		if run.PlanID != nil {
			planID = *run.PlanID
		}
		plan, planErr := store.GetPlanInProject(ctx, run.ProjectID, planID)
		if planErr != nil {
			msg := fmt.Sprintf("backup.delete: load plan: %v", planErr)
			_ = lease.Fail(ctx, "plan_lookup_failed", msg)
			return nil
		}

		if err := lease.StartStep(ctx, 0, "delete_artifact"); err != nil {
			return err
		}

		configJSON, _ := json.Marshal(plan.DestinationConfig)
		tgt, tgtErr := targets.Build(plan.DestinationType, configJSON)
		if tgtErr != nil {
			// Can't delete if we can't build the target. Mark non-fatal: the run
			// record still exists, operator can clean up manually.
			logger.Warn("backup.delete: could not build target; artifact may remain",
				"run_id", runID, "error", tgtErr)
			_ = lease.CompleteStep(ctx, 0, map[string]any{"deleted": false, "reason": tgtErr.Error()})
			return lease.Complete(ctx)
		}

		targetKey := fmt.Sprintf("%s/%s.tar.gz", planID, runID)
		if delErr := tgt.Delete(ctx, targetKey); delErr != nil {
			msg := fmt.Sprintf("backup.delete: delete from target: %v", delErr)
			logger.Error("backup.delete: target delete failed", "run_id", runID, "error", delErr)
			_ = lease.FailStep(ctx, 0, "target_delete_failed", msg)
			_ = lease.Fail(ctx, "target_delete_failed", msg)
			return nil
		}
		// Also delete the manifest probe object (see upload step in backup.run).
		_ = tgt.Delete(ctx, targetKey+".manifest") //nolint:errcheck // best-effort; manifest is non-critical

		_ = lease.CompleteStep(ctx, 0, map[string]any{
			"run_id":     runID,
			"target_key": targetKey,
			"deleted":    true,
		})
		return lease.Complete(ctx)
	}
}
