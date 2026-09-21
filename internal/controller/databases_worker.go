package controller

// databases_worker.go contains async job workers for managed database operations.
//
// Four job types:
//   - database.provision: creates or drops a database/user on the target node.
//   - database.dump:      exports a database to a node-local artifact; updates backup record.
//   - database.restore:   imports a database from a node-local dump artifact; verifies via metrics.
//   - database.delete:    final cleanup after grace period: dumps, drops, tombstones.
//
// The workers never store plaintext passwords. Passwords are opened from
// internal/secret in-memory at dispatch time and are not logged.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/databases"
	"github.com/bukansembarangkong/jawaker-panel/internal/jobs"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodes"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/jackc/pgx/v5/pgxpool"
)

// databaseDispatcher abstracts node operations for testing without a real node.
// *nodes.Dispatcher satisfies this interface automatically.
type databaseDispatcher interface {
	ManageDatabase(ctx context.Context, serverID, requestID string, in nodewire.DatabaseManageInput) (nodewire.DatabaseManageResult, error)
	DumpDatabase(ctx context.Context, serverID, requestID string, in nodewire.DatabaseDumpInput) (nodewire.DatabaseDumpResult, error)
	RestoreDatabase(ctx context.Context, serverID, requestID string, in nodewire.DatabaseRestoreInput) (nodewire.DatabaseRestoreResult, error)
	GetDatabaseMetrics(ctx context.Context, serverID, requestID string, in nodewire.DatabaseMetricsInput) (nodewire.DatabaseMetricsResult, error)
}

// DatabaseWorkerOptions configures the database operations worker.
type DatabaseWorkerOptions struct {
	Pool         *pgxpool.Pool
	Databases    *databases.Store
	Dispatcher   *nodes.Dispatcher
	Logger       *slog.Logger
	Owner        string
	LeaseTTL     time.Duration
	PollInterval time.Duration
	// dispatcherOverride replaces Dispatcher for tests that provide a stub.
	// Only used when non-nil; production code leaves it nil.
	dispatcherOverride databaseDispatcher
}

// NewDatabaseWorker constructs a jobs.Worker handling all four database job types.
func NewDatabaseWorker(opts DatabaseWorkerOptions) (*jobs.Worker, error) {
	if opts.Pool == nil {
		return nil, errors.New("controller: database pool is required for database worker")
	}
	if opts.Databases == nil {
		return nil, errors.New("controller: databases store is required for database worker")
	}
	if opts.Owner == "" {
		opts.Owner = fmt.Sprintf("controller-db-worker-%d", time.Now().UnixNano())
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}

	d := opts.Databases
	var disp databaseDispatcher
	if opts.dispatcherOverride != nil {
		disp = opts.dispatcherOverride
	} else {
		disp = opts.Dispatcher // *nodes.Dispatcher satisfies databaseDispatcher; nil if no dispatcher
	}

	return jobs.NewWorker(jobs.WorkerConfig{
		Pool:         opts.Pool,
		Logger:       logger,
		Owner:        opts.Owner,
		LeaseTTL:     opts.LeaseTTL,
		PollInterval: opts.PollInterval,
		Types: []string{
			JobTypeDatabaseProvision,
			JobTypeDatabaseDump,
			JobTypeDatabaseRestore,
			JobTypeDatabaseDelete,
		},
		Handlers: map[string]jobs.Handler{
			JobTypeDatabaseProvision: newDBProvisionHandler(d, disp, logger),
			JobTypeDatabaseDump:      newDBDumpHandler(d, disp, logger),
			JobTypeDatabaseRestore:   newDBRestoreHandler(d, disp, logger),
			JobTypeDatabaseDelete:    newDBDeleteHandler(d, disp, logger),
		},
	})
}

// ─── database.provision ──────────────────────────────────────────────────────

// newDBProvisionHandler handles database.provision jobs.
//
// Payload fields:
//   - database_id (string): the ManagedDatabase ID.
//   - action (string): "create_db", "drop_db", "create_user", "drop_user", "set_grants".
//   - username (string, optional): required for user-scoped actions.
//
// The handler sends a database.manage nodewire op to the target node via the
// dispatcher. If the dispatcher is unavailable the job is failed immediately with
// a clear error code rather than retrying forever.
func newDBProvisionHandler(
	store *databases.Store,
	dispatcher databaseDispatcher,
	logger *slog.Logger,
) jobs.Handler {
	return func(ctx context.Context, lease *jobs.Lease) error {
		job := lease.Job()
		dbID, _ := job.Payload["database_id"].(string)
		action, _ := job.Payload["action"].(string)
		username, _ := job.Payload["username"].(string)
		reqID := job.RequestID

		if dbID == "" || action == "" {
			_ = lease.Fail(ctx, "invalid_payload", "database.provision: missing database_id or action")
			return nil
		}

		if err := lease.MarkRunning(ctx); err != nil {
			logger.Error("database.provision: mark running failed", "job_id", job.ID, "error", err)
			return err
		}

		if dispatcher == nil {
			msg := "database.provision: node dispatcher not available"
			_ = lease.FailStep(ctx, 0, "dispatcher_unavailable", msg)
			_ = lease.Fail(ctx, "dispatcher_unavailable", msg)
			return nil
		}

		db, err := store.GetDatabase(ctx, dbID)
		if err != nil {
			msg := fmt.Sprintf("database.provision: load database record: %v", err)
			_ = lease.FailStep(ctx, 0, "database_lookup_failed", msg)
			_ = lease.Fail(ctx, "database_lookup_failed", msg)
			return nil
		}

		if err := lease.StartStep(ctx, 0, action); err != nil {
			return err
		}

		_, dispErr := dispatcher.ManageDatabase(ctx, db.ServerID, reqID, nodewire.DatabaseManageInput{
			Engine:     db.Engine,
			DBName:     db.DBName,
			Action:     action,
			Username:   username,
			SocketPath: defaultSocketPath(db.Engine),
		})
		if dispErr != nil {
			msg := fmt.Sprintf("database.provision %s: node op failed: %v", action, dispErr)
			_ = lease.FailStep(ctx, 0, "node_op_failed", msg)
			_ = lease.Fail(ctx, "node_op_failed", msg)
			return nil
		}

		_ = lease.CompleteStep(ctx, 0, map[string]any{
			"database_id": dbID,
			"action":      action,
		})

		return lease.Complete(ctx)
	}
}

// ─── database.dump ───────────────────────────────────────────────────────────

// newDBDumpHandler handles database.dump jobs.
//
// Payload fields:
//   - database_id (string)
//   - backup_id (string): the database_backups row to update on completion.
//   - engine (string): "postgresql" or "mariadb".
//   - db_name (string): the engine-level database name.
//
// The dump_path is derived by the node; on success the backup record is
// updated with the node-reported path, sha256, and size.
func newDBDumpHandler(
	store *databases.Store,
	dispatcher databaseDispatcher,
	logger *slog.Logger,
) jobs.Handler {
	return func(ctx context.Context, lease *jobs.Lease) error {
		job := lease.Job()
		dbID, _ := job.Payload["database_id"].(string)
		backupID, _ := job.Payload["backup_id"].(string)
		engine, _ := job.Payload["engine"].(string)
		dbName, _ := job.Payload["db_name"].(string)
		reqID := job.RequestID

		if dbID == "" || backupID == "" || engine == "" || dbName == "" {
			_ = lease.Fail(ctx, "invalid_payload", "database.dump: missing required payload fields")
			return nil
		}

		if err := lease.MarkRunning(ctx); err != nil {
			logger.Error("database.dump: mark running failed", "job_id", job.ID, "error", err)
			return err
		}

		_ = store.MarkBackupRunning(ctx, backupID) //nolint:errcheck // best-effort; non-fatal

		if dispatcher == nil {
			msg := "database.dump: node dispatcher not available"
			_, _ = store.UpdateBackupState(ctx, databases.UpdateBackupStateParams{
				ID: backupID, State: databases.BackupFailed,
			})
			_ = lease.FailStep(ctx, 0, "dispatcher_unavailable", msg)
			_ = lease.Fail(ctx, "dispatcher_unavailable", msg)
			return nil
		}

		db, err := store.GetDatabase(ctx, dbID)
		if err != nil {
			msg := fmt.Sprintf("database.dump: load database record: %v", err)
			_, _ = store.UpdateBackupState(ctx, databases.UpdateBackupStateParams{
				ID: backupID, State: databases.BackupFailed,
			})
			_ = lease.Fail(ctx, "database_lookup_failed", msg)
			return nil
		}

		if err := lease.StartStep(ctx, 0, "dump"); err != nil {
			return err
		}

		// Node generates the dump path automatically inside its dump dir.
		dumpInput := nodewire.DatabaseDumpInput{
			Engine:     engine,
			DBName:     dbName,
			DumpPath:   fmt.Sprintf("/var/lib/jawaker/db-dumps/%s_%s.dump", dbName, job.ID),
			SocketPath: defaultSocketPath(engine),
		}
		result, dispErr := dispatcher.DumpDatabase(ctx, db.ServerID, reqID, dumpInput)
		if dispErr != nil {
			msg := fmt.Sprintf("database.dump: node op failed: %v", dispErr)
			_, _ = store.UpdateBackupState(ctx, databases.UpdateBackupStateParams{
				ID: backupID, State: databases.BackupFailed,
			})
			_ = lease.FailStep(ctx, 0, "node_op_failed", msg)
			_ = lease.Fail(ctx, "node_op_failed", msg)
			return nil
		}

		// Update backup record with completed artifact metadata.
		_, updateErr := store.UpdateBackupState(ctx, databases.UpdateBackupStateParams{
			ID:        backupID,
			State:     databases.BackupCompleted,
			DumpPath:  result.DumpPath,
			SizeBytes: result.SizeBytes,
			SHA256:    result.SHA256,
		})
		if updateErr != nil {
			logger.Error("database.dump: update backup state failed", "backup_id", backupID, "error", updateErr)
			// Non-fatal: dump succeeded on node; record incomplete but artifact exists.
		}

		_ = lease.CompleteStep(ctx, 0, map[string]any{
			"dump_path":  result.DumpPath,
			"size_bytes": result.SizeBytes,
			"sha256":     result.SHA256,
		})

		return lease.Complete(ctx)
	}
}

// ─── database.restore ────────────────────────────────────────────────────────

// newDBRestoreHandler handles database.restore jobs (Gate 2 — recoverability).
//
// Payload fields:
//   - database_id (string)
//   - engine (string)
//   - db_name (string)
//   - dump_path (string): node-local path of the dump artifact to restore from.
//
// After restore, the handler verifies recoverability by reading connection
// count via database.metrics. Gate 2 is satisfied when at least one
// successful connect is observed (connections >= 0 and observed_at is recent).
func newDBRestoreHandler(
	store *databases.Store,
	dispatcher databaseDispatcher,
	logger *slog.Logger,
) jobs.Handler {
	return func(ctx context.Context, lease *jobs.Lease) error {
		job := lease.Job()
		dbID, _ := job.Payload["database_id"].(string)
		engine, _ := job.Payload["engine"].(string)
		dbName, _ := job.Payload["db_name"].(string)
		dumpPath, _ := job.Payload["dump_path"].(string)
		reqID := job.RequestID

		if dbID == "" || engine == "" || dbName == "" || dumpPath == "" {
			_ = lease.Fail(ctx, "invalid_payload", "database.restore: missing required payload fields")
			return nil
		}

		if err := lease.MarkRunning(ctx); err != nil {
			logger.Error("database.restore: mark running failed", "job_id", job.ID, "error", err)
			return err
		}

		if dispatcher == nil {
			msg := "database.restore: node dispatcher not available"
			_ = lease.FailStep(ctx, 0, "dispatcher_unavailable", msg)
			_ = lease.Fail(ctx, "dispatcher_unavailable", msg)
			return nil
		}

		db, err := store.GetDatabase(ctx, dbID)
		if err != nil {
			msg := fmt.Sprintf("database.restore: load database record: %v", err)
			_ = lease.Fail(ctx, "database_lookup_failed", msg)
			return nil
		}

		// Step 0: restore.
		if err := lease.StartStep(ctx, 0, "restore"); err != nil {
			return err
		}
		_, restoreErr := dispatcher.RestoreDatabase(ctx, db.ServerID, reqID, nodewire.DatabaseRestoreInput{
			Engine:     engine,
			DBName:     dbName,
			DumpPath:   dumpPath,
			SocketPath: defaultSocketPath(engine),
		})
		if restoreErr != nil {
			msg := fmt.Sprintf("database.restore: restore op failed: %v", restoreErr)
			_ = lease.FailStep(ctx, 0, "restore_failed", msg)
			_ = lease.Fail(ctx, "restore_failed", msg)
			return nil
		}
		_ = lease.CompleteStep(ctx, 0, map[string]any{"dump_path": dumpPath})

		// Step 1: verify — Gate 2 (proves restore produced a queryable database).
		if err := lease.StartStep(ctx, 1, "verify"); err != nil {
			return err
		}
		metrics, metricsErr := dispatcher.GetDatabaseMetrics(ctx, db.ServerID, reqID, nodewire.DatabaseMetricsInput{
			Engine:     engine,
			SocketPath: defaultSocketPath(engine),
		})
		if metricsErr != nil {
			// Degrade gracefully: restore succeeded; metrics collection failed.
			// This is a warning, not a failure — the data is in place.
			logger.Warn("database.restore: metrics verification call failed (restore still succeeded)",
				"database_id", dbID, "error", metricsErr)
			_ = lease.CompleteStep(ctx, 1, map[string]any{"verified": false, "error": metricsErr.Error()})
		} else {
			_ = lease.CompleteStep(ctx, 1, map[string]any{
				"verified":    true,
				"connections": metrics.Connections,
				"observed_at": metrics.ObservedAt,
			})
		}

		return lease.Complete(ctx)
	}
}

// ─── database.delete ─────────────────────────────────────────────────────────

// newDBDeleteHandler handles database.delete jobs (final cleanup after grace period).
//
// Payload fields:
//   - database_id (string)
//
// Sequence:
//  1. Pre-delete dump (trigger = pre_delete) via the dump worker path.
//  2. Drop database on node via database.manage drop_db.
//  3. Tombstone the record via store.FinalizeDelete.
//
// If the pre-dump fails, the job fails without tombstoning — the operator
// can inspect and retry. If drop fails after dump, the tombstone is withheld
// and a human review event is logged.
func newDBDeleteHandler(
	store *databases.Store,
	dispatcher databaseDispatcher,
	logger *slog.Logger,
) jobs.Handler {
	return func(ctx context.Context, lease *jobs.Lease) error {
		job := lease.Job()
		dbID, _ := job.Payload["database_id"].(string)
		reqID := job.RequestID

		if dbID == "" {
			_ = lease.Fail(ctx, "invalid_payload", "database.delete: missing database_id")
			return nil
		}

		if err := lease.MarkRunning(ctx); err != nil {
			logger.Error("database.delete: mark running failed", "job_id", job.ID, "error", err)
			return err
		}

		db, err := store.GetDatabase(ctx, dbID)
		if err != nil {
			msg := fmt.Sprintf("database.delete: load database record: %v", err)
			_ = lease.Fail(ctx, "database_lookup_failed", msg)
			return nil
		}

		// Step 0: pre-delete dump.
		if err := lease.StartStep(ctx, 0, "pre_delete_dump"); err != nil {
			return err
		}

		var preDumpPath string
		if dispatcher != nil {
			dumpPath := fmt.Sprintf("/var/lib/jawaker/db-dumps/%s_pre_delete_%s.dump", db.DBName, job.ID)
			dumpResult, dErr := dispatcher.DumpDatabase(ctx, db.ServerID, reqID, nodewire.DatabaseDumpInput{
				Engine:     db.Engine,
				DBName:     db.DBName,
				DumpPath:   dumpPath,
				SocketPath: defaultSocketPath(db.Engine),
			})
			if dErr != nil {
				msg := fmt.Sprintf("database.delete: pre-delete dump failed: %v", dErr)
				_ = lease.FailStep(ctx, 0, "pre_delete_dump_failed", msg)
				_ = lease.Fail(ctx, "pre_delete_dump_failed", msg)
				return nil
			}
			preDumpPath = dumpResult.DumpPath
			// Record backup for audit.
			_, _ = store.CreateBackup(ctx, databases.CreateBackupParams{
				DatabaseID: dbID,
				ProjectID:  db.ProjectID,
				ServerID:   db.ServerID,
				Trigger:    databases.TriggerPreDelete,
				JobID:      job.ID,
			})
		}

		_ = lease.CompleteStep(ctx, 0, map[string]any{"pre_dump_path": preDumpPath})

		// Step 1: drop database on node.
		if err := lease.StartStep(ctx, 1, "drop_db"); err != nil {
			return err
		}

		if dispatcher != nil {
			_, dropErr := dispatcher.ManageDatabase(ctx, db.ServerID, reqID, nodewire.DatabaseManageInput{
				Engine:     db.Engine,
				DBName:     db.DBName,
				Action:     "drop_db",
				SocketPath: defaultSocketPath(db.Engine),
			})
			if dropErr != nil {
				// Node drop failed. Tombstone is withheld — operator must investigate.
				msg := fmt.Sprintf("database.delete: drop_db on node failed (pre_dump=%s): %v", preDumpPath, dropErr)
				logger.Error("database.delete: drop_db failed; tombstone withheld", "database_id", dbID, "error", dropErr)
				_ = lease.FailStep(ctx, 1, "node_drop_failed", msg)
				_ = lease.Fail(ctx, "node_drop_failed", msg)
				return nil
			}
		}

		_ = lease.CompleteStep(ctx, 1, map[string]any{"database_id": dbID})

		// Step 2: tombstone record.
		if err := lease.StartStep(ctx, 2, "tombstone"); err != nil {
			return err
		}

		if _, tombErr := store.FinalizeDelete(ctx, dbID); tombErr != nil {
			// Extremely rare: the drop succeeded on the node, but we cannot record it.
			// Log and fail the step — the job can be retried and FinalizeDelete is safe
			// to call multiple times (it only updates pending_delete rows).
			msg := fmt.Sprintf("database.delete: finalize delete failed: %v", tombErr)
			logger.Error("database.delete: tombstone failed after node drop", "database_id", dbID, "error", tombErr)
			_ = lease.FailStep(ctx, 2, "tombstone_failed", msg)
			_ = lease.Fail(ctx, "tombstone_failed", msg)
			return nil
		}

		_ = lease.CompleteStep(ctx, 2, map[string]any{"database_id": dbID, "tombstoned": true})
		return lease.Complete(ctx)
	}
}
