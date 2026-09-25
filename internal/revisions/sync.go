// Package revisions: GitOps synchronization worker (PRD §24).
//
// Per PRD §24.3, local revisions succeed first. A background worker drains
// pending revisions in created_at order and records the resulting Git commit SHA,
// or transitions to 'failed' with error context on transient failure.
package revisions

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Syncer performs the actual push/commit of a revision to an external Git repository.
type Syncer interface {
	SyncRevision(ctx context.Context, rev Revision) (commitSHA string, err error)
}

// GitSyncWorker periodically processes pending Git sync revisions (PRD §24.3).
type GitSyncWorker struct {
	pool     *pgxpool.Pool
	syncer   Syncer
	logger   *slog.Logger
	interval time.Duration
}

// NewGitSyncWorker creates a new GitOps background worker.
func NewGitSyncWorker(pool *pgxpool.Pool, syncer Syncer, logger *slog.Logger, interval time.Duration) *GitSyncWorker {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &GitSyncWorker{
		pool:     pool,
		syncer:   syncer,
		logger:   logger,
		interval: interval,
	}
}

// Run executes the sync loop until ctx is cancelled.
func (w *GitSyncWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.DrainOnce(ctx, 50); err != nil {
				w.logger.Warn("gitsync: drain pass error", "error", err)
			}
		}
	}
}

// DrainOnce processes up to limit pending revisions.
func (w *GitSyncWorker) DrainOnce(ctx context.Context, limit int) error {
	if w.pool == nil {
		return nil
	}

	pending, err := PendingGitSync(ctx, w.pool, limit)
	if err != nil {
		return err
	}

	for _, rev := range pending {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		if w.syncer == nil {
			// Without an external syncer configured, mark not_required to prevent unbounded backlog
			if err := MarkGitNotRequired(ctx, w.pool, rev.ID); err != nil {
				w.logger.Warn("gitsync: mark not_required error", "revision_id", rev.ID, "error", err)
			}
			continue
		}

		sha, err := w.syncer.SyncRevision(ctx, rev)
		if err != nil {
			w.logger.Warn("gitsync: sync failed", "revision_id", rev.ID, "error", err)
			_ = MarkGitFailed(ctx, w.pool, rev.ID, err.Error())
		} else {
			_ = MarkGitSynced(ctx, w.pool, rev.ID, sha)
		}
	}

	return nil
}
