// Package cleanup manages background pruning and retention enforcement (PRD §42).
//
// Per PRD §42 (Background Cleanup and Disk Safety):
//   - All persistent data classes must have explicit retention policies.
//   - Cleanup tasks must be idempotent, quota-aware, safe under interruption, observable.
//   - Covers preview environments, job history, and temporary records.
package cleanup

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PurgeExpiredPreviews terminates preview environments that have reached their expires_at
// or are older than maxAge (default 7 days) if no explicit expiry was set.
func PurgeExpiredPreviews(ctx context.Context, pool *pgxpool.Pool, defaultTTL time.Duration) (int64, error) {
	if pool == nil {
		return 0, nil
	}
	if defaultTTL <= 0 {
		defaultTTL = 7 * 24 * time.Hour
	}

	cutoff := time.Now().Add(-defaultTTL)
	tag, err := pool.Exec(ctx, `
		UPDATE app_previews
		SET status = 'terminated'
		WHERE status != 'terminated'
		  AND (
		    (expires_at IS NOT NULL AND expires_at <= NOW())
		    OR
		    (expires_at IS NULL AND created_at <= $1)
		  )`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("cleanup: purge expired previews: %w", err)
	}
	return tag.RowsAffected(), nil
}

// PruneOldJobs deletes terminal jobs (succeeded, failed, cancelled) older than retention.
func PruneOldJobs(ctx context.Context, pool *pgxpool.Pool, retention time.Duration) (int64, error) {
	if pool == nil {
		return 0, nil
	}
	if retention <= 0 {
		retention = 30 * 24 * time.Hour
	}

	cutoff := time.Now().Add(-retention)
	tag, err := pool.Exec(ctx, `
		DELETE FROM jobs
		WHERE state IN ('succeeded', 'failed', 'cancelled')
		  AND finished_at IS NOT NULL
		  AND finished_at <= $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("cleanup: prune old jobs: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Cleaner coordinates scheduled background cleanup runs.
type Cleaner struct {
	pool       *pgxpool.Pool
	logger     *slog.Logger
	interval   time.Duration
	previewTTL time.Duration
	jobTTL     time.Duration
}

// New creates a new background cleaner.
func New(pool *pgxpool.Pool, logger *slog.Logger, interval time.Duration) *Cleaner {
	if interval <= 0 {
		interval = 1 * time.Hour
	}
	return &Cleaner{
		pool:       pool,
		logger:     logger,
		interval:   interval,
		previewTTL: 7 * 24 * time.Hour,
		jobTTL:     30 * 24 * time.Hour,
	}
}

// Run executes the periodic cleanup loop until ctx is cancelled.
func (c *Cleaner) Run(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	// Run once immediately at startup.
	c.RunOnce(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.RunOnce(ctx)
		}
	}
}

// RunOnce executes a single cleanup pass.
func (c *Cleaner) RunOnce(ctx context.Context) {
	if c.pool == nil {
		return
	}

	previewsTerminated, err := PurgeExpiredPreviews(ctx, c.pool, c.previewTTL)
	if err != nil {
		c.logger.Warn("cleanup: preview purge error", "error", err)
	} else if previewsTerminated > 0 {
		c.logger.Info("cleanup: purged expired previews", "count", previewsTerminated)
	}

	jobsPruned, err := PruneOldJobs(ctx, c.pool, c.jobTTL)
	if err != nil {
		c.logger.Warn("cleanup: job prune error", "error", err)
	} else if jobsPruned > 0 {
		c.logger.Info("cleanup: pruned old terminal jobs", "count", jobsPruned)
	}
}
