package controller

// backups_scheduler.go — the scheduled-run loop for backup plans.
//
// One tick: ask the store for plans whose next_run_at has passed, create a
// scheduled run for each, enqueue a backup.run job, and advance next_run_at
// using the plan's cron expression. A second duty in the same tick: retention.
// For each due plan, runs beyond the retention window are marked expired and
// a backup.delete job is enqueued per expired run.
//
// Concurrency safety comes from the jobs engine, not from this loop: the
// backup.run job carries LockKeys ["backup_plan:<id>"] and CreateRun refuses a
// second active run for the same plan (ErrConflictActive), so two controller
// instances ticking simultaneously produce exactly one run.
//
// No cron library: internal/backups.NextRun is a hand-rolled 5-field parser
// (zero new dependencies). A plan whose expression never matches again logs an
// error and is left with its next_run_at untouched rather than being silently
// disabled.

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/backups"
	"github.com/bukansembarangkong/jawaker-panel/internal/jobs"
	"github.com/jackc/pgx/v5/pgxpool"
)

// BackupSchedulerOptions configures the scheduler loop.
type BackupSchedulerOptions struct {
	Pool    *pgxpool.Pool
	Backups *backups.Store
	Logger  *slog.Logger
	// TickInterval is how often the loop polls for due plans. Zero means 1 minute.
	TickInterval time.Duration
}

// BackupScheduler enqueues scheduled backup runs.
type BackupScheduler struct {
	pool   *pgxpool.Pool
	store  *backups.Store
	logger *slog.Logger
	tick   time.Duration
}

// NewBackupScheduler validates and constructs the scheduler.
func NewBackupScheduler(opts BackupSchedulerOptions) (*BackupScheduler, error) {
	if opts.Pool == nil {
		return nil, errors.New("controller: pool is required for backup scheduler")
	}
	if opts.Backups == nil {
		return nil, errors.New("controller: backups store is required for backup scheduler")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	tick := opts.TickInterval
	if tick <= 0 {
		tick = time.Minute
	}
	return &BackupScheduler{
		pool:   opts.Pool,
		store:  opts.Backups,
		logger: logger,
		tick:   tick,
	}, nil
}

// Run polls until ctx is canceled. It blocks; callers run it in a goroutine.
// Errors inside one tick are logged and never stop the loop — a transient
// database outage must not take down the process.
func (s *BackupScheduler) Run(ctx context.Context) error {
	ticker := time.NewTicker(s.tick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			s.tickOnce(ctx)
		}
	}
}

// tickOnce is one scheduler pass. Split out so tests can drive it directly.
func (s *BackupScheduler) tickOnce(ctx context.Context) {
	now := time.Now().UTC()
	plans, err := s.store.DuePlans(ctx, now)
	if err != nil {
		s.logger.Error("backup scheduler: due plans query failed", "error", err)
		return
	}
	for _, plan := range plans {
		s.enqueueScheduledRun(ctx, plan, now)
		s.enforceRetention(ctx, plan, now)
		s.advance(ctx, plan, now)
	}
}

func (s *BackupScheduler) enqueueScheduledRun(ctx context.Context, plan backups.Plan, now time.Time) {
	run, err := s.store.CreateRun(ctx, backups.CreateRunParams{
		PlanID:          plan.ID,
		ProjectID:       plan.ProjectID,
		ServerID:        plan.ServerID,
		Trigger:         backups.TriggerScheduled,
		RequestedByType: "system",
		// Idempotency key = plan + scheduled minute: two controllers ticking
		// in the same minute return the same run instead of double-archiving.
		IdempotencyKey: "sched:" + plan.ID + ":" + now.UTC().Format("200601021504"),
	})
	if err != nil {
		// A previous run is still active — skip this schedule point; the next
		// tick (or the next cron fire) will pick up. Not an error worth an alert.
		if errors.Is(err, backups.ErrConflictActive) {
			s.logger.Info("backup scheduler: plan already has an active run; skipping",
				"plan_id", plan.ID)
			return
		}
		s.logger.Error("backup scheduler: create run failed", "plan_id", plan.ID, "error", err)
		return
	}

	job, jErr := jobs.Enqueue(ctx, s.pool, jobs.Requested{
		Type:             JobTypeBackupRun,
		ServerID:         plan.ServerID,
		ProjectID:        plan.ProjectID,
		IdempotencyKey:   run.ID,
		IdempotencyScope: "backup.run:" + plan.ID,
		RequestedByType:  "system",
		Payload: map[string]any{
			"plan_id": plan.ID,
			"run_id":  run.ID,
		},
		Steps:    []jobs.StepPlan{{Name: "archive"}, {Name: "upload"}, {Name: "checksum"}, {Name: "notify"}},
		LockKeys: []string{"backup_plan:" + plan.ID},
	})
	if jErr != nil {
		s.logger.Error("backup scheduler: enqueue run job failed", "plan_id", plan.ID, "error", jErr)
		_ = s.store.MarkRunFailed(ctx, run.ID, "failed to enqueue scheduled job: "+jErr.Error())
		return
	}
	_ = s.store.SetRunJob(ctx, run.ID, job.ID)
	s.logger.Info("backup scheduler: scheduled run enqueued",
		"plan_id", plan.ID, "run_id", run.ID, "job_id", job.ID)
}

// enforceRetention marks runs past the plan's retention window as expired and
// enqueues backup.delete jobs to remove their artifacts.
func (s *BackupScheduler) enforceRetention(ctx context.Context, plan backups.Plan, now time.Time) {
	// No age window when RetentionDays is zero: retention is count-only, and
	// ExpireOldRuns with a far-future cutoff still drops everything beyond
	// keepCount.
	olderThan := now.Add(time.Hour)
	if plan.RetentionDays > 0 {
		olderThan = now.AddDate(0, 0, -plan.RetentionDays)
	}
	keep := plan.RetentionCount
	if keep < 0 {
		keep = 0
	}
	expired, err := s.store.ExpireOldRuns(ctx, plan.ID, keep, olderThan)
	if err != nil {
		s.logger.Error("backup scheduler: retention query failed", "plan_id", plan.ID, "error", err)
		return
	}
	for _, runID := range expired {
		_, jErr := jobs.Enqueue(ctx, s.pool, jobs.Requested{
			Type:             JobTypeBackupDelete,
			ServerID:         plan.ServerID,
			ProjectID:        plan.ProjectID,
			IdempotencyKey:   "delete-run:" + runID,
			IdempotencyScope: "backup.delete:" + runID,
			RequestedByType:  "system",
			Payload:          map[string]any{"run_id": runID},
			Steps:            []jobs.StepPlan{{Name: "delete_artifact"}},
			LockKeys:         []string{"backup_run:" + runID},
		})
		if jErr != nil {
			s.logger.Error("backup scheduler: enqueue retention delete failed",
				"plan_id", plan.ID, "run_id", runID, "error", jErr)
		}
	}
	if len(expired) > 0 {
		s.logger.Info("backup scheduler: retention expired runs", "plan_id", plan.ID, "count", len(expired))
	}
}

func (s *BackupScheduler) advance(ctx context.Context, plan backups.Plan, now time.Time) {
	if plan.ScheduleCron == "" {
		return
	}
	next, err := backups.NextRun(plan.ScheduleCron, now)
	if err != nil {
		s.logger.Error("backup scheduler: cron parse failed; next_run_at unchanged",
			"plan_id", plan.ID, "cron", plan.ScheduleCron, "error", err)
		return
	}
	if err := s.store.AdvanceNextRun(ctx, plan.ID, next); err != nil {
		s.logger.Error("backup scheduler: advance next_run_at failed", "plan_id", plan.ID, "error", err)
	}
}
