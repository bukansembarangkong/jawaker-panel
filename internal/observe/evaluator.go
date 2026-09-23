package observe

// evaluator.go — Phase 7 PR-D: metric evaluator + retention + report scheduler.
//
// Three responsibilities, all run by the same ticker-driven loop:
//
//  1. EvaluateRules – read all enabled rules, fetch samples since
//     rule.DurationSeconds ago, decide fire/recover, open/close incidents,
//     publish alert notifications exactly once per transition.
//
//  2. PruneOldSamples – enforce bounded retention: keep at most retentionRows
//     rows per (server, metric) pair, drop anything older than retentionCutoff.
//     Never deletes an open incident's newest sample — that's enforced by the
//     bounded row count, not by age.
//
//  3. RunDueSchedules – fetch schedules whose next_run_at <= now, publish a
//     report.summary notification, then advance next_run_at by one cadence.
//
// The evaluator has no additional Go dependencies; it re-uses the Store and
// notify packages already imported by the rest of the controller surface.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/notify"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EvaluatorConfig holds tunable knobs; zero values pick the defaults below.
type EvaluatorConfig struct {
	// Interval between evaluation ticks (default 30s).
	Interval time.Duration
	// RetentionCutoff is the age after which samples are eligible for pruning
	// (default 7 days). Samples within this window are never touched.
	RetentionCutoff time.Duration
	// RetentionMaxRows is the hard cap per (server, metric) pair (default 2016,
	// which at 30s intervals covers exactly 7 days). Oldest rows beyond the cap
	// are deleted first, before the age cutoff is applied.
	RetentionMaxRows int
}

func (c *EvaluatorConfig) withDefaults() EvaluatorConfig {
	out := *c
	if out.Interval <= 0 {
		out.Interval = 30 * time.Second
	}
	if out.RetentionCutoff <= 0 {
		out.RetentionCutoff = 7 * 24 * time.Hour
	}
	if out.RetentionMaxRows <= 0 {
		out.RetentionMaxRows = 2016 // 7d × 24h × 6 ticks/h = 1008; ×2 for safety
	}
	return out
}

// Evaluator runs the periodic metric evaluation loop.
type Evaluator struct {
	store  *Store
	pool   *pgxpool.Pool
	now    func() time.Time
	logger *slog.Logger
	cfg    EvaluatorConfig
}

// NewEvaluator creates an Evaluator.
func NewEvaluator(store *Store, pool *pgxpool.Pool, now func() time.Time, logger *slog.Logger, cfg EvaluatorConfig) *Evaluator {
	if now == nil {
		now = time.Now
	}
	return &Evaluator{
		store:  store,
		pool:   pool,
		now:    now,
		logger: logger,
		cfg:    cfg.withDefaults(),
	}
}

// Run blocks until ctx is canceled, ticking every cfg.Interval.
func (ev *Evaluator) Run(ctx context.Context) {
	ticker := time.NewTicker(ev.cfg.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			ev.tick(ctx)
		}
	}
}

func (ev *Evaluator) tick(ctx context.Context) {
	now := ev.now().UTC()
	ev.evaluateRules(ctx, now)
	ev.pruneOldSamples(ctx, now)
	ev.runDueSchedules(ctx, now)
}

// --- rule evaluation ----------------------------------------------------------

func (ev *Evaluator) evaluateRules(ctx context.Context, now time.Time) {
	rules, err := ev.store.EnabledRules(ctx)
	if err != nil {
		ev.logger.Error("evaluator: list rules", "error", err)
		return
	}
	for _, rule := range rules {
		ev.evalRule(ctx, rule, now)
	}
}

func (ev *Evaluator) evalRule(ctx context.Context, rule AlertRule, now time.Time) {
	window := time.Duration(rule.DurationSeconds) * time.Second
	since := now.Add(-window)

	samples, err := ev.store.SamplesSince(ctx, rule.ServerID, rule.Metric, since)
	if err != nil {
		ev.logger.Error("evaluator: samples since", "rule", rule.ID, "error", err)
		return
	}
	if len(samples) == 0 {
		return // no data — neither fire nor recover
	}

	// All samples in the window must satisfy the condition for a fire.
	firing := allSatisfy(samples, rule.Comparator, rule.Threshold)
	dedupKey := "rule:" + rule.ID

	if firing {
		ev.handleFiring(ctx, rule, dedupKey, samples[0].Value)
	} else {
		ev.handleRecovery(ctx, dedupKey, rule)
	}
}

func allSatisfy(samples []Sample, comparator string, threshold float64) bool {
	if len(samples) == 0 {
		return false
	}
	for _, s := range samples {
		var ok bool
		switch comparator {
		case "gt":
			ok = s.Value > threshold
		case "lt":
			ok = s.Value < threshold
		default:
			return false
		}
		if !ok {
			return false
		}
	}
	return true
}

func (ev *Evaluator) handleFiring(ctx context.Context, rule AlertRule, dedupKey string, currentValue float64) {
	incident, created, err := ev.store.OpenIncident(ctx, rule.ID, rule.ServerID, dedupKey)
	if err != nil {
		ev.logger.Error("evaluator: open incident", "rule", rule.ID, "error", err)
		return
	}
	// Only notify on first open; subsequent ticks with the same open incident
	// are suppressed by dedup in notify.Publish.
	if created || incident.NotifiedAt == nil {
		ev.publishAlert(ctx, rule, incident.ID, currentValue)
	}
}

func (ev *Evaluator) handleRecovery(ctx context.Context, dedupKey string, rule AlertRule) {
	resolvedID, err := ev.store.ResolveOpenByDedup(ctx, dedupKey)
	if err != nil {
		ev.logger.Error("evaluator: resolve by dedup", "rule", rule.ID, "error", err)
		return
	}
	if resolvedID == "" {
		return // nothing was open
	}
	ev.publishRecovery(ctx, rule, resolvedID)
}

func (ev *Evaluator) publishAlert(ctx context.Context, rule AlertRule, incidentID string, value float64) {
	title := fmt.Sprintf("[%s] %s threshold exceeded", rule.Severity, rule.Name)
	body := fmt.Sprintf("Metric %s %s %.2f (current %.2f) on server %s for %ds.",
		rule.Metric, rule.Comparator, rule.Threshold, value, rule.ServerID, rule.DurationSeconds)
	ev.publish(ctx, notify.Event{
		Event:        "alert.fired",
		Severity:     rule.Severity,
		ResourceType: "alert_incident",
		ResourceID:   incidentID,
		ServerID:     rule.ServerID,
		Title:        title,
		Body:         body,
		DedupKey:     "rule:" + rule.ID,
		Payload: map[string]any{
			"rule_id":          rule.ID,
			"metric":           rule.Metric,
			"comparator":       rule.Comparator,
			"threshold":        rule.Threshold,
			"current_value":    value,
			"duration_seconds": rule.DurationSeconds,
		},
	})
	if err := ev.store.MarkIncidentNotified(ctx, incidentID); err != nil {
		ev.logger.Error("evaluator: mark notified", "incident", incidentID, "error", err)
	}
}

func (ev *Evaluator) publishRecovery(ctx context.Context, rule AlertRule, incidentID string) {
	title := fmt.Sprintf("[resolved] %s back to normal", rule.Name)
	body := fmt.Sprintf("Metric %s on server %s no longer exceeds threshold %.2f.",
		rule.Metric, rule.ServerID, rule.Threshold)
	ev.publish(ctx, notify.Event{
		Event:        "alert.recovered",
		Severity:     notify.SeverityInfo,
		ResourceType: "alert_incident",
		ResourceID:   incidentID,
		ServerID:     rule.ServerID,
		Title:        title,
		Body:         body,
		// No dedup key: recovery is a discrete event, not a repeating condition.
	})
}

func (ev *Evaluator) publish(ctx context.Context, event notify.Event) {
	_, err := notify.Publish(ctx, ev.pool, event, notify.PublishOptions{})
	if err != nil {
		ev.logger.Error("evaluator: publish notification", "event", event.Event, "error", err)
	}
}

// --- retention ----------------------------------------------------------------

func (ev *Evaluator) pruneOldSamples(ctx context.Context, now time.Time) {
	cutoff := now.Add(-ev.cfg.RetentionCutoff)
	deleted, err := ev.store.PruneSamples(ctx, cutoff, ev.cfg.RetentionMaxRows)
	if err != nil {
		ev.logger.Error("evaluator: prune samples", "error", err)
		return
	}
	if deleted > 0 {
		ev.logger.Info("evaluator: pruned metric samples", "deleted", deleted)
	}
}

// --- report schedules ---------------------------------------------------------

func (ev *Evaluator) runDueSchedules(ctx context.Context, now time.Time) {
	schedules, err := ev.store.DueSchedules(ctx, now)
	if err != nil {
		ev.logger.Error("evaluator: due schedules", "error", err)
		return
	}
	for _, sched := range schedules {
		ev.runSchedule(ctx, sched, now)
	}
}

func (ev *Evaluator) runSchedule(ctx context.Context, sched ReportSchedule, now time.Time) {
	open, err := ev.store.CountOpenIncidents(ctx)
	if err != nil {
		ev.logger.Error("evaluator: count open incidents for report", "error", err)
		return
	}

	title := fmt.Sprintf("%s report: %s", sched.Cadence, sched.Name)
	body := fmt.Sprintf("Scheduled %s report '%s'. Open incidents: %d.", sched.Cadence, sched.Name, open)
	ev.publish(ctx, notify.Event{
		Event:    "report.summary",
		Severity: notify.SeverityInfo,
		Title:    title,
		Body:     body,
		Payload: map[string]any{
			"schedule_id":    sched.ID,
			"cadence":        sched.Cadence,
			"open_incidents": open,
		},
	})

	next := advanceCadence(now, sched.Cadence)
	if err := ev.store.AdvanceSchedule(ctx, sched.ID, now, next); err != nil {
		ev.logger.Error("evaluator: advance schedule", "schedule", sched.ID, "error", err)
	}
}

// advanceCadence returns the next run time one cadence period after now.
func advanceCadence(now time.Time, cadence string) time.Time {
	switch cadence {
	case CadenceWeekly:
		return now.AddDate(0, 0, 7)
	case CadenceMonthly:
		return now.AddDate(0, 1, 0)
	default: // CadenceDaily
		return now.AddDate(0, 0, 1)
	}
}
