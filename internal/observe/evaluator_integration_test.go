//go:build integration

package observe

// evaluator_integration_test.go — Phase 7 PR-D gate tests.
//
// Gate 1: a rule firing for the full duration window opens an incident and
//         marks it notified.
// Gate 2: a previously-firing rule whose samples drop below threshold resolves
//         the open incident.
// Gate 3: PruneSamples enforces the maxRows cap per (server, metric) pair.

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"io"

	"github.com/jackc/pgx/v5/pgxpool"
)

func newTestEvaluator(t *testing.T, s *Store, pool *pgxpool.Pool, now time.Time) *Evaluator {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	clock := func() time.Time { return now }
	return NewEvaluator(s, pool, clock, logger, EvaluatorConfig{Interval: time.Hour}) // long interval = never auto-tick in tests
}

// TestEvaluatorRuleFires is gate 1.
func TestEvaluatorRuleFires(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	rule, err := f.store.CreateRule(ctx, CreateRuleParams{
		ServerID:        f.serverID,
		Name:            "hot cpu",
		Metric:          MetricCPUPct,
		Comparator:      "gt",
		Threshold:       80,
		DurationSeconds: 60,
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}

	now := time.Now().UTC()
	if err := f.store.RecordSamples(ctx, []Sample{
		{ServerID: f.serverID, Metric: MetricCPUPct, Value: 95, ObservedAt: now.Add(-50 * time.Second)},
		{ServerID: f.serverID, Metric: MetricCPUPct, Value: 90, ObservedAt: now.Add(-20 * time.Second)},
	}); err != nil {
		t.Fatalf("record samples: %v", err)
	}

	ev := newTestEvaluator(t, f.store, f.pool, now)
	ev.evaluateRules(ctx, now)

	dedupKey := "rule:" + rule.ID
	inc, err := f.store.GetOpenIncident(ctx, dedupKey)
	if err != nil {
		t.Fatalf("get open incident: %v", err)
	}
	if inc.State != IncidentOpen {
		t.Errorf("state = %q, want %q", inc.State, IncidentOpen)
	}
	// MarkIncidentNotified must have been called.
	if inc.NotifiedAt == nil {
		t.Error("notified_at nil after first fire")
	}
}

// TestEvaluatorRuleRecovers is gate 2.
func TestEvaluatorRuleRecovers(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	rule, err := f.store.CreateRule(ctx, CreateRuleParams{
		ServerID:        f.serverID,
		Name:            "hot cpu",
		Metric:          MetricCPUPct,
		Comparator:      "gt",
		Threshold:       80,
		DurationSeconds: 60,
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}

	now := time.Now().UTC()
	ev := newTestEvaluator(t, f.store, f.pool, now)

	// Fire: one above-threshold sample in the window.
	if err := f.store.RecordSamples(ctx, []Sample{
		{ServerID: f.serverID, Metric: MetricCPUPct, Value: 95, ObservedAt: now.Add(-30 * time.Second)},
	}); err != nil {
		t.Fatalf("record firing sample: %v", err)
	}
	ev.evaluateRules(ctx, now)

	dedupKey := "rule:" + rule.ID
	if _, err := f.store.GetOpenIncident(ctx, dedupKey); err != nil {
		t.Fatalf("incident not open after fire tick: %v", err)
	}

	// Recovery: replace with a below-threshold sample.
	if _, err := f.pool.Exec(ctx,
		`DELETE FROM metric_samples WHERE server_id = $1::uuid AND metric = $2`,
		f.serverID, MetricCPUPct,
	); err != nil {
		t.Fatalf("delete samples: %v", err)
	}
	if err := f.store.RecordSamples(ctx, []Sample{
		{ServerID: f.serverID, Metric: MetricCPUPct, Value: 40, ObservedAt: now.Add(-10 * time.Second)},
	}); err != nil {
		t.Fatalf("record recovery sample: %v", err)
	}
	ev.evaluateRules(ctx, now)

	// Incident must be resolved (GetOpenIncident returns ErrNotFound).
	if _, err := f.store.GetOpenIncident(ctx, dedupKey); err == nil {
		t.Error("incident still open after recovery tick")
	}
}

// TestEvaluatorPruneSamples is gate 3.
func TestEvaluatorPruneSamples(t *testing.T) {
	ctx := context.Background()
	f := newFixture(t)

	now := time.Now().UTC()
	samples := make([]Sample, 10)
	for i := range samples {
		samples[i] = Sample{
			ServerID:   f.serverID,
			Metric:     MetricCPUPct,
			Value:      float64(50 + i),
			ObservedAt: now.Add(-time.Duration(10-i) * time.Minute),
		}
	}
	if err := f.store.RecordSamples(ctx, samples); err != nil {
		t.Fatalf("record samples: %v", err)
	}

	// maxRows=5, cutoff=far future so only the cap matters.
	deleted, err := f.store.PruneSamples(ctx, now.Add(time.Hour), 5)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if deleted < 5 {
		t.Errorf("deleted = %d, want >= 5", deleted)
	}

	var remaining int
	if err := f.pool.QueryRow(ctx,
		`SELECT count(*) FROM metric_samples WHERE server_id = $1::uuid`, f.serverID,
	).Scan(&remaining); err != nil {
		t.Fatalf("count: %v", err)
	}
	if remaining > 5 {
		t.Errorf("remaining = %d after prune, want <= 5", remaining)
	}
}
