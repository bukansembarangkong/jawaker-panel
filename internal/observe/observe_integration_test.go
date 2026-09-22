//go:build integration

package observe

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/db/migrate"
	"github.com/bukansembarangkong/jawaker-panel/internal/dbtest"
	"github.com/bukansembarangkong/jawaker-panel/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMain(m *testing.M) {
	base := dbtest.FixtureURL()
	if base == "" {
		os.Exit(m.Run())
	}
	dsn, err := dbtest.IsolatedDatabase(base, "observe")
	if err != nil {
		fmt.Fprintf(os.Stderr, "observe: isolated test database: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("JAWAKER_TEST_DATABASE_URL", dsn); err != nil {
		fmt.Fprintf(os.Stderr, "observe: set test database: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = dbtest.DropDatabase(base, "observe")
	os.Exit(code)
}

type fixture struct {
	store    *Store
	pool     *pgxpool.Pool
	serverID string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	base := dbtest.FixtureURL()
	if base == "" {
		t.Skip("JAWAKER_TEST_DATABASE_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)

	pool, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := migrate.New(migrations.FS, logger)
	if err != nil {
		t.Fatalf("migrate.New: %v", err)
	}
	if _, err := m.Up(ctx, pool); err != nil {
		t.Fatalf("migrate up: %v", err)
	}

	var serverID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO servers (name, address, status)
		VALUES ('observe-node', '127.0.0.1:9462', 'active')
		RETURNING id`).Scan(&serverID); err != nil {
		t.Fatalf("insert fixture server: %v", err)
	}
	return fixture{store: NewStore(pool, nil), pool: pool, serverID: serverID}
}

func TestSampleLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// Batch record.
	samples := []Sample{
		{ServerID: f.serverID, Metric: MetricCPUPct, Value: 10, ObservedAt: now.Add(-2 * time.Minute)},
		{ServerID: f.serverID, Metric: MetricCPUPct, Value: 90, ObservedAt: now.Add(-time.Minute)},
		{ServerID: f.serverID, Metric: MetricMemPct, Value: 55, ObservedAt: now},
	}
	if err := f.store.RecordSamples(ctx, samples); err != nil {
		t.Fatalf("record: %v", err)
	}

	// Invalid metric refused.
	if err := f.store.RecordSamples(ctx, []Sample{
		{ServerID: f.serverID, Metric: "bogus", Value: 1, ObservedAt: now},
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid metric: got %v, want ErrInvalid", err)
	}

	// Newest first.
	got, err := f.store.QuerySamples(ctx, f.serverID, MetricCPUPct, now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 2 || got[0].Value != 90 {
		t.Fatalf("query: got %+v, want 90 first", got)
	}

	// SamplesSince oldest-first for the evaluator window.
	since, err := f.store.SamplesSince(ctx, f.serverID, MetricCPUPct, now.Add(-time.Hour))
	if err != nil {
		t.Fatalf("samples since: %v", err)
	}
	if len(since) != 2 || since[0].Value != 10 {
		t.Fatalf("samples since: got %+v, want 10 first", since)
	}
}

func TestPruneSamplesRetentionBounded(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// 5 old samples, 2 fresh.
	old := make([]Sample, 0, 7)
	for i := 0; i < 5; i++ {
		old = append(old, Sample{ServerID: f.serverID, Metric: MetricCPUPct, Value: 1, ObservedAt: now.Add(-48 * time.Hour)})
	}
	for i := 0; i < 2; i++ {
		old = append(old, Sample{ServerID: f.serverID, Metric: MetricCPUPct, Value: 2, ObservedAt: now})
	}
	if err := f.store.RecordSamples(ctx, old); err != nil {
		t.Fatalf("record: %v", err)
	}

	deleted, err := f.store.PruneSamples(ctx, now.Add(-24*time.Hour), 0)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if deleted != 5 {
		t.Fatalf("prune: deleted %d, want 5", deleted)
	}
	got, err := f.store.QuerySamples(ctx, f.serverID, MetricCPUPct, now.Add(-time.Hour), 10)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("after prune: got %d rows, want 2", len(got))
	}

	// Row cap: keep only 1.
	deleted, err = f.store.PruneSamples(ctx, now.Add(-24*time.Hour), 1)
	if err != nil {
		t.Fatalf("prune cap: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("prune cap: deleted %d, want 1", deleted)
	}
}

func TestRuleLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	rule, err := f.store.CreateRule(ctx, CreateRuleParams{
		ServerID: f.serverID, Name: "cpu high", Metric: MetricCPUPct,
		Comparator: ComparatorGT, Threshold: 90, DurationSeconds: 300, Severity: SeverityWarning,
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	if rule.State != "active" || !rule.Enabled {
		t.Fatalf("new rule: %+v", rule)
	}

	// Bad metric / comparator / duration refused.
	if _, err := f.store.CreateRule(ctx, CreateRuleParams{
		ServerID: f.serverID, Name: "x", Metric: "bogus", Comparator: ComparatorGT,
		Threshold: 1, DurationSeconds: 300, Severity: SeverityWarning,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad metric: got %v, want ErrInvalid", err)
	}

	got, err := f.store.GetRule(ctx, rule.ID)
	if err != nil || got.ID != rule.ID {
		t.Fatalf("get rule: %v", got)
	}

	rules, err := f.store.ListRules(ctx, f.serverID, 10, 0)
	if err != nil || len(rules) != 1 {
		t.Fatalf("list rules: %v, %d", err, len(rules))
	}

	enabled, err := f.store.EnabledRules(ctx)
	if err != nil || len(enabled) != 1 {
		t.Fatalf("enabled rules: %v, %d", err, len(enabled))
	}

	threshold := 50.0
	updated, err := f.store.UpdateRule(ctx, rule.ID, UpdateRuleParams{Threshold: &threshold})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Threshold != 50 {
		t.Fatalf("update: threshold %v, want 50", updated.Threshold)
	}

	if err := f.store.DeleteRule(ctx, rule.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := f.store.GetRule(ctx, rule.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get deleted: got %v, want ErrNotFound", err)
	}
}

func TestIncidentDedupAndResolve(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	rule, err := f.store.CreateRule(ctx, CreateRuleParams{
		ServerID: f.serverID, Name: "disk high", Metric: MetricDiskPct,
		Comparator: ComparatorGT, Threshold: 85, DurationSeconds: 300, Severity: SeverityCritical,
	})
	if err != nil {
		t.Fatalf("create rule: %v", err)
	}
	key := "rule:" + rule.ID

	// First open creates.
	inc, created, err := f.store.OpenIncident(ctx, rule.ID, f.serverID, key)
	if err != nil || !created {
		t.Fatalf("open: created=%v err=%v", created, err)
	}

	// Second open returns the same incident, created=false (dedup).
	inc2, created2, err := f.store.OpenIncident(ctx, rule.ID, f.serverID, key)
	if err != nil {
		t.Fatalf("open again: %v", err)
	}
	if created2 || inc2.ID != inc.ID {
		t.Fatalf("dedup: created=%v id=%s want false %s", created2, inc2.ID, inc.ID)
	}

	if err := f.store.MarkIncidentNotified(ctx, inc.ID); err != nil {
		t.Fatalf("mark notified: %v", err)
	}

	open, err := f.store.ListIncidents(ctx, f.serverID, IncidentOpen, 10, 0)
	if err != nil || len(open) != 1 {
		t.Fatalf("list open: %v, %d", err, len(open))
	}

	n, err := f.store.CountOpenIncidents(ctx)
	if err != nil || n != 1 {
		t.Fatalf("count open: %v, %d", err, n)
	}

	// Resolve via dedup key.
	resolvedID, err := f.store.ResolveOpenByDedup(ctx, key)
	if err != nil || resolvedID != inc.ID {
		t.Fatalf("resolve: id=%s err=%v", resolvedID, err)
	}
	// Second resolve is a no-op.
	resolvedID, err = f.store.ResolveOpenByDedup(ctx, key)
	if err != nil || resolvedID != "" {
		t.Fatalf("resolve twice: id=%q err=%v", resolvedID, err)
	}

	// Double resolve by id returns ErrState.
	if err := f.store.ResolveIncident(ctx, inc.ID); !errors.Is(err, ErrState) {
		t.Fatalf("resolve resolved: got %v, want ErrState", err)
	}

	// A new incident can open after resolution.
	inc3, created3, err := f.store.OpenIncident(ctx, rule.ID, f.serverID, key)
	if err != nil || !created3 || inc3.ID == inc.ID {
		t.Fatalf("reopen: created=%v err=%v", created3, err)
	}
}

func TestScheduleLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	now := time.Now().UTC()

	if _, err := f.store.CreateSchedule(ctx, "daily", "bogus", now, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad cadence: got %v, want ErrInvalid", err)
	}

	sched, err := f.store.CreateSchedule(ctx, "Daily report", CadenceDaily, now.Add(-time.Minute), "")
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	due, err := f.store.DueSchedules(ctx, now)
	if err != nil || len(due) != 1 || due[0].ID != sched.ID {
		t.Fatalf("due: %v, %d", err, len(due))
	}

	next := now.Add(24 * time.Hour)
	if err := f.store.AdvanceSchedule(ctx, sched.ID, now, next); err != nil {
		t.Fatalf("advance: %v", err)
	}
	due, err = f.store.DueSchedules(ctx, now)
	if err != nil || len(due) != 0 {
		t.Fatalf("due after advance: %v, %d", err, len(due))
	}

	if err := f.store.DeleteSchedule(ctx, sched.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := f.store.DeleteSchedule(ctx, sched.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete twice: got %v, want ErrNotFound", err)
	}
}
