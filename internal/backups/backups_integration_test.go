//go:build integration

package backups

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
	dsn, err := dbtest.IsolatedDatabase(base, "backups")
	if err != nil {
		fmt.Fprintf(os.Stderr, "backups: isolated test database: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("JAWAKER_TEST_DATABASE_URL", dsn); err != nil {
		fmt.Fprintf(os.Stderr, "backups: set test database: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = dbtest.DropDatabase(base, "backups")
	os.Exit(code)
}

type fixture struct {
	store     *Store
	pool      *pgxpool.Pool
	projectID string
	serverID  string
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

	var serverID, projectID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO servers (name, address, status)
		VALUES ('backup-node', '127.0.0.1:9461', 'active')
		RETURNING id`).Scan(&serverID); err != nil {
		t.Fatalf("insert fixture server: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO projects (slug, name, state)
		VALUES ('backup-project', 'Backup Project', 'active')
		RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("insert fixture project: %v", err)
	}

	return fixture{store: NewStore(pool, nil), pool: pool, projectID: projectID, serverID: serverID}
}

func (f fixture) createPlan(t *testing.T, slug string) Plan {
	t.Helper()
	p, err := f.store.CreatePlan(context.Background(), CreatePlanParams{
		ProjectID:       f.projectID,
		ServerID:        f.serverID,
		Name:            "Plan " + slug,
		Slug:            slug,
		ScopeType:       ScopeProject,
		DestinationType: DestLocal,
		ScheduleCron:    "0 2 * * *",
	})
	if err != nil {
		t.Fatalf("create plan %s: %v", slug, err)
	}
	return p
}

func TestPlanLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	p := f.createPlan(t, "nightly")
	if p.State != StateActive || !p.Live() {
		t.Fatalf("new plan: got %+v, want active", p)
	}

	// Slug taken in same project.
	_, err := f.store.CreatePlan(ctx, CreatePlanParams{
		ProjectID: f.projectID, ServerID: f.serverID,
		Name: "dup", Slug: "nightly", ScopeType: ScopeProject, DestinationType: DestLocal,
	})
	if !errors.Is(err, ErrSlugTaken) {
		t.Fatalf("duplicate slug: got %v, want ErrSlugTaken", err)
	}

	// Update name + retention.
	name := "Renamed"
	count := 3
	updated, err := f.store.UpdatePlan(ctx, f.projectID, p.ID, UpdatePlanParams{Name: &name, RetentionCount: &count})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != name || updated.RetentionCount != 3 {
		t.Fatalf("update: got %+v", updated)
	}

	// Cross-project read returns not-found (anti-enumeration).
	var otherProject string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO projects (slug, name, state) VALUES ('other-proj', 'Other', 'active') RETURNING id`,
	).Scan(&otherProject); err != nil {
		t.Fatalf("insert other project: %v", err)
	}
	if _, err := f.store.GetPlanInProject(ctx, otherProject, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-project get: got %v, want ErrNotFound", err)
	}

	// Tombstone lifecycle.
	del, err := f.store.MarkPendingDelete(ctx, f.projectID, p.ID, time.Second)
	if err != nil {
		t.Fatalf("mark pending delete: %v", err)
	}
	if del.State != StatePendingDelete || del.DeleteAfter == nil {
		t.Fatalf("pending delete: got %+v", del)
	}
	if err := f.store.FinalizeDelete(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("finalize before grace: got %v, want ErrNotFound", err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err := f.store.FinalizeDelete(ctx, p.ID); err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if _, err := f.store.GetPlanInProject(ctx, f.projectID, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get deleted plan: got %v, want ErrNotFound", err)
	}
}

func TestRunLifecycleAndIdempotency(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	p := f.createPlan(t, "runs")

	run, err := f.store.CreateRun(ctx, CreateRunParams{
		PlanID: p.ID, ProjectID: f.projectID, ServerID: f.serverID,
		Trigger: TriggerManual, RequestedByType: "user", RequestedByID: "tester",
		IdempotencyKey: "run:1",
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}
	if run.State != RunQueued || run.Verification != VerifUnverified {
		t.Fatalf("new run: got %+v", run)
	}

	// Active-run conflict: second queued run for the same plan is refused.
	_, err = f.store.CreateRun(ctx, CreateRunParams{
		PlanID: p.ID, ProjectID: f.projectID, ServerID: f.serverID,
		Trigger: TriggerManual, RequestedByType: "user", IdempotencyKey: "run:2",
	})
	if !errors.Is(err, ErrConflictActive) {
		t.Fatalf("second active run: got %v, want ErrConflictActive", err)
	}

	// Idempotency duplicate returns the existing run.
	dup, err := f.store.CreateRun(ctx, CreateRunParams{
		ProjectID: f.projectID, ServerID: f.serverID,
		Trigger: TriggerManual, RequestedByType: "user", IdempotencyKey: "run:1",
	})
	if err != nil {
		t.Fatalf("idempotent create: %v", err)
	}
	if dup.ID != run.ID {
		t.Fatalf("idempotent create: got %s, want %s", dup.ID, run.ID)
	}

	// State machine: queued -> running -> completed.
	if err := f.store.MarkRunRunning(ctx, run.ID); err != nil {
		t.Fatalf("mark running: %v", err)
	}
	if err := f.store.MarkRunRunning(ctx, run.ID); !errors.Is(err, ErrState) {
		t.Fatalf("double running: got %v, want ErrState", err)
	}
	if err := f.store.MarkRunCompleted(ctx, CompleteRunParams{
		ID: run.ID, ArchivePath: "/backups/run1.tar.gz", ArchiveSize: 2048,
		SHA256: "deadbeef", Manifest: map[string]any{"files": 3},
	}); err != nil {
		t.Fatalf("complete: %v", err)
	}
	done, err := f.store.GetRun(ctx, f.projectID, run.ID)
	if err != nil {
		t.Fatalf("get run: %v", err)
	}
	if done.State != RunCompleted || done.ArchiveSize != 2048 || done.CompletedAt == nil {
		t.Fatalf("completed run: got %+v", done)
	}
	if done.Manifest["files"] != float64(3) {
		t.Fatalf("manifest: got %+v", done.Manifest)
	}

	// Verification transitions.
	if err := f.store.UpdateRunVerification(ctx, run.ID, VerifVerified); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := f.store.UpdateRunVerification(ctx, run.ID, "bogus"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("bad verification state: got %v, want ErrInvalid", err)
	}

	// Failed transition from terminal state refused.
	if err := f.store.MarkRunFailed(ctx, run.ID, "too late"); !errors.Is(err, ErrState) {
		t.Fatalf("fail completed run: got %v, want ErrState", err)
	}
}

func TestSchedulerDuePlans(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	p := f.createPlan(t, "sched")
	past := time.Now().UTC().Add(-time.Hour)
	next := &past
	if _, err := f.store.UpdatePlan(ctx, f.projectID, p.ID, UpdatePlanParams{NextRunAt: &next}); err != nil {
		t.Fatalf("set next_run_at: %v", err)
	}

	due, err := f.store.DuePlans(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("due plans: %v", err)
	}
	if len(due) != 1 || due[0].ID != p.ID {
		t.Fatalf("due plans: got %d entries, want the scheduled plan", len(due))
	}

	future := time.Now().UTC().Add(24 * time.Hour)
	if err := f.store.AdvanceNextRun(ctx, p.ID, future); err != nil {
		t.Fatalf("advance: %v", err)
	}
	due, err = f.store.DuePlans(ctx, time.Now().UTC())
	if err != nil {
		t.Fatalf("due plans after advance: %v", err)
	}
	if len(due) != 0 {
		t.Fatalf("due plans after advance: got %d, want 0", len(due))
	}
}

func TestExpiringLinkRedemption(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	p := f.createPlan(t, "links")
	run, err := f.store.CreateRun(ctx, CreateRunParams{
		PlanID: p.ID, ProjectID: f.projectID, ServerID: f.serverID,
		Trigger: TriggerManual, RequestedByType: "system",
	})
	if err != nil {
		t.Fatalf("create run: %v", err)
	}

	link, err := f.store.CreateExpiringLink(ctx, CreateExpiringLinkParams{
		RunID: run.ID, ProjectID: f.projectID, TokenHash: "hash-abc", TTL: time.Hour, SingleUse: true,
	})
	if err != nil {
		t.Fatalf("create link: %v", err)
	}
	if link.ExpiresAt.Before(time.Now()) {
		t.Fatalf("link already expired: %+v", link)
	}

	// Redeem once.
	runID, err := f.store.RedeemExpiringLink(ctx, "hash-abc")
	if err != nil || runID != run.ID {
		t.Fatalf("redeem: %v runID=%s", err, runID)
	}
	// Single-use: second redeem fails, indistinguishable from unknown token.
	if _, err := f.store.RedeemExpiringLink(ctx, "hash-abc"); !errors.Is(err, ErrLinkExpired) {
		t.Fatalf("double redeem: got %v, want ErrLinkExpired", err)
	}
	if _, err := f.store.RedeemExpiringLink(ctx, "hash-unknown"); !errors.Is(err, ErrLinkExpired) {
		t.Fatalf("unknown token: got %v, want ErrLinkExpired", err)
	}

	// TTL bounds.
	_, err = f.store.CreateExpiringLink(ctx, CreateExpiringLinkParams{
		RunID: run.ID, ProjectID: f.projectID, TokenHash: "hash-bad-ttl", TTL: 48 * time.Hour,
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("48h ttl: got %v, want ErrInvalid", err)
	}

	// Revoke.
	link2, err := f.store.CreateExpiringLink(ctx, CreateExpiringLinkParams{
		RunID: run.ID, ProjectID: f.projectID, TokenHash: "hash-rev", TTL: time.Hour, SingleUse: false,
	})
	if err != nil {
		t.Fatalf("create link2: %v", err)
	}
	if err := f.store.RevokeExpiringLink(ctx, f.projectID, link2.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := f.store.RedeemExpiringLink(ctx, "hash-rev"); !errors.Is(err, ErrLinkExpired) {
		t.Fatalf("redeem revoked: got %v, want ErrLinkExpired", err)
	}
}

func TestRetentionExpiry(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	p := f.createPlan(t, "retain")

	// Create 3 completed runs with staggered timestamps.
	for i := 0; i < 3; i++ {
		run, err := f.store.CreateRun(ctx, CreateRunParams{
			PlanID: p.ID, ProjectID: f.projectID, ServerID: f.serverID,
			Trigger: TriggerScheduled, RequestedByType: "system",
		})
		if err != nil {
			// Second/third hit the active-run conflict only while one is
			// queued; complete the previous run first.
			t.Fatalf("create run %d: %v", i, err)
		}
		if err := f.store.MarkRunRunning(ctx, run.ID); err != nil {
			t.Fatalf("mark running %d: %v", i, err)
		}
		if err := f.store.MarkRunCompleted(ctx, CompleteRunParams{
			ID: run.ID, ArchivePath: fmt.Sprintf("/backups/run%d.tar.gz", i), SHA256: "x",
		}); err != nil {
			t.Fatalf("complete %d: %v", i, err)
		}
		// Age the row so retention sees it as old.
		if _, err := f.pool.Exec(ctx,
			`UPDATE backup_runs SET created_at = now() - interval '60 days' WHERE id = $1::uuid`, run.ID); err != nil {
			t.Fatalf("age run %d: %v", i, err)
		}
	}

	// keep 1 newest; everything older than 30 days beyond that expires.
	expired, err := f.store.ExpireOldRuns(ctx, p.ID, 1, time.Now().UTC().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatalf("expire: %v", err)
	}
	if len(expired) != 2 {
		t.Fatalf("expired: got %d, want 2 (kept newest 1)", len(expired))
	}
}
