//go:build integration

package apps

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
	dsn, err := dbtest.IsolatedDatabase(base, "apps")
	if err != nil {
		fmt.Fprintf(os.Stderr, "apps: isolated test database: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("JAWAKER_TEST_DATABASE_URL", dsn); err != nil {
		fmt.Fprintf(os.Stderr, "apps: set test database: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = dbtest.DropDatabase(base, "apps")
	os.Exit(code)
}

type appFixture struct {
	store     *Store
	pool      *pgxpool.Pool
	projectID string
	serverID  string
}

func newFixture(t *testing.T) appFixture {
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
		VALUES ('test-node-1', '127.0.0.1:9443', 'active')
		RETURNING id`).Scan(&serverID); err != nil {
		t.Fatalf("insert fixture server: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO projects (slug, name, state)
		VALUES ('main-project', 'Main Project', 'active')
		RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("insert fixture project: %v", err)
	}

	store := NewStore(pool, nil)
	return appFixture{store: store, pool: pool, projectID: projectID, serverID: serverID}
}

func TestAppCreationAndLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// 1. Create node app
	app, err := f.store.CreateApp(ctx, CreateAppParams{
		ProjectID:     f.projectID,
		ServerID:      f.serverID,
		Slug:          "my-node-app",
		Name:          "My Node App",
		RuntimeType:   RuntimeNode,
		GitRepoURL:    "git@github.com:example/app.git",
		GitRefDefault: "main",
		BuildProgram:  "npm",
		BuildArgs:     []string{"run", "build"},
		StartProgram:  "node",
		StartArgs:     []string{"dist/server.js"},
		Port:          intPtr(3000),
	})
	if err != nil {
		t.Fatalf("CreateApp: %v", err)
	}
	if app.State != StateActive {
		t.Errorf("state = %q, want active", app.State)
	}
	if app.RuntimeType != RuntimeNode {
		t.Errorf("runtime_type = %q, want node", app.RuntimeType)
	}
	if app.Port == nil || *app.Port != 3000 {
		t.Errorf("port = %v, want 3000", app.Port)
	}
	if len(app.BuildArgs) != 2 || app.BuildArgs[0] != "run" {
		t.Errorf("build_args = %v, want [run build]", app.BuildArgs)
	}

	// 2. GetApp + GetAppInProject
	got, err := f.store.GetApp(ctx, app.ID)
	if err != nil {
		t.Fatalf("GetApp: %v", err)
	}
	if got.Slug != "my-node-app" {
		t.Errorf("got slug = %q, want my-node-app", got.Slug)
	}

	gotInProj, err := f.store.GetAppInProject(ctx, f.projectID, app.ID)
	if err != nil {
		t.Fatalf("GetAppInProject: %v", err)
	}
	if gotInProj.ID != app.ID {
		t.Errorf("got id mismatch")
	}

	// 3. Cross-project lookup returns ErrNotFound (not 403)
	var otherProjectID string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO projects (slug, name, state)
		VALUES ('other-project', 'Other Project', 'active')
		RETURNING id`).Scan(&otherProjectID); err != nil {
		t.Fatalf("insert other project: %v", err)
	}
	_, crossErr := f.store.GetAppInProject(ctx, otherProjectID, app.ID)
	if !errors.Is(crossErr, ErrNotFound) {
		t.Errorf("cross-project err = %v, want ErrNotFound", crossErr)
	}

	// 4. Duplicate slug in same project refused
	_, dupErr := f.store.CreateApp(ctx, CreateAppParams{
		ProjectID:   f.projectID,
		ServerID:    f.serverID,
		Slug:        "my-node-app",
		Name:        "Duplicate",
		RuntimeType: RuntimeNode,
	})
	if !errors.Is(dupErr, ErrSlugTaken) {
		t.Errorf("duplicate slug err = %v, want ErrSlugTaken", dupErr)
	}

	// 5. Same slug in different project is allowed
	otherApp, err := f.store.CreateApp(ctx, CreateAppParams{
		ProjectID:   otherProjectID,
		ServerID:    f.serverID,
		Slug:        "my-node-app",
		Name:        "Other Node App",
		RuntimeType: RuntimeNode,
	})
	if err != nil {
		t.Fatalf("same slug in different project: %v", err)
	}
	if otherApp.ProjectID != otherProjectID {
		t.Errorf("other app project mismatch")
	}

	// 6. Update editable fields
	newName := "My Node App v2"
	updated, err := f.store.UpdateApp(ctx, app.ID, UpdateAppParams{Name: &newName})
	if err != nil {
		t.Fatalf("UpdateApp: %v", err)
	}
	if updated.Name != newName {
		t.Errorf("updated name = %q, want %q", updated.Name, newName)
	}

	// 7. ListApps filters by project server-side
	list, total, err := f.store.ListApps(ctx, f.projectID, 50, 0)
	if err != nil {
		t.Fatalf("ListApps: %v", err)
	}
	if total != 1 || len(list) != 1 {
		t.Errorf("ListApps total=%d len=%d, want 1", total, len(list))
	}

	// 8. RequestDelete -> CancelDelete workflow
	pending, err := f.store.RequestDelete(ctx, app.ID, 0)
	if err != nil {
		t.Fatalf("RequestDelete: %v", err)
	}
	if pending.State != StatePendingDelete || pending.DeleteAfter == nil {
		t.Errorf("pending_delete: state=%q delete_after=%v", pending.State, pending.DeleteAfter)
	}
	cancelled, err := f.store.CancelDelete(ctx, app.ID)
	if err != nil {
		t.Fatalf("CancelDelete: %v", err)
	}
	if cancelled.State != StateActive || cancelled.DeleteAfter != nil {
		t.Errorf("after CancelDelete: state=%q delete_after=%v", cancelled.State, cancelled.DeleteAfter)
	}

	// 9. FinalizeDelete respects grace period
	if _, err := f.store.RequestDelete(ctx, app.ID, 24*time.Hour); err != nil {
		t.Fatalf("re-RequestDelete: %v", err)
	}
	// Too early
	_, prematureErr := f.store.FinalizeDelete(ctx, app.ID)
	if !errors.Is(prematureErr, ErrState) {
		t.Errorf("premature finalize err = %v, want ErrState", prematureErr)
	}
}

func TestAppRefusesNonActiveProject(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	var suspProjectID string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO projects (slug, name, state)
		VALUES ('susp-proj', 'Suspended', 'suspended')
		RETURNING id`).Scan(&suspProjectID); err != nil {
		t.Fatalf("insert suspended project: %v", err)
	}
	_, err := f.store.CreateApp(ctx, CreateAppParams{
		ProjectID:   suspProjectID,
		ServerID:    f.serverID,
		Slug:        "test-app",
		Name:        "Test App",
		RuntimeType: RuntimeNode,
	})
	if !errors.Is(err, ErrState) {
		t.Errorf("create in suspended project err = %v, want ErrState", err)
	}
}

func TestEnvVarSetAndList(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	app, err := f.store.CreateApp(ctx, CreateAppParams{
		ProjectID:   f.projectID,
		ServerID:    f.serverID,
		Slug:        "env-test-app",
		Name:        "Env Test App",
		RuntimeType: RuntimeNode,
	})
	if err != nil {
		t.Fatalf("CreateApp: %v", err)
	}

	// Set a literal env var
	ev, err := f.store.SetEnvVar(ctx, app.ID, "NODE_ENV", ValueLiteral, "production")
	if err != nil {
		t.Fatalf("SetEnvVar literal: %v", err)
	}
	if ev.ValueSource != ValueLiteral || ev.LiteralValue == nil || *ev.LiteralValue != "production" {
		t.Errorf("literal env var mismatch: %+v", ev)
	}
	if ev.SecretRef != nil {
		t.Error("secret_ref should be nil for literal")
	}

	// Set a secret ref
	secretURI := "secret://project/123/app/abc/env/DB_PASSWORD"
	evSecret, err := f.store.SetEnvVar(ctx, app.ID, "DB_PASSWORD", ValueSecretRef, secretURI)
	if err != nil {
		t.Fatalf("SetEnvVar secret: %v", err)
	}
	if evSecret.ValueSource != ValueSecretRef || evSecret.SecretRef == nil || *evSecret.SecretRef != secretURI {
		t.Errorf("secret env var mismatch: %+v", evSecret)
	}
	if evSecret.LiteralValue != nil {
		t.Error("literal_value should be nil for secret_ref")
	}

	// Invalid secret ref (not secret://) must be rejected
	_, badErr := f.store.SetEnvVar(ctx, app.ID, "BAD_SECRET", ValueSecretRef, "plaintext-password")
	if !errors.Is(badErr, ErrInvalid) {
		t.Errorf("bad secret ref err = %v, want ErrInvalid", badErr)
	}

	// Upsert updates an existing var
	updated, err := f.store.SetEnvVar(ctx, app.ID, "NODE_ENV", ValueLiteral, "staging")
	if err != nil {
		t.Fatalf("SetEnvVar upsert: %v", err)
	}
	if updated.LiteralValue == nil || *updated.LiteralValue != "staging" {
		t.Errorf("upserted value = %v, want staging", updated.LiteralValue)
	}

	// ListEnvVars returns both
	vars, err := f.store.ListEnvVars(ctx, app.ID)
	if err != nil {
		t.Fatalf("ListEnvVars: %v", err)
	}
	if len(vars) != 2 {
		t.Errorf("len(vars) = %d, want 2", len(vars))
	}

	// DeleteEnvVar removes it
	if err := f.store.DeleteEnvVar(ctx, app.ID, "NODE_ENV"); err != nil {
		t.Fatalf("DeleteEnvVar: %v", err)
	}
	vars2, _ := f.store.ListEnvVars(ctx, app.ID)
	if len(vars2) != 1 {
		t.Errorf("after delete len(vars) = %d, want 1", len(vars2))
	}
}

func TestDeploymentLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	app, err := f.store.CreateApp(ctx, CreateAppParams{
		ProjectID:   f.projectID,
		ServerID:    f.serverID,
		Slug:        "deploy-test-app",
		Name:        "Deploy Test App",
		RuntimeType: RuntimeNode,
	})
	if err != nil {
		t.Fatalf("CreateApp: %v", err)
	}

	sha := "abc1234"
	d, err := f.store.CreateDeployment(ctx, CreateDeploymentParams{
		AppID:     app.ID,
		ProjectID: f.projectID,
		ServerID:  f.serverID,
		Trigger:   TriggerManual,
		CommitSHA: &sha,
		GitRef:    "main",
	})
	if err != nil {
		t.Fatalf("CreateDeployment: %v", err)
	}
	if d.State != DeployQueued {
		t.Errorf("state = %q, want queued", d.State)
	}

	// Second concurrent deployment must fail with ErrConflictActive
	_, conflictErr := f.store.CreateDeployment(ctx, CreateDeploymentParams{
		AppID:     app.ID,
		ProjectID: f.projectID,
		ServerID:  f.serverID,
		Trigger:   TriggerManual,
		CommitSHA: &sha,
		GitRef:    "main",
	})
	if !errors.Is(conflictErr, ErrConflictActive) {
		t.Errorf("concurrent deployment err = %v, want ErrConflictActive", conflictErr)
	}

	// Idempotency key deduplication
	ikey := "webhook:abc1234"
	d2, err := f.store.CreateDeployment(ctx, CreateDeploymentParams{
		AppID:          app.ID,
		ProjectID:      f.projectID,
		ServerID:       f.serverID,
		Trigger:        TriggerWebhook,
		CommitSHA:      &sha,
		GitRef:         "main",
		IdempotencyKey: &ikey,
	})
	// Should conflict since one is still queued (active guard fires first)
	if err == nil {
		// If somehow created, check idempotency key is correct
		if d2.IdempotencyKey == nil || *d2.IdempotencyKey != ikey {
			t.Errorf("idempotency key mismatch")
		}
	} else if !errors.Is(err, ErrConflictActive) {
		t.Errorf("idempotency/conflict err = %v, want ErrConflictActive", err)
	}

	// Advance deployment to running, then succeeded
	dRunning, err := f.store.UpdateDeploymentState(ctx, d.ID, UpdateDeploymentStateParams{
		State: DeployRunning,
	})
	if err != nil {
		t.Fatalf("UpdateDeploymentState running: %v", err)
	}
	if dRunning.State != DeployRunning {
		t.Errorf("state = %q, want running", dRunning.State)
	}
	if dRunning.StartedAt == nil {
		t.Error("started_at should be set")
	}

	dDone, err := f.store.UpdateDeploymentState(ctx, d.ID, UpdateDeploymentStateParams{
		State: DeploySucceeded,
	})
	if err != nil {
		t.Fatalf("UpdateDeploymentState succeeded: %v", err)
	}
	if dDone.State != DeploySucceeded || dDone.FinishedAt == nil {
		t.Errorf("finished: state=%q finished_at=%v", dDone.State, dDone.FinishedAt)
	}

	// After terminal state, a new deployment can be created for the same app
	sha2 := "def5678"
	d3, err := f.store.CreateDeployment(ctx, CreateDeploymentParams{
		AppID:     app.ID,
		ProjectID: f.projectID,
		ServerID:  f.serverID,
		Trigger:   TriggerManual,
		CommitSHA: &sha2,
		GitRef:    "main",
	})
	if err != nil {
		t.Fatalf("second deployment after first succeeded: %v", err)
	}
	if d3.State != DeployQueued {
		t.Errorf("state = %q, want queued", d3.State)
	}
}

func TestReleaseCurrentTracking(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	app, err := f.store.CreateApp(ctx, CreateAppParams{
		ProjectID:   f.projectID,
		ServerID:    f.serverID,
		Slug:        "release-test-app",
		Name:        "Release Test App",
		RuntimeType: RuntimeNode,
	})
	if err != nil {
		t.Fatalf("CreateApp: %v", err)
	}

	sha := "abc1234"
	d, err := f.store.CreateDeployment(ctx, CreateDeploymentParams{
		AppID:     app.ID,
		ProjectID: f.projectID,
		ServerID:  f.serverID,
		Trigger:   TriggerManual,
		CommitSHA: &sha,
		GitRef:    "main",
	})
	if err != nil {
		t.Fatalf("CreateDeployment: %v", err)
	}

	r1, err := f.store.CreateRelease(ctx, app.ID, d.ID, "/var/www/jawaker/proj/app/releases/1-abc1234", "abc1234")
	if err != nil {
		t.Fatalf("CreateRelease: %v", err)
	}
	r1Current, err := f.store.MarkCurrentRelease(ctx, r1.ID, app.ID)
	if err != nil {
		t.Fatalf("MarkCurrentRelease r1: %v", err)
	}
	if !r1Current.IsCurrent {
		t.Error("r1 should be current")
	}

	// Create a second deployment and release; it becomes current
	_, _ = f.store.UpdateDeploymentState(ctx, d.ID, UpdateDeploymentStateParams{State: DeploySucceeded}) //nolint:errcheck
	sha2 := "def5678"
	d2, _ := f.store.CreateDeployment(ctx, CreateDeploymentParams{
		AppID:     app.ID,
		ProjectID: f.projectID,
		ServerID:  f.serverID,
		Trigger:   TriggerManual,
		CommitSHA: &sha2,
		GitRef:    "main",
	})
	r2, _ := f.store.CreateRelease(ctx, app.ID, d2.ID, "/var/www/jawaker/proj/app/releases/2-def5678", "def5678")
	r2Current, err := f.store.MarkCurrentRelease(ctx, r2.ID, app.ID)
	if err != nil {
		t.Fatalf("MarkCurrentRelease r2: %v", err)
	}
	if !r2Current.IsCurrent {
		t.Error("r2 should be current")
	}

	// List releases — 2 total
	releases, err := f.store.ListReleases(ctx, app.ID, 10)
	if err != nil {
		t.Fatalf("ListReleases: %v", err)
	}
	if len(releases) != 2 {
		t.Errorf("len(releases) = %d, want 2", len(releases))
	}
	// Exactly one is current
	currentCount := 0
	for _, r := range releases {
		if r.IsCurrent {
			currentCount++
			if r.ID != r2.ID {
				t.Errorf("current release should be r2 (%s), got %s", r2.ID, r.ID)
			}
		}
	}
	if currentCount != 1 {
		t.Errorf("current releases = %d, want exactly 1", currentCount)
	}
}

func TestWebhookTokenLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	app, err := f.store.CreateApp(ctx, CreateAppParams{
		ProjectID:   f.projectID,
		ServerID:    f.serverID,
		Slug:        "webhook-test-app",
		Name:        "Webhook Test App",
		RuntimeType: RuntimeNode,
	})
	if err != nil {
		t.Fatalf("CreateApp: %v", err)
	}

	// Store hash (SHA-256 hex of "supersecret"), not plaintext
	hash := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	wt, err := f.store.CreateWebhookToken(ctx, app.ID, hash)
	if err != nil {
		t.Fatalf("CreateWebhookToken: %v", err)
	}
	if wt.State != "active" {
		t.Errorf("state = %q, want active", wt.State)
	}

	// Lookup by hash
	found, err := f.store.GetWebhookTokenByHash(ctx, hash)
	if err != nil {
		t.Fatalf("GetWebhookTokenByHash: %v", err)
	}
	if found.AppID != app.ID {
		t.Errorf("AppID mismatch")
	}

	// Touch updates last_used_at
	if err := f.store.TouchWebhookToken(ctx, wt.ID); err != nil {
		t.Fatalf("TouchWebhookToken: %v", err)
	}

	// Revoke
	if err := f.store.RevokeWebhookToken(ctx, wt.ID); err != nil {
		t.Fatalf("RevokeWebhookToken: %v", err)
	}

	// Revoked token not found by hash (only active returned)
	_, notFoundErr := f.store.GetWebhookTokenByHash(ctx, hash)
	if !errors.Is(notFoundErr, ErrNotFound) {
		t.Errorf("revoked token err = %v, want ErrNotFound", notFoundErr)
	}
}

func intPtr(i int) *int { return &i }
