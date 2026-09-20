//go:build integration

package sites

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
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
	dsn, err := dbtest.IsolatedDatabase(base, "sites")
	if err != nil {
		fmt.Fprintf(os.Stderr, "sites: isolated test database: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("JAWAKER_TEST_DATABASE_URL", dsn); err != nil {
		fmt.Fprintf(os.Stderr, "sites: set test database: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = dbtest.DropDatabase(base, "sites")
	os.Exit(code)
}

type mutableClock struct {
	mu sync.Mutex
	at time.Time
}

func newClock(start time.Time) *mutableClock { return &mutableClock{at: start} }

func (c *mutableClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *mutableClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

type siteFixture struct {
	store     *Store
	clock     *mutableClock
	pool      *pgxpool.Pool
	projectID string
	serverID  string
}

func newFixture(t *testing.T) siteFixture {
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

	// Insert parent fixtures. Server must exist (FK RESTRICT), project must
	// exist in 'active' state (INSERT...WHERE EXISTS subquery).
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

	clk := newClock(time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC))
	store := NewStore(pool, clk.now)
	return siteFixture{
		store:     store,
		clock:     clk,
		pool:      pool,
		projectID: projectID,
		serverID:  serverID,
	}
}

func TestSiteCreationAndLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// 1. Create static site
	site, err := f.store.Create(ctx, CreateParams{
		ProjectID: f.projectID,
		ServerID:  f.serverID,
		Slug:      "landing",
		Name:      "Landing Page",
		Mode:      ModeStatic,
	})
	if err != nil {
		t.Fatalf("Create static site: %v", err)
	}
	if site.State != StateActive {
		t.Errorf("state = %q, want active", site.State)
	}
	if site.Mode != ModeStatic {
		t.Errorf("mode = %q, want static", site.Mode)
	}

	// 2. Fetch via Get and GetInProject
	got, err := f.store.Get(ctx, site.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Slug != "landing" {
		t.Errorf("got slug = %q, want landing", got.Slug)
	}
	gotInProj, err := f.store.GetInProject(ctx, f.projectID, site.ID)
	if err != nil {
		t.Fatalf("GetInProject: %v", err)
	}
	if gotInProj.ID != site.ID {
		t.Errorf("got id = %q, want %q", gotInProj.ID, site.ID)
	}

	// 3. Cross-project lookup returns ErrNotFound (crucial: 404 not 403)
	// Create another project
	var otherProjectID string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO projects (slug, name, state)
		VALUES ('second-project', 'Second Project', 'active')
		RETURNING id`).Scan(&otherProjectID); err != nil {
		t.Fatalf("insert second project: %v", err)
	}
	_, crossErr := f.store.GetInProject(ctx, otherProjectID, site.ID)
	if !errors.Is(crossErr, ErrNotFound) {
		t.Errorf("cross-project GetInProject err = %v, want ErrNotFound", crossErr)
	}

	// 4. Duplicate slug in SAME project refused (409 Conflict)
	_, dupErr := f.store.Create(ctx, CreateParams{
		ProjectID: f.projectID,
		ServerID:  f.serverID,
		Slug:      "landing",
		Name:      "Duplicate Landing",
		Mode:      ModeStatic,
	})
	if !errors.Is(dupErr, ErrSlugTaken) {
		t.Errorf("duplicate slug err = %v, want ErrSlugTaken", dupErr)
	}

	// 5. Same slug in DIFFERENT project accepted (slug unique per project)
	otherSite, err := f.store.Create(ctx, CreateParams{
		ProjectID: otherProjectID,
		ServerID:  f.serverID,
		Slug:      "landing",
		Name:      "Other Landing",
		Mode:      ModeStatic,
	})
	if err != nil {
		t.Fatalf("create same slug in different project failed: %v", err)
	}
	if otherSite.ProjectID != otherProjectID {
		t.Errorf("other site project = %q, want %q", otherSite.ProjectID, otherProjectID)
	}

	// 6. Update editable fields
	newName := "New Landing Title"
	newDocRoot := "/var/www/jawaker/site-1"
	updated, err := f.store.Update(ctx, site.ID, UpdateParams{
		Name:    &newName,
		DocRoot: &newDocRoot,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.Name != newName || updated.DocRoot != newDocRoot {
		t.Errorf("updated fields mismatch: name=%q docRoot=%q", updated.Name, updated.DocRoot)
	}

	// 7. Suspend and Resume
	suspended, err := f.store.Suspend(ctx, site.ID)
	if err != nil {
		t.Fatalf("Suspend: %v", err)
	}
	if suspended.State != StateSuspended {
		t.Errorf("state = %q, want suspended", suspended.State)
	}
	resumed, err := f.store.Resume(ctx, site.ID)
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if resumed.State != StateActive {
		t.Errorf("state = %q, want active", resumed.State)
	}

	// 8. Safe-delete workflow (RequestDelete -> CancelDelete)
	pending, err := f.store.RequestDelete(ctx, site.ID, 0) // 0 = DefaultDeleteGrace (7d)
	if err != nil {
		t.Fatalf("RequestDelete: %v", err)
	}
	if pending.State != StatePendingDelete {
		t.Errorf("state = %q, want pending_delete", pending.State)
	}
	if pending.DeleteAfter == nil {
		t.Fatal("delete_after is nil on pending_delete site")
	}
	cancelled, err := f.store.CancelDelete(ctx, site.ID)
	if err != nil {
		t.Fatalf("CancelDelete: %v", err)
	}
	if cancelled.State != StateActive {
		t.Errorf("state = %q, want active", cancelled.State)
	}
	if cancelled.DeleteAfter != nil {
		t.Error("delete_after is still set after CancelDelete")
	}

	// 9. FinalizeDelete enforces the grace period
	_, err = f.store.RequestDelete(ctx, site.ID, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("re-RequestDelete: %v", err)
	}
	// Try to finalize immediately — must fail (grace not elapsed)
	_, prematureErr := f.store.FinalizeDelete(ctx, site.ID)
	if !errors.Is(prematureErr, ErrState) {
		t.Errorf("premature FinalizeDelete err = %v, want ErrState", prematureErr)
	}

	// Advance clock past grace period, now FinalizeDelete must succeed
	f.clock.advance(7*24*time.Hour + time.Minute)
	finalized, err := f.store.FinalizeDelete(ctx, site.ID)
	if err != nil {
		t.Fatalf("FinalizeDelete after grace: %v", err)
	}
	if finalized.State != StateDeleted {
		t.Errorf("state = %q, want deleted", finalized.State)
	}
	if finalized.DeletedAt == nil {
		t.Error("deleted_at is nil on finalized site")
	}
	if finalized.DeleteAfter != nil {
		t.Error("delete_after is still populated on finalized site; schema check forbids this")
	}

	// Tombstoned site is no longer returned by Get
	_, deadErr := f.store.Get(ctx, site.ID)
	if !errors.Is(deadErr, ErrNotFound) {
		t.Errorf("Get on tombstone err = %v, want ErrNotFound", deadErr)
	}
}

func TestSiteCreationRefusesNonActiveProject(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// Suspended project
	var suspProjectID string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO projects (slug, name, state)
		VALUES ('suspended-tenant', 'Suspended Tenant', 'suspended')
		RETURNING id`).Scan(&suspProjectID); err != nil {
		t.Fatalf("insert suspended project: %v", err)
	}

	_, err := f.store.Create(ctx, CreateParams{
		ProjectID: suspProjectID,
		ServerID:  f.serverID,
		Slug:      "test-site",
		Name:      "Test Site",
		Mode:      ModeStatic,
	})
	if !errors.Is(err, ErrState) {
		t.Errorf("Create in suspended project err = %v, want ErrState", err)
	}
}

func TestSiteCreationEnforcesModeFieldRules(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// Reverse proxy WITHOUT upstream must fail
	_, err := f.store.Create(ctx, CreateParams{
		ProjectID: f.projectID,
		ServerID:  f.serverID,
		Slug:      "bad-proxy",
		Name:      "Bad Proxy",
		Mode:      ModeReverseProxy,
		Upstream:  "", // missing!
	})
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("reverse_proxy without upstream err = %v, want ErrInvalid", err)
	}

	// Static site WITH upstream must fail
	_, err = f.store.Create(ctx, CreateParams{
		ProjectID: f.projectID,
		ServerID:  f.serverID,
		Slug:      "bad-static",
		Name:      "Bad Static",
		Mode:      ModeStatic,
		Upstream:  "http://backend", // forbidden on static!
	})
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("static with upstream err = %v, want ErrInvalid", err)
	}

	// Valid reverse proxy
	proxySite, err := f.store.Create(ctx, CreateParams{
		ProjectID: f.projectID,
		ServerID:  f.serverID,
		Slug:      "good-proxy",
		Name:      "Good Proxy",
		Mode:      ModeReverseProxy,
		Upstream:  "http://127.0.0.1:3000",
	})
	if err != nil {
		t.Fatalf("valid reverse_proxy creation failed: %v", err)
	}
	if proxySite.Upstream != "http://127.0.0.1:3000" {
		t.Errorf("upstream = %q, want http://127.0.0.1:3000", proxySite.Upstream)
	}
}

func TestSiteListFiltersByProjectServerSide(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// Insert second project
	var projB string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO projects (slug, name, state)
		VALUES ('project-b', 'Project B', 'active')
		RETURNING id`).Scan(&projB); err != nil {
		t.Fatalf("insert project-b: %v", err)
	}

	// Create 3 sites in project A, 2 in project B
	for _, slug := range []string{"site-a1", "site-a2", "site-a3"} {
		if _, err := f.store.Create(ctx, CreateParams{
			ProjectID: f.projectID, ServerID: f.serverID, Slug: slug, Name: slug, Mode: ModeStatic,
		}); err != nil {
			t.Fatalf("create site in A: %v", err)
		}
	}
	for _, slug := range []string{"site-b1", "site-b2"} {
		if _, err := f.store.Create(ctx, CreateParams{
			ProjectID: projB, ServerID: f.serverID, Slug: slug, Name: slug, Mode: ModeStatic,
		}); err != nil {
			t.Fatalf("create site in B: %v", err)
		}
	}

	// Listing project A sees EXACTLY 3 sites
	listA, totalA, err := f.store.List(ctx, f.projectID, 50, 0, "")
	if err != nil {
		t.Fatalf("List A: %v", err)
	}
	if totalA != 3 || len(listA) != 3 {
		t.Errorf("List A got total=%d len=%d, want 3", totalA, len(listA))
	}
	for _, s := range listA {
		if s.ProjectID != f.projectID {
			t.Errorf("List A leaked site %s from project %s", s.ID, s.ProjectID)
		}
	}

	// Listing project B sees EXACTLY 2 sites
	listB, totalB, err := f.store.List(ctx, projB, 50, 0, "")
	if err != nil {
		t.Fatalf("List B: %v", err)
	}
	if totalB != 2 || len(listB) != 2 {
		t.Errorf("List B got total=%d len=%d, want 2", totalB, len(listB))
	}
}
