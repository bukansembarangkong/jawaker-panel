//go:build integration

package projects

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

// TestMain gives this package its own database so parallel packages cannot reset
// the schema underneath it.
func TestMain(m *testing.M) {
	base := dbtest.FixtureURL()
	if base == "" {
		os.Exit(m.Run())
	}
	dsn, err := dbtest.IsolatedDatabase(base, "projects")
	if err != nil {
		fmt.Fprintf(os.Stderr, "projects: isolated test database: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("JAWAKER_TEST_DATABASE_URL", dsn); err != nil {
		fmt.Fprintf(os.Stderr, "projects: set test database: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = dbtest.DropDatabase(base, "projects")
	os.Exit(code)
}

// mutableClock drives the grace period deterministically rather than sleeping.
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

// newStore builds a store over a freshly migrated database with a controllable
// clock. Every test gets a clean schema so cases cannot leak state into each
// other.
func newStore(t *testing.T) (*Store, *mutableClock) {
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

	clock := newClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	return NewStore(pool, clock.now), clock
}

func mustCreate(t *testing.T, s *Store, slug string) Project {
	t.Helper()
	p, err := s.Create(context.Background(), CreateParams{Slug: slug, Name: "Project " + slug})
	if err != nil {
		t.Fatalf("create %s: %v", slug, err)
	}
	return p
}

// --- creation and slug validation --------------------------------------------

func TestCreateStartsActiveAndLive(t *testing.T) {
	s, _ := newStore(t)
	p := mustCreate(t, s, "acme")

	if p.State != StateActive {
		t.Errorf("state = %q, want %q", p.State, StateActive)
	}
	if !p.Live() {
		t.Error("a freshly created project should be live")
	}
	if !p.Usable() {
		t.Error("an active project should be usable")
	}
	if p.DeleteAfter != nil {
		t.Errorf("delete_after = %v, want nil for an active project", p.DeleteAfter)
	}
}

// The slug is lowercased and trimmed so an operator typing "Acme" and one typing
// "acme" get the same project rather than two that look alike.
func TestCreateNormalizesSlug(t *testing.T) {
	s, _ := newStore(t)
	p := mustCreate(t, s, "  AcMe  ")
	if p.Slug != "acme" {
		t.Errorf("slug = %q, want %q", p.Slug, "acme")
	}
}

// A bad slug is refused by the Go validator with a message naming the value, not
// by a raw PostgreSQL error naming the constraint.
func TestCreateRejectsBadSlug(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	for _, bad := range []string{
		"../../etc/passwd",
		"acme/../other",
		"-acme",
		"acme-",
		"acme_corp",
		"acme corp",
		"ab", // too short
		"",   // empty
	} {
		_, err := s.Create(ctx, CreateParams{Slug: bad, Name: "x"})
		if err == nil {
			t.Errorf("create slug %q: accepted, want rejection", bad)
			continue
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("create slug %q: err = %v, want ErrInvalid", bad, err)
		}
	}
}

// The Go validator and the schema constraint must agree. This is the test that
// catches them drifting: if validateSlug ever accepts something the CHECK
// rejects, Create wraps the schema error instead of returning ErrInvalid, and
// this test fails rather than shipping a disagreement.
func TestValidatorAndSchemaAgree(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	// A slug the validator accepts must also be storable. If the schema refused
	// it, Create would return a wrapped schema error, not ErrSlugTaken.
	for _, good := range []string{"acme", "acme-corp", "a1b", "9lives"} {
		if err := validateSlug(good); err != nil {
			t.Fatalf("validateSlug(%q) = %v, want nil", good, err)
		}
		if _, err := s.Create(ctx, CreateParams{Slug: good, Name: good}); err != nil {
			t.Errorf("create %q: %v (validator accepted it, schema refused)", good, err)
		}
	}
}

// A duplicate live slug is refused; a tombstoned project's slug is reusable.
func TestSlugTakenAndReusableAfterDelete(t *testing.T) {
	s, clock := newStore(t)
	ctx := context.Background()

	p := mustCreate(t, s, "acme")

	if _, err := s.Create(ctx, CreateParams{Slug: "acme", Name: "Other"}); !errors.Is(err, ErrSlugTaken) {
		t.Errorf("duplicate slug: err = %v, want ErrSlugTaken", err)
	}

	// Drive it all the way to deleted so the slug frees up.
	if _, err := s.RequestDelete(ctx, p.ID, time.Hour); err != nil {
		t.Fatalf("request delete: %v", err)
	}
	clock.advance(2 * time.Hour)
	if _, err := s.FinalizeDelete(ctx, p.ID); err != nil {
		t.Fatalf("finalize delete: %v", err)
	}

	if _, err := s.Create(ctx, CreateParams{Slug: "acme", Name: "Reused"}); err != nil {
		t.Errorf("recreate after tombstone: %v, want success", err)
	}
}

// --- reads and tombstones -----------------------------------------------------

// Get excludes tombstoned projects: answering with a deleted row would make the
// tombstone decorative.
func TestGetExcludesTombstoned(t *testing.T) {
	s, clock := newStore(t)
	ctx := context.Background()

	p := mustCreate(t, s, "acme")
	if _, err := s.Get(ctx, p.ID); err != nil {
		t.Fatalf("get live project: %v", err)
	}

	if _, err := s.RequestDelete(ctx, p.ID, time.Hour); err != nil {
		t.Fatalf("request delete: %v", err)
	}
	clock.advance(2 * time.Hour)
	if _, err := s.FinalizeDelete(ctx, p.ID); err != nil {
		t.Fatalf("finalize delete: %v", err)
	}

	if _, err := s.Get(ctx, p.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("get tombstoned: err = %v, want ErrNotFound", err)
	}
}

// A suspended project is still live (it exists and can be resumed) but not
// usable (workloads must not start in it).
func TestSuspendedIsLiveButNotUsable(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	p := mustCreate(t, s, "acme")
	suspended, err := s.Suspend(ctx, p.ID)
	if err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if suspended.State != StateSuspended {
		t.Errorf("state = %q, want %q", suspended.State, StateSuspended)
	}
	if !suspended.Live() {
		t.Error("a suspended project should still be live")
	}
	if suspended.Usable() {
		t.Error("a suspended project should not be usable")
	}
}

// --- the state machine --------------------------------------------------------

func TestStateTransitionsAreAllowed(t *testing.T) {
	s, clock := newStore(t)
	ctx := context.Background()

	p := mustCreate(t, s, "acme")

	// active -> suspended -> active
	if _, err := s.Suspend(ctx, p.ID); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if _, err := s.Resume(ctx, p.ID); err != nil {
		t.Fatalf("resume: %v", err)
	}

	// active -> pending_delete -> active (cancel)
	if _, err := s.RequestDelete(ctx, p.ID, time.Hour); err != nil {
		t.Fatalf("request delete: %v", err)
	}
	if _, err := s.CancelDelete(ctx, p.ID); err != nil {
		t.Fatalf("cancel delete: %v", err)
	}
	got, err := s.Get(ctx, p.ID)
	if err != nil {
		t.Fatalf("get after cancel: %v", err)
	}
	if got.State != StateActive {
		t.Errorf("state after cancel = %q, want %q", got.State, StateActive)
	}
	if got.DeleteAfter != nil {
		t.Errorf("delete_after after cancel = %v, want nil (a sweeper must not still be aiming at it)", got.DeleteAfter)
	}

	// suspended -> pending_delete is allowed (an operator pauses, then deletes)
	if _, err := s.Suspend(ctx, p.ID); err != nil {
		t.Fatalf("suspend again: %v", err)
	}
	if _, err := s.RequestDelete(ctx, p.ID, time.Hour); err != nil {
		t.Fatalf("request delete from suspended: %v", err)
	}
	clock.advance(2 * time.Hour)
	if _, err := s.FinalizeDelete(ctx, p.ID); err != nil {
		t.Fatalf("finalize delete: %v", err)
	}
}

// A transition that is not permitted is refused rather than performed. Resume on
// an active project, Suspend on a deleted one, etc.
func TestIllegalTransitionsAreRefused(t *testing.T) {
	s, clock := newStore(t)
	ctx := context.Background()

	p := mustCreate(t, s, "acme")

	// Cannot resume an active project.
	if _, err := s.Resume(ctx, p.ID); !errors.Is(err, ErrState) {
		t.Errorf("resume active: err = %v, want ErrState", err)
	}
	// Cannot cancel-delete an active project.
	if _, err := s.CancelDelete(ctx, p.ID); !errors.Is(err, ErrState) {
		t.Errorf("cancel-delete active: err = %v, want ErrState", err)
	}
	// Cannot finalize an active project (nothing to finalize).
	if _, err := s.FinalizeDelete(ctx, p.ID); !errors.Is(err, ErrState) {
		t.Errorf("finalize active: err = %v, want ErrState", err)
	}

	// Once deleted, no transition out.
	if _, err := s.RequestDelete(ctx, p.ID, time.Hour); err != nil {
		t.Fatalf("request delete: %v", err)
	}
	clock.advance(2 * time.Hour)
	if _, err := s.FinalizeDelete(ctx, p.ID); err != nil {
		t.Fatalf("finalize delete: %v", err)
	}
	if _, err := s.Resume(ctx, p.ID); !errors.Is(err, ErrState) {
		t.Errorf("resume deleted: err = %v, want ErrState", err)
	}
}

// THE GRACE PERIOD IS MEASURED, NOT ASSUMED. FinalizeDelete must refuse until
// the deadline has passed, measured against the store clock — so a caller cannot
// finalize early, and cannot finalize by passing a stale project it read before
// the request.
func TestFinalizeDeleteRespectsGracePeriod(t *testing.T) {
	s, clock := newStore(t)
	ctx := context.Background()

	p := mustCreate(t, s, "acme")
	if _, err := s.RequestDelete(ctx, p.ID, 24*time.Hour); err != nil {
		t.Fatalf("request delete: %v", err)
	}

	// Before the deadline: refused.
	clock.advance(23 * time.Hour)
	if _, err := s.FinalizeDelete(ctx, p.ID); !errors.Is(err, ErrState) {
		t.Errorf("finalize before grace elapsed: err = %v, want ErrState", err)
	}

	// After: succeeds.
	clock.advance(2 * time.Hour)
	final, err := s.FinalizeDelete(ctx, p.ID)
	if err != nil {
		t.Fatalf("finalize after grace: %v", err)
	}
	if final.State != StateDeleted {
		t.Errorf("state = %q, want %q", final.State, StateDeleted)
	}
	if final.DeletedAt == nil {
		t.Error("deleted_at must be set on a finalized project")
	}
}

// The sweeper reads deadlines, not a caller-maintained list. A project whose
// grace has elapsed appears; one whose has not does not.
func TestListDueForDeleteUsesDeadlines(t *testing.T) {
	s, clock := newStore(t)
	ctx := context.Background()

	early := mustCreate(t, s, "early")
	late := mustCreate(t, s, "late")

	if _, err := s.RequestDelete(ctx, early.ID, time.Hour); err != nil {
		t.Fatalf("request delete early: %v", err)
	}
	if _, err := s.RequestDelete(ctx, late.ID, 48*time.Hour); err != nil {
		t.Fatalf("request delete late: %v", err)
	}

	clock.advance(2 * time.Hour)
	due, err := s.ListDueForDelete(ctx, 100)
	if err != nil {
		t.Fatalf("list due: %v", err)
	}
	if len(due) != 1 || due[0].ID != early.ID {
		t.Errorf("due = %v, want only the early project", due)
	}

	clock.advance(48 * time.Hour)
	due, err = s.ListDueForDelete(ctx, 100)
	if err != nil {
		t.Fatalf("list due after: %v", err)
	}
	if len(due) != 2 {
		t.Errorf("due = %d, want 2 after both grace periods elapsed", len(due))
	}
}

// --- concurrency --------------------------------------------------------------

// Two concurrent RequestDelete calls on the same project must not both succeed in
// a way that corrupts state. The transition is a single conditional UPDATE, so
// the database arbitrates: one wins, the other either no-ops into the same state
// or is refused. What must NOT happen is a double-write leaving delete_after set
// twice or the row in an inconsistent state.
func TestConcurrentTransitionsAreArbitrated(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	p := mustCreate(t, s, "acme")

	const goroutines = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, err := s.Suspend(ctx, p.ID)
			mu.Lock()
			if err == nil {
				successes++
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	// Exactly one may move active -> suspended; the rest find it already
	// suspended and are refused. If more than one "succeeded", the transition is
	// not actually preconditioned in the database.
	if successes != 1 {
		t.Errorf("concurrent suspend: %d succeeded, want exactly 1", successes)
	}

	got, err := s.Get(ctx, p.ID)
	if err != nil {
		t.Fatalf("get after concurrent suspend: %v", err)
	}
	if got.State != StateSuspended {
		t.Errorf("state = %q, want %q", got.State, StateSuspended)
	}
}

// --- listing ------------------------------------------------------------------

func TestListFiltersAndPaginates(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	for _, slug := range []string{"aaa", "bbb", "ccc"} {
		mustCreate(t, s, slug)
	}
	suspended := mustCreate(t, s, "ddd")
	if _, err := s.Suspend(ctx, suspended.ID); err != nil {
		t.Fatalf("suspend: %v", err)
	}

	// All live projects.
	all, total, err := s.List(ctx, 100, 0, "")
	if err != nil {
		t.Fatalf("list all: %v", err)
	}
	if total != 4 || len(all) != 4 {
		t.Errorf("all = %d (total %d), want 4", len(all), total)
	}

	// Only active.
	active, total, err := s.List(ctx, 100, 0, StateActive)
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	if total != 3 || len(active) != 3 {
		t.Errorf("active = %d (total %d), want 3", len(active), total)
	}

	// Only suspended.
	susp, _, err := s.List(ctx, 100, 0, StateSuspended)
	if err != nil {
		t.Fatalf("list suspended: %v", err)
	}
	if len(susp) != 1 || susp[0].ID != suspended.ID {
		t.Errorf("suspended = %v, want the one suspended project", susp)
	}

	// Pagination: the count is of the whole filter, the page is a slice.
	page, total, err := s.List(ctx, 2, 0, "")
	if err != nil {
		t.Fatalf("list page: %v", err)
	}
	if len(page) != 2 {
		t.Errorf("page len = %d, want 2", len(page))
	}
	if total != 4 {
		t.Errorf("page total = %d, want 4 (count is of the filter, not the page)", total)
	}
}

func TestListRejectsBadArgs(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	if _, _, err := s.List(ctx, 0, 0, ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("limit 0: err = %v, want ErrInvalid", err)
	}
	if _, _, err := s.List(ctx, maxListLimit+1, 0, ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("limit too big: err = %v, want ErrInvalid", err)
	}
	if _, _, err := s.List(ctx, 10, -1, ""); !errors.Is(err, ErrInvalid) {
		t.Errorf("negative offset: err = %v, want ErrInvalid", err)
	}
	if _, _, err := s.List(ctx, 10, 0, "bogus"); !errors.Is(err, ErrInvalid) {
		t.Errorf("unknown state: err = %v, want ErrInvalid", err)
	}
}

// --- update -------------------------------------------------------------------

func TestUpdateChangesOnlyProvidedFields(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	p := mustCreate(t, s, "acme")
	if _, err := s.Update(ctx, p.ID, UpdateParams{Description: strPtr("initial")}); err != nil {
		t.Fatalf("set description: %v", err)
	}

	// Update the name only; the description must survive.
	updated, err := s.Update(ctx, p.ID, UpdateParams{Name: strPtr("Renamed")})
	if err != nil {
		t.Fatalf("update name: %v", err)
	}
	if updated.Name != "Renamed" {
		t.Errorf("name = %q, want %q", updated.Name, "Renamed")
	}
	if updated.Description != "initial" {
		t.Errorf("description = %q, want it preserved as %q", updated.Description, "initial")
	}

	// An empty name is refused.
	if _, err := s.Update(ctx, p.ID, UpdateParams{Name: strPtr("   ")}); !errors.Is(err, ErrInvalid) {
		t.Errorf("empty name: err = %v, want ErrInvalid", err)
	}
	// Nothing to update is refused.
	if _, err := s.Update(ctx, p.ID, UpdateParams{}); !errors.Is(err, ErrInvalid) {
		t.Errorf("no fields: err = %v, want ErrInvalid", err)
	}
}

func strPtr(s string) *string { return &s }
