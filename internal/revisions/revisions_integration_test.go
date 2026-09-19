//go:build integration

// Integration tests for the immutable revision model against real PostgreSQL.
//
// The guarantees here are database facts — an immutability trigger, a partial
// unique index, a base-revision precondition — so they are only meaningful when
// exercised against the real schema the controller runs.

package revisions

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"

	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/db/migrate"
	"github.com/bukansembarangkong/jawaker-panel/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("JAWAKER_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("JAWAKER_TEST_DATABASE_URL not set; skipping revisions integration tests")
	}
	return url
}

func setup(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, testDatabaseURL(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	m, err := migrate.New(migrations.FS, discardLogger())
	if err != nil {
		t.Fatalf("migrator: %v", err)
	}
	if _, err := m.Up(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return pool, ctx
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

const (
	testResourceType = "site"
	testResourceID   = "site-0001"
	testActorID      = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
)

func mustCreate(t *testing.T, ctx context.Context, pool *pgxpool.Pool, p Proposed) Revision {
	t.Helper()
	r, err := Create(ctx, pool, p)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return r
}

// A revision is immutable: the schema forbids in-place edits of its substance,
// and the package must surface that as an error rather than a silent success.
func TestRevisionSubstanceIsImmutable(t *testing.T) {
	pool, ctx := setup(t)

	r := mustCreate(t, ctx, pool, Proposed{
		ResourceType: testResourceType, ResourceID: testResourceID,
		ActorType: audit.ActorUser, ActorID: testActorID,
		Candidate: Candidate{"domain": "example.test"},
	})

	if _, err := pool.Exec(ctx,
		`UPDATE revisions SET candidate = '{"domain":"tampered"}'::jsonb WHERE id = $1`, r.ID); err == nil {
		t.Fatal("an in-place edit of candidate succeeded; the immutability trigger did not fire")
	}
	if _, err := pool.Exec(ctx,
		`UPDATE revisions SET candidate_hash = 'deadbeef' WHERE id = $1`, r.ID); err == nil {
		t.Fatal("an in-place edit of candidate_hash succeeded")
	}

	// The outcome columns still move, so lifecycle recording is not blocked.
	if _, err := pool.Exec(ctx,
		`UPDATE revisions SET state = 'validated' WHERE id = $1`, r.ID); err != nil {
		t.Fatalf("updating a state column failed: %v", err)
	}
}

// Optimistic concurrency (API.md s12): a stale base is rejected, not merged.
func TestApplyRejectsStaleBase(t *testing.T) {
	pool, ctx := setup(t)

	first := mustCreate(t, ctx, pool, Proposed{
		ResourceType: testResourceType, ResourceID: testResourceID,
		ActorType: audit.ActorUser, ActorID: testActorID,
		Candidate: Candidate{"domain": "example.test"},
	})
	if _, err := MarkValidated(ctx, pool, first.ID, ValidationResult{OK: true}, testActorID, ""); err != nil {
		t.Fatalf("validate first: %v", err)
	}
	applied1, err := Apply(ctx, pool, first.ID, ApplyResult{}, testActorID, "")
	if err != nil {
		t.Fatalf("apply first: %v", err)
	}
	if !applied1.Applied() || applied1.AppliedAt == nil {
		t.Fatalf("first revision not applied: %+v", applied1)
	}

	// A second change correctly based on the first applies cleanly and
	// supersedes it.
	second := mustCreate(t, ctx, pool, Proposed{
		ResourceType: testResourceType, ResourceID: testResourceID,
		ActorType: audit.ActorUser, ActorID: testActorID,
		BaseRevisionID: first.ID,
		Candidate:      Candidate{"domain": "example.test", "php": "8.4"},
	})
	if _, err := MarkValidated(ctx, pool, second.ID, ValidationResult{OK: true}, testActorID, ""); err != nil {
		t.Fatalf("validate second: %v", err)
	}
	if _, err := Apply(ctx, pool, second.ID, ApplyResult{}, testActorID, ""); err != nil {
		t.Fatalf("apply second: %v", err)
	}

	// Exactly one applied revision may exist per resource.
	current, err := CurrentApplied(ctx, pool, testResourceType, testResourceID)
	if err != nil {
		t.Fatalf("CurrentApplied: %v", err)
	}
	if current.ID != second.ID {
		t.Fatalf("applied revision = %s, want the second %s", current.ID, second.ID)
	}
	firstAfter, err := Get(ctx, pool, first.ID)
	if err != nil {
		t.Fatalf("Get first: %v", err)
	}
	if firstAfter.State != StateSuperseded {
		t.Errorf("superseded revision state = %q, want superseded", firstAfter.State)
	}

	// Now a THIRD change that was based on the FIRST (now superseded) — a stale
	// base. Create flags it immediately, so the draft is taken from the error
	// path; the change is still recorded, which is what makes the concurrent
	// edit visible.
	stale, createErr := Create(ctx, pool, Proposed{
		ResourceType: testResourceType, ResourceID: testResourceID,
		ActorType: audit.ActorUser, ActorID: testActorID,
		BaseRevisionID: first.ID, // stale: second is applied
		Candidate:      Candidate{"domain": "stale.test"},
	})
	if !errors.Is(createErr, ErrStaleBase) {
		t.Fatalf("Create with a superseded base = %v, want ErrStaleBase", createErr)
	}
	if stale.ID == "" {
		t.Fatal("the stale draft was not persisted")
	}

	if _, err := MarkValidated(ctx, pool, stale.ID, ValidationResult{OK: true}, testActorID, ""); err != nil {
		t.Fatalf("validate stale: %v", err)
	}
	// The apply gate must reject it too, independently of Create's early check:
	// a revision can become stale between creation and apply.
	if _, err := Apply(ctx, pool, stale.ID, ApplyResult{}, testActorID, ""); !errors.Is(err, ErrStaleBase) {
		t.Fatalf("apply with stale base = %v, want ErrStaleBase", err)
	}

	// The applied revision is unchanged by the rejected attempt.
	afterStale, err := CurrentApplied(ctx, pool, testResourceType, testResourceID)
	if err != nil {
		t.Fatalf("CurrentApplied after stale: %v", err)
	}
	if afterStale.ID != second.ID {
		t.Fatalf("applied revision changed to %s after a rejected apply", afterStale.ID)
	}
}

// Create distinguishes two kinds of stale base, and only one of them can be
// recorded: a superseded-but-existing base still yields a draft (evidence of
// what the caller tried), while a nonexistent base cannot, because
// base_revision_id is a foreign key.
func TestCreateStaleBaseCases(t *testing.T) {
	pool, ctx := setup(t)

	first := mustCreate(t, ctx, pool, Proposed{
		ResourceType: testResourceType, ResourceID: testResourceID,
		ActorType: audit.ActorUser, ActorID: testActorID,
		Candidate: Candidate{"domain": "example.test"},
	})
	if _, err := MarkValidated(ctx, pool, first.ID, ValidationResult{OK: true}, testActorID, ""); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, err := Apply(ctx, pool, first.ID, ApplyResult{}, testActorID, ""); err != nil {
		t.Fatalf("apply: %v", err)
	}
	second := mustCreate(t, ctx, pool, Proposed{
		ResourceType: testResourceType, ResourceID: testResourceID,
		ActorType: audit.ActorUser, ActorID: testActorID,
		BaseRevisionID: first.ID,
		Candidate:      Candidate{"domain": "example.test", "php": "8.4"},
	})
	if _, err := MarkValidated(ctx, pool, second.ID, ValidationResult{OK: true}, testActorID, ""); err != nil {
		t.Fatalf("validate second: %v", err)
	}
	if _, err := Apply(ctx, pool, second.ID, ApplyResult{}, testActorID, ""); err != nil {
		t.Fatalf("apply second: %v", err)
	}

	// Case 1: the base EXISTS but is superseded. The draft is recorded with the
	// stale error, because the row is the evidence of the concurrent edit.
	draft, err := Create(ctx, pool, Proposed{
		ResourceType: testResourceType, ResourceID: testResourceID,
		ActorType: audit.ActorUser, ActorID: testActorID,
		BaseRevisionID: first.ID, // exists, but superseded
		Candidate:      Candidate{"domain": "new.test"},
	})
	if !errors.Is(err, ErrStaleBase) {
		t.Fatalf("Create with a superseded base = %v, want ErrStaleBase", err)
	}
	if draft.ID == "" {
		t.Fatal("the stale-base draft was not persisted; its evidence is lost")
	}
	if draft.State != StateDraft {
		t.Errorf("draft state = %q, want draft", draft.State)
	}
	// And it is readable back — the row really is committed.
	if _, err := Get(ctx, pool, draft.ID); err != nil {
		t.Fatalf("Get persisted draft: %v", err)
	}

	// Case 2: the base does NOT exist. The foreign key forbids the insert, so
	// there is no row to keep, and the caller gets a stale-base error rather
	// than a raw constraint violation.
	missing, err := Create(ctx, pool, Proposed{
		ResourceType: testResourceType, ResourceID: testResourceID,
		ActorType: audit.ActorUser, ActorID: testActorID,
		BaseRevisionID: "deadbeef-dead-dead-dead-deaddeaddead",
		Candidate:      Candidate{"domain": "orphan.test"},
	})
	if !errors.Is(err, ErrStaleBase) {
		t.Fatalf("Create with a nonexistent base = %v, want ErrStaleBase", err)
	}
	if missing.ID != "" {
		t.Errorf("a nonexistent base produced revision %s; the foreign key was not enforced", missing.ID)
	}

	var rows int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM revisions
		WHERE resource_type = $1 AND resource_id = $2 AND candidate->>'domain' = 'orphan.test'`,
		testResourceType, testResourceID).Scan(&rows); err != nil {
		t.Fatalf("count orphan drafts: %v", err)
	}
	if rows != 0 {
		t.Errorf("orphan-base drafts in the table = %d, want 0", rows)
	}
}

// Two concurrent applies for the same resource must not both win. The partial
// unique index (migration 0010) makes exactly one commit; the other sees a
// stale base.
func TestConcurrentApplyYieldsOneWinner(t *testing.T) {
	pool, ctx := setup(t)

	first := mustCreate(t, ctx, pool, Proposed{
		ResourceType: testResourceType, ResourceID: testResourceID,
		ActorType: audit.ActorUser, ActorID: testActorID,
		Candidate: Candidate{"domain": "example.test"},
	})
	if _, err := MarkValidated(ctx, pool, first.ID, ValidationResult{OK: true}, testActorID, ""); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, err := Apply(ctx, pool, first.ID, ApplyResult{}, testActorID, ""); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// Two changes both based on the same applied revision race to replace it.
	const contenders = 6
	ids := make([]string, contenders)
	for i := 0; i < contenders; i++ {
		c := mustCreate(t, ctx, pool, Proposed{
			ResourceType: testResourceType, ResourceID: testResourceID,
			ActorType: audit.ActorUser, ActorID: testActorID,
			BaseRevisionID: first.ID,
			Candidate:      Candidate{"domain": fmt.Sprintf("race-%d.test", i)},
		})
		if _, err := MarkValidated(ctx, pool, c.ID, ValidationResult{OK: true}, testActorID, ""); err != nil {
			t.Fatalf("validate contender %d: %v", i, err)
		}
		ids[i] = c.ID
	}

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		won   int
		stale int
		other []error
	)
	start := make(chan struct{})
	for _, id := range ids {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			<-start
			_, err := Apply(ctx, pool, id, ApplyResult{}, testActorID, "")
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won++
			case errors.Is(err, ErrStaleBase):
				stale++
			default:
				other = append(other, err)
			}
		}(id)
	}
	close(start)
	wg.Wait()

	if len(other) > 0 {
		t.Fatalf("unexpected apply errors: %v", other)
	}
	if won != 1 {
		t.Fatalf("concurrent applies: %d won, %d stale; want exactly 1 winner", won, stale)
	}

	// And the database agrees there is exactly one applied row.
	var appliedCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM revisions
		WHERE resource_type = $1 AND resource_id = $2 AND state = 'applied'`,
		testResourceType, testResourceID).Scan(&appliedCount); err != nil {
		t.Fatalf("count applied: %v", err)
	}
	if appliedCount != 1 {
		t.Fatalf("applied revisions = %d, want 1 (the unique index was bypassed)", appliedCount)
	}
}

// A failed validation keeps the revision in draft with the findings recorded,
// so the user sees the same evidence the server saw.
func TestFailedValidationStaysDraftWithFindings(t *testing.T) {
	pool, ctx := setup(t)

	r := mustCreate(t, ctx, pool, Proposed{
		ResourceType: testResourceType, ResourceID: testResourceID,
		ActorType: audit.ActorUser, ActorID: testActorID,
		Candidate: Candidate{"domain": "bad.test", "server": "listen 0.0.0.0:80"},
	})
	result := ValidationResult{
		OK:      false,
		Summary: "nginx config invalid",
		Findings: []Finding{
			{Severity: "error", Message: "unknown directive", Path: "server.listen"},
		},
	}
	updated, err := MarkValidated(ctx, pool, r.ID, result, testActorID, "")
	if err != nil {
		t.Fatalf("MarkValidated: %v", err)
	}
	if updated.State != StateDraft {
		t.Errorf("state = %q, want draft after failed validation", updated.State)
	}
	if ok, _ := updated.Validation["ok"].(bool); ok {
		t.Error("recorded validation says ok=true after a failed validation")
	}
	// Cannot apply a revision that never validated.
	if _, err := Apply(ctx, pool, r.ID, ApplyResult{}, testActorID, ""); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("apply of unvalidated revision = %v, want ErrInvalidTransition", err)
	}
}

// Rollback produces a NEW revision carrying the previous candidate; the forward
// history is preserved, not mutated.
func TestRollbackCreatesNewRevisionAndPreservesHistory(t *testing.T) {
	pool, ctx := setup(t)

	first := mustCreate(t, ctx, pool, Proposed{
		ResourceType: testResourceType, ResourceID: testResourceID,
		ActorType: audit.ActorUser, ActorID: testActorID,
		Candidate: Candidate{"domain": "example.test"},
	})
	if _, err := MarkValidated(ctx, pool, first.ID, ValidationResult{OK: true}, testActorID, ""); err != nil {
		t.Fatalf("validate first: %v", err)
	}
	if _, err := Apply(ctx, pool, first.ID, ApplyResult{}, testActorID, ""); err != nil {
		t.Fatalf("apply first: %v", err)
	}

	second := mustCreate(t, ctx, pool, Proposed{
		ResourceType: testResourceType, ResourceID: testResourceID,
		ActorType: audit.ActorUser, ActorID: testActorID,
		BaseRevisionID: first.ID,
		Candidate:      Candidate{"domain": "example.test", "php": "8.4"},
	})
	if _, err := MarkValidated(ctx, pool, second.ID, ValidationResult{OK: true}, testActorID, ""); err != nil {
		t.Fatalf("validate second: %v", err)
	}
	applied2, err := Apply(ctx, pool, second.ID, ApplyResult{}, testActorID, "")
	if err != nil {
		t.Fatalf("apply second: %v", err)
	}
	// RollbackRef defaulted to the superseded candidate (first.Candidate).
	if applied2.RollbackRef["domain"] != "example.test" || applied2.RollbackRef["php"] != nil {
		t.Fatalf("rollback_ref = %v, want the first revision's candidate", applied2.RollbackRef)
	}

	rolled, err := Rollback(ctx, pool, second.ID, "php broke the site", audit.ActorUser, testActorID, "")
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if rolled.ID == second.ID {
		t.Fatal("rollback mutated the second revision instead of creating a new one")
	}
	if !rolled.Applied() {
		t.Errorf("rolled-back-to revision state = %q, want applied", rolled.State)
	}
	if rolled.Candidate["domain"] != "example.test" || rolled.Candidate["php"] != nil {
		t.Errorf("rollback candidate = %v, want the previous configuration", rolled.Candidate)
	}

	secondAfter, err := Get(ctx, pool, second.ID)
	if err != nil {
		t.Fatalf("Get second: %v", err)
	}
	if secondAfter.State != StateRolledBack {
		t.Errorf("rolled-back revision state = %q, want rolled_back", secondAfter.State)
	}

	// History is intact: all three revisions still exist and are readable.
	history, err := List(ctx, pool, testResourceType, testResourceID, 50)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(history) != 3 {
		t.Fatalf("history has %d revisions, want 3 (first, second, rollback)", len(history))
	}
}

// Git synchronization is a mirror: a failed push leaves the local applied
// change intact and merely marks the sync (PRD s24.3).
func TestGitSyncFailureDoesNotAffectLocalChange(t *testing.T) {
	pool, ctx := setup(t)

	r := mustCreate(t, ctx, pool, Proposed{
		ResourceType: testResourceType, ResourceID: testResourceID,
		ActorType: audit.ActorUser, ActorID: testActorID,
		Candidate: Candidate{"domain": "example.test"},
	})
	if r.GitSyncState != GitPending {
		t.Fatalf("git_sync_state = %q, want pending on create", r.GitSyncState)
	}
	if _, err := MarkValidated(ctx, pool, r.ID, ValidationResult{OK: true}, testActorID, ""); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if _, err := Apply(ctx, pool, r.ID, ApplyResult{}, testActorID, ""); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// A failed push is recorded, and the change stays applied.
	if err := MarkGitFailed(ctx, pool, r.ID, "github unreachable"); err != nil {
		t.Fatalf("MarkGitFailed: %v", err)
	}
	afterFail, err := Get(ctx, pool, r.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if afterFail.GitSyncState != GitFailed || afterFail.GitSyncError != "github unreachable" {
		t.Errorf("git state = %q/%q, want failed with the error recorded",
			afterFail.GitSyncState, afterFail.GitSyncError)
	}
	if !afterFail.Applied() {
		t.Fatalf("a git sync failure changed the applied state to %q", afterFail.State)
	}

	// The pending backlog no longer includes it.
	pending, err := PendingGitSync(ctx, pool, 100)
	if err != nil {
		t.Fatalf("PendingGitSync: %v", err)
	}
	for _, p := range pending {
		if p.ID == r.ID {
			t.Errorf("a failed-sync revision is still in the pending backlog")
		}
	}

	// A retry that succeeds clears the error and records the sha.
	if _, err := pool.Exec(ctx,
		`UPDATE revisions SET git_sync_state = 'pending', git_sync_error = NULL WHERE id = $1`, r.ID); err != nil {
		t.Fatalf("reset git state: %v", err)
	}
	if err := MarkGitSynced(ctx, pool, r.ID, "abc123def456"); err != nil {
		t.Fatalf("MarkGitSynced: %v", err)
	}
	synced, err := Get(ctx, pool, r.ID)
	if err != nil {
		t.Fatalf("Get synced: %v", err)
	}
	if synced.GitSyncState != GitSynced || synced.GitCommitSHA != "abc123def456" {
		t.Errorf("git state = %q/%q, want synced with the commit sha",
			synced.GitSyncState, synced.GitCommitSHA)
	}
	if !synced.Applied() {
		t.Errorf("syncing changed the applied state to %q", synced.State)
	}
}

func TestCandidateHashIsStableAndOrderIndependent(t *testing.T) {
	a := Candidate{"domain": "example.test", "php": "8.4", "tls": true}
	b := Candidate{"tls": true, "php": "8.4", "domain": "example.test"}
	c := Candidate{"domain": "example.test", "php": "8.3", "tls": true}

	ha, err := CandidateHash(a)
	if err != nil {
		t.Fatalf("hash a: %v", err)
	}
	hb, err := CandidateHash(b)
	if err != nil {
		t.Fatalf("hash b: %v", err)
	}
	hc, err := CandidateHash(c)
	if err != nil {
		t.Fatalf("hash c: %v", err)
	}
	if ha != hb {
		t.Errorf("equal documents hashed differently: %q vs %q", ha, hb)
	}
	if ha == hc {
		t.Errorf("different documents hashed the same: %q", ha)
	}
	if _, err := CandidateHash(nil); err == nil {
		t.Error("hashing a nil candidate succeeded")
	}
}

func TestCreateValidation(t *testing.T) {
	pool, ctx := setup(t)
	cases := map[string]Proposed{
		"no resource type": {ResourceID: testResourceID, ActorType: audit.ActorUser, Candidate: Candidate{"a": 1}},
		"no resource id":   {ResourceType: testResourceType, ActorType: audit.ActorUser, Candidate: Candidate{"a": 1}},
		"bad actor type":   {ResourceType: testResourceType, ResourceID: testResourceID, ActorType: "wizard", Candidate: Candidate{"a": 1}},
		"empty candidate":  {ResourceType: testResourceType, ResourceID: testResourceID, ActorType: audit.ActorUser, Candidate: Candidate{}},
	}
	for label, p := range cases {
		t.Run(label, func(t *testing.T) {
			if _, err := Create(ctx, pool, p); err == nil {
				t.Error("invalid proposal accepted")
			}
		})
	}
}

func TestApplyFailedRecordsFailureState(t *testing.T) {
	pool, ctx := setup(t)

	r := mustCreate(t, ctx, pool, Proposed{
		ResourceType: testResourceType, ResourceID: testResourceID,
		ActorType: audit.ActorUser, ActorID: testActorID,
		Candidate: Candidate{"domain": "example.test"},
	})
	if _, err := MarkValidated(ctx, pool, r.ID, ValidationResult{OK: true}, testActorID, ""); err != nil {
		t.Fatalf("validate: %v", err)
	}
	failed, err := Apply(ctx, pool, r.ID, ApplyResult{
		Failed: true, ErrorCode: "apply_failed", ErrorSummary: "nginx reload failed",
	}, testActorID, "")
	if err != nil {
		t.Fatalf("Apply(failed): %v", err)
	}
	if failed.State != StateFailed {
		t.Errorf("state = %q, want failed", failed.State)
	}
	// The resource has no applied revision after a failed apply.
	if _, err := CurrentApplied(ctx, pool, testResourceType, testResourceID); !errors.Is(err, ErrNotFound) {
		t.Errorf("CurrentApplied = %v, want ErrNotFound after a failed apply", err)
	}
}

func TestRecordHealthRejectsNonApplied(t *testing.T) {
	pool, ctx := setup(t)

	r := mustCreate(t, ctx, pool, Proposed{
		ResourceType: testResourceType, ResourceID: testResourceID,
		ActorType: audit.ActorUser, ActorID: testActorID,
		Candidate: Candidate{"domain": "example.test"},
	})
	// A draft has no health to record.
	if _, err := RecordHealth(ctx, pool, r.ID, Candidate{"healthy": true}, testActorID, ""); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("RecordHealth on a draft = %v, want ErrInvalidTransition", err)
	}
}
