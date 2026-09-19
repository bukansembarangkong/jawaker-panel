package revisions

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ValidationResult is the recorded outcome of validation.
type ValidationResult struct {
	// OK reports whether the candidate may be applied.
	OK bool
	// Findings is the bounded structured detail shown to the user, e.g. the
	// failing line of a config file. Never secret material.
	Findings []Finding
	// Summary is a short human explanation, required when OK is false.
	Summary string
}

// Finding is one validation message.
type Finding struct {
	Severity string `json:"severity"` // error | warning | info
	Message  string `json:"message"`
	// Path locates the problem inside the candidate, e.g. "server.listen".
	Path string `json:"path,omitempty"`
}

// MarkValidated records the validation outcome.
//
// A failing validation is recorded, not thrown away: the revision stays in
// draft with the findings attached, so a user who is told "this config is
// invalid" can also see the same evidence the server saw. A passing validation
// moves the revision to validated, where it becomes applicable.
func MarkValidated(ctx context.Context, pool *pgxpool.Pool, id string, validationResult ValidationResult, actorID, requestID string) (Revision, error) {
	if pool == nil {
		return Revision{}, errors.New("revisions: database is required")
	}
	if !validationResult.OK && validationResult.Summary == "" {
		return Revision{}, errors.New("revisions: a failed validation needs a summary")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return Revision{}, fmt.Errorf("revisions: begin validate: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	current, err := getForUpdate(ctx, tx, id)
	if err != nil {
		return Revision{}, err
	}
	if current.State != StateDraft {
		return current, fmt.Errorf("%w: cannot validate a %s revision", ErrInvalidTransition, current.State)
	}

	nextState := StateDraft
	if validationResult.OK {
		nextState = StateValidated
	}
	recorded := encodeValidation(validationResult)
	r, err := updateRevision(ctx, tx, id, `
		SET state = $2, validation_result = $3::jsonb`,
		nextState, recorded)
	if err != nil {
		return Revision{}, err
	}

	auditResult := audit.ResultSuccess
	if !validationResult.OK {
		auditResult = audit.ResultFailure
	}
	if err := audit.Record(ctx, tx, audit.Event{
		ActorType:    r.ActorType,
		ActorID:      actorID,
		Action:       "revision.validate",
		ResourceType: r.ResourceType,
		ResourceID:   r.ResourceID,
		RequestID:    requestID,
		RevisionID:   r.ID,
		Result:       auditResult,
		Reason:       validationResult.Summary,
		Context:      map[string]any{"findings": validationResult.Findings},
	}); err != nil {
		return Revision{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Revision{}, fmt.Errorf("revisions: commit validate: %w", err)
	}
	return r, nil
}

// ApplyResult carries what the caller did to make the candidate real.
type ApplyResult struct {
	// JobID is the durable job that performed the apply, when the apply is
	// asynchronous. Empty for an apply performed inline.
	JobID string
	// Failed reports whether the apply attempt failed.
	Failed bool
	// ErrorCode and ErrorSummary describe a failed apply.
	ErrorCode    string
	ErrorSummary string
	// RollbackRef is what a later rollback needs to restore the previous state.
	RollbackRef Candidate
}

// Apply marks a validated revision as applied, superseding whatever it replaces.
//
// This is the optimistic-concurrency gate (API.md §12), and it relies on two
// database facts rather than on a read-then-write check:
//
//   - the supersede-then-apply pair runs in one transaction, so the partial
//     unique index from migration 0010 sees at most one applied row per
//     resource at any commit boundary;
//   - the new revision's recorded base must be the revision being superseded.
//     If it is not, the caller derived their change from something that is no
//     longer current, and that is a conflict to report, not a change to merge.
//
// A concurrent apply therefore loses on the unique index and is reported as
// ErrStaleBase, which is precisely true: someone else advanced the resource.
func Apply(ctx context.Context, pool *pgxpool.Pool, id string, result ApplyResult, actorID, requestID string) (Revision, error) {
	if pool == nil {
		return Revision{}, errors.New("revisions: database is required")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return Revision{}, fmt.Errorf("revisions: begin apply: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	pending, err := getForUpdate(ctx, tx, id)
	if err != nil {
		return Revision{}, err
	}
	if result.Failed {
		return finishFailedApply(ctx, tx, pending, result, actorID, requestID)
	}
	if pending.State != StateValidated {
		return pending, fmt.Errorf("%w: cannot apply a %s revision", ErrInvalidTransition, pending.State)
	}

	current, err := currentAppliedForUpdate(ctx, tx, pending.ResourceType, pending.ResourceID)
	if err != nil {
		return Revision{}, err
	}
	switch {
	case current == nil && pending.BaseRevisionID != "":
		// The caller based this change on a revision that has since been
		// rolled back, so there is nothing left to replace. Applying would
		// silently overwrite whatever state exists now.
		return pending, fmt.Errorf("%w: base %s, no applied revision", ErrStaleBase, pending.BaseRevisionID)
	case current != nil && current.ID != pending.BaseRevisionID:
		return pending, fmt.Errorf("%w: base %s, applied %s", ErrStaleBase, pending.BaseRevisionID, current.ID)
	}

	if current != nil {
		if _, supersedeErr := tx.Exec(ctx,
			`UPDATE revisions SET state = $2 WHERE id = $1`, current.ID, StateSuperseded); supersedeErr != nil {
			return Revision{}, fmt.Errorf("revisions: supersede %s: %w", current.ID, supersedeErr)
		}
	}

	rollback := result.RollbackRef
	if rollback == nil && current != nil {
		// Default recovery: restore the superseded candidate. Recording it now
		// means rollback stays possible even if the previous revision is
		// pruned later by retention.
		rollback = current.Candidate
	}
	encodedRollback := encodeCandidateOrNull(rollback)

	r, err := updateRevision(ctx, tx, id, `
		SET state = 'applied', applied_at = now(),
		    apply_job_id = NULLIF($2, '')::uuid,
		    rollback_ref = COALESCE($3::jsonb, rollback_ref)`,
		result.JobID, encodedRollback)
	if err != nil {
		if isUniqueViolation(err) {
			// Two applies raced and the other one committed first. The index is
			// the arbiter; this caller's base is now stale by definition.
			return pending, fmt.Errorf("%w: another apply committed first", ErrStaleBase)
		}
		return Revision{}, err
	}

	if err := audit.Record(ctx, tx, audit.Event{
		ActorType:    r.ActorType,
		ActorID:      actorID,
		Action:       "revision.apply",
		ResourceType: r.ResourceType,
		ResourceID:   r.ResourceID,
		RequestID:    requestID,
		RevisionID:   r.ID,
		JobID:        r.ApplyJobID,
		Result:       audit.ResultSuccess,
		Context: map[string]any{
			"superseded": currentRevisionID(current),
		},
	}); err != nil {
		return Revision{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		if isUniqueViolation(err) {
			return pending, fmt.Errorf("%w: another apply committed first", ErrStaleBase)
		}
		return Revision{}, fmt.Errorf("revisions: commit apply: %w", err)
	}
	return r, nil
}

func finishFailedApply(ctx context.Context, tx pgx.Tx, pending Revision, result ApplyResult, actorID, requestID string) (Revision, error) {
	if pending.State != StateValidated {
		return pending, fmt.Errorf("%w: cannot fail a %s revision", ErrInvalidTransition, pending.State)
	}
	r, err := updateRevision(ctx, tx, pending.ID, `
		SET state = 'failed', apply_job_id = NULLIF($2, '')::uuid`,
		result.JobID)
	if err != nil {
		return Revision{}, err
	}
	if err := audit.Record(ctx, tx, audit.Event{
		ActorType:    r.ActorType,
		ActorID:      actorID,
		Action:       "revision.apply",
		ResourceType: r.ResourceType,
		ResourceID:   r.ResourceID,
		RequestID:    requestID,
		RevisionID:   r.ID,
		JobID:        r.ApplyJobID,
		Result:       audit.ResultFailure,
		ErrorCode:    result.ErrorCode,
		Reason:       result.ErrorSummary,
	}); err != nil {
		return Revision{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Revision{}, fmt.Errorf("revisions: commit failed apply: %w", err)
	}
	return r, nil
}

// RecordHealth stores the post-apply health check result.
//
// Health is recorded separately from the apply because "the change was written"
// and "the service still works" are different facts. A configuration can apply
// cleanly and leave a broken server, and the operator needs to see exactly that
// rather than a single ambiguous success. An unhealthy result does not by itself
// revert anything: reverting is a decision, and Apply/Rollback are where
// decisions are made.
func RecordHealth(ctx context.Context, pool *pgxpool.Pool, id string, health Candidate, actorID, requestID string) (Revision, error) {
	if pool == nil {
		return Revision{}, errors.New("revisions: database is required")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return Revision{}, fmt.Errorf("revisions: begin health: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	pending, err := getForUpdate(ctx, tx, id)
	if err != nil {
		return Revision{}, err
	}
	if pending.State != StateApplied && pending.State != StateSuperseded {
		return pending, fmt.Errorf("%w: cannot record health for a %s revision", ErrInvalidTransition, pending.State)
	}

	encoded := encodeCandidateOrNull(health)
	r, err := updateRevision(ctx, tx, id, `
		SET health_result = $2::jsonb`, encoded)
	if err != nil {
		return Revision{}, err
	}

	healthy, _ := health["healthy"].(bool)
	result := audit.ResultSuccess
	if !healthy {
		result = audit.ResultFailure
	}
	if err := audit.Record(ctx, tx, audit.Event{
		ActorType:    audit.ActorSystem,
		ActorID:      actorID,
		Action:       "revision.health",
		ResourceType: r.ResourceType,
		ResourceID:   r.ResourceID,
		RequestID:    requestID,
		RevisionID:   r.ID,
		Result:       result,
	}); err != nil {
		return Revision{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Revision{}, fmt.Errorf("revisions: commit health: %w", err)
	}
	return r, nil
}

// Rollback reverts a resource to what an applied revision replaced.
//
// It is implemented as a new revision rather than by mutating history: the
// forward apply is evidence of what happened and must stay readable. The new
// revision records the old candidate, so the trail shows the original change,
// the revert, and the reason for each.
func Rollback(ctx context.Context, pool *pgxpool.Pool, id, reason, actorType, actorID, requestID string) (Revision, error) {
	if pool == nil {
		return Revision{}, errors.New("revisions: database is required")
	}
	if reason == "" {
		return Revision{}, errors.New("revisions: a rollback requires a reason")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return Revision{}, fmt.Errorf("revisions: begin rollback: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	target, err := getForUpdate(ctx, tx, id)
	if err != nil {
		return Revision{}, err
	}
	if target.State != StateApplied {
		return target, fmt.Errorf("%w: cannot roll back a %s revision", ErrInvalidTransition, target.State)
	}
	if len(target.RollbackRef) == 0 {
		return target, errors.New("revisions: revision has no recorded rollback state")
	}

	// The replacement is a new draft carrying the previous configuration. It is
	// applied by the normal path, so a rollback goes through validation exactly
	// like any other change.
	replacement := Proposed{
		ResourceType:   target.ResourceType,
		ResourceID:     target.ResourceID,
		ActorType:      actorType,
		ActorID:        actorID,
		BaseRevisionID: target.ID,
		Candidate:      target.RollbackRef,
		Previous:       target.Candidate,
		RequestID:      requestID,
	}
	hash, err := CandidateHash(replacement.Candidate)
	if err != nil {
		return Revision{}, err
	}
	created, err := insert(ctx, tx, replacement, replacement.Previous, replacement.BaseRevisionID, hash)
	if err != nil {
		return Revision{}, err
	}
	if _, rolledErr := tx.Exec(ctx,
		`UPDATE revisions SET state = $2 WHERE id = $1`, target.ID, StateRolledBack); rolledErr != nil {
		return Revision{}, fmt.Errorf("revisions: mark rolled back: %w", rolledErr)
	}
	if _, applyErr := tx.Exec(ctx, `
		UPDATE revisions SET state = 'applied', applied_at = now() WHERE id = $1`,
		created.ID); applyErr != nil {
		if isUniqueViolation(applyErr) {
			return created, fmt.Errorf("%w: another change applied during rollback", ErrStaleBase)
		}
		return Revision{}, fmt.Errorf("revisions: apply rollback revision: %w", applyErr)
	}

	if auditErr := audit.Record(ctx, tx, audit.Event{
		ActorType:    actorType,
		ActorID:      actorID,
		Action:       "revision.rollback",
		ResourceType: target.ResourceType,
		ResourceID:   target.ResourceID,
		RequestID:    requestID,
		RevisionID:   created.ID,
		Result:       audit.ResultSuccess,
		Reason:       reason,
		Context:      map[string]any{"rolled_back_revision": target.ID},
	}); auditErr != nil {
		return Revision{}, auditErr
	}

	if commitErr := tx.Commit(ctx); commitErr != nil {
		if isUniqueViolation(commitErr) {
			return created, fmt.Errorf("%w: another change applied during rollback", ErrStaleBase)
		}
		return Revision{}, fmt.Errorf("revisions: commit rollback: %w", commitErr)
	}

	applied, err := Get(ctx, pool, created.ID)
	if err != nil {
		return Revision{}, err
	}
	return applied, nil
}

// MarkGitSynced records a successful push.
func MarkGitSynced(ctx context.Context, pool *pgxpool.Pool, id, commitSHA string) error {
	if commitSHA == "" {
		return errors.New("revisions: a synced revision needs a commit sha")
	}
	return setGitState(ctx, pool, id, GitSynced, commitSHA, "")
}

// MarkGitFailed records a failed push. The local change is untouched: GitHub is
// a mirror, never the system of record, so a sync failure is a note on the
// revision and never a reason to reject or revert a working change
// (PRD §24.3).
func MarkGitFailed(ctx context.Context, pool *pgxpool.Pool, id, syncError string) error {
	if syncError == "" {
		return errors.New("revisions: a failed sync needs an error detail")
	}
	return setGitState(ctx, pool, id, GitFailed, "", syncError)
}

// MarkGitNotRequired records that this revision is outside the Git-backed
// subset, so it stops appearing in the pending backlog.
func MarkGitNotRequired(ctx context.Context, pool *pgxpool.Pool, id string) error {
	return setGitState(ctx, pool, id, GitNotRequired, "", "")
}

func setGitState(ctx context.Context, pool *pgxpool.Pool, id, state, commitSHA, syncError string) error {
	if pool == nil {
		return errors.New("revisions: database is required")
	}
	tag, err := pool.Exec(ctx, `
		UPDATE revisions
		SET git_sync_state = $2,
		    git_commit_sha = COALESCE(NULLIF($3, ''), git_commit_sha),
		    git_sync_error = NULLIF($4, '')
		WHERE id = $1`, id, state, commitSHA, syncError)
	if err != nil {
		return fmt.Errorf("revisions: set git state: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// getForUpdate loads a revision and locks the row for the rest of the
// transaction, so two lifecycle transitions cannot interleave.
func getForUpdate(ctx context.Context, tx pgx.Tx, id string) (Revision, error) {
	return scanRevision(tx.QueryRow(ctx, selectColumns+` WHERE id = $1 FOR UPDATE`, id))
}

func currentAppliedForUpdate(ctx context.Context, tx pgx.Tx, resourceType, resourceID string) (*Revision, error) {
	r, err := scanRevision(tx.QueryRow(ctx, selectColumns+`
		WHERE resource_type = $1 AND resource_id = $2 AND state = 'applied'
		FOR UPDATE`, resourceType, resourceID))
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// updateRevision runs an UPDATE with a fixed RETURNING clause and re-reads the
// row through the shared scanner, so every transition decodes identically.
func updateRevision(ctx context.Context, tx pgx.Tx, id, setClause string, args ...any) (Revision, error) {
	full := append([]any{id}, args...)
	// The WHERE is part of the helper, not the caller's SET clause, so every
	// transition is pinned to one row by construction and $1 is always used.
	query := `UPDATE revisions ` + setClause + ` WHERE id = $1 RETURNING ` + returnColumns
	return scanRevision(tx.QueryRow(ctx, query, full...))
}

// returnColumns must match scanRevision's expectations exactly.
const returnColumns = `
	id, resource_type, resource_id, actor_type,
	COALESCE(actor_id::text, ''), COALESCE(base_revision_id::text, ''),
	candidate, previous, candidate_hash, state, validation_result,
	COALESCE(apply_job_id::text, ''), health_result, rollback_ref,
	git_sync_state, COALESCE(git_commit_sha, ''), COALESCE(git_sync_error, ''),
	created_at, applied_at`

func encodeValidation(vr ValidationResult) []byte {
	encoded, err := json.Marshal(map[string]any{
		"ok":       vr.OK,
		"summary":  vr.Summary,
		"findings": vr.Findings,
	})
	if err != nil {
		// Validation results are always encodable: they are strings and bools
		// built by this package. A failure here would be a programming error,
		// and dropping it silently would hide it, so store a marker instead.
		return []byte(`{"ok":false,"summary":"validation result could not be recorded"}`)
	}
	return encoded
}

func encodeCandidateOrNull(c Candidate) []byte {
	encoded, err := encodeCandidate(c)
	if err != nil {
		return nil
	}
	return encoded
}

func currentRevisionID(r *Revision) string {
	if r == nil {
		return ""
	}
	return r.ID
}
