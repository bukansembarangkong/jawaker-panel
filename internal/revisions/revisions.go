// Package revisions is the immutable configuration-change model
// (ARCHITECTURE.md §6, API.md §12).
//
// A revision is the durable record of ONE attempted change to ONE resource:
// who asked, what the resource looked like before, what it should look like
// after, what validation said, what applying it did, whether the result was
// healthy, and how to undo it. The substance is immutable — migration 0004
// installs a trigger that rejects any UPDATE touching the candidate, its hash,
// the resource identity, or created_at — while the outcome columns are filled
// in as the change progresses.
//
// Three properties are load-bearing, and each is enforced by the database
// rather than by convention:
//
//   - Optimistic concurrency: a revision records the base it was derived from.
//     Applying requires that base to still be the applied revision, so a stale
//     edit is rejected instead of silently overwriting concurrent work.
//   - One applied revision per resource: migration 0010 turns that into a
//     partial unique index, so two concurrent applies collide and exactly one
//     wins even when both read the same base.
//   - Git synchronization is never on the critical path (PRD §24.3): git state
//     is a separate column with its own transitions, and no local operation
//     waits on it. A failed push leaves a working change with a failed sync
//     marker, which is the honest outcome.
package revisions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors.
var (
	// ErrNotFound means the revision does not exist.
	ErrNotFound = errors.New("revisions: not found")
	// ErrStaleBase means the caller's base revision is no longer the applied
	// one: someone else changed the resource first. Callers map this to a 409
	// with the current revision so the client can re-read and reconcile.
	ErrStaleBase = errors.New("revisions: base revision is stale")
	// ErrInvalidTransition means the requested state change is not allowed from
	// the revision's current state.
	ErrInvalidTransition = errors.New("revisions: invalid state transition")
)

// States. Kept in sync with the revisions.state CHECK constraint (migration
// 0004).
const (
	// StateDraft is a proposed change that has not been validated.
	StateDraft = "draft"
	// StateValidated passed validation and may be applied.
	StateValidated = "validated"
	// StateApplied is the change currently in force for the resource.
	StateApplied = "applied"
	// StateFailed is a change whose apply attempt failed.
	StateFailed = "failed"
	// StateRolledBack was applied and then reverted.
	StateRolledBack = "rolled_back"
	// StateSuperseded was applied until a later revision replaced it.
	StateSuperseded = "superseded"
)

// Git sync states. Kept in sync with the revisions.git_sync_state CHECK
// constraint.
const (
	// GitPending means local work is done and a push is still owed.
	GitPending = "pending"
	// GitSynced means the revision is recorded in the Git-backed store.
	GitSynced = "synced"
	// GitFailed means the push failed. The local change stands regardless.
	GitFailed = "failed"
	// GitNotRequired means this change is not part of the Git-backed subset.
	GitNotRequired = "not_required"
)

// Candidate is a proposed resource configuration, as a plain document. Resource
// shapes are module-defined, so this stays a map rather than a typed struct:
// the change model must not require a schema change per module.
type Candidate map[string]any

// Proposed describes a change to create.
type Proposed struct {
	// ResourceType and ResourceID identify the changed resource. Required.
	ResourceType string
	ResourceID   string
	// ActorType and ActorID attribute the change. ActorType is required.
	ActorType string
	ActorID   string
	// BaseRevisionID is the revision this change was derived from. Empty means
	// the caller believes the resource has no applied revision yet; applying
	// then only succeeds if that is still true.
	BaseRevisionID string
	// Candidate is the new configuration. Required.
	Candidate Candidate
	// Previous is the configuration the candidate was derived from. Optional:
	// when omitted, it is filled from the currently applied revision so the
	// diff stays renderable.
	Previous Candidate
	// RequestID correlates the change with the HTTP request that caused it.
	RequestID string
}

func (p Proposed) validate() error {
	var errs []error
	if p.ResourceType == "" {
		errs = append(errs, errors.New("revisions: resource_type is required"))
	}
	if p.ResourceID == "" {
		errs = append(errs, errors.New("revisions: resource_id is required"))
	}
	switch p.ActorType {
	case audit.ActorUser, audit.ActorAPIToken, audit.ActorService, audit.ActorSystem, audit.ActorAI:
	default:
		errs = append(errs, fmt.Errorf("revisions: actor_type %q is not valid", p.ActorType))
	}
	if len(p.Candidate) == 0 {
		// An empty candidate is indistinguishable from "delete everything",
		// which is not a change any caller means to express by accident.
		errs = append(errs, errors.New("revisions: candidate is required"))
	}
	return errors.Join(errs...)
}

// Revision is one revision row.
type Revision struct {
	ID             string
	ResourceType   string
	ResourceID     string
	ActorType      string
	ActorID        string
	BaseRevisionID string
	Candidate      Candidate
	Previous       Candidate
	CandidateHash  string
	State          string
	Validation     Candidate
	ApplyJobID     string
	HealthResult   Candidate
	RollbackRef    Candidate
	GitSyncState   string
	GitCommitSHA   string
	GitSyncError   string
	CreatedAt      time.Time
	AppliedAt      *time.Time
}

// Applied reports whether this revision is the one currently in force.
func (r Revision) Applied() bool { return r.State == StateApplied }

// Terminal reports whether no further transition is expected. A superseded or
// rolled-back revision is history and must not be mutated again.
func (r Revision) Terminal() bool {
	switch r.State {
	case StateSuperseded, StateRolledBack, StateFailed:
		return true
	default:
		return false
	}
}

// CandidateHash returns the stable digest of a candidate document.
//
// Go's encoding/json sorts map keys, so marshaling the same logical document
// twice yields the same bytes and therefore the same hash. That is what makes
// the hash usable for drift detection: it compares documents, not formatting.
// A json.Number-free representation is deliberate — callers pass decoded JSON,
// where every number is already float64, so two documents that differ only in
// how a number was written are the same document.
func CandidateHash(c Candidate) (string, error) {
	if c == nil {
		return "", errors.New("revisions: cannot hash a nil candidate")
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("revisions: hash candidate: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// Create records a proposed change. It does NOT apply anything: a revision is
// created, validated, and applied as separate steps so a validation failure is
// recorded against a durable row rather than lost with the request.
//
// When Previous is omitted it is copied from the currently applied revision, so
// the recorded diff is the diff the apply will actually produce.
//
// A base that is not the applied revision is reported as ErrStaleBase, and the
// two cases differ in what can be recorded:
//
//   - the base EXISTS but is no longer applied (someone superseded or rolled it
//     back): the draft is still written, because the evidence of what the caller
//     tried is exactly what makes the concurrent edit visible. Create returns
//     the row alongside the error.
//   - the base does NOT exist: no row can be written at all, because
//     base_revision_id is a foreign key. Create returns ErrStaleBase with no
//     revision, and that is the honest answer — there is nothing to attach the
//     draft to and a NULL base would misrepresent what the caller based on.
func Create(ctx context.Context, pool *pgxpool.Pool, proposed Proposed) (Revision, error) {
	if err := proposed.validate(); err != nil {
		return Revision{}, err
	}
	if pool == nil {
		return Revision{}, errors.New("revisions: database is required")
	}

	hash, err := CandidateHash(proposed.Candidate)
	if err != nil {
		return Revision{}, err
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return Revision{}, fmt.Errorf("revisions: begin create: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	current, err := currentApplied(ctx, tx, proposed.ResourceType, proposed.ResourceID)
	if err != nil {
		return Revision{}, err
	}

	previous := proposed.Previous
	if previous == nil && current != nil {
		previous = current.Candidate
	}
	baseID := proposed.BaseRevisionID
	if baseID == "" && current != nil {
		baseID = current.ID
	}

	created, err := insert(ctx, tx, proposed, previous, baseID, hash)
	if err != nil {
		return Revision{}, err
	}

	// The audit row commits with the revision, so a recorded change always has
	// an explaining audit event (SECURITY.md §16).
	if err := audit.Record(ctx, tx, audit.Event{
		ActorType:    proposed.ActorType,
		ActorID:      proposed.ActorID,
		Action:       "revision.create",
		ResourceType: proposed.ResourceType,
		ResourceID:   proposed.ResourceID,
		RequestID:    proposed.RequestID,
		RevisionID:   created.ID,
		Result:       audit.ResultSuccess,
		Context: map[string]any{
			"candidate_hash": hash,
			"base_revision":  baseID,
		},
	}); err != nil {
		return Revision{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Revision{}, fmt.Errorf("revisions: commit create: %w", err)
	}

	// Report a stale base after the row is safely recorded: the draft is useful
	// evidence of what the caller tried, and discarding it would hide the
	// concurrent-edit that caused it.
	if proposed.BaseRevisionID != "" && (current == nil || current.ID != proposed.BaseRevisionID) {
		var currentID string
		if current != nil {
			currentID = current.ID
		}
		return created, fmt.Errorf("%w: base %s, applied %s",
			ErrStaleBase, proposed.BaseRevisionID, currentID)
	}
	return created, nil
}

func insert(ctx context.Context, tx pgx.Tx, p Proposed, previous Candidate, baseID, hash string) (Revision, error) {
	previousJSON, err := encodeCandidate(previous)
	if err != nil {
		return Revision{}, err
	}
	candidateJSON, err := encodeCandidate(p.Candidate)
	if err != nil {
		return Revision{}, err
	}

	var r Revision
	var candidate, prev, validation, health, rollback []byte
	err = tx.QueryRow(ctx, `
		INSERT INTO revisions (resource_type, resource_id, actor_type, actor_id,
		                       base_revision_id, candidate, previous, candidate_hash)
		VALUES ($1, $2, $3, NULLIF($4, '')::uuid, NULLIF($5, '')::uuid,
		        $6::jsonb, $7::jsonb, $8)
		RETURNING id, resource_type, resource_id, actor_type,
		          COALESCE(actor_id::text, ''), COALESCE(base_revision_id::text, ''),
		          candidate, previous, candidate_hash, state, validation_result,
		          COALESCE(apply_job_id::text, ''), health_result, rollback_ref,
		          git_sync_state, COALESCE(git_commit_sha, ''), COALESCE(git_sync_error, ''),
		          created_at, applied_at`,
		p.ResourceType, p.ResourceID, p.ActorType, p.ActorID, baseID,
		candidateJSON, previousJSON, hash).
		Scan(&r.ID, &r.ResourceType, &r.ResourceID, &r.ActorType,
			&r.ActorID, &r.BaseRevisionID,
			&candidate, &prev, &r.CandidateHash, &r.State, &validation,
			&r.ApplyJobID, &health, &rollback,
			&r.GitSyncState, &r.GitCommitSHA, &r.GitSyncError,
			&r.CreatedAt, &r.AppliedAt)
	if err != nil {
		if isForeignKeyViolation(err) {
			// The base revision does not exist. From the caller's point of view
			// that is exactly a stale base: the change they derived from is not
			// something this system can build on. The constraint remains the
			// authority; translating it keeps the API honest (409, not 500).
			return Revision{}, fmt.Errorf("%w: base revision %s does not exist",
				ErrStaleBase, baseID)
		}
		return Revision{}, fmt.Errorf("revisions: insert: %w", err)
	}

	if r.Candidate, err = decodeCandidate(candidate); err != nil {
		return Revision{}, err
	}
	if r.Previous, err = decodeCandidate(prev); err != nil {
		return Revision{}, err
	}
	if r.Validation, err = decodeCandidate(validation); err != nil {
		return Revision{}, err
	}
	if r.HealthResult, err = decodeCandidate(health); err != nil {
		return Revision{}, err
	}
	if r.RollbackRef, err = decodeCandidate(rollback); err != nil {
		return Revision{}, err
	}
	return r, nil
}

// Get loads one revision.
func Get(ctx context.Context, pool *pgxpool.Pool, id string) (Revision, error) {
	return scanRevision(pool.QueryRow(ctx, selectColumns+` WHERE id = $1`, id))
}

// CurrentApplied returns the revision currently in force for a resource.
// It returns ErrNotFound when nothing has been applied yet, which is the normal
// state for a resource that has never been configured.
func CurrentApplied(ctx context.Context, pool *pgxpool.Pool, resourceType, resourceID string) (Revision, error) {
	return scanRevision(pool.QueryRow(ctx, selectColumns+`
		WHERE resource_type = $1 AND resource_id = $2 AND state = 'applied'`,
		resourceType, resourceID))
}

func currentApplied(ctx context.Context, tx pgx.Tx, resourceType, resourceID string) (*Revision, error) {
	r, err := scanRevision(tx.QueryRow(ctx, selectColumns+`
		WHERE resource_type = $1 AND resource_id = $2 AND state = 'applied'`,
		resourceType, resourceID))
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// List returns a resource's revisions, newest first. Only a bounded page is
// read: revision history grows without limit and a UI never needs all of it.
func List(ctx context.Context, pool *pgxpool.Pool, resourceType, resourceID string, limit int) ([]Revision, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := pool.Query(ctx, selectColumns+`
		WHERE resource_type = $1 AND resource_id = $2
		ORDER BY created_at DESC
		LIMIT $3`, resourceType, resourceID, limit)
	if err != nil {
		return nil, fmt.Errorf("revisions: list: %w", err)
	}
	defer rows.Close()

	var out []Revision
	for rows.Next() {
		r, err := scanRevision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("revisions: iterate: %w", err)
	}
	return out, nil
}

// PendingGitSync returns revisions whose Git push is still owed, oldest first,
// so a sync worker drains the backlog in the order changes were made.
func PendingGitSync(ctx context.Context, pool *pgxpool.Pool, limit int) ([]Revision, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := pool.Query(ctx, selectColumns+`
		WHERE git_sync_state = 'pending'
		ORDER BY created_at ASC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("revisions: list pending git sync: %w", err)
	}
	defer rows.Close()

	var out []Revision
	for rows.Next() {
		r, err := scanRevision(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("revisions: iterate pending git sync: %w", err)
	}
	return out, nil
}

const selectColumns = `
	SELECT id, resource_type, resource_id, actor_type,
	       COALESCE(actor_id::text, ''), COALESCE(base_revision_id::text, ''),
	       candidate, previous, candidate_hash, state, validation_result,
	       COALESCE(apply_job_id::text, ''), health_result, rollback_ref,
	       git_sync_state, COALESCE(git_commit_sha, ''), COALESCE(git_sync_error, ''),
	       created_at, applied_at
	FROM revisions`

// rowScanner is satisfied by pgx.Row and pgx.Rows alike, so the same scan works
// for single-row and multi-row reads.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanRevision(row rowScanner) (Revision, error) {
	var r Revision
	var candidate, prev, validation, health, rollback []byte
	err := row.Scan(&r.ID, &r.ResourceType, &r.ResourceID, &r.ActorType,
		&r.ActorID, &r.BaseRevisionID,
		&candidate, &prev, &r.CandidateHash, &r.State, &validation,
		&r.ApplyJobID, &health, &rollback,
		&r.GitSyncState, &r.GitCommitSHA, &r.GitSyncError,
		&r.CreatedAt, &r.AppliedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Revision{}, ErrNotFound
	}
	if err != nil {
		return Revision{}, fmt.Errorf("revisions: scan: %w", err)
	}
	if r.Candidate, err = decodeCandidate(candidate); err != nil {
		return Revision{}, err
	}
	if r.Previous, err = decodeCandidate(prev); err != nil {
		return Revision{}, err
	}
	if r.Validation, err = decodeCandidate(validation); err != nil {
		return Revision{}, err
	}
	if r.HealthResult, err = decodeCandidate(health); err != nil {
		return Revision{}, err
	}
	if r.RollbackRef, err = decodeCandidate(rollback); err != nil {
		return Revision{}, err
	}
	return r, nil
}

func encodeCandidate(c Candidate) ([]byte, error) {
	if len(c) == 0 {
		return nil, nil
	}
	encoded, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("revisions: encode candidate: %w", err)
	}
	return encoded, nil
}

func decodeCandidate(data []byte) (Candidate, error) {
	if len(data) == 0 {
		return nil, nil
	}
	decoded := Candidate{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("revisions: decode candidate: %w", err)
	}
	return decoded, nil
}

// isUniqueViolation reports the PostgreSQL unique-violation code.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// isForeignKeyViolation reports the PostgreSQL foreign-key-violation code.
func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}
