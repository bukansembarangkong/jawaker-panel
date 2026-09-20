// Package projects owns the tenant boundary: projects, their membership, and
// their quotas.
//
// Everything else in the hosting domain hangs off a project. DATABASE.md §6
// requires every tenant-bound resource be traceable to its project boundary and
// forbids authorization queries that depend on an inferred ownership chain, so
// this package's job is to make "which project owns this?" a single lookup that
// cannot be wrong rather than a chain of joins a caller assembles.
//
// The store holds no authorization logic of its own. RBAC decides whether a
// caller may act; this package decides what acting means, and it is deliberately
// the only place that writes these tables so the state machine cannot be
// bypassed by a second caller.
package projects

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors. Callers branch on these to choose an HTTP status, so they are
// exported and stable.
var (
	// ErrInvalid is returned for a caller-supplied value that cannot be stored.
	ErrInvalid = errors.New("projects: invalid argument")
	// ErrNotFound is returned when the project does not exist or is tombstoned.
	// Both cases return the same error: distinguishing them would tell a caller
	// that a project id it guessed corresponds to a real, deleted row.
	ErrNotFound = errors.New("projects: not found")
	// ErrSlugTaken is returned when a live project already uses the slug.
	ErrSlugTaken = errors.New("projects: slug already in use")
	// ErrState is returned for a transition the lifecycle does not permit.
	ErrState = errors.New("projects: invalid state transition")
)

// Lifecycle states (DATABASE.md §7, migrations/0014).
const (
	StateActive        = "active"
	StateSuspended     = "suspended"
	StatePendingDelete = "pending_delete"
	StateDeleted       = "deleted"
)

// DefaultDeleteGrace is how long a project stays in pending_delete before it may
// be finalized. The spec requires a recoverable delete but never states a
// duration; seven days is recorded as a decision in docs/decisions.md.
const DefaultDeleteGrace = 7 * 24 * time.Hour

// maxDeleteGrace bounds what a caller may ask for. An unbounded grace period is
// a project that is never deleted, which defeats the purpose of having one.
const maxDeleteGrace = 90 * 24 * time.Hour

// maxListLimit bounds a page. Matches the convention in internal/nodes so a
// caller cannot ask for the whole table and call it a list.
const maxListLimit = 200

// Project is one tenant boundary.
type Project struct {
	ID          string
	Slug        string
	Name        string
	Description string
	State       string
	CreatedBy   *string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	// DeleteAfter is the instant a pending_delete project may be finalized.
	// Non-nil exactly when State is pending_delete; the schema enforces that
	// shape, so this field is never a guess.
	DeleteAfter *time.Time
	DeletedAt   *time.Time
}

// Live reports whether the project is not tombstoned. A suspended project is
// still live: it exists, it can be resumed, and its resources are intact.
func (p Project) Live() bool { return p.DeletedAt == nil }

// Usable reports whether workloads may run in the project. Only an active
// project is usable; suspended and pending_delete are not, and treating
// pending_delete as usable would let a site be created inside a project that is
// on its way out.
func (p Project) Usable() bool { return p.State == StateActive }

const projectColumns = `id, slug, name, description, state, created_by,
	created_at, updated_at, delete_after, deleted_at`

func scanProject(row pgx.Row) (Project, error) {
	var p Project
	err := row.Scan(&p.ID, &p.Slug, &p.Name, &p.Description, &p.State, &p.CreatedBy,
		&p.CreatedAt, &p.UpdatedAt, &p.DeleteAfter, &p.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, fmt.Errorf("projects: scan project: %w", err)
	}
	return p, nil
}

// Store reads and writes the projects domain.
type Store struct {
	pool  *pgxpool.Pool
	clock func() time.Time
}

// NewStore builds a store over a pool. now may be nil, which means time.Now; it
// exists so tests can drive the grace period deterministically rather than
// sleeping.
func NewStore(pool *pgxpool.Pool, now func() time.Time) *Store {
	clock := now
	if clock == nil {
		clock = time.Now
	}
	return &Store{pool: pool, clock: clock}
}

// CreateParams configures project creation.
type CreateParams struct {
	Slug        string
	Name        string
	Description string
	CreatedBy   string
}

// Create inserts a project in the active state.
//
// The slug is validated here as well as by the schema. The schema constraint is
// the authority — it is what makes a bad slug unstorable no matter who writes
// — but checking first means the caller gets a message naming the offending
// value instead of a PostgreSQL error string that leaks the constraint name.
func (s *Store) Create(ctx context.Context, p CreateParams) (Project, error) {
	slug := strings.ToLower(strings.TrimSpace(p.Slug))
	if err := validateSlug(slug); err != nil {
		return Project{}, err
	}
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return Project{}, fmt.Errorf("%w: name is required", ErrInvalid)
	}

	var createdBy any
	if v := strings.TrimSpace(p.CreatedBy); v != "" {
		createdBy = v
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO projects (slug, name, description, created_by)
		VALUES ($1, $2, $3, $4)
		RETURNING %s`, projectColumns),
		slug, name, p.Description, createdBy)

	project, err := scanProject(row)
	if err != nil {
		if isUniqueViolation(err) {
			return Project{}, ErrSlugTaken
		}
		if isCheckViolation(err) {
			// The schema refused something the Go validator accepted. Reporting
			// it as ErrInvalid would hide the disagreement; this is a bug in one
			// of the two and must be visible.
			return Project{}, fmt.Errorf("projects: schema rejected slug %q: %w", slug, err)
		}
		return Project{}, err
	}
	return project, nil
}

// Get returns one project by id. Tombstoned projects are not returned: a caller
// asking for a deleted project is asking for something that no longer exists,
// and answering with a row would make the tombstone decorative.
func (s *Store) Get(ctx context.Context, id string) (Project, error) {
	if strings.TrimSpace(id) == "" {
		return Project{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT %s FROM projects WHERE id = $1 AND deleted_at IS NULL`, projectColumns), id)
	return scanProject(row)
}

// List returns a page of live projects, newest first, plus the total count of
// rows matching the filter.
//
// The count and the page share one predicate so they cannot disagree — a UI that
// shows "3 of 10" must be counting the same 10 it is paging through.
func (s *Store) List(ctx context.Context, limit, offset int, state string) ([]Project, int, error) {
	if limit <= 0 || limit > maxListLimit {
		return nil, 0, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalid, maxListLimit)
	}
	if offset < 0 {
		return nil, 0, fmt.Errorf("%w: offset cannot be negative", ErrInvalid)
	}
	// An empty filter means "any live state". The allowlist is explicit: an
	// arbitrary value would either silently match nothing or, if interpolated,
	// become an injection surface.
	var filter any
	switch state {
	case "":
		filter = nil
	case StateActive, StateSuspended, StatePendingDelete:
		filter = state
	default:
		return nil, 0, fmt.Errorf("%w: unknown state filter %q", ErrInvalid, state)
	}

	const where = `WHERE deleted_at IS NULL AND ($1::text IS NULL OR state = $1)`

	var total int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM projects `+where, filter).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("projects: count projects: %w", err)
	}

	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM projects %s
		ORDER BY created_at DESC, id
		LIMIT $2 OFFSET $3`, projectColumns, where), filter, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("projects: list projects: %w", err)
	}
	defer rows.Close()

	out := make([]Project, 0, limit)
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("projects: iterate projects: %w", err)
	}
	return out, total, nil
}

// UpdateParams carries the editable fields. A nil pointer means "leave
// unchanged", which is how a partial update avoids clearing a field the caller
// never mentioned.
type UpdateParams struct {
	Name        *string
	Description *string
}

// Update changes the editable fields of a live project.
func (s *Store) Update(ctx context.Context, id string, p UpdateParams) (Project, error) {
	if strings.TrimSpace(id) == "" {
		return Project{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	if p.Name == nil && p.Description == nil {
		return Project{}, fmt.Errorf("%w: nothing to update", ErrInvalid)
	}

	name := ""
	if p.Name != nil {
		name = strings.TrimSpace(*p.Name)
		if name == "" {
			return Project{}, fmt.Errorf("%w: name cannot be empty", ErrInvalid)
		}
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE projects SET
			name        = COALESCE($2, name),
			description = COALESCE($3, description),
			updated_at  = $4
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING %s`, projectColumns),
		id, nullableString(p.Name, name), p.Description, s.clock())

	project, err := scanProject(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Project{}, ErrNotFound
		}
		if isCheckViolation(err) {
			return Project{}, fmt.Errorf("%w: name is not acceptable", ErrInvalid)
		}
		return Project{}, err
	}
	return project, nil
}

// Suspend moves an active project to suspended. Workloads keep existing but the
// project is no longer usable, which is what an operator means by "pause this
// customer".
func (s *Store) Suspend(ctx context.Context, id string) (Project, error) {
	return s.transition(ctx, id, StateSuspended, nil, []string{StateActive})
}

// Resume returns a suspended project to active. A pending_delete project is
// resumed by CancelDelete, not here, because resuming it must also clear the
// deadline — leaving delete_after set would keep a sweeper aiming at a project
// the operator just saved.
func (s *Store) Resume(ctx context.Context, id string) (Project, error) {
	return s.transition(ctx, id, StateActive, nil, []string{StateSuspended})
}

// RequestDelete moves a live project to pending_delete and records the instant
// it may be finalized.
//
// This is the recoverable half of the safe-delete workflow: nothing is destroyed
// here, the row and its resources stay intact, and CancelDelete undoes it. A
// grace duration of zero means DefaultDeleteGrace.
func (s *Store) RequestDelete(ctx context.Context, id string, grace time.Duration) (Project, error) {
	if grace == 0 {
		grace = DefaultDeleteGrace
	}
	if grace < 0 || grace > maxDeleteGrace {
		return Project{}, fmt.Errorf("%w: grace must be between 1s and %s", ErrInvalid, maxDeleteGrace)
	}
	after := s.clock().Add(grace)
	return s.transition(ctx, id, StatePendingDelete, &after,
		[]string{StateActive, StateSuspended})
}

// CancelDelete returns a pending_delete project to active and clears the
// deadline, so a sweeper can no longer finalize it.
func (s *Store) CancelDelete(ctx context.Context, id string) (Project, error) {
	return s.transition(ctx, id, StateActive, nil, []string{StatePendingDelete})
}

// FinalizeDelete tombstones a project whose grace period has elapsed.
//
// It refuses unless the deadline has actually passed and is measured against the
// store clock, so a caller cannot finalize early by passing a stale project it
// read before the request. Finalization sets deleted_at and state together: the
// schema's shape constraint means one without the other is unstorable, so the
// pair is written in one statement rather than two that could be interrupted
// between them.
//
// It also clears delete_after in that same statement. The deadline is a
// pending_delete-only attribute (projects_delete_after_shape), and once the row
// is being tombstoned the deadline has done its job — leaving it set would make
// the update violate the constraint, which is what the grace-period tests caught.
//
// Note what this does NOT do: it does not remove files, Unix users, or site
// rows. Those are separate, separately-audited steps, and doing them here would
// make an unrecoverable filesystem change happen inside a call whose name says
// "finalize a database row".
func (s *Store) FinalizeDelete(ctx context.Context, id string) (Project, error) {
	if strings.TrimSpace(id) == "" {
		return Project{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}

	now := s.clock()
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE projects
		   SET state = 'deleted', deleted_at = $2, delete_after = NULL, updated_at = $2
		 WHERE id = $1
		   AND state = 'pending_delete'
		   AND delete_after IS NOT NULL
		   AND delete_after <= $2
		RETURNING %s`, projectColumns), id, now)

	project, err := scanProject(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// The UPDATE matched nothing. That is either "no such project",
			// "not pending_delete", or "the grace period has not elapsed" — and
			// telling the caller which would leak the state of a project they
			// may not be allowed to see. One error covers all three.
			return Project{}, fmt.Errorf("%w: not deletable", ErrState)
		}
		return Project{}, err
	}
	return project, nil
}

// ListDueForDelete returns projects whose grace period has elapsed, oldest
// deadline first. This is the sweeper's input: it reads the deadline rather than
// trusting a caller to have kept a list.
func (s *Store) ListDueForDelete(ctx context.Context, limit int) ([]Project, error) {
	if limit <= 0 || limit > maxListLimit {
		return nil, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalid, maxListLimit)
	}
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM projects
		 WHERE state = 'pending_delete'
		   AND delete_after IS NOT NULL
		   AND delete_after <= $1
		 ORDER BY delete_after, id
		 LIMIT $2`, projectColumns), s.clock(), limit)
	if err != nil {
		return nil, fmt.Errorf("projects: list due for delete: %w", err)
	}
	defer rows.Close()

	out := make([]Project, 0, limit)
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("projects: iterate due projects: %w", err)
	}
	return out, nil
}

// transition moves a project between states, refusing unless its current state
// is one of allowed.
//
// The current state is read INSIDE the same UPDATE via a WHERE clause rather
// than by a separate SELECT: a read-then-write pair would let two concurrent
// transitions both pass the check and both write, and the loser's write would
// silently win. Making the precondition part of the UPDATE means the database
// arbitrates, and exactly one caller can succeed.
func (s *Store) transition(ctx context.Context, id, to string, deleteAfter *time.Time, allowed []string) (Project, error) {
	if strings.TrimSpace(id) == "" {
		return Project{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	if len(allowed) == 0 {
		return Project{}, errors.New("projects: transition requires at least one allowed source state")
	}
	now := s.clock()

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE projects
		   SET state = $2, delete_after = $3, updated_at = $4
		 WHERE id = $1
		   AND deleted_at IS NULL
		   AND state = ANY($5::text[])
		RETURNING %s`, projectColumns),
		id, to, deleteAfter, now, allowed)

	project, err := scanProject(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// Either the project is gone or its state is not one this
			// transition may start from. Both are ErrState, because the caller
			// asked for a transition that cannot happen, not for a row.
			return Project{}, fmt.Errorf("%w: cannot move to %s", ErrState, to)
		}
		return Project{}, err
	}
	return project, nil
}

// validateSlug mirrors migrations/0014's projects_slug_safe and
// projects_slug_length. Keeping the two in step is a test's job, not a
// comment's: see the slug-alphabet test in internal/projects.
func validateSlug(slug string) error {
	if len(slug) < 3 || len(slug) > 48 {
		return fmt.Errorf("%w: slug must be between 3 and 48 characters", ErrInvalid)
	}
	for i := 0; i < len(slug); i++ {
		c := slug[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' && i > 0 && i < len(slug)-1:
			// A hyphen is legal only between two alphanumerics. The position
			// check is what makes ".." and "-a" unreachable, and it is also why
			// a slug can never be a path fragment: '/' is not in the alphabet at
			// all.
		default:
			return fmt.Errorf("%w: slug %q contains %q; allowed are a-z, 0-9 and single hyphens",
				ErrInvalid, slug, string(c))
		}
	}
	return nil
}

// nullableString returns the trimmed value when the pointer was set, else nil,
// so COALESCE leaves the column untouched. Explicit rather than relying on pgx
// dereferencing the pointer: a partial update must not be able to distinguish
// "caller omitted this field" from "caller sent an empty one", and this makes
// that distinction the only thing nil can mean.
func nullableString(set *string, trimmed string) any {
	if set == nil {
		return nil
	}
	return trimmed
}

// isUniqueViolation reports a PostgreSQL unique-constraint breach (23505).
func isUniqueViolation(err error) bool { return pgCode(err) == "23505" }

// isCheckViolation reports a CHECK constraint breach (23514).
func isCheckViolation(err error) bool { return pgCode(err) == "23514" }

func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}
