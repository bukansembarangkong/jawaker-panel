// Package sites owns the hosted-site rows: the lifecycle, the mode-specific
// shape, and the pointer to the configuration revision currently in force.
//
// A site belongs to exactly one project and runs on exactly one server
// (migrations/0014). This package is deliberately the ONLY writer of the `sites`
// table, so the state machine cannot be bypassed by a second caller assembling
// its own UPDATE — the same rule internal/projects follows for the tenant
// boundary above it.
//
// It holds no authorization logic. RBAC decides whether a caller may act; this
// package decides what acting means and makes the schema's invariants impossible
// to violate by accident.
package sites

import (
	"context"
	"encoding/json"
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
	ErrInvalid = errors.New("sites: invalid argument")
	// ErrNotFound is returned when the site does not exist or is tombstoned. A
	// missing site and a deleted one return the SAME error: distinguishing them
	// would tell a caller that an id it guessed corresponds to a real, deleted
	// row, which is an enumeration oracle.
	ErrNotFound = errors.New("sites: not found")
	// ErrSlugTaken is returned when a live site in the same project already uses
	// the slug. Slug uniqueness is per project (sites_slug_unique_idx), so two
	// projects may each have a "www".
	ErrSlugTaken = errors.New("sites: slug already in use in this project")
	// ErrState is returned for a transition the lifecycle does not permit, or for
	// an operation refused because the parent project is not usable.
	ErrState = errors.New("sites: invalid state transition")
)

// Lifecycle states (DATABASE.md §7, migrations/0014). Identical vocabulary to
// projects: a site moves active -> pending_delete -> deleted and keeps its row,
// because revision and audit rows reference it and must stay resolvable.
const (
	StateActive        = "active"
	StateSuspended     = "suspended"
	StatePendingDelete = "pending_delete"
	StateDeleted       = "deleted"
)

// Serving modes (PRD.md §9.1, IMPLEMENTATION_PLAN.md Phase 3). The schema CHECK
// bounds `mode` to exactly these three; containerised and external-upstream modes
// arrive with the phases that own them. ModeNodeJS extends Phase 3 with
// per-site Node.js process management (migrations/0038).
const (
	ModeStatic       = "static"
	ModePHP          = "php"
	ModeReverseProxy = "reverse_proxy"
	ModeNodeJS       = "nodejs"
)

// DefaultDeleteGrace is how long a site stays in pending_delete before it may be
// finalized. The spec requires a recoverable delete but never states a duration;
// seven days matches the project-level decision recorded in docs/decisions.md.
const DefaultDeleteGrace = 7 * 24 * time.Hour

// maxDeleteGrace bounds what a caller may ask for. An unbounded grace period is a
// site that is never deleted, which defeats the purpose of having one.
const maxDeleteGrace = 90 * 24 * time.Hour

// maxListLimit bounds a page. Matches internal/projects and internal/nodes so a
// caller cannot ask for the whole table and call it a list.
const maxListLimit = 200

// Site is one hosted site.
type Site struct {
	ID        string
	ProjectID string
	ServerID  string
	Slug      string
	Name      string
	Mode      string
	State     string
	// DocRoot, Upstream and PHPUnit are paths and units AS THE NODE SEES THEM.
	// Upstream is non-empty exactly when Mode is reverse_proxy, and PHPUnit only
	// when Mode is php; the schema CHECKs enforce both shapes, so these fields are
	// never a guess.
	DocRoot  string
	Upstream string
	PHPUnit  string
	// AppliedRevisionID is the configuration revision currently in force. Nil
	// until the first configuration is applied — a site exists before it serves.
	AppliedRevisionID *string
	CreatedBy         *string
	CreatedAt         time.Time
	UpdatedAt         time.Time
	// DeleteAfter is non-nil exactly when State is pending_delete; DeletedAt is
	// non-nil exactly when State is deleted. The schema's two shape constraints
	// make those the only storable combinations.
	DeleteAfter *time.Time
	DeletedAt   *time.Time
}

// Live reports whether the site is not tombstoned. A suspended site is still
// live: it exists, it can be resumed, and its files are intact.
func (s Site) Live() bool { return s.DeletedAt == nil }

// Usable reports whether the site may serve. Only an active site is usable;
// suspended and pending_delete are not.
func (s Site) Usable() bool { return s.State == StateActive }

const siteColumns = `id, project_id, server_id, slug, name, mode, state,
	doc_root, upstream, php_unit, applied_revision_id, created_by,
	created_at, updated_at, delete_after, deleted_at`

func scanSite(row pgx.Row) (Site, error) {
	var s Site
	err := row.Scan(&s.ID, &s.ProjectID, &s.ServerID, &s.Slug, &s.Name, &s.Mode, &s.State,
		&s.DocRoot, &s.Upstream, &s.PHPUnit, &s.AppliedRevisionID, &s.CreatedBy,
		&s.CreatedAt, &s.UpdatedAt, &s.DeleteAfter, &s.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Site{}, ErrNotFound
	}
	if err != nil {
		return Site{}, fmt.Errorf("sites: scan site: %w", err)
	}
	return s, nil
}

// Store reads and writes the sites table.
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

// CreateParams configures site creation.
type CreateParams struct {
	ProjectID string
	ServerID  string
	Slug      string
	Name      string
	Mode      string
	// DocRoot is optional at creation; the deploy pipeline may set it later.
	DocRoot string
	// Upstream is required when Mode is reverse_proxy and must be empty otherwise.
	Upstream string
	// PHPUnit is only meaningful when Mode is php and must be empty otherwise.
	PHPUnit   string
	CreatedBy string
}

// Create inserts a site in the active state.
//
// The parent project must be ACTIVE: a site created inside a suspended or
// pending_delete project would be a workload running in a tenant that is paused
// or on its way out. That precondition is checked INSIDE the INSERT via a WHERE
// EXISTS subquery rather than by a separate SELECT, so a project suspended
// concurrently with this create cannot let a site slip in — the database
// arbitrates and exactly one outcome is possible.
//
// Mode-specific fields are validated here as well as by the schema. The schema
// constraint is the authority; checking first means the caller gets a message
// naming the offending value instead of a PostgreSQL error string.
func (s *Store) Create(ctx context.Context, p CreateParams) (Site, error) {
	projectID := strings.TrimSpace(p.ProjectID)
	if projectID == "" {
		return Site{}, fmt.Errorf("%w: project_id is required", ErrInvalid)
	}
	serverID := strings.TrimSpace(p.ServerID)
	if serverID == "" {
		return Site{}, fmt.Errorf("%w: server_id is required", ErrInvalid)
	}
	slug := strings.ToLower(strings.TrimSpace(p.Slug))
	if err := validateSlug(slug); err != nil {
		return Site{}, err
	}
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return Site{}, fmt.Errorf("%w: name is required", ErrInvalid)
	}
	mode := strings.TrimSpace(p.Mode)
	if err := validateMode(mode); err != nil {
		return Site{}, err
	}
	upstream := strings.TrimSpace(p.Upstream)
	phpUnit := strings.TrimSpace(p.PHPUnit)
	if err := validateModeFields(mode, upstream, phpUnit); err != nil {
		return Site{}, err
	}

	var createdBy any
	if v := strings.TrimSpace(p.CreatedBy); v != "" {
		createdBy = v
	}

	// INSERT ... SELECT ... WHERE EXISTS keeps the "project is active" precondition
	// atomic with the insert. When the project is missing, not active, or
	// tombstoned the SELECT yields no row, the INSERT writes nothing, and the
	// RETURNING scan sees no rows — reported as ErrState, not as a silent success.
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO sites (project_id, server_id, slug, name, mode, doc_root, upstream, php_unit, created_by)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9
		 WHERE EXISTS (
			SELECT 1 FROM projects
			 WHERE id = $1 AND state = 'active' AND deleted_at IS NULL)
		RETURNING %s`, siteColumns),
		projectID, serverID, slug, name, mode, p.DocRoot, upstream, phpUnit, createdBy)

	site, err := scanSite(row)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			// The WHERE EXISTS matched nothing: the project is absent, suspended,
			// or pending_delete. All three are "you may not create here", reported
			// as one state error so the response does not disclose which.
			return Site{}, fmt.Errorf("%w: the project is not active or does not exist", ErrState)
		case isUniqueViolation(err):
			return Site{}, ErrSlugTaken
		case isForeignKeyViolation(err):
			// server_id (or project_id) names a row that does not exist. The
			// controller authorizes the project before reaching here, so in
			// practice this is a bad server_id.
			return Site{}, fmt.Errorf("%w: the project or server does not exist", ErrInvalid)
		case isCheckViolation(err):
			// The schema refused something the Go validator accepted. Reporting it
			// as ErrInvalid would hide the disagreement; this is a bug in one of
			// the two and must be visible.
			return Site{}, fmt.Errorf("sites: schema rejected site: %w", err)
		default:
			return Site{}, err
		}
	}
	return site, nil
}

// Get returns one live site by id.
func (s *Store) Get(ctx context.Context, id string) (Site, error) {
	if strings.TrimSpace(id) == "" {
		return Site{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT %s FROM sites WHERE id = $1 AND deleted_at IS NULL`, siteColumns), id)
	return scanSite(row)
}

// GetInProject returns one live site by id, but only when it belongs to the named
// project. A site in a different project is reported as ErrNotFound — NOT as a
// permission error — so the controller can answer 404 rather than 403 and avoid
// confirming that the id exists in someone else's project.
func (s *Store) GetInProject(ctx context.Context, projectID, id string) (Site, error) {
	if strings.TrimSpace(projectID) == "" || strings.TrimSpace(id) == "" {
		return Site{}, fmt.Errorf("%w: project_id and id are required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT %s FROM sites
		 WHERE id = $1 AND project_id = $2 AND deleted_at IS NULL`, siteColumns), id, projectID)
	return scanSite(row)
}

// List returns a page of live sites in one project, newest first, plus the total
// count matching the filter.
//
// The project predicate is applied SERVER-SIDE in both the count and the page
// (API.md §5): a list endpoint must filter inaccessible rows in the query, never
// fetch everything and hide some client-side.
func (s *Store) List(ctx context.Context, projectID string, limit, offset int, state string) ([]Site, int, error) {
	if strings.TrimSpace(projectID) == "" {
		return nil, 0, fmt.Errorf("%w: project_id is required", ErrInvalid)
	}
	if limit <= 0 || limit > maxListLimit {
		return nil, 0, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalid, maxListLimit)
	}
	if offset < 0 {
		return nil, 0, fmt.Errorf("%w: offset cannot be negative", ErrInvalid)
	}
	var filter any
	switch state {
	case "":
		filter = nil
	case StateActive, StateSuspended, StatePendingDelete:
		filter = state
	default:
		return nil, 0, fmt.Errorf("%w: unknown state filter %q", ErrInvalid, state)
	}

	// project_id is $1 in both queries so the count and the page cannot disagree
	// about whose sites they are describing.
	const where = `WHERE deleted_at IS NULL AND project_id = $1 AND ($2::text IS NULL OR state = $2)`

	var total int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM sites `+where, projectID, filter).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("sites: count sites: %w", err)
	}

	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM sites %s
		ORDER BY created_at DESC, id
		LIMIT $3 OFFSET $4`, siteColumns, where), projectID, filter, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("sites: list sites: %w", err)
	}
	defer rows.Close()

	out := make([]Site, 0, limit)
	for rows.Next() {
		site, err := scanSite(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, site)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("sites: iterate sites: %w", err)
	}
	return out, total, nil
}

// UpdateParams carries the editable fields. A nil pointer means "leave
// unchanged", which is how a partial update avoids clearing a field the caller
// never mentioned.
//
// Mode is NOT editable: changing static -> php would invalidate the entire
// generated configuration and the runtime model, so it is a delete-and-recreate,
// not an edit. The mode-specific CHECKs are evaluated against the site's EXISTING
// mode, so an upstream on a non-proxy site is refused by the schema.
type UpdateParams struct {
	Name     *string
	DocRoot  *string
	Upstream *string
	PHPUnit  *string
}

// Update changes the editable fields of a live site.
func (s *Store) Update(ctx context.Context, id string, p UpdateParams) (Site, error) {
	if strings.TrimSpace(id) == "" {
		return Site{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	if p.Name == nil && p.DocRoot == nil && p.Upstream == nil && p.PHPUnit == nil {
		return Site{}, fmt.Errorf("%w: nothing to update", ErrInvalid)
	}
	if p.Name != nil && strings.TrimSpace(*p.Name) == "" {
		return Site{}, fmt.Errorf("%w: name cannot be empty", ErrInvalid)
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE sites SET
			name      = COALESCE($2, name),
			doc_root  = COALESCE($3, doc_root),
			upstream  = COALESCE($4, upstream),
			php_unit  = COALESCE($5, php_unit),
			updated_at = $6
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING %s`, siteColumns),
		id, nullableTrimmed(p.Name), nullableTrimmed(p.DocRoot),
		nullableTrimmed(p.Upstream), nullableTrimmed(p.PHPUnit), s.clock())

	site, err := scanSite(row)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			return Site{}, ErrNotFound
		case isCheckViolation(err):
			// Almost always a mode/field mismatch (an upstream on a static site, a
			// php_unit on a non-php site). The schema is the authority; the message
			// names the rule without echoing the constraint internals.
			return Site{}, fmt.Errorf("%w: a field is not valid for this site's mode", ErrInvalid)
		default:
			return Site{}, err
		}
	}
	return site, nil
}

// SetAppliedRevision records the configuration revision now in force for a live
// site. The deploy pipeline calls this AFTER revisions.Apply succeeds, so the
// site row and the revision history agree about what is serving.
//
// It does not change the site's lifecycle state: a site is active from creation,
// and whether it has a configuration applied yet is answered by
// AppliedRevisionID, not by State.
func (s *Store) SetAppliedRevision(ctx context.Context, id, revisionID string) (Site, error) {
	if strings.TrimSpace(id) == "" || strings.TrimSpace(revisionID) == "" {
		return Site{}, fmt.Errorf("%w: id and revision_id are required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE sites SET applied_revision_id = $2, updated_at = $3
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING %s`, siteColumns), id, revisionID, s.clock())
	site, err := scanSite(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Site{}, ErrNotFound
		}
		return Site{}, err
	}
	return site, nil
}

// Suspend moves an active site to suspended.
func (s *Store) Suspend(ctx context.Context, id string) (Site, error) {
	return s.transition(ctx, id, StateSuspended, nil, []string{StateActive})
}

// Resume returns a suspended site to active.
func (s *Store) Resume(ctx context.Context, id string) (Site, error) {
	return s.transition(ctx, id, StateActive, nil, []string{StateSuspended})
}

// RequestDelete moves a live site to pending_delete and records the instant it
// may be finalized. This is the recoverable half of the safe-delete workflow:
// nothing is destroyed here and CancelDelete undoes it. A grace of zero means
// DefaultDeleteGrace.
func (s *Store) RequestDelete(ctx context.Context, id string, grace time.Duration) (Site, error) {
	if grace == 0 {
		grace = DefaultDeleteGrace
	}
	if grace < 0 || grace > maxDeleteGrace {
		return Site{}, fmt.Errorf("%w: grace must be between 1s and %s", ErrInvalid, maxDeleteGrace)
	}
	after := s.clock().Add(grace)
	return s.transition(ctx, id, StatePendingDelete, &after,
		[]string{StateActive, StateSuspended})
}

// CancelDelete returns a pending_delete site to active and clears the deadline,
// so a sweeper can no longer finalize it.
func (s *Store) CancelDelete(ctx context.Context, id string) (Site, error) {
	return s.transition(ctx, id, StateActive, nil, []string{StatePendingDelete})
}

// FinalizeDelete tombstones a site whose grace period has elapsed.
//
// It refuses unless the deadline has actually passed, measured against the store
// clock, so a caller cannot finalize early with a stale row it read before the
// request. state, deleted_at and a cleared delete_after are written in ONE
// statement: the two shape constraints mean any other combination is unstorable.
// This is the same defect class that FinalizeDelete in internal/projects hit, and
// the fix is the same — clearing delete_after as part of the tombstone.
//
// Note what this does NOT do: it does not remove files, the nginx config, or the
// Unix user. Those are separate, separately-audited steps performed through the
// validated pipeline; doing them here would make an unrecoverable filesystem
// change happen inside a call whose name says "finalize a database row".
func (s *Store) FinalizeDelete(ctx context.Context, id string) (Site, error) {
	if strings.TrimSpace(id) == "" {
		return Site{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	now := s.clock()
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE sites
		   SET state = 'deleted', deleted_at = $2, delete_after = NULL, updated_at = $2
		 WHERE id = $1
		   AND state = 'pending_delete'
		   AND delete_after IS NOT NULL
		   AND delete_after <= $2
		RETURNING %s`, siteColumns), id, now)
	site, err := scanSite(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			// No such site, not pending_delete, or the grace has not elapsed. One
			// error covers all three so the response cannot leak which.
			return Site{}, fmt.Errorf("%w: not deletable", ErrState)
		}
		return Site{}, err
	}
	return site, nil
}

// ListDueForDelete returns sites whose grace period has elapsed, oldest deadline
// first. This is the sweeper's input: it reads the deadline rather than trusting
// a caller to have kept a list.
func (s *Store) ListDueForDelete(ctx context.Context, limit int) ([]Site, error) {
	if limit <= 0 || limit > maxListLimit {
		return nil, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalid, maxListLimit)
	}
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM sites
		 WHERE state = 'pending_delete'
		   AND delete_after IS NOT NULL
		   AND delete_after <= $1
		 ORDER BY delete_after, id
		 LIMIT $2`, siteColumns), s.clock(), limit)
	if err != nil {
		return nil, fmt.Errorf("sites: list due for delete: %w", err)
	}
	defer rows.Close()

	out := make([]Site, 0, limit)
	for rows.Next() {
		site, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, site)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("sites: iterate due sites: %w", err)
	}
	return out, nil
}

// transition moves a site between states, refusing unless its current state is
// one of allowed.
//
// The precondition is part of the UPDATE's WHERE clause rather than a separate
// SELECT: a read-then-write pair would let two concurrent transitions both pass
// the check and both write, and the loser's write would silently win. With the
// precondition in the UPDATE, the database arbitrates and exactly one caller can
// succeed.
func (s *Store) transition(ctx context.Context, id, to string, deleteAfter *time.Time, allowed []string) (Site, error) {
	if strings.TrimSpace(id) == "" {
		return Site{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	if len(allowed) == 0 {
		return Site{}, errors.New("sites: transition requires at least one allowed source state")
	}
	now := s.clock()

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE sites
		   SET state = $2, delete_after = $3, updated_at = $4
		 WHERE id = $1
		   AND deleted_at IS NULL
		   AND state = ANY($5::text[])
		RETURNING %s`, siteColumns),
		id, to, deleteAfter, now, allowed)

	site, err := scanSite(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return Site{}, fmt.Errorf("%w: cannot move to %s", ErrState, to)
		}
		return Site{}, err
	}
	return site, nil
}

// validateSlug mirrors migrations/0014's sites_slug_safe and sites_slug_length.
// NOTE the length bound differs from projects: a site slug is 1..48, a project
// slug is 3..48. The alphabet is identical — lowercase alphanumerics and single
// internal hyphens — which is what makes a slug safe to use as a path fragment
// and a Unix-friendly name: '/' and every shell metacharacter are simply absent.
func validateSlug(slug string) error {
	if len(slug) < 1 || len(slug) > 48 {
		return fmt.Errorf("%w: slug must be between 1 and 48 characters", ErrInvalid)
	}
	for i := 0; i < len(slug); i++ {
		c := slug[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= '0' && c <= '9':
		case c == '-' && i > 0 && i < len(slug)-1:
			// A hyphen is legal only between two alphanumerics. The position check
			// is what makes ".." and a leading/trailing hyphen unreachable.
		default:
			return fmt.Errorf("%w: slug %q contains %q; allowed are a-z, 0-9 and single hyphens",
				ErrInvalid, slug, string(c))
		}
	}
	return nil
}

// validateMode bounds the mode to the Phase 3 serves plus nodejs.
func validateMode(mode string) error {
	switch mode {
	case ModeStatic, ModePHP, ModeReverseProxy, ModeNodeJS:
		return nil
	default:
		return fmt.Errorf("%w: mode %q must be one of static, php, reverse_proxy, nodejs", ErrInvalid, mode)
	}
}

// validateModeFields enforces the mode/field shape CHECKs in Go so the caller
// gets a precise message. The schema is still the authority; this only front-runs
// it.
//
//	sites_upstream_matches_mode: (mode IN ('reverse_proxy','nodejs')) = (upstream <> '')
//	sites_php_unit_matches_mode: mode = 'php' OR php_unit = ''
func validateModeFields(mode, upstream, phpUnit string) error {
	if mode == ModeReverseProxy || mode == ModeNodeJS {
		if upstream == "" {
			return fmt.Errorf("%w: a %s site requires an upstream", ErrInvalid, mode)
		}
	} else if upstream != "" {
		return fmt.Errorf("%w: only a reverse_proxy or nodejs site may set an upstream", ErrInvalid)
	}
	if mode != ModePHP && phpUnit != "" {
		return fmt.Errorf("%w: only a php site may set a php_unit", ErrInvalid)
	}
	return nil
}

// nullableTrimmed returns the trimmed value when the pointer was set, else nil, so
// COALESCE leaves the column untouched. Explicit rather than relying on pgx to
// dereference: a partial update must not distinguish "caller omitted this field"
// from "caller sent an empty one", and this makes nil mean exactly one thing.
func nullableTrimmed(set *string) any {
	if set == nil {
		return nil
	}
	return strings.TrimSpace(*set)
}

// isUniqueViolation reports a PostgreSQL unique-constraint breach (23505).
func isUniqueViolation(err error) bool { return pgCode(err) == "23505" }

// isCheckViolation reports a CHECK constraint breach (23514).
func isCheckViolation(err error) bool { return pgCode(err) == "23514" }

// isForeignKeyViolation reports a foreign-key breach (23503).
func isForeignKeyViolation(err error) bool { return pgCode(err) == "23503" }

func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// ─── Node.js runtime configuration ───────────────────────────────────────────

// NodeJSConfig holds the per-site Node.js runtime settings stored in
// site_nodejs_configs (migrations/0038).
type NodeJSConfig struct {
	ID          string
	SiteID      string
	NodeVersion string
	AppRoot     string
	StartupFile string
	StartArgs   []string
	EnvVars     map[string]string
	Port        int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// UpsertNodeJSConfigParams carries the fields an operator may set.
type UpsertNodeJSConfigParams struct {
	NodeVersion string
	AppRoot     string
	StartupFile string
	StartArgs   []string
	EnvVars     map[string]string
	Port        int
}

const nodejsColumns = `id, site_id, node_version, app_root, startup_file, start_args, env_vars, port, created_at, updated_at`

func scanNodeJSConfig(row pgx.Row) (NodeJSConfig, error) {
	var c NodeJSConfig
	var startArgs, envVars []byte
	err := row.Scan(
		&c.ID, &c.SiteID, &c.NodeVersion, &c.AppRoot, &c.StartupFile,
		&startArgs, &envVars, &c.Port, &c.CreatedAt, &c.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return NodeJSConfig{}, ErrNotFound
	}
	if err != nil {
		return NodeJSConfig{}, fmt.Errorf("sites: scan nodejs config: %w", err)
	}
	if err := json.Unmarshal(startArgs, &c.StartArgs); err != nil {
		return NodeJSConfig{}, fmt.Errorf("sites: unmarshal start_args: %w", err)
	}
	if err := json.Unmarshal(envVars, &c.EnvVars); err != nil {
		return NodeJSConfig{}, fmt.Errorf("sites: unmarshal env_vars: %w", err)
	}
	return c, nil
}

// GetNodeJSConfig returns the Node.js config for the given site.
// Returns ErrNotFound when no config row exists yet.
func (s *Store) GetNodeJSConfig(ctx context.Context, siteID string) (NodeJSConfig, error) {
	if strings.TrimSpace(siteID) == "" {
		return NodeJSConfig{}, fmt.Errorf("%w: site_id is required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM site_nodejs_configs WHERE site_id = $1`, nodejsColumns), siteID)
	return scanNodeJSConfig(row)
}

// UpsertNodeJSConfig creates or replaces the Node.js config for a site.
// The site must exist (FK enforced by schema). Updated fields replace all
// existing values — this is a full overwrite, not a partial update.
func (s *Store) UpsertNodeJSConfig(ctx context.Context, siteID string, p UpsertNodeJSConfigParams) (NodeJSConfig, error) {
	if strings.TrimSpace(siteID) == "" {
		return NodeJSConfig{}, fmt.Errorf("%w: site_id is required", ErrInvalid)
	}
	if p.Port != 0 && (p.Port < 1024 || p.Port > 65535) {
		return NodeJSConfig{}, fmt.Errorf("%w: port must be between 1024 and 65535", ErrInvalid)
	}
	port := p.Port
	if port == 0 {
		port = 3000
	}
	startArgs := p.StartArgs
	if startArgs == nil {
		startArgs = []string{}
	}
	startArgsJSON, err := json.Marshal(startArgs)
	if err != nil {
		return NodeJSConfig{}, fmt.Errorf("%w: start_args: %v", ErrInvalid, err)
	}
	envVars := p.EnvVars
	if envVars == nil {
		envVars = map[string]string{}
	}
	envVarsJSON, err := json.Marshal(envVars)
	if err != nil {
		return NodeJSConfig{}, fmt.Errorf("%w: env_vars: %v", ErrInvalid, err)
	}

	nodeVersion := p.NodeVersion
	if nodeVersion == "" {
		nodeVersion = "system"
	}
	startupFile := p.StartupFile
	if startupFile == "" {
		startupFile = "server.js"
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO site_nodejs_configs
			(site_id, node_version, app_root, startup_file, start_args, env_vars, port, updated_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7, $8)
		ON CONFLICT (site_id) DO UPDATE SET
			node_version = EXCLUDED.node_version,
			app_root     = EXCLUDED.app_root,
			startup_file = EXCLUDED.startup_file,
			start_args   = EXCLUDED.start_args,
			env_vars     = EXCLUDED.env_vars,
			port         = EXCLUDED.port,
			updated_at   = EXCLUDED.updated_at
		RETURNING %s`, nodejsColumns),
		siteID, nodeVersion, p.AppRoot, startupFile,
		string(startArgsJSON), string(envVarsJSON), port, s.clock())

	c, err := scanNodeJSConfig(row)
	if err != nil {
		switch {
		case isForeignKeyViolation(err):
			return NodeJSConfig{}, fmt.Errorf("%w: site does not exist", ErrInvalid)
		case isCheckViolation(err):
			return NodeJSConfig{}, fmt.Errorf("sites: schema rejected nodejs config: %w", err)
		default:
			return NodeJSConfig{}, err
		}
	}
	return c, nil
}
