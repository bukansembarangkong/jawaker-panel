// Package apps owns the application lifecycle: the state machine, deployment
// records, release tracking, environment variables, and webhook tokens.
//
// An application belongs to exactly one project and runs on exactly one server
// (migrations/0016, docs/decisions.md D-003). This package is the ONLY writer
// of the apps-domain tables; the state machine cannot be bypassed by another
// caller assembling its own UPDATE.
//
// It holds no authorization logic. RBAC decides whether a caller may act; this
// package decides what acting means and makes the schema's invariants impossible
// to violate by accident.
package apps

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors. Callers branch on these to choose an HTTP status.
var (
	// ErrInvalid is returned for a caller-supplied value that cannot be stored.
	ErrInvalid = errors.New("apps: invalid argument")
	// ErrNotFound is returned when the resource does not exist or is tombstoned.
	// A missing and a deleted row return the SAME error to avoid enumeration oracles.
	ErrNotFound = errors.New("apps: not found")
	// ErrSlugTaken is returned when a live app in the same project already uses
	// the slug.
	ErrSlugTaken = errors.New("apps: slug already in use in this project")
	// ErrState is returned for a transition the lifecycle does not permit.
	ErrState = errors.New("apps: invalid state transition")
	// ErrConflictActive is returned when an operation requires no active
	// deployment but one already exists (queued or running).
	ErrConflictActive = errors.New("apps: a deployment is already queued or running")
)

// App lifecycle states (DATABASE.md §7, migrations/0016).
const (
	StateActive        = "active"
	StateSuspended     = "suspended"
	StatePendingDelete = "pending_delete"
	StateDeleted       = "deleted"
)

// Runtime types (PRD.md §10, IMPLEMENTATION_PLAN.md Phase 4).
const (
	RuntimeNode   = "node"
	RuntimeBun    = "bun"
	RuntimePython = "python"
	RuntimePHP    = "php"
	RuntimeStatic = "static"
)

// Deployment states (migrations/0016).
const (
	DeployQueued     = "queued"
	DeployRunning    = "running"
	DeploySucceeded  = "succeeded"
	DeployFailed     = "failed"
	DeployRolledBack = "rolled_back"
	DeployCanceled   = "canceled"
)

// DeployTrigger values (migrations/0016).
const (
	TriggerManual   = "manual"
	TriggerWebhook  = "webhook"
	TriggerRollback = "rollback"
)

// HealthState values for app_releases.
const (
	HealthUnknown   = "unknown"
	HealthHealthy   = "healthy"
	HealthUnhealthy = "unhealthy"
)

// ValueSource for app_env_vars.
const (
	ValueLiteral   = "literal"
	ValueSecretRef = "secret_ref"
)

const (
	DefaultDeleteGrace = 7 * 24 * time.Hour
	maxDeleteGrace     = 90 * 24 * time.Hour
	maxListLimit       = 200
)

// App is one managed application workload.
type App struct {
	ID               string
	ProjectID        string
	ServerID         string
	Slug             string
	Name             string
	RuntimeType      string
	State            string
	GitRepoURL       string
	GitRefDefault    string
	GitCredentialRef *string
	BuildProgram     string
	BuildArgs        []string
	StartProgram     string
	StartArgs        []string
	WorkingDir       string
	Port             *int
	HealthPath       *string
	EnvName          string
	CreatedBy        *string
	CreatedAt        time.Time
	UpdatedAt        time.Time
	DeleteAfter      *time.Time
	DeletedAt        *time.Time
}

// Live reports whether the app is not tombstoned.
func (a App) Live() bool { return a.DeletedAt == nil }

// Usable reports whether the app may accept deployments.
func (a App) Usable() bool { return a.State == StateActive }

const appColumns = `id, project_id, server_id, slug, name, runtime_type, state,
	git_repo_url, git_ref_default, git_credential_ref,
	build_program, build_args, start_program, start_args, working_dir,
	port, health_path, env_name, created_by, created_at, updated_at,
	delete_after, deleted_at`

func scanApp(row pgx.Row) (App, error) {
	var a App
	var buildArgs, startArgs []byte
	err := row.Scan(
		&a.ID, &a.ProjectID, &a.ServerID, &a.Slug, &a.Name, &a.RuntimeType, &a.State,
		&a.GitRepoURL, &a.GitRefDefault, &a.GitCredentialRef,
		&a.BuildProgram, &buildArgs, &a.StartProgram, &startArgs, &a.WorkingDir,
		&a.Port, &a.HealthPath, &a.EnvName, &a.CreatedBy,
		&a.CreatedAt, &a.UpdatedAt, &a.DeleteAfter, &a.DeletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return App{}, ErrNotFound
	}
	if err != nil {
		return App{}, fmt.Errorf("apps: scan app: %w", err)
	}
	if err := json.Unmarshal(buildArgs, &a.BuildArgs); err != nil {
		return App{}, fmt.Errorf("apps: unmarshal build_args: %w", err)
	}
	if err := json.Unmarshal(startArgs, &a.StartArgs); err != nil {
		return App{}, fmt.Errorf("apps: unmarshal start_args: %w", err)
	}
	return a, nil
}

// Deployment is one deployment attempt record.
type Deployment struct {
	ID             string
	AppID          string
	ProjectID      string
	ServerID       string
	Trigger        string
	CommitSHA      *string
	GitRef         string
	State          string
	ErrorCode      string
	ErrorSummary   string
	JobID          *string
	RequestedBy    *string
	IdempotencyKey *string
	CreatedAt      time.Time
	StartedAt      *time.Time
	FinishedAt     *time.Time
}

const deployColumns = `id, app_id, project_id, server_id, trigger, commit_sha,
	git_ref, state, error_code, error_summary, job_id, requested_by,
	idempotency_key, created_at, started_at, finished_at`

func scanDeployment(row pgx.Row) (Deployment, error) {
	var d Deployment
	err := row.Scan(
		&d.ID, &d.AppID, &d.ProjectID, &d.ServerID, &d.Trigger, &d.CommitSHA,
		&d.GitRef, &d.State, &d.ErrorCode, &d.ErrorSummary, &d.JobID, &d.RequestedBy,
		&d.IdempotencyKey, &d.CreatedAt, &d.StartedAt, &d.FinishedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return Deployment{}, ErrNotFound
	}
	if err != nil {
		return Deployment{}, fmt.Errorf("apps: scan deployment: %w", err)
	}
	return d, nil
}

// Release is one atomic release directory.
type Release struct {
	ID           string
	AppID        string
	DeploymentID string
	ReleasePath  string
	CommitSHA    string
	IsCurrent    bool
	HealthState  string
	CreatedAt    time.Time
}

const releaseColumns = `id, app_id, deployment_id, release_path, commit_sha, is_current, health_state, created_at`

func scanRelease(row pgx.Row) (Release, error) {
	var r Release
	err := row.Scan(&r.ID, &r.AppID, &r.DeploymentID, &r.ReleasePath, &r.CommitSHA, &r.IsCurrent, &r.HealthState, &r.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Release{}, ErrNotFound
	}
	if err != nil {
		return Release{}, fmt.Errorf("apps: scan release: %w", err)
	}
	return r, nil
}

// EnvVar is one environment variable or secret reference for an app.
type EnvVar struct {
	ID          string
	AppID       string
	Name        string
	ValueSource string
	// LiteralValue is set when ValueSource == ValueLiteral.
	LiteralValue *string
	// SecretRef is set when ValueSource == ValueSecretRef.
	// It is always a secret:// URI — the plaintext value is never stored here.
	SecretRef *string
	CreatedAt time.Time
	UpdatedAt time.Time
}

const envVarColumns = `id, app_id, name, value_source, literal_value, secret_ref, created_at, updated_at`

func scanEnvVar(row pgx.Row) (EnvVar, error) {
	var e EnvVar
	err := row.Scan(&e.ID, &e.AppID, &e.Name, &e.ValueSource, &e.LiteralValue, &e.SecretRef, &e.CreatedAt, &e.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return EnvVar{}, ErrNotFound
	}
	if err != nil {
		return EnvVar{}, fmt.Errorf("apps: scan env_var: %w", err)
	}
	return e, nil
}

// WebhookToken is a git push trigger token for an app.
type WebhookToken struct {
	ID         string
	AppID      string
	TokenHash  string
	State      string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// Store reads and writes the apps-domain tables.
type Store struct {
	pool  *pgxpool.Pool
	clock func() time.Time
}

// NewStore builds a Store over a pool. now may be nil (defaults to time.Now).
func NewStore(pool *pgxpool.Pool, now func() time.Time) *Store {
	clock := now
	if clock == nil {
		clock = time.Now
	}
	return &Store{pool: pool, clock: clock}
}

// ─── App CRUD ────────────────────────────────────────────────────────────────

// CreateAppParams configures application creation.
type CreateAppParams struct {
	ProjectID     string
	ServerID      string
	Slug          string
	Name          string
	RuntimeType   string
	GitRepoURL    string
	GitRefDefault string
	BuildProgram  string
	BuildArgs     []string
	StartProgram  string
	StartArgs     []string
	WorkingDir    string
	Port          *int
	HealthPath    *string
	EnvName       string
	CreatedBy     string
}

// CreateApp inserts an app in the active state.
//
// The parent project must be active — the INSERT uses a WHERE EXISTS to make this
// atomic with the insert, so a project suspended concurrently cannot slip an app in.
func (s *Store) CreateApp(ctx context.Context, p CreateAppParams) (App, error) {
	projectID := strings.TrimSpace(p.ProjectID)
	if projectID == "" {
		return App{}, fmt.Errorf("%w: project_id is required", ErrInvalid)
	}
	serverID := strings.TrimSpace(p.ServerID)
	if serverID == "" {
		return App{}, fmt.Errorf("%w: server_id is required", ErrInvalid)
	}
	slug := strings.ToLower(strings.TrimSpace(p.Slug))
	if err := validateSlug(slug); err != nil {
		return App{}, err
	}
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return App{}, fmt.Errorf("%w: name is required", ErrInvalid)
	}
	if err := validateRuntimeType(p.RuntimeType); err != nil {
		return App{}, err
	}
	buildArgs, err := marshalArgs(p.BuildArgs)
	if err != nil {
		return App{}, fmt.Errorf("%w: build_args: %v", ErrInvalid, err)
	}
	startArgs, err := marshalArgs(p.StartArgs)
	if err != nil {
		return App{}, fmt.Errorf("%w: start_args: %v", ErrInvalid, err)
	}
	if p.Port != nil && (*p.Port < 1024 || *p.Port > 65535) {
		return App{}, fmt.Errorf("%w: port must be between 1024 and 65535", ErrInvalid)
	}
	envName := strings.TrimSpace(p.EnvName)
	if envName == "" {
		envName = "production"
	}
	var createdBy any
	if v := strings.TrimSpace(p.CreatedBy); v != "" {
		createdBy = v
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO apps (
			project_id, server_id, slug, name, runtime_type,
			git_repo_url, git_ref_default,
			build_program, build_args, start_program, start_args, working_dir,
			port, health_path, env_name, created_by
		)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10, $11::jsonb, $12, $13, $14, $15, $16
		 WHERE EXISTS (
			SELECT 1 FROM projects
			 WHERE id = $1 AND state = 'active' AND deleted_at IS NULL)
		RETURNING %s`, appColumns),
		projectID, serverID, slug, name, p.RuntimeType,
		strings.TrimSpace(p.GitRepoURL), strings.TrimSpace(p.GitRefDefault),
		strings.TrimSpace(p.BuildProgram), buildArgs,
		strings.TrimSpace(p.StartProgram), startArgs,
		strings.TrimSpace(p.WorkingDir), p.Port, p.HealthPath, envName, createdBy,
	)
	app, err := scanApp(row)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			return App{}, fmt.Errorf("%w: the project is not active or does not exist", ErrState)
		case isUniqueViolation(err):
			return App{}, ErrSlugTaken
		case isForeignKeyViolation(err):
			return App{}, fmt.Errorf("%w: the project or server does not exist", ErrInvalid)
		case isCheckViolation(err):
			return App{}, fmt.Errorf("apps: schema rejected app: %w", err)
		default:
			return App{}, err
		}
	}
	return app, nil
}

// GetApp returns one live app by id.
func (s *Store) GetApp(ctx context.Context, id string) (App, error) {
	if strings.TrimSpace(id) == "" {
		return App{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM apps WHERE id = $1 AND deleted_at IS NULL`, appColumns), id)
	return scanApp(row)
}

// GetAppInProject returns one live app by id, only when it belongs to the named project.
// A cross-project lookup returns ErrNotFound (not ErrForbidden) to avoid confirming id ownership.
func (s *Store) GetAppInProject(ctx context.Context, projectID, id string) (App, error) {
	if strings.TrimSpace(projectID) == "" || strings.TrimSpace(id) == "" {
		return App{}, fmt.Errorf("%w: project_id and id are required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM apps WHERE id = $1 AND project_id = $2 AND deleted_at IS NULL`, appColumns), id, projectID)
	return scanApp(row)
}

// ListApps returns a page of live apps in one project, newest first.
func (s *Store) ListApps(ctx context.Context, projectID string, limit, offset int) ([]App, int, error) {
	if strings.TrimSpace(projectID) == "" {
		return nil, 0, fmt.Errorf("%w: project_id is required", ErrInvalid)
	}
	if limit <= 0 || limit > maxListLimit {
		return nil, 0, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalid, maxListLimit)
	}
	if offset < 0 {
		return nil, 0, fmt.Errorf("%w: offset cannot be negative", ErrInvalid)
	}

	var total int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM apps WHERE deleted_at IS NULL AND project_id = $1`, projectID,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("apps: count apps: %w", err)
	}

	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM apps
		 WHERE deleted_at IS NULL AND project_id = $1
		 ORDER BY created_at DESC, id
		 LIMIT $2 OFFSET $3`, appColumns), projectID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("apps: list apps: %w", err)
	}
	defer rows.Close()

	out := make([]App, 0, limit)
	for rows.Next() {
		app, err := scanApp(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, app)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("apps: iterate apps: %w", err)
	}
	return out, total, nil
}

// UpdateAppParams carries editable fields. Nil pointer means "leave unchanged".
type UpdateAppParams struct {
	Name          *string
	GitRepoURL    *string
	GitRefDefault *string
	BuildProgram  *string
	BuildArgs     *[]string
	StartProgram  *string
	StartArgs     *[]string
	WorkingDir    *string
	Port          *int
	HealthPath    *string
}

// UpdateApp modifies editable fields of a live app.
func (s *Store) UpdateApp(ctx context.Context, id string, p UpdateAppParams) (App, error) {
	if strings.TrimSpace(id) == "" {
		return App{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	if p.Port != nil && (*p.Port < 1024 || *p.Port > 65535) {
		return App{}, fmt.Errorf("%w: port must be between 1024 and 65535", ErrInvalid)
	}
	var buildArgsJSON, startArgsJSON any
	if p.BuildArgs != nil {
		b, err := marshalArgs(*p.BuildArgs)
		if err != nil {
			return App{}, fmt.Errorf("%w: build_args: %v", ErrInvalid, err)
		}
		buildArgsJSON = string(b)
	}
	if p.StartArgs != nil {
		b, err := marshalArgs(*p.StartArgs)
		if err != nil {
			return App{}, fmt.Errorf("%w: start_args: %v", ErrInvalid, err)
		}
		startArgsJSON = string(b)
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE apps SET
			name          = COALESCE($2, name),
			git_repo_url  = COALESCE($3, git_repo_url),
			git_ref_default = COALESCE($4, git_ref_default),
			build_program = COALESCE($5, build_program),
			build_args    = COALESCE($6::jsonb, build_args),
			start_program = COALESCE($7, start_program),
			start_args    = COALESCE($8::jsonb, start_args),
			working_dir   = COALESCE($9, working_dir),
			port          = CASE WHEN $10::integer IS NOT NULL THEN $10::integer ELSE port END,
			health_path   = CASE WHEN $11::text IS NOT NULL THEN $11::text ELSE health_path END,
			updated_at    = $12
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING %s`, appColumns),
		id,
		nullableTrimmed(p.Name),
		nullableTrimmed(p.GitRepoURL),
		nullableTrimmed(p.GitRefDefault),
		nullableTrimmed(p.BuildProgram),
		buildArgsJSON,
		nullableTrimmed(p.StartProgram),
		startArgsJSON,
		nullableTrimmed(p.WorkingDir),
		p.Port,
		p.HealthPath,
		s.clock(),
	)
	app, err := scanApp(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return App{}, ErrNotFound
		}
		return App{}, err
	}
	return app, nil
}

// RequestDelete moves an active or suspended app to pending_delete.
func (s *Store) RequestDelete(ctx context.Context, id string, grace time.Duration) (App, error) {
	if grace == 0 {
		grace = DefaultDeleteGrace
	}
	if grace < 0 || grace > maxDeleteGrace {
		return App{}, fmt.Errorf("%w: grace must be between 1s and %s", ErrInvalid, maxDeleteGrace)
	}
	after := s.clock().Add(grace)
	return s.transition(ctx, id, StatePendingDelete, &after, []string{StateActive, StateSuspended})
}

// CancelDelete returns a pending_delete app to active.
func (s *Store) CancelDelete(ctx context.Context, id string) (App, error) {
	return s.transition(ctx, id, StateActive, nil, []string{StatePendingDelete})
}

// FinalizeDelete tombstones an app whose grace period has elapsed.
func (s *Store) FinalizeDelete(ctx context.Context, id string) (App, error) {
	if strings.TrimSpace(id) == "" {
		return App{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	now := s.clock()
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE apps
		   SET state = 'deleted', deleted_at = $2, delete_after = NULL, updated_at = $2
		 WHERE id = $1
		   AND state = 'pending_delete'
		   AND delete_after IS NOT NULL
		   AND delete_after <= $2
		RETURNING %s`, appColumns), id, now)
	app, err := scanApp(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return App{}, fmt.Errorf("%w: not deletable", ErrState)
		}
		return App{}, err
	}
	return app, nil
}

func (s *Store) transition(ctx context.Context, id, to string, deleteAfter *time.Time, allowed []string) (App, error) {
	if strings.TrimSpace(id) == "" {
		return App{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	now := s.clock()
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE apps
		   SET state = $2, delete_after = $3, updated_at = $4
		 WHERE id = $1
		   AND deleted_at IS NULL
		   AND state = ANY($5::text[])
		RETURNING %s`, appColumns),
		id, to, deleteAfter, now, allowed)
	app, err := scanApp(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return App{}, fmt.Errorf("%w: cannot move to %s", ErrState, to)
		}
		return App{}, err
	}
	return app, nil
}

// ─── Environment Variables ────────────────────────────────────────────────────

// SetEnvVar upserts a named environment variable for an app.
// For secret_ref, the value must be a secret:// URI; the plaintext value is
// never stored (PRD.md §20.4, DATABASE.md §12).
func (s *Store) SetEnvVar(ctx context.Context, appID, name, valueSource, value string) (EnvVar, error) {
	if strings.TrimSpace(appID) == "" {
		return EnvVar{}, fmt.Errorf("%w: app_id is required", ErrInvalid)
	}
	if !envNameRE.MatchString(name) {
		return EnvVar{}, fmt.Errorf("%w: env name %q must match ^[A-Za-z_][A-Za-z0-9_]*$", ErrInvalid, name)
	}
	var literalValue, secretRef any
	switch valueSource {
	case ValueLiteral:
		literalValue = value
	case ValueSecretRef:
		if !strings.HasPrefix(value, "secret://") {
			return EnvVar{}, fmt.Errorf("%w: secret_ref must start with secret://", ErrInvalid)
		}
		secretRef = value
	default:
		return EnvVar{}, fmt.Errorf("%w: value_source must be literal or secret_ref", ErrInvalid)
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO app_env_vars (app_id, name, value_source, literal_value, secret_ref, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (app_id, name) DO UPDATE SET
			value_source  = EXCLUDED.value_source,
			literal_value = EXCLUDED.literal_value,
			secret_ref    = EXCLUDED.secret_ref,
			updated_at    = EXCLUDED.updated_at
		RETURNING %s`, envVarColumns),
		appID, name, valueSource, literalValue, secretRef, s.clock())
	return scanEnvVar(row)
}

// GetEnvVar returns one named env var for an app.
func (s *Store) GetEnvVar(ctx context.Context, appID, name string) (EnvVar, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM app_env_vars WHERE app_id = $1 AND name = $2`, envVarColumns), appID, name)
	return scanEnvVar(row)
}

// ListEnvVars returns all env vars for an app.
// Note: literal_value is included for non-secret vars; callers that render UI
// must mask secret_ref rows and MUST NOT display or return literal_value for
// secret_ref rows (there are none — the schema enforces XOR).
func (s *Store) ListEnvVars(ctx context.Context, appID string) ([]EnvVar, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT %s FROM app_env_vars WHERE app_id = $1 ORDER BY name`, envVarColumns), appID)
	if err != nil {
		return nil, fmt.Errorf("apps: list env vars: %w", err)
	}
	defer rows.Close()

	var out []EnvVar
	for rows.Next() {
		ev, err := scanEnvVar(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// DeleteEnvVar removes a named env var for an app.
func (s *Store) DeleteEnvVar(ctx context.Context, appID, name string) error {
	ct, err := s.pool.Exec(ctx,
		`DELETE FROM app_env_vars WHERE app_id = $1 AND name = $2`, appID, name)
	if err != nil {
		return fmt.Errorf("apps: delete env var: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ─── Deployments ─────────────────────────────────────────────────────────────

// CreateDeploymentParams configures a deployment record.
type CreateDeploymentParams struct {
	AppID          string
	ProjectID      string
	ServerID       string
	Trigger        string
	CommitSHA      *string
	GitRef         string
	JobID          *string
	RequestedBy    string
	IdempotencyKey *string
}

// CreateDeployment inserts a deployment in the queued state.
//
// The partial unique index on (app_id) WHERE state IN ('queued','running') is the
// database guard against concurrent active deployments; the application-level
// ErrConflictActive unwraps the 23505 unique violation from that index so callers
// get a typed error rather than a postgres error string.
func (s *Store) CreateDeployment(ctx context.Context, p CreateDeploymentParams) (Deployment, error) {
	appID := strings.TrimSpace(p.AppID)
	if appID == "" {
		return Deployment{}, fmt.Errorf("%w: app_id is required", ErrInvalid)
	}
	gitRef := strings.TrimSpace(p.GitRef)
	if gitRef == "" {
		gitRef = "main"
	}
	switch p.Trigger {
	case TriggerManual, TriggerWebhook, TriggerRollback:
	default:
		return Deployment{}, fmt.Errorf("%w: trigger must be manual, webhook, or rollback", ErrInvalid)
	}
	var requestedBy any
	if v := strings.TrimSpace(p.RequestedBy); v != "" {
		requestedBy = v
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO app_deployments (
			app_id, project_id, server_id, trigger, commit_sha, git_ref,
			job_id, requested_by, idempotency_key
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING %s`, deployColumns),
		appID, p.ProjectID, p.ServerID, p.Trigger, p.CommitSHA, gitRef,
		p.JobID, requestedBy, p.IdempotencyKey,
	)
	d, err := scanDeployment(row)
	if err != nil {
		switch {
		case isUniqueViolation(err):
			// Could be the active-deployment guard index or idempotency_key.
			// Both are "conflict" from the caller's perspective.
			return Deployment{}, ErrConflictActive
		default:
			return Deployment{}, err
		}
	}
	return d, nil
}

// GetDeployment returns a deployment by id.
func (s *Store) GetDeployment(ctx context.Context, id string) (Deployment, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM app_deployments WHERE id = $1`, deployColumns), id)
	return scanDeployment(row)
}

// GetDeploymentInApp returns a deployment by id only when it belongs to the named app.
func (s *Store) GetDeploymentInApp(ctx context.Context, appID, id string) (Deployment, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM app_deployments WHERE id = $1 AND app_id = $2`, deployColumns), id, appID)
	return scanDeployment(row)
}

// ListDeployments returns a page of deployments for one app, newest first.
func (s *Store) ListDeployments(ctx context.Context, appID string, limit, offset int) ([]Deployment, int, error) {
	if limit <= 0 || limit > maxListLimit {
		return nil, 0, fmt.Errorf("%w: limit must be 1–%d", ErrInvalid, maxListLimit)
	}
	var total int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM app_deployments WHERE app_id = $1`, appID,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("apps: count deployments: %w", err)
	}
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM app_deployments
		 WHERE app_id = $1
		 ORDER BY created_at DESC, id
		 LIMIT $2 OFFSET $3`, deployColumns), appID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("apps: list deployments: %w", err)
	}
	defer rows.Close()

	out := make([]Deployment, 0, limit)
	for rows.Next() {
		d, err := scanDeployment(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, d)
	}
	return out, total, rows.Err()
}

// UpdateDeploymentStateParams carries state transition fields.
type UpdateDeploymentStateParams struct {
	State        string
	ErrorCode    string
	ErrorSummary string
	JobID        *string
}

// UpdateDeploymentState advances a deployment's state and records terminal fields.
func (s *Store) UpdateDeploymentState(ctx context.Context, id string, p UpdateDeploymentStateParams) (Deployment, error) {
	now := s.clock()
	var startedAt, finishedAt any
	if p.State == DeployRunning {
		startedAt = now
	}
	switch p.State {
	case DeploySucceeded, DeployFailed, DeployRolledBack, DeployCanceled:
		finishedAt = now
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE app_deployments SET
			state         = $2,
			error_code    = COALESCE($3, error_code),
			error_summary = COALESCE($4, error_summary),
			job_id        = COALESCE($5, job_id),
			started_at    = COALESCE(started_at, $6),
			finished_at   = COALESCE(finished_at, $7)
		WHERE id = $1
		RETURNING %s`, deployColumns),
		id, p.State,
		nullableStr(p.ErrorCode), nullableStr(p.ErrorSummary), p.JobID,
		startedAt, finishedAt,
	)
	return scanDeployment(row)
}

// ─── Releases ────────────────────────────────────────────────────────────────

// CreateRelease inserts a release record.
func (s *Store) CreateRelease(ctx context.Context, appID, deploymentID, releasePath, commitSHA string) (Release, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO app_releases (app_id, deployment_id, release_path, commit_sha)
		VALUES ($1, $2, $3, $4)
		RETURNING %s`, releaseColumns),
		appID, deploymentID, releasePath, commitSHA)
	return scanRelease(row)
}

// MarkCurrentRelease sets is_current = true for one release and clears it for all
// prior releases of the same app in a single transaction.
func (s *Store) MarkCurrentRelease(ctx context.Context, releaseID, appID string) (Release, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Release{}, fmt.Errorf("apps: begin mark-current tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, execErr := tx.Exec(ctx,
		`UPDATE app_releases SET is_current = false WHERE app_id = $1 AND is_current = true`,
		appID); execErr != nil {
		return Release{}, fmt.Errorf("apps: clear current releases: %w", execErr)
	}

	row := tx.QueryRow(ctx, fmt.Sprintf(`
		UPDATE app_releases SET is_current = true
		WHERE id = $1
		RETURNING %s`, releaseColumns), releaseID)
	r, err := scanRelease(row)
	if err != nil {
		return Release{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return Release{}, fmt.Errorf("apps: commit mark-current: %w", err)
	}
	return r, nil
}

// ListReleases returns the N most recent releases for an app.
func (s *Store) ListReleases(ctx context.Context, appID string, limit int) ([]Release, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM app_releases
		 WHERE app_id = $1
		 ORDER BY created_at DESC, id
		 LIMIT $2`, releaseColumns), appID, limit)
	if err != nil {
		return nil, fmt.Errorf("apps: list releases: %w", err)
	}
	defer rows.Close()

	var out []Release
	for rows.Next() {
		r, err := scanRelease(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// UpdateReleaseHealth records health state for a release.
func (s *Store) UpdateReleaseHealth(ctx context.Context, releaseID, healthState string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE app_releases SET health_state = $2 WHERE id = $1`, releaseID, healthState)
	if err != nil {
		return fmt.Errorf("apps: update release health: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ─── Webhook Tokens ──────────────────────────────────────────────────────────

// CreateWebhookToken inserts a new active webhook token (hash only).
// The plaintext token is generated by the caller and displayed once; only its
// SHA-256 hex hash is persisted here.
func (s *Store) CreateWebhookToken(ctx context.Context, appID, tokenHash string) (WebhookToken, error) {
	var wt WebhookToken
	err := s.pool.QueryRow(ctx, `
		INSERT INTO app_webhook_tokens (app_id, token_hash)
		VALUES ($1, $2)
		RETURNING id, app_id, token_hash, state, created_at, last_used_at`,
		appID, tokenHash,
	).Scan(&wt.ID, &wt.AppID, &wt.TokenHash, &wt.State, &wt.CreatedAt, &wt.LastUsedAt)
	if err != nil {
		return WebhookToken{}, fmt.Errorf("apps: create webhook token: %w", err)
	}
	return wt, nil
}

// GetWebhookTokenByHash looks up an active webhook token by its hash.
func (s *Store) GetWebhookTokenByHash(ctx context.Context, tokenHash string) (WebhookToken, error) {
	var wt WebhookToken
	err := s.pool.QueryRow(ctx, `
		SELECT id, app_id, token_hash, state, created_at, last_used_at
		  FROM app_webhook_tokens
		 WHERE token_hash = $1 AND state = 'active'`,
		tokenHash,
	).Scan(&wt.ID, &wt.AppID, &wt.TokenHash, &wt.State, &wt.CreatedAt, &wt.LastUsedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return WebhookToken{}, ErrNotFound
	}
	if err != nil {
		return WebhookToken{}, fmt.Errorf("apps: get webhook token: %w", err)
	}
	return wt, nil
}

// TouchWebhookToken updates last_used_at for a webhook token.
func (s *Store) TouchWebhookToken(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE app_webhook_tokens SET last_used_at = $2 WHERE id = $1`, id, s.clock())
	return err
}

// RevokeWebhookToken marks a webhook token as revoked.
func (s *Store) RevokeWebhookToken(ctx context.Context, id string) error {
	ct, err := s.pool.Exec(ctx,
		`UPDATE app_webhook_tokens SET state = 'revoked' WHERE id = $1 AND state = 'active'`, id)
	if err != nil {
		return fmt.Errorf("apps: revoke webhook token: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

// envNameRE mirrors the app_env_vars_name_safe CHECK in migrations/0016.
var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

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
		default:
			return fmt.Errorf("%w: slug %q contains %q; allowed are a-z, 0-9 and single hyphens",
				ErrInvalid, slug, string(c))
		}
	}
	return nil
}

func validateRuntimeType(rt string) error {
	switch rt {
	case RuntimeNode, RuntimeBun, RuntimePython, RuntimePHP, RuntimeStatic:
		return nil
	default:
		return fmt.Errorf("%w: runtime_type %q must be one of node, bun, python, php, static", ErrInvalid, rt)
	}
}

func marshalArgs(args []string) ([]byte, error) {
	if args == nil {
		return []byte("[]"), nil
	}
	b, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func nullableTrimmed(set *string) any {
	if set == nil {
		return nil
	}
	return strings.TrimSpace(*set)
}

func nullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func isUniqueViolation(err error) bool     { return pgCode(err) == "23505" }
func isCheckViolation(err error) bool      { return pgCode(err) == "23514" }
func isForeignKeyViolation(err error) bool { return pgCode(err) == "23503" }

func pgCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}
