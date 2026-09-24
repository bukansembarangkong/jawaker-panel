// Package containers owns the container platform inventory: registries,
// images, compose stacks, containers, and volumes hosted on project servers.
//
// Security invariant: registry credentials (tokens/passwords) are NEVER stored
// in this table. They are sealed into the secret subsystem via internal/secret
// and referenced by a secret:// URI. No query over this package can return a
// plaintext credential.
package containers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors.
var (
	ErrNotFound = errors.New("containers: not found")
	ErrInvalid  = errors.New("containers: invalid argument")
	ErrConflict = errors.New("containers: conflict")
	ErrState    = errors.New("containers: invalid state transition")
)

// Container state constants.
const (
	StateRunning    = "running"
	StateStopped    = "stopped"
	StatePaused     = "paused"
	StateRestarting = "restarting"
	StateExited     = "exited"
	StateDead       = "dead"
	StateUnknown    = "unknown"
)

// Stack state constants.
const (
	StackActive   = "active"
	StackStopped  = "stopped"
	StackDegraded = "degraded"
	StackUpdating = "updating"
	StackRemoved  = "removed"
)

// Health state constants.
const (
	HealthHealthy   = "healthy"
	HealthUnhealthy = "unhealthy"
	HealthStarting  = "starting"
	HealthNone      = "none"
)

// Registry holds a container registry credential reference.
type Registry struct {
	ID        string
	ProjectID string
	Name      string
	Host      string
	SecretRef *string // sealed credential; never exposed over HTTP; nil when no credential
	CreatedAt time.Time
	DeletedAt *time.Time
}

// Image is a Docker/OCI image entry in the inventory.
type Image struct {
	ID         string
	ProjectID  string
	ServerID   *string
	RegistryID *string
	Reference  string
	ImageID    string
	SizeBytes  *int64
	CreatedAt  time.Time
	DeletedAt  *time.Time
}

// Stack is a Docker Compose stack.
type Stack struct {
	ID          string
	ProjectID   string
	ServerID    string
	Name        string
	State       string
	ComposeYAML string
	CreatedAt   time.Time
	DeletedAt   *time.Time
}

// Container is a single running or stopped container.
type Container struct {
	ID          string
	ProjectID   string
	ServerID    string
	StackID     *string
	Name        string
	ContainerID string
	ImageRef    string
	State       string
	CPULimit    float32
	MemLimitMB  int
	Privileged  bool
	Health      string
	StartedAt   *time.Time
	CreatedAt   time.Time
	DeletedAt   *time.Time
}

// Volume is a Docker volume mounted by (or associated with) a container.
type Volume struct {
	ID          string
	ProjectID   string
	ServerID    string
	ContainerID *string
	Name        string
	Driver      string
	MountPoint  string
	SizeBytes   *int64
	CreatedAt   time.Time
	DeletedAt   *time.Time
}

const registryColumns = `id, project_id, name, host, secret_ref, created_at, deleted_at`
const stackColumns = `id, project_id, server_id, name, state, compose_yaml, created_at, deleted_at`
const containerColumns = `id, project_id, server_id, stack_id, name, container_id, image_ref, state, cpu_limit, mem_limit_mb, privileged, health, started_at, created_at, deleted_at`
const volumeColumns = `id, project_id, server_id, container_id, name, driver, mount_point, size_bytes, created_at, deleted_at`

// Store owns all container-platform read/write operations.
type Store struct {
	pool    *pgxpool.Pool
	secrets *secret.Store
}

// NewStore builds a container store.
func NewStore(pool *pgxpool.Pool, secrets *secret.Store) *Store {
	return &Store{pool: pool, secrets: secrets}
}

// ── Registries ────────────────────────────────────────────────────────────────

func scanRegistry(row pgx.Row) (Registry, error) {
	var r Registry
	err := row.Scan(&r.ID, &r.ProjectID, &r.Name, &r.Host, &r.SecretRef, &r.CreatedAt, &r.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Registry{}, ErrNotFound
	}
	if err != nil {
		return Registry{}, fmt.Errorf("containers: scan registry: %w", err)
	}
	return r, nil
}

// CreateRegistryParams configures registry creation.
type CreateRegistryParams struct {
	ProjectID string
	Name      string
	Host      string
	// Password/token sealed into the secret subsystem.
	Password string
}

// CreateRegistry seals the password (if any) and inserts a registry row.
func (s *Store) CreateRegistry(ctx context.Context, p CreateRegistryParams) (Registry, error) {
	if strings.TrimSpace(p.ProjectID) == "" || strings.TrimSpace(p.Name) == "" || strings.TrimSpace(p.Host) == "" {
		return Registry{}, fmt.Errorf("%w: project_id, name, host are required", ErrInvalid)
	}

	var ref any
	if pw := strings.TrimSpace(p.Password); pw != "" && s.secrets != nil {
		var regID string
		if err := s.pool.QueryRow(ctx, `SELECT gen_random_uuid()::text`).Scan(&regID); err != nil {
			return Registry{}, fmt.Errorf("containers: generate registry id: %w", err)
		}
		secretRef := fmt.Sprintf("secret://registries/%s/credential", regID)
		if err := s.secrets.Create(ctx, secretRef, pw, fmt.Sprintf("registry credential for %s", p.Name)); err != nil {
			return Registry{}, fmt.Errorf("containers: seal registry credential: %w", err)
		}
		ref = secretRef
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO container_registries (project_id, name, host, secret_ref)
		VALUES ($1, $2, $3, $4)
		RETURNING %s`, registryColumns),
		p.ProjectID, p.Name, p.Host, ref)
	return scanRegistry(row)
}

// GetRegistry returns one registry by id.
func (s *Store) GetRegistry(ctx context.Context, id string) (Registry, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM container_registries WHERE id = $1 AND deleted_at IS NULL`, registryColumns), id)
	return scanRegistry(row)
}

// ListRegistries returns all registries for a project.
func (s *Store) ListRegistries(ctx context.Context, projectID string) ([]Registry, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT %s FROM container_registries WHERE project_id = $1 AND deleted_at IS NULL ORDER BY created_at ASC`, registryColumns), projectID)
	if err != nil {
		return nil, fmt.Errorf("containers: list registries: %w", err)
	}
	defer rows.Close()
	return collectRegistries(rows)
}

func collectRegistries(rows pgx.Rows) ([]Registry, error) {
	var out []Registry
	for rows.Next() {
		r, err := scanRegistry(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteRegistry soft-deletes a registry.
func (s *Store) DeleteRegistry(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE container_registries SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("containers: delete registry: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Stacks ────────────────────────────────────────────────────────────────────

func scanStack(row pgx.Row) (Stack, error) {
	var s Stack
	err := row.Scan(&s.ID, &s.ProjectID, &s.ServerID, &s.Name, &s.State, &s.ComposeYAML, &s.CreatedAt, &s.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Stack{}, ErrNotFound
	}
	if err != nil {
		return Stack{}, fmt.Errorf("containers: scan stack: %w", err)
	}
	return s, nil
}

// CreateStackParams configures stack creation.
type CreateStackParams struct {
	ProjectID   string
	ServerID    string
	Name        string
	ComposeYAML string
}

// CreateStack inserts a compose stack.
func (s *Store) CreateStack(ctx context.Context, p CreateStackParams) (Stack, error) {
	if strings.TrimSpace(p.ProjectID) == "" || strings.TrimSpace(p.ServerID) == "" || strings.TrimSpace(p.Name) == "" {
		return Stack{}, fmt.Errorf("%w: project_id, server_id, name are required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO compose_stacks (project_id, server_id, name, compose_yaml)
		VALUES ($1, $2, $3, $4)
		RETURNING %s`, stackColumns),
		p.ProjectID, p.ServerID, p.Name, p.ComposeYAML)
	st, err := scanStack(row)
	if err != nil {
		if isUniqueViolation(err) {
			return Stack{}, fmt.Errorf("%w: stack name already exists on this server", ErrConflict)
		}
		return Stack{}, err
	}
	return st, nil
}

// GetStack returns one stack by id.
func (s *Store) GetStack(ctx context.Context, id string) (Stack, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM compose_stacks WHERE id = $1 AND deleted_at IS NULL`, stackColumns), id)
	return scanStack(row)
}

// ListStacks returns all stacks for a project.
func (s *Store) ListStacks(ctx context.Context, projectID string) ([]Stack, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT %s FROM compose_stacks WHERE project_id = $1 AND deleted_at IS NULL ORDER BY created_at ASC`, stackColumns), projectID)
	if err != nil {
		return nil, fmt.Errorf("containers: list stacks: %w", err)
	}
	defer rows.Close()
	var out []Stack
	for rows.Next() {
		st, err := scanStack(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// UpdateStackState transitions a stack to a new state.
func (s *Store) UpdateStackState(ctx context.Context, id, state string) (Stack, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE compose_stacks SET state = $2 WHERE id = $1 AND deleted_at IS NULL
		RETURNING %s`, stackColumns), id, state)
	return scanStack(row)
}

// DeleteStack soft-deletes a stack.
func (s *Store) DeleteStack(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE compose_stacks SET deleted_at = now(), state = 'removed' WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("containers: delete stack: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Containers ────────────────────────────────────────────────────────────────

func scanContainer(row pgx.Row) (Container, error) {
	var c Container
	err := row.Scan(
		&c.ID, &c.ProjectID, &c.ServerID, &c.StackID, &c.Name,
		&c.ContainerID, &c.ImageRef, &c.State, &c.CPULimit, &c.MemLimitMB,
		&c.Privileged, &c.Health, &c.StartedAt, &c.CreatedAt, &c.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Container{}, ErrNotFound
	}
	if err != nil {
		return Container{}, fmt.Errorf("containers: scan container: %w", err)
	}
	return c, nil
}

// CreateContainerParams configures container record creation.
type CreateContainerParams struct {
	ProjectID   string
	ServerID    string
	StackID     string
	Name        string
	ContainerID string
	ImageRef    string
	State       string
	CPULimit    float32
	MemLimitMB  int
	Privileged  bool
	Health      string
}

// CreateContainer inserts a container inventory row.
func (s *Store) CreateContainer(ctx context.Context, p CreateContainerParams) (Container, error) {
	if strings.TrimSpace(p.ProjectID) == "" || strings.TrimSpace(p.ServerID) == "" || strings.TrimSpace(p.Name) == "" {
		return Container{}, fmt.Errorf("%w: project_id, server_id, name are required", ErrInvalid)
	}
	state := p.State
	if state == "" {
		state = StateUnknown
	}
	health := p.Health
	if health == "" {
		health = HealthNone
	}
	var stackID any
	if v := strings.TrimSpace(p.StackID); v != "" {
		stackID = v
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO containers (project_id, server_id, stack_id, name, container_id, image_ref, state, cpu_limit, mem_limit_mb, privileged, health)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING %s`, containerColumns),
		p.ProjectID, p.ServerID, stackID, p.Name, p.ContainerID, p.ImageRef, state, p.CPULimit, p.MemLimitMB, p.Privileged, health)
	return scanContainer(row)
}

// GetContainer returns one container by id.
func (s *Store) GetContainer(ctx context.Context, id string) (Container, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM containers WHERE id = $1 AND deleted_at IS NULL`, containerColumns), id)
	return scanContainer(row)
}

// ListContainers returns all containers for a project, optionally filtered by server.
func (s *Store) ListContainers(ctx context.Context, projectID string, serverID string) ([]Container, error) {
	var rows pgx.Rows
	var err error
	if serverID != "" {
		rows, err = s.pool.Query(ctx, fmt.Sprintf(
			`SELECT %s FROM containers WHERE project_id = $1 AND server_id = $2 AND deleted_at IS NULL ORDER BY created_at ASC`,
			containerColumns), projectID, serverID)
	} else {
		rows, err = s.pool.Query(ctx, fmt.Sprintf(
			`SELECT %s FROM containers WHERE project_id = $1 AND deleted_at IS NULL ORDER BY created_at ASC`,
			containerColumns), projectID)
	}
	if err != nil {
		return nil, fmt.Errorf("containers: list containers: %w", err)
	}
	defer rows.Close()
	var out []Container
	for rows.Next() {
		c, err := scanContainer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// UpdateContainerState transitions a container to a new state.
func (s *Store) UpdateContainerState(ctx context.Context, id, state, health string) (Container, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE containers SET state = $2, health = $3 WHERE id = $1 AND deleted_at IS NULL
		RETURNING %s`, containerColumns), id, state, health)
	return scanContainer(row)
}

// DeleteContainer soft-deletes a container row.
func (s *Store) DeleteContainer(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE containers SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("containers: delete container: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListPrivileged returns running containers with privileged=true.
// Gate: "unsafe privileged configuration warnings".
func (s *Store) ListPrivileged(ctx context.Context, projectID string) ([]Container, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM containers
		WHERE project_id = $1 AND privileged = true AND deleted_at IS NULL
		ORDER BY created_at ASC`, containerColumns), projectID)
	if err != nil {
		return nil, fmt.Errorf("containers: list privileged: %w", err)
	}
	defer rows.Close()
	var out []Container
	for rows.Next() {
		c, err := scanContainer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ── Volumes ───────────────────────────────────────────────────────────────────

func scanVolume(row pgx.Row) (Volume, error) {
	var v Volume
	err := row.Scan(&v.ID, &v.ProjectID, &v.ServerID, &v.ContainerID, &v.Name, &v.Driver, &v.MountPoint, &v.SizeBytes, &v.CreatedAt, &v.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Volume{}, ErrNotFound
	}
	if err != nil {
		return Volume{}, fmt.Errorf("containers: scan volume: %w", err)
	}
	return v, nil
}

// CreateVolumeParams configures volume creation.
type CreateVolumeParams struct {
	ProjectID   string
	ServerID    string
	ContainerID string
	Name        string
	Driver      string
	MountPoint  string
}

// CreateVolume inserts a volume row.
func (s *Store) CreateVolume(ctx context.Context, p CreateVolumeParams) (Volume, error) {
	if strings.TrimSpace(p.ProjectID) == "" || strings.TrimSpace(p.ServerID) == "" || strings.TrimSpace(p.Name) == "" {
		return Volume{}, fmt.Errorf("%w: project_id, server_id, name are required", ErrInvalid)
	}
	driver := p.Driver
	if driver == "" {
		driver = "local"
	}
	var containerID any
	if v := strings.TrimSpace(p.ContainerID); v != "" {
		containerID = v
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO container_volumes (project_id, server_id, container_id, name, driver, mount_point)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING %s`, volumeColumns),
		p.ProjectID, p.ServerID, containerID, p.Name, driver, p.MountPoint)
	return scanVolume(row)
}

// GetVolume returns one volume by id.
func (s *Store) GetVolume(ctx context.Context, id string) (Volume, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM container_volumes WHERE id = $1 AND deleted_at IS NULL`, volumeColumns), id)
	return scanVolume(row)
}

// ListVolumes returns all volumes for a project.
func (s *Store) ListVolumes(ctx context.Context, projectID string) ([]Volume, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT %s FROM container_volumes WHERE project_id = $1 AND deleted_at IS NULL ORDER BY created_at ASC`, volumeColumns), projectID)
	if err != nil {
		return nil, fmt.Errorf("containers: list volumes: %w", err)
	}
	defer rows.Close()
	var out []Volume
	for rows.Next() {
		v, err := scanVolume(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// DeleteVolume soft-deletes a volume.
func (s *Store) DeleteVolume(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE container_volumes SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("containers: delete volume: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// isFKViolation is an alias kept for test compatibility.
var _ = isForeignKeyViolation
