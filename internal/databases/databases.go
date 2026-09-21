// Package databases owns the managed database lifecycle: the state machine,
// database user/grant management, and local backup records.
//
// A managed database belongs to exactly one project and runs on exactly one
// server (migrations/0017, docs/decisions.md D-003 by analogy). This package
// is the ONLY writer of the databases-domain tables; the state machine cannot
// be bypassed by another caller assembling its own UPDATE.
//
// It holds no authorization logic. RBAC decides whether a caller may act; this
// package decides what acting means and makes the schema's invariants impossible
// to violate by accident.
//
// Passwords are NEVER stored in this package. secret_ref values are opaque
// secret:// URIs pointing to internal/secret (PRD.md §20.4, DATABASE.md §12).
package databases

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
	ErrInvalid = errors.New("databases: invalid argument")
	// ErrNotFound is returned when the resource does not exist or is tombstoned.
	// A missing and a deleted row return the SAME error to avoid enumeration oracles.
	ErrNotFound = errors.New("databases: not found")
	// ErrSlugTaken is returned when a live database in the same project already
	// uses the slug.
	ErrSlugTaken = errors.New("databases: slug already in use in this project")
	// ErrDBNameTaken is returned when a live database on the same server already
	// uses the db_name.
	ErrDBNameTaken = errors.New("databases: db_name already in use on this server")
	// ErrState is returned for a transition the lifecycle does not permit.
	ErrState = errors.New("databases: invalid state transition")
	// ErrUsernameTaken is returned when an active user with the same username
	// already exists for this database.
	ErrUsernameTaken = errors.New("databases: username already in use for this database")
	// ErrConflictActive is returned when an operation requires no active backup
	// job but one already exists.
	ErrConflictActive = errors.New("databases: a backup job is already queued or running")
)

// Database lifecycle states (DATABASE.md §7, migrations/0017).
const (
	StateActive        = "active"
	StateSuspended     = "suspended"
	StatePendingDelete = "pending_delete"
	StateDeleted       = "deleted"
)

// Engine values (PRD.md §12.1).
const (
	EnginePostgreSQL = "postgresql"
	EngineMariaDB    = "mariadb"
)

// Backup trigger values (migrations/0017).
const (
	TriggerManual     = "manual"
	TriggerScheduled  = "scheduled"
	TriggerPreUpgrade = "pre_upgrade"
	TriggerPreDelete  = "pre_delete"
)

// Backup state values.
const (
	BackupQueued    = "queued"
	BackupRunning   = "running"
	BackupCompleted = "completed"
	BackupFailed    = "failed"
)

const (
	DefaultDeleteGrace = 7 * 24 * time.Hour
	maxDeleteGrace     = 90 * 24 * time.Hour
	maxListLimit       = 200
)

var (
	slugRE     = regexp.MustCompile(`^[a-z0-9]([a-z0-9_]*[a-z0-9])?$`)
	dbNameRE   = regexp.MustCompile(`^[a-z0-9_]{2,63}$`)
	usernameRE = regexp.MustCompile(`^[a-z0-9_]{2,32}$`)
)

// AllowedPrivileges is the set of SQL privilege names the store accepts.
// The node executor enforces the same list.
var AllowedPrivileges = map[string]bool{
	"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true,
	"CREATE": true, "DROP": true, "ALL": true,
}

// ManagedDatabase is one managed database instance.
type ManagedDatabase struct {
	ID            string
	ProjectID     string
	ServerID      string
	Slug          string
	Name          string
	Engine        string
	EngineVersion string
	DBName        string
	State         string
	CreatedBy     *string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeleteAfter   *time.Time
	DeletedAt     *time.Time
}

// Live reports whether the database is not tombstoned.
func (d ManagedDatabase) Live() bool { return d.DeletedAt == nil }

// Usable reports whether the database may accept operations.
func (d ManagedDatabase) Usable() bool { return d.State == StateActive }

const dbColumns = `id, project_id, server_id, slug, name, engine, engine_version, db_name, state,
	created_by, created_at, updated_at, delete_after, deleted_at`

func scanDatabase(row pgx.Row) (ManagedDatabase, error) {
	var d ManagedDatabase
	err := row.Scan(
		&d.ID, &d.ProjectID, &d.ServerID, &d.Slug, &d.Name, &d.Engine, &d.EngineVersion, &d.DBName, &d.State,
		&d.CreatedBy, &d.CreatedAt, &d.UpdatedAt, &d.DeleteAfter, &d.DeletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return ManagedDatabase{}, ErrNotFound
	}
	if err != nil {
		return ManagedDatabase{}, fmt.Errorf("databases: scan database: %w", err)
	}
	return d, nil
}

// DatabaseUser is one database user with scoped privileges.
// SecretRef is a secret:// URI; the password itself is never stored here.
type DatabaseUser struct {
	ID         string
	DatabaseID string
	Username   string
	SecretRef  string
	Privileges []string
	CreatedAt  time.Time
	RevokedAt  *time.Time
}

// Active reports whether this user has not been revoked.
func (u DatabaseUser) Active() bool { return u.RevokedAt == nil }

const userColumns = `id, database_id, username, secret_ref, privileges, created_at, revoked_at`

func scanUser(row pgx.Row) (DatabaseUser, error) {
	var u DatabaseUser
	var privJSON []byte
	err := row.Scan(&u.ID, &u.DatabaseID, &u.Username, &u.SecretRef, &privJSON, &u.CreatedAt, &u.RevokedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return DatabaseUser{}, ErrNotFound
	}
	if err != nil {
		return DatabaseUser{}, fmt.Errorf("databases: scan user: %w", err)
	}
	if err := json.Unmarshal(privJSON, &u.Privileges); err != nil {
		return DatabaseUser{}, fmt.Errorf("databases: unmarshal privileges: %w", err)
	}
	return u, nil
}

// DatabaseBackup is one local dump artifact record.
type DatabaseBackup struct {
	ID             string
	DatabaseID     string
	ProjectID      string
	ServerID       string
	Trigger        string
	State          string
	DumpPath       string
	SizeBytes      int64
	SHA256         string
	JobID          *string
	RequestedBy    *string
	IdempotencyKey *string
	CreatedAt      time.Time
	StartedAt      *time.Time
	CompletedAt    *time.Time
}

const backupColumns = `id, database_id, project_id, server_id, trigger, state, dump_path,
	size_bytes, sha256, job_id, requested_by, idempotency_key, created_at, started_at, completed_at`

func scanBackup(row pgx.Row) (DatabaseBackup, error) {
	var b DatabaseBackup
	err := row.Scan(
		&b.ID, &b.DatabaseID, &b.ProjectID, &b.ServerID, &b.Trigger, &b.State, &b.DumpPath,
		&b.SizeBytes, &b.SHA256, &b.JobID, &b.RequestedBy, &b.IdempotencyKey,
		&b.CreatedAt, &b.StartedAt, &b.CompletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return DatabaseBackup{}, ErrNotFound
	}
	if err != nil {
		return DatabaseBackup{}, fmt.Errorf("databases: scan backup: %w", err)
	}
	return b, nil
}

// Store reads and writes the databases-domain tables.
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

// ─── Database CRUD ────────────────────────────────────────────────────────────

// CreateDatabaseParams configures database creation.
type CreateDatabaseParams struct {
	ProjectID     string
	ServerID      string
	Slug          string
	Name          string
	Engine        string
	EngineVersion string
	DBName        string
	CreatedBy     string
}

// CreateDatabase inserts a managed database in the active state.
//
// The parent project must be active — the INSERT uses a WHERE EXISTS to make
// this atomic with the insert, so a project suspended concurrently cannot slip
// a database in.
func (s *Store) CreateDatabase(ctx context.Context, p CreateDatabaseParams) (ManagedDatabase, error) {
	projectID := strings.TrimSpace(p.ProjectID)
	if projectID == "" {
		return ManagedDatabase{}, fmt.Errorf("%w: project_id is required", ErrInvalid)
	}
	serverID := strings.TrimSpace(p.ServerID)
	if serverID == "" {
		return ManagedDatabase{}, fmt.Errorf("%w: server_id is required", ErrInvalid)
	}
	slug := strings.ToLower(strings.TrimSpace(p.Slug))
	if err := validateSlug(slug); err != nil {
		return ManagedDatabase{}, err
	}
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return ManagedDatabase{}, fmt.Errorf("%w: name is required", ErrInvalid)
	}
	if err := validateEngine(p.Engine); err != nil {
		return ManagedDatabase{}, err
	}
	dbName := strings.TrimSpace(p.DBName)
	if !dbNameRE.MatchString(dbName) {
		return ManagedDatabase{}, fmt.Errorf("%w: db_name %q must match ^[a-z0-9_]{2,63}$", ErrInvalid, dbName)
	}
	var createdBy any
	if v := strings.TrimSpace(p.CreatedBy); v != "" {
		createdBy = v
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO managed_databases (
			project_id, server_id, slug, name, engine, engine_version, db_name, created_by
		)
		SELECT $1, $2, $3, $4, $5, $6, $7, $8
		 WHERE EXISTS (
			SELECT 1 FROM projects
			 WHERE id = $1 AND state = 'active' AND deleted_at IS NULL)
		RETURNING %s`, dbColumns),
		projectID, serverID, slug, name, p.Engine, strings.TrimSpace(p.EngineVersion), dbName, createdBy,
	)
	db, err := scanDatabase(row)
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			return ManagedDatabase{}, fmt.Errorf("%w: the project is not active or does not exist", ErrState)
		case isUniqueViolation(err):
			// Could be slug or db_name; constraint name distinguishes them.
			if isConstraint(err, "databases_server_dbname_idx") {
				return ManagedDatabase{}, ErrDBNameTaken
			}
			return ManagedDatabase{}, ErrSlugTaken
		case isForeignKeyViolation(err):
			return ManagedDatabase{}, fmt.Errorf("%w: the project or server does not exist", ErrInvalid)
		case isCheckViolation(err):
			return ManagedDatabase{}, fmt.Errorf("databases: schema rejected database: %w", err)
		default:
			return ManagedDatabase{}, err
		}
	}
	return db, nil
}

// GetDatabase returns one live database by id.
func (s *Store) GetDatabase(ctx context.Context, id string) (ManagedDatabase, error) {
	if strings.TrimSpace(id) == "" {
		return ManagedDatabase{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM managed_databases WHERE id = $1 AND deleted_at IS NULL`, dbColumns), id)
	return scanDatabase(row)
}

// GetDatabaseInProject returns one live database by id, only when it belongs
// to the named project. A cross-project lookup returns ErrNotFound (not
// ErrForbidden) to avoid confirming id ownership.
func (s *Store) GetDatabaseInProject(ctx context.Context, projectID, id string) (ManagedDatabase, error) {
	if strings.TrimSpace(projectID) == "" || strings.TrimSpace(id) == "" {
		return ManagedDatabase{}, fmt.Errorf("%w: project_id and id are required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM managed_databases WHERE id = $1 AND project_id = $2 AND deleted_at IS NULL`, dbColumns),
		id, projectID)
	return scanDatabase(row)
}

// ListDatabases returns all live databases in one project, newest first.
func (s *Store) ListDatabases(ctx context.Context, projectID string) ([]ManagedDatabase, error) {
	if strings.TrimSpace(projectID) == "" {
		return nil, fmt.Errorf("%w: project_id is required", ErrInvalid)
	}
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM managed_databases
		 WHERE deleted_at IS NULL AND project_id = $1
		 ORDER BY created_at DESC, id`, dbColumns), projectID)
	if err != nil {
		return nil, fmt.Errorf("databases: list databases: %w", err)
	}
	defer rows.Close()
	var out []ManagedDatabase
	for rows.Next() {
		db, err := scanDatabase(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, db)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("databases: iterate databases: %w", err)
	}
	return out, nil
}

// UpdateDatabaseParams carries editable fields. Nil pointer means "leave unchanged".
type UpdateDatabaseParams struct {
	Name          *string
	EngineVersion *string
}

// UpdateDatabase modifies editable fields of a live database.
func (s *Store) UpdateDatabase(ctx context.Context, id string, p UpdateDatabaseParams) (ManagedDatabase, error) {
	if strings.TrimSpace(id) == "" {
		return ManagedDatabase{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE managed_databases SET
			name           = COALESCE($2, name),
			engine_version = COALESCE($3, engine_version),
			updated_at     = $4
		WHERE id = $1 AND deleted_at IS NULL
		RETURNING %s`, dbColumns),
		id,
		nullableTrimmed(p.Name),
		nullableTrimmed(p.EngineVersion),
		s.clock(),
	)
	db, err := scanDatabase(row)
	if err != nil {
		return ManagedDatabase{}, err
	}
	return db, nil
}

// RequestDelete moves an active or suspended database to pending_delete.
func (s *Store) RequestDelete(ctx context.Context, id string, grace time.Duration) (ManagedDatabase, error) {
	if grace == 0 {
		grace = DefaultDeleteGrace
	}
	if grace < 0 || grace > maxDeleteGrace {
		return ManagedDatabase{}, fmt.Errorf("%w: grace must be between 1s and %s", ErrInvalid, maxDeleteGrace)
	}
	after := s.clock().Add(grace)
	return s.transition(ctx, id, StatePendingDelete, &after, []string{StateActive, StateSuspended})
}

// CancelDelete returns a pending_delete database to active.
func (s *Store) CancelDelete(ctx context.Context, id string) (ManagedDatabase, error) {
	return s.transition(ctx, id, StateActive, nil, []string{StatePendingDelete})
}

// FinalizeDelete tombstones a database whose grace period has elapsed.
func (s *Store) FinalizeDelete(ctx context.Context, id string) (ManagedDatabase, error) {
	if strings.TrimSpace(id) == "" {
		return ManagedDatabase{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	now := s.clock()
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE managed_databases
		   SET state = 'deleted', deleted_at = $2, delete_after = NULL, updated_at = $2
		 WHERE id = $1
		   AND state = 'pending_delete'
		   AND delete_after IS NOT NULL
		   AND delete_after <= $2
		RETURNING %s`, dbColumns), id, now)
	db, err := scanDatabase(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ManagedDatabase{}, fmt.Errorf("%w: not deletable", ErrState)
		}
		return ManagedDatabase{}, err
	}
	return db, nil
}

func (s *Store) transition(ctx context.Context, id, to string, deleteAfter *time.Time, allowed []string) (ManagedDatabase, error) {
	if strings.TrimSpace(id) == "" {
		return ManagedDatabase{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	now := s.clock()
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE managed_databases
		   SET state = $2, delete_after = $3, updated_at = $4
		 WHERE id = $1
		   AND deleted_at IS NULL
		   AND state = ANY($5::text[])
		RETURNING %s`, dbColumns),
		id, to, deleteAfter, now, allowed)
	db, err := scanDatabase(row)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return ManagedDatabase{}, fmt.Errorf("%w: cannot move to %s", ErrState, to)
		}
		return ManagedDatabase{}, err
	}
	return db, nil
}

// ─── Database Users ───────────────────────────────────────────────────────────

// CreateUserParams configures user creation.
type CreateUserParams struct {
	DatabaseID string
	Username   string
	// SecretRef is the secret:// URI returned by internal/secret after sealing
	// the generated password. The plaintext is NEVER passed or stored here.
	SecretRef  string
	Privileges []string
}

// CreateUser inserts a new active database user.
//
// The caller (controller) is responsible for generating the password, sealing
// it via internal/secret, and passing only the resulting ref here.
func (s *Store) CreateUser(ctx context.Context, p CreateUserParams) (DatabaseUser, error) {
	dbID := strings.TrimSpace(p.DatabaseID)
	if dbID == "" {
		return DatabaseUser{}, fmt.Errorf("%w: database_id is required", ErrInvalid)
	}
	if !usernameRE.MatchString(p.Username) {
		return DatabaseUser{}, fmt.Errorf("%w: username %q must match ^[a-z0-9_]{2,32}$", ErrInvalid, p.Username)
	}
	if !strings.HasPrefix(p.SecretRef, "secret://") {
		return DatabaseUser{}, fmt.Errorf("%w: secret_ref must start with secret://", ErrInvalid)
	}
	privs := p.Privileges
	if len(privs) == 0 {
		privs = []string{"ALL"}
	}
	if err := validatePrivileges(privs); err != nil {
		return DatabaseUser{}, err
	}
	privJSON, err := json.Marshal(privs)
	if err != nil {
		return DatabaseUser{}, fmt.Errorf("%w: privileges: %v", ErrInvalid, err)
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO database_users (database_id, username, secret_ref, privileges)
		VALUES ($1, $2, $3, $4::jsonb)
		RETURNING %s`, userColumns),
		dbID, p.Username, p.SecretRef, string(privJSON),
	)
	u, err := scanUser(row)
	if err != nil {
		switch {
		case isUniqueViolation(err):
			return DatabaseUser{}, ErrUsernameTaken
		case isForeignKeyViolation(err):
			return DatabaseUser{}, fmt.Errorf("%w: database does not exist", ErrInvalid)
		default:
			return DatabaseUser{}, err
		}
	}
	return u, nil
}

// ListUsers returns all active users for one database.
// The SecretRef field is present but the password itself is never returned
// by this package (the caller must call internal/secret to open it).
func (s *Store) ListUsers(ctx context.Context, databaseID string) ([]DatabaseUser, error) {
	if strings.TrimSpace(databaseID) == "" {
		return nil, fmt.Errorf("%w: database_id is required", ErrInvalid)
	}
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM database_users
		 WHERE database_id = $1 AND revoked_at IS NULL
		 ORDER BY created_at`, userColumns), databaseID)
	if err != nil {
		return nil, fmt.Errorf("databases: list users: %w", err)
	}
	defer rows.Close()
	var out []DatabaseUser
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("databases: iterate users: %w", err)
	}
	return out, nil
}

// GetUser returns one active database user by username.
func (s *Store) GetUser(ctx context.Context, databaseID, username string) (DatabaseUser, error) {
	if strings.TrimSpace(databaseID) == "" || strings.TrimSpace(username) == "" {
		return DatabaseUser{}, fmt.Errorf("%w: database_id and username are required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT %s FROM database_users
		 WHERE database_id = $1 AND username = $2 AND revoked_at IS NULL`, userColumns),
		databaseID, username)
	return scanUser(row)
}

// UpdateUserSecretRef replaces the secret_ref for an active user.
// Called after a successful password rotation — the caller sealed the new
// password first and passes only the new ref.
func (s *Store) UpdateUserSecretRef(ctx context.Context, databaseID, username, newSecretRef string) error {
	if strings.TrimSpace(databaseID) == "" || strings.TrimSpace(username) == "" {
		return fmt.Errorf("%w: database_id and username are required", ErrInvalid)
	}
	if !strings.HasPrefix(newSecretRef, "secret://") {
		return fmt.Errorf("%w: secret_ref must start with secret://", ErrInvalid)
	}
	ct, err := s.pool.Exec(ctx, `
		UPDATE database_users
		   SET secret_ref = $3
		 WHERE database_id = $1 AND username = $2 AND revoked_at IS NULL`,
		databaseID, username, newSecretRef)
	if err != nil {
		return fmt.Errorf("databases: update user secret_ref: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RevokeUser marks a database user as revoked.
func (s *Store) RevokeUser(ctx context.Context, databaseID, username string) error {
	if strings.TrimSpace(databaseID) == "" || strings.TrimSpace(username) == "" {
		return fmt.Errorf("%w: database_id and username are required", ErrInvalid)
	}
	now := s.clock()
	ct, err := s.pool.Exec(ctx, `
		UPDATE database_users
		   SET revoked_at = $3
		 WHERE database_id = $1 AND username = $2 AND revoked_at IS NULL`,
		databaseID, username, now)
	if err != nil {
		return fmt.Errorf("databases: revoke user: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ─── Backup Records ───────────────────────────────────────────────────────────

// CreateBackupParams configures backup record creation.
type CreateBackupParams struct {
	DatabaseID     string
	ProjectID      string
	ServerID       string
	Trigger        string
	RequestedBy    string
	IdempotencyKey string
	JobID          string
}

// CreateBackup inserts a backup record in the queued state.
func (s *Store) CreateBackup(ctx context.Context, p CreateBackupParams) (DatabaseBackup, error) {
	if strings.TrimSpace(p.DatabaseID) == "" {
		return DatabaseBackup{}, fmt.Errorf("%w: database_id is required", ErrInvalid)
	}
	if err := validateTrigger(p.Trigger); err != nil {
		return DatabaseBackup{}, err
	}
	var requestedBy, idempotencyKey, jobID any
	if v := strings.TrimSpace(p.RequestedBy); v != "" {
		requestedBy = v
	}
	if v := strings.TrimSpace(p.IdempotencyKey); v != "" {
		idempotencyKey = v
	}
	if v := strings.TrimSpace(p.JobID); v != "" {
		jobID = v
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO database_backups (database_id, project_id, server_id, trigger, requested_by, idempotency_key, job_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING %s`, backupColumns),
		p.DatabaseID, p.ProjectID, p.ServerID, p.Trigger, requestedBy, idempotencyKey, jobID,
	)
	b, err := scanBackup(row)
	if err != nil {
		switch {
		case isUniqueViolation(err):
			return DatabaseBackup{}, ErrConflictActive
		case isForeignKeyViolation(err):
			return DatabaseBackup{}, fmt.Errorf("%w: database does not exist", ErrInvalid)
		default:
			return DatabaseBackup{}, err
		}
	}
	return b, nil
}

// GetBackup returns one backup record by id.
func (s *Store) GetBackup(ctx context.Context, id string) (DatabaseBackup, error) {
	if strings.TrimSpace(id) == "" {
		return DatabaseBackup{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM database_backups WHERE id = $1`, backupColumns), id)
	return scanBackup(row)
}

// ListBackups returns backup records for one database, newest first.
func (s *Store) ListBackups(ctx context.Context, databaseID string, limit int) ([]DatabaseBackup, error) {
	if strings.TrimSpace(databaseID) == "" {
		return nil, fmt.Errorf("%w: database_id is required", ErrInvalid)
	}
	if limit <= 0 || limit > maxListLimit {
		return nil, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalid, maxListLimit)
	}
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM database_backups
		 WHERE database_id = $1
		 ORDER BY created_at DESC, id
		 LIMIT $2`, backupColumns), databaseID, limit)
	if err != nil {
		return nil, fmt.Errorf("databases: list backups: %w", err)
	}
	defer rows.Close()
	var out []DatabaseBackup
	for rows.Next() {
		b, err := scanBackup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("databases: iterate backups: %w", err)
	}
	return out, nil
}

// UpdateBackupStateParams carries completion data for a finished backup.
type UpdateBackupStateParams struct {
	ID        string
	State     string
	DumpPath  string
	SizeBytes int64
	SHA256    string
}

// UpdateBackupState updates a backup record after the worker finishes.
func (s *Store) UpdateBackupState(ctx context.Context, p UpdateBackupStateParams) (DatabaseBackup, error) {
	if strings.TrimSpace(p.ID) == "" {
		return DatabaseBackup{}, fmt.Errorf("%w: id is required", ErrInvalid)
	}
	switch p.State {
	case BackupCompleted, BackupFailed:
	default:
		return DatabaseBackup{}, fmt.Errorf("%w: state must be completed or failed", ErrInvalid)
	}
	now := s.clock()
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		UPDATE database_backups
		   SET state        = $2,
		       dump_path    = $3,
		       size_bytes   = $4,
		       sha256       = $5,
		       completed_at = $6,
		       started_at   = COALESCE(started_at, $6)
		 WHERE id = $1
		RETURNING %s`, backupColumns),
		p.ID, p.State, p.DumpPath, p.SizeBytes, p.SHA256, now,
	)
	b, err := scanBackup(row)
	if err != nil {
		return DatabaseBackup{}, err
	}
	return b, nil
}

// MarkBackupRunning sets a backup record to running state.
func (s *Store) MarkBackupRunning(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("%w: id is required", ErrInvalid)
	}
	now := s.clock()
	ct, err := s.pool.Exec(ctx, `
		UPDATE database_backups
		   SET state = 'running', started_at = $2
		 WHERE id = $1 AND state = 'queued'`,
		id, now)
	if err != nil {
		return fmt.Errorf("databases: mark backup running: %w", err)
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("%w: backup not in queued state", ErrState)
	}
	return nil
}

// ─── Connection String ────────────────────────────────────────────────────────

// ConnectionString generates a connection string for the given database and
// user. The password is passed in plaintext — it must have been opened from
// internal/secret by the caller and must not be logged or stored.
func ConnectionString(db ManagedDatabase, username, password string) string {
	switch db.Engine {
	case EnginePostgreSQL:
		// URL-encode minimal characters for safety; avoid generic url.PathEscape
		// which would encode characters valid in PG DSNs.
		user := pgDSNEscape(username)
		pass := pgDSNEscape(password)
		return fmt.Sprintf("postgresql://%s:%s@localhost/%s?sslmode=disable", user, pass, db.DBName)
	case EngineMariaDB:
		user := pgDSNEscape(username)
		pass := pgDSNEscape(password)
		return fmt.Sprintf("mysql://%s:%s@unix(/var/run/mysqld/mysqld.sock)/%s", user, pass, db.DBName)
	default:
		return ""
	}
}

// pgDSNEscape percent-encodes the characters that would break a URI userinfo
// component. Minimal set: @, /, :, %, space, #, ?, [, ].
func pgDSNEscape(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch c {
		case '@', '/', ':', '%', ' ', '#', '?', '[', ']':
			fmt.Fprintf(&b, "%%%02X", c)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}

// ─── Validators ───────────────────────────────────────────────────────────────

func validateSlug(slug string) error {
	if len(slug) < 2 || len(slug) > 48 {
		return fmt.Errorf("%w: slug must be between 2 and 48 characters", ErrInvalid)
	}
	if !slugRE.MatchString(slug) {
		return fmt.Errorf("%w: slug %q must match ^[a-z0-9]([a-z0-9_]*[a-z0-9])?$", ErrInvalid, slug)
	}
	return nil
}

func validateEngine(e string) error {
	switch e {
	case EnginePostgreSQL, EngineMariaDB:
		return nil
	default:
		return fmt.Errorf("%w: engine %q must be postgresql or mariadb", ErrInvalid, e)
	}
}

func validateTrigger(t string) error {
	switch t {
	case TriggerManual, TriggerScheduled, TriggerPreUpgrade, TriggerPreDelete:
		return nil
	default:
		return fmt.Errorf("%w: trigger %q is not valid", ErrInvalid, t)
	}
}

func validatePrivileges(privs []string) error {
	for _, p := range privs {
		if !AllowedPrivileges[strings.ToUpper(p)] {
			return fmt.Errorf("%w: privilege %q is not allowed", ErrInvalid, p)
		}
	}
	return nil
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func nullableTrimmed(set *string) any {
	if set == nil {
		return nil
	}
	return strings.TrimSpace(*set)
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

// isConstraint reports whether a unique-violation names this constraint or
// index. For CREATE UNIQUE INDEX (without CONSTRAINT), PostgreSQL fills
// pgErr.ConstraintName with the index name.
func isConstraint(err error, name string) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.ConstraintName == name
	}
	return false
}
