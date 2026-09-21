//go:build integration

package databases

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
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
	dsn, err := dbtest.IsolatedDatabase(base, "databases")
	if err != nil {
		fmt.Fprintf(os.Stderr, "databases: isolated test database: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("JAWAKER_TEST_DATABASE_URL", dsn); err != nil {
		fmt.Fprintf(os.Stderr, "databases: set test database: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = dbtest.DropDatabase(base, "databases")
	os.Exit(code)
}

type dbFixture struct {
	store     *Store
	pool      *pgxpool.Pool
	projectID string
	serverID  string
}

func newFixture(t *testing.T) dbFixture {
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

	store := NewStore(pool, nil)
	return dbFixture{store: store, pool: pool, projectID: projectID, serverID: serverID}
}

func (f dbFixture) createDB(t *testing.T, slug, dbName string) ManagedDatabase {
	t.Helper()
	db, err := f.store.CreateDatabase(context.Background(), CreateDatabaseParams{
		ProjectID:     f.projectID,
		ServerID:      f.serverID,
		Slug:          slug,
		Name:          "Test DB " + slug,
		Engine:        EnginePostgreSQL,
		EngineVersion: "17",
		DBName:        dbName,
	})
	if err != nil {
		t.Fatalf("create database %s: %v", slug, err)
	}
	return db
}

func TestDatabaseCreationAndLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	db := f.createDB(t, "mydb", "jw_main_mydb")
	if db.State != StateActive || !db.Live() || !db.Usable() {
		t.Fatalf("new database state: got %+v, want active", db)
	}

	// Slug taken
	_, err := f.store.CreateDatabase(ctx, CreateDatabaseParams{
		ProjectID: f.projectID, ServerID: f.serverID,
		Slug: "mydb", Name: "dup", Engine: EnginePostgreSQL, DBName: "jw_main_dup",
	})
	if !errors.Is(err, ErrSlugTaken) {
		t.Fatalf("duplicate slug: got %v, want ErrSlugTaken", err)
	}

	// db_name taken on same server
	_, err = f.store.CreateDatabase(ctx, CreateDatabaseParams{
		ProjectID: f.projectID, ServerID: f.serverID,
		Slug: "other", Name: "dup name", Engine: EnginePostgreSQL, DBName: "jw_main_mydb",
	})
	if !errors.Is(err, ErrDBNameTaken) {
		t.Fatalf("duplicate db_name: got %v, want ErrDBNameTaken", err)
	}

	// Update
	name := "Renamed"
	ver := "17.2"
	updated, err := f.store.UpdateDatabase(ctx, db.ID, UpdateDatabaseParams{Name: &name, EngineVersion: &ver})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Name != name || updated.EngineVersion != ver {
		t.Fatalf("update: got %q/%q", updated.Name, updated.EngineVersion)
	}

	// Delete lifecycle: active -> pending_delete -> deleted
	del, err := f.store.RequestDelete(ctx, db.ID, time.Hour)
	if err != nil {
		t.Fatalf("request delete: %v", err)
	}
	if del.State != StatePendingDelete || del.DeleteAfter == nil {
		t.Fatalf("pending delete: got %+v", del)
	}
	cancelled, err := f.store.CancelDelete(ctx, db.ID)
	if err != nil || cancelled.State != StateActive {
		t.Fatalf("cancel delete: %v %+v", err, cancelled)
	}
	if _, err := f.store.RequestDelete(ctx, db.ID, time.Second); err != nil {
		t.Fatalf("request delete again: %v", err)
	}
	if _, err := f.store.FinalizeDelete(ctx, db.ID); err == nil {
		t.Fatalf("finalize before grace elapsed should fail")
	}
	time.Sleep(2 * time.Second)
	final, err := f.store.FinalizeDelete(ctx, db.ID)
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if final.State != StateDeleted || final.DeletedAt == nil {
		t.Fatalf("deleted: got %+v", final)
	}
	if _, err := f.store.GetDatabase(ctx, db.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get deleted: got %v, want ErrNotFound", err)
	}
}

func TestDatabaseNonActiveProjectRefused(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// Insert suspended project
	var suspProject string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO projects (slug, name, state)
		VALUES ('suspended-proj', 'Suspended', 'suspended')
		RETURNING id`).Scan(&suspProject); err != nil {
		t.Fatalf("insert suspended project: %v", err)
	}

	_, err := f.store.CreateDatabase(ctx, CreateDatabaseParams{
		ProjectID: suspProject, ServerID: f.serverID,
		Slug: "blocked", Name: "blocked", Engine: EnginePostgreSQL, DBName: "jw_susp_blocked",
	})
	if !errors.Is(err, ErrState) {
		t.Fatalf("create in suspended project: got %v, want ErrState", err)
	}
}

func TestDatabaseCrossProjectIsolation(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	var otherProject string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO projects (slug, name, state)
		VALUES ('other-project', 'Other', 'active')
		RETURNING id`).Scan(&otherProject); err != nil {
		t.Fatalf("insert other project: %v", err)
	}

	db := f.createDB(t, "isolated", "jw_main_isolated")

	// Own project: found
	if _, err := f.store.GetDatabaseInProject(ctx, f.projectID, db.ID); err != nil {
		t.Fatalf("own project lookup: %v", err)
	}
	// Other project: not found (anti-enumeration)
	if _, err := f.store.GetDatabaseInProject(ctx, otherProject, db.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-project lookup: got %v, want ErrNotFound", err)
	}
	// List in other project is empty
	list, err := f.store.ListDatabases(ctx, otherProject)
	if err != nil || len(list) != 0 {
		t.Fatalf("list other project: %v len=%d, want empty", err, len(list))
	}
}

func TestDatabaseUserLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	db := f.createDB(t, "userdb", "jw_main_userdb")

	u, err := f.store.CreateUser(ctx, CreateUserParams{
		DatabaseID: db.ID,
		Username:   "app_user",
		SecretRef:  "secret://project/" + f.projectID + "/database/" + db.ID + "/user/app_user/password",
		Privileges: []string{"SELECT", "INSERT"},
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if !u.Active() || len(u.Privileges) != 2 {
		t.Fatalf("created user: got %+v", u)
	}

	// Username taken
	_, err = f.store.CreateUser(ctx, CreateUserParams{
		DatabaseID: db.ID, Username: "app_user",
		SecretRef: "secret://other/ref",
	})
	if !errors.Is(err, ErrUsernameTaken) {
		t.Fatalf("duplicate username: got %v, want ErrUsernameTaken", err)
	}

	// Bad secret ref rejected
	_, err = f.store.CreateUser(ctx, CreateUserParams{
		DatabaseID: db.ID, Username: "another",
		SecretRef: "plaintext-password",
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-secret ref: got %v, want ErrInvalid", err)
	}

	// Rotate: update secret ref
	newRef := "secret://project/" + f.projectID + "/database/" + db.ID + "/user/app_user/password/v2"
	if err := f.store.UpdateUserSecretRef(ctx, db.ID, "app_user", newRef); err != nil {
		t.Fatalf("rotate ref: %v", err)
	}
	got, err := f.store.GetUser(ctx, db.ID, "app_user")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if got.SecretRef != newRef {
		t.Fatalf("rotated ref: got %q, want %q", got.SecretRef, newRef)
	}

	// Revoke
	if err := f.store.RevokeUser(ctx, db.ID, "app_user"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	users, err := f.store.ListUsers(ctx, db.ID)
	if err != nil || len(users) != 0 {
		t.Fatalf("list after revoke: %v len=%d, want empty", err, len(users))
	}
	if err := f.store.RevokeUser(ctx, db.ID, "app_user"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double revoke: got %v, want ErrNotFound", err)
	}
}

func TestDatabaseBackupLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	db := f.createDB(t, "backupdb", "jw_main_backupdb")

	b, err := f.store.CreateBackup(ctx, CreateBackupParams{
		DatabaseID:     db.ID,
		ProjectID:      f.projectID,
		ServerID:       f.serverID,
		Trigger:        TriggerManual,
		IdempotencyKey: "manual:test-1",
	})
	if err != nil {
		t.Fatalf("create backup: %v", err)
	}
	if b.State != BackupQueued {
		t.Fatalf("new backup state: got %q, want queued", b.State)
	}

	// Idempotency: same key rejected
	_, err = f.store.CreateBackup(ctx, CreateBackupParams{
		DatabaseID: db.ID, ProjectID: f.projectID, ServerID: f.serverID,
		Trigger: TriggerManual, IdempotencyKey: "manual:test-1",
	})
	if !errors.Is(err, ErrConflictActive) {
		t.Fatalf("duplicate idempotency key: got %v, want ErrConflictActive", err)
	}

	// Running -> completed
	if err := f.store.MarkBackupRunning(ctx, b.ID); err != nil {
		t.Fatalf("mark running: %v", err)
	}
	if err := f.store.MarkBackupRunning(ctx, b.ID); !errors.Is(err, ErrState) {
		t.Fatalf("double running: got %v, want ErrState", err)
	}
	done, err := f.store.UpdateBackupState(ctx, UpdateBackupStateParams{
		ID: b.ID, State: BackupCompleted,
		DumpPath:  "/var/lib/jawaker/db-dumps/" + db.ID + ".dump",
		SizeBytes: 1024, SHA256: "abc123",
	})
	if err != nil {
		t.Fatalf("complete backup: %v", err)
	}
	if done.State != BackupCompleted || done.SizeBytes != 1024 || done.CompletedAt == nil {
		t.Fatalf("completed backup: got %+v", done)
	}

	// List
	list, err := f.store.ListBackups(ctx, db.ID, 10)
	if err != nil || len(list) != 1 {
		t.Fatalf("list backups: %v len=%d, want 1", err, len(list))
	}
}

func TestDatabaseValidationRejectsBadInput(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	cases := []struct {
		name string
		p    CreateDatabaseParams
	}{
		{"bad engine", CreateDatabaseParams{ProjectID: f.projectID, ServerID: f.serverID, Slug: "x1", Name: "x", Engine: "sqlite", DBName: "jw_x_1"}},
		{"bad db_name (hyphen)", CreateDatabaseParams{ProjectID: f.projectID, ServerID: f.serverID, Slug: "x2", Name: "x", Engine: EnginePostgreSQL, DBName: "jw-x-2"}},
		{"bad db_name (uppercase)", CreateDatabaseParams{ProjectID: f.projectID, ServerID: f.serverID, Slug: "x3", Name: "x", Engine: EnginePostgreSQL, DBName: "JW_X_3"}},
		{"empty slug", CreateDatabaseParams{ProjectID: f.projectID, ServerID: f.serverID, Slug: "", Name: "x", Engine: EnginePostgreSQL, DBName: "jw_x_4"}},
		{"missing project", CreateDatabaseParams{ServerID: f.serverID, Slug: "x5", Name: "x", Engine: EnginePostgreSQL, DBName: "jw_x_5"}},
	}
	for _, tc := range cases {
		_, err := f.store.CreateDatabase(ctx, tc.p)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: got %v, want ErrInvalid", tc.name, err)
		}
	}
}
