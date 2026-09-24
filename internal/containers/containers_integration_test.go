//go:build integration

package containers

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
	dsn, err := dbtest.IsolatedDatabase(base, "containers")
	if err != nil {
		fmt.Fprintf(os.Stderr, "containers: isolated test database: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("JAWAKER_TEST_DATABASE_URL", dsn); err != nil {
		fmt.Fprintf(os.Stderr, "containers: set test database: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = dbtest.DropDatabase(base, "containers")
	os.Exit(code)
}

type fixture struct {
	store     *Store
	pool      *pgxpool.Pool
	projectID string
	serverID  string
}

func newFixture(t *testing.T) fixture {
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
	if err := pool.QueryRow(ctx, `INSERT INTO servers (name, address, status) VALUES ('cnt-srv','127.0.0.1:9443','active') RETURNING id`).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if err := pool.QueryRow(ctx, `INSERT INTO projects (slug, name, state) VALUES ('cnt-proj','Container Project','active') RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	return fixture{store: NewStore(pool, nil), pool: pool, projectID: projectID, serverID: serverID}
}

// TestRegistryLifecycle proves registry create, get, list, delete.
func TestRegistryLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	reg, err := f.store.CreateRegistry(ctx, CreateRegistryParams{
		ProjectID: f.projectID,
		Name:      "GHCR",
		Host:      "ghcr.io",
	})
	if err != nil {
		t.Fatalf("CreateRegistry: %v", err)
	}
	if reg.ID == "" {
		t.Error("id empty")
	}

	got, err := f.store.GetRegistry(ctx, reg.ID)
	if err != nil {
		t.Fatalf("GetRegistry: %v", err)
	}
	if got.Host != "ghcr.io" {
		t.Errorf("host = %q, want ghcr.io", got.Host)
	}

	list, err := f.store.ListRegistries(ctx, f.projectID)
	if err != nil {
		t.Fatalf("ListRegistries: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("len(list) = %d, want 1", len(list))
	}

	if err := f.store.DeleteRegistry(ctx, reg.ID); err != nil {
		t.Fatalf("DeleteRegistry: %v", err)
	}
	// second delete must return not found
	if err := f.store.DeleteRegistry(ctx, reg.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("second delete err = %v, want ErrNotFound", err)
	}
}

// TestStackLifecycle proves compose stack create, get, update state, delete.
func TestStackLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	st, err := f.store.CreateStack(ctx, CreateStackParams{
		ProjectID:   f.projectID,
		ServerID:    f.serverID,
		Name:        "web",
		ComposeYAML: "version: '3'\nservices:\n  web:\n    image: nginx",
	})
	if err != nil {
		t.Fatalf("CreateStack: %v", err)
	}
	if st.State != StackActive {
		t.Errorf("initial state = %q, want active", st.State)
	}

	// Duplicate name must conflict
	_, err = f.store.CreateStack(ctx, CreateStackParams{ProjectID: f.projectID, ServerID: f.serverID, Name: "web"})
	if !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate stack err = %v, want ErrConflict", err)
	}

	updated, err := f.store.UpdateStackState(ctx, st.ID, StackDegraded)
	if err != nil {
		t.Fatalf("UpdateStackState: %v", err)
	}
	if updated.State != StackDegraded {
		t.Errorf("state = %q, want degraded", updated.State)
	}

	if err := f.store.DeleteStack(ctx, st.ID); err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
}

// TestContainerPrivilegedGate proves that ListPrivileged returns only
// privileged containers. Gate: "unsafe privileged configuration warnings".
func TestContainerPrivilegedGate(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// Unprivileged container
	_, err := f.store.CreateContainer(ctx, CreateContainerParams{
		ProjectID: f.projectID, ServerID: f.serverID,
		Name: "safe", ImageRef: "nginx:latest", State: StateRunning, Privileged: false,
	})
	if err != nil {
		t.Fatalf("create safe container: %v", err)
	}

	// Privileged container (Gate flag)
	c, err := f.store.CreateContainer(ctx, CreateContainerParams{
		ProjectID: f.projectID, ServerID: f.serverID,
		Name: "priv", ImageRef: "nginx:latest", State: StateRunning, Privileged: true,
	})
	if err != nil {
		t.Fatalf("create privileged container: %v", err)
	}

	priv, err := f.store.ListPrivileged(ctx, f.projectID)
	if err != nil {
		t.Fatalf("ListPrivileged: %v", err)
	}
	if len(priv) != 1 {
		t.Fatalf("len(priv) = %d, want 1", len(priv))
	}
	if priv[0].ID != c.ID {
		t.Errorf("priv[0].ID = %q, want %q", priv[0].ID, c.ID)
	}

	// UpdateContainerState
	updated, err := f.store.UpdateContainerState(ctx, c.ID, StateStopped, HealthNone)
	if err != nil {
		t.Fatalf("UpdateContainerState: %v", err)
	}
	if updated.State != StateStopped {
		t.Errorf("state = %q, want stopped", updated.State)
	}
}

// TestVolumeLifecycle proves volume create, get, list, delete.
func TestVolumeLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	v, err := f.store.CreateVolume(ctx, CreateVolumeParams{
		ProjectID:  f.projectID,
		ServerID:   f.serverID,
		Name:       "data",
		Driver:     "local",
		MountPoint: "/var/lib/data",
	})
	if err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}

	got, err := f.store.GetVolume(ctx, v.ID)
	if err != nil {
		t.Fatalf("GetVolume: %v", err)
	}
	if got.Driver != "local" {
		t.Errorf("driver = %q, want local", got.Driver)
	}

	vols, err := f.store.ListVolumes(ctx, f.projectID)
	if err != nil {
		t.Fatalf("ListVolumes: %v", err)
	}
	if len(vols) != 1 {
		t.Fatalf("len(vols) = %d, want 1", len(vols))
	}

	if err := f.store.DeleteVolume(ctx, v.ID); err != nil {
		t.Fatalf("DeleteVolume: %v", err)
	}
	if _, err := f.store.GetVolume(ctx, v.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetVolume after delete err = %v, want ErrNotFound", err)
	}
}
