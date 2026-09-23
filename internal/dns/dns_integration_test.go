//go:build integration

package dns

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"

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
	dsn, err := dbtest.IsolatedDatabase(base, "dns")
	if err != nil {
		fmt.Fprintf(os.Stderr, "dns: isolated test database: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("JAWAKER_TEST_DATABASE_URL", dsn); err != nil {
		fmt.Fprintf(os.Stderr, "dns: set test database: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = dbtest.DropDatabase(base, "dns")
	os.Exit(code)
}

func setupDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := dbtest.FixtureURL()
	if dsn == "" {
		t.Skip("JAWAKER_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mig, err := migrate.New(migrations.FS, logger)
	if err != nil {
		t.Fatalf("migrate.New: %v", err)
	}
	if _, err := mig.Up(ctx, pool); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	return pool
}


// seedProject inserts a minimal project and returns its id.
func seedProject(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(),
		`INSERT INTO projects (name, slug) VALUES ('test', 'test-dns') RETURNING id`).Scan(&id)
	if err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return id
}

func TestProviderCRUD(t *testing.T) {
	pool := setupDB(t)
	store := NewStore(pool, nil)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	p, err := store.CreateProvider(ctx, CreateProviderParams{
		ProjectID: projectID,
		Name:      "CF prod",
		Provider:  ProviderCloudflare,
		SecretRef: "secret://dns/cf-test/token",
	})
	if err != nil {
		t.Fatalf("CreateProvider: %v", err)
	}
	if p.Provider != ProviderCloudflare {
		t.Errorf("provider = %q, want cloudflare", p.Provider)
	}
	// SecretRef must be present (not redacted at store level).
	if p.SecretRef == "" {
		t.Error("SecretRef empty")
	}

	got, err := store.GetProvider(ctx, p.ID)
	if err != nil {
		t.Fatalf("GetProvider: %v", err)
	}
	if got.ID != p.ID {
		t.Errorf("id mismatch")
	}

	list, err := store.ListProviders(ctx, projectID)
	if err != nil {
		t.Fatalf("ListProviders: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("list len = %d, want 1", len(list))
	}

	if err := store.DeleteProvider(ctx, p.ID); err != nil {
		t.Fatalf("DeleteProvider: %v", err)
	}
	if _, err := store.GetProvider(ctx, p.ID); !isNotFound(err) {
		t.Errorf("expected not found after delete, got %v", err)
	}
}

func TestZoneCRUD(t *testing.T) {
	pool := setupDB(t)
	store := NewStore(pool, nil)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	prov, _ := store.CreateProvider(ctx, CreateProviderParams{
		ProjectID: projectID,
		Name:      "cf",
		Provider:  ProviderCloudflare,
		SecretRef: "secret://dns/z/token",
	})

	z, err := store.CreateZone(ctx, CreateZoneParams{
		ProjectID:  projectID,
		ProviderID: prov.ID,
		Apex:       "example.com",
		ExternalID: "cf-zone-abc",
	})
	if err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
	if z.Apex != "example.com" {
		t.Errorf("apex = %q", z.Apex)
	}

	// duplicate apex must fail
	_, err = store.CreateZone(ctx, CreateZoneParams{
		ProjectID:  projectID,
		ProviderID: prov.ID,
		Apex:       "example.com",
	})
	if !isInvalid(err) {
		t.Errorf("duplicate apex: expected invalid, got %v", err)
	}

	// degrade then recover
	if err := store.MarkZoneDegraded(ctx, z.ID, "timeout"); err != nil {
		t.Fatalf("MarkZoneDegraded: %v", err)
	}
	if err := store.MarkZoneSynced(ctx, z.ID, "cf-zone-abc"); err != nil {
		t.Fatalf("MarkZoneSynced: %v", err)
	}

	got, _ := store.GetZone(ctx, z.ID)
	if got.State != ZoneStateActive {
		t.Errorf("state = %q after sync, want active", got.State)
	}
	if got.LastError != nil {
		t.Errorf("last_error should be nil after sync")
	}

	if err := store.DeleteZone(ctx, z.ID); err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}
}

func TestRecordCRUD(t *testing.T) {
	pool := setupDB(t)
	store := NewStore(pool, nil)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	prov, _ := store.CreateProvider(ctx, CreateProviderParams{
		ProjectID: projectID, Name: "cf", Provider: ProviderCloudflare,
		SecretRef: "secret://dns/r/token",
	})
	z, _ := store.CreateZone(ctx, CreateZoneParams{
		ProjectID: projectID, ProviderID: prov.ID, Apex: "rec.example.com",
	})

	r, err := store.CreateRecord(ctx, CreateRecordParams{
		ZoneID: z.ID, RType: "A", Name: "@", Value: "1.2.3.4", TTL: 300,
	})
	if err != nil {
		t.Fatalf("CreateRecord: %v", err)
	}
	if r.SyncState != SyncPending {
		t.Errorf("sync_state = %q, want pending", r.SyncState)
	}

	if err := store.MarkRecordSynced(ctx, r.ID, "cf-rec-1"); err != nil {
		t.Fatalf("MarkRecordSynced: %v", err)
	}
	if err := store.MarkRecordDrifted(ctx, r.ID); err != nil {
		t.Fatalf("MarkRecordDrifted: %v", err)
	}

	got, _ := store.GetRecord(ctx, r.ID)
	if got.SyncState != SyncDrifted {
		t.Errorf("sync_state = %q, want drifted", got.SyncState)
	}

	updated, err := store.UpdateRecord(ctx, r.ID, UpdateRecordParams{Value: "5.6.7.8", TTL: 600})
	if err != nil {
		t.Fatalf("UpdateRecord: %v", err)
	}
	if updated.Value != "5.6.7.8" {
		t.Errorf("value = %q", updated.Value)
	}
	if updated.SyncState != SyncPending {
		t.Errorf("sync_state = %q after update, want pending", updated.SyncState)
	}

	if err := store.DeleteRecord(ctx, r.ID); err != nil {
		t.Fatalf("DeleteRecord: %v", err)
	}
	got2, _ := store.GetRecord(ctx, r.ID)
	if got2.SyncState != SyncDeleting {
		t.Errorf("sync_state = %q after delete, want deleting", got2.SyncState)
	}
}

func TestOrderStateMachine(t *testing.T) {
	pool := setupDB(t)
	store := NewStore(pool, nil)
	ctx := context.Background()
	projectID := seedProject(t, pool)

	o, err := store.CreateOrder(ctx, CreateOrderParams{
		ProjectID:   projectID,
		Identifiers: []string{"*.example.com", "example.com"},
	})
	if err != nil {
		t.Fatalf("CreateOrder: %v", err)
	}
	if o.State != OrderPending {
		t.Errorf("state = %q, want pending", o.State)
	}

	// pending → ready
	o, err = store.AdvanceOrderState(ctx, o.ID, OrderReady,
		WithOrderURL("https://acme.example/order/1"),
		WithChallengeToken("token-abc"),
		WithChallengeKeyAuth("token-abc.key"),
	)
	if err != nil {
		t.Fatalf("advance pending→ready: %v", err)
	}
	if o.State != OrderReady {
		t.Errorf("state = %q, want ready", o.State)
	}

	// invalid transition: ready → valid (must go through processing)
	_, err = store.AdvanceOrderState(ctx, o.ID, OrderValid)
	if !isState(err) {
		t.Errorf("invalid transition: expected state error, got %v", err)
	}

	// ready → processing
	o, _ = store.AdvanceOrderState(ctx, o.ID, OrderProcessing)
	// processing → valid
	o, err = store.AdvanceOrderState(ctx, o.ID, OrderValid)
	if err != nil {
		t.Fatalf("advance processing→valid: %v", err)
	}
	if o.CompletedAt == nil {
		t.Error("completed_at should be set on valid")
	}

	// terminal state rejects further transitions
	_, err = store.AdvanceOrderState(ctx, o.ID, OrderCanceled)
	if !isState(err) {
		t.Errorf("terminal state: expected state error, got %v", err)
	}
}

func isNotFound(err error) bool { return err != nil && (err == ErrNotFound || containsErr(err, ErrNotFound)) }
func isInvalid(err error) bool  { return err != nil && containsErr(err, ErrInvalid) }
func isState(err error) bool    { return err != nil && containsErr(err, ErrState) }

func containsErr(err, target error) bool {
	for err != nil {
		if err == target {
			return true
		}
		err = unwrap(err)
	}
	return false
}

func unwrap(err error) error {
	type unwrapper interface{ Unwrap() error }
	if u, ok := err.(unwrapper); ok {
		return u.Unwrap()
	}
	return nil
}
