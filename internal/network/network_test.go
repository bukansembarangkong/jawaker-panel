//go:build integration

package network

import (
	"context"
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
	dsn, err := dbtest.IsolatedDatabase(base, "network")
	if err != nil {
		fmt.Fprintf(os.Stderr, "network: isolated test database: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("JAWAKER_TEST_DATABASE_URL", dsn); err != nil {
		fmt.Fprintf(os.Stderr, "network: set test database: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = dbtest.DropDatabase(base, "network")
	os.Exit(code)
}

type fixture struct {
	store    *Store
	pool     *pgxpool.Pool
	serverID string
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
	mg, err := migrate.New(migrations.FS, logger)
	if err != nil {
		t.Fatalf("migrate.New: %v", err)
	}
	if _, err := mg.Up(ctx, pool); err != nil {
		t.Fatalf("migrate up: %v", err)
	}

	var serverID string
	if err := pool.QueryRow(ctx, `INSERT INTO servers (name, address, status) VALUES ('net-srv','127.0.0.1:9443','active') RETURNING id`).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}

	return fixture{store: NewStore(pool), pool: pool, serverID: serverID}
}

// TestZoneLifecycle proves zone create, list, delete.
func TestZoneLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	z, err := f.store.CreateZone(ctx, CreateZoneParams{
		ServerID:   f.serverID,
		Name:       "management",
		Kind:       "management",
		Interfaces: "wg0",
	})
	if err != nil {
		t.Fatalf("CreateZone: %v", err)
	}
	if z.Name != "management" {
		t.Errorf("name = %q, want management", z.Name)
	}

	zones, err := f.store.ListZones(ctx, f.serverID)
	if err != nil {
		t.Fatalf("ListZones: %v", err)
	}
	if len(zones) != 1 {
		t.Errorf("ListZones count = %d, want 1", len(zones))
	}

	if err := f.store.DeleteZone(ctx, z.ID); err != nil {
		t.Fatalf("DeleteZone: %v", err)
	}
	zones, _ = f.store.ListZones(ctx, f.serverID)
	if len(zones) != 0 {
		t.Errorf("after delete, zone count = %d, want 0", len(zones))
	}
}

// TestFirewallRuleLifecycle proves rule create, activate, list, delete.
func TestFirewallRuleLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	r, err := f.store.CreateRule(ctx, CreateRuleParams{
		ServerID:    f.serverID,
		Chain:       "INPUT",
		Priority:    50,
		Protocol:    "tcp",
		DestPortMin: 22,
		DestPortMax: 22,
		Action:      "accept",
		Enabled:     true,
		Description: "allow SSH",
		State:       StateCandidate,
	})
	if err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	if r.Chain != "INPUT" {
		t.Errorf("chain = %q, want INPUT", r.Chain)
	}
	if r.State != StateCandidate {
		t.Errorf("state = %q, want candidate", r.State)
	}

	// Activate transitions candidate → active.
	if err := f.store.ActivateRules(ctx, f.serverID); err != nil {
		t.Fatalf("ActivateRules: %v", err)
	}
	r2, err := f.store.GetRule(ctx, r.ID)
	if err != nil {
		t.Fatalf("GetRule after activate: %v", err)
	}
	if r2.State != StateActive {
		t.Errorf("after activate, state = %q, want active", r2.State)
	}

	if err := f.store.DeleteRule(ctx, r.ID); err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
}

// TestPortForwardConflict proves the unique-port conflict check.
func TestPortForwardConflict(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	fwd, err := f.store.CreateForward(ctx, CreateForwardParams{
		ServerID:    f.serverID,
		Protocol:    "tcp",
		ListenPort:  8080,
		DestAddress: "10.0.0.5",
		DestPort:    80,
		Enabled:     true,
	})
	if err != nil {
		t.Fatalf("CreateForward: %v", err)
	}
	if fwd.ListenPort != 8080 {
		t.Errorf("listen_port = %d, want 8080", fwd.ListenPort)
	}

	// Activate so the port is "owned".
	if err := f.store.ActivateForwards(ctx, f.serverID); err != nil {
		t.Fatalf("ActivateForwards: %v", err)
	}

	// Second forward on same proto+port must conflict.
	_, err = f.store.CreateForward(ctx, CreateForwardParams{
		ServerID:    f.serverID,
		Protocol:    "tcp",
		ListenPort:  8080,
		DestAddress: "10.0.0.6",
		DestPort:    80,
	})
	if err == nil {
		t.Error("expected ErrConflict for duplicate port, got nil")
	}
}

// TestWireGuardPeerLifecycle proves peer create, list, delete.
func TestWireGuardPeerLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	// 44-char base64 WireGuard public key (test vector).
	pubKey := "dGVzdGtleXRlc3RrZXl0ZXN0a2V5dGVzdGtleXQ="
	p, err := f.store.CreatePeer(ctx, CreatePeerParams{
		ServerID:   f.serverID,
		PublicKey:  pubKey,
		Label:      "controller",
		AllowedIPs: "10.100.0.0/24",
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("CreatePeer: %v", err)
	}
	if p.Label != "controller" {
		t.Errorf("label = %q, want controller", p.Label)
	}

	peers, err := f.store.ListPeers(ctx, f.serverID)
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(peers) != 1 {
		t.Errorf("peer count = %d, want 1", len(peers))
	}

	if err := f.store.DeletePeer(ctx, p.ID); err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}
}

// TestApplyLog proves record and list.
func TestApplyLog(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	log, err := f.store.RecordApply(ctx, f.serverID, "user-abc", OutcomeApplied, "",
		[]byte(`{"rules":1}`), []byte(`{}`))
	if err != nil {
		t.Fatalf("RecordApply: %v", err)
	}
	if log.Outcome != OutcomeApplied {
		t.Errorf("outcome = %q, want applied", log.Outcome)
	}

	logs, err := f.store.ListApplyLog(ctx, f.serverID, 10)
	if err != nil {
		t.Fatalf("ListApplyLog: %v", err)
	}
	if len(logs) != 1 {
		t.Errorf("log count = %d, want 1", len(logs))
	}
}
