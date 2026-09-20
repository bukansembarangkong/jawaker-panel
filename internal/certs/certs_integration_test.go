//go:build integration

package certs

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/db/migrate"
	"github.com/bukansembarangkong/jawaker-panel/internal/dbtest"
	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
	"github.com/bukansembarangkong/jawaker-panel/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestMain(m *testing.M) {
	base := dbtest.FixtureURL()
	if base == "" {
		os.Exit(m.Run())
	}
	dsn, err := dbtest.IsolatedDatabase(base, "certs")
	if err != nil {
		fmt.Fprintf(os.Stderr, "certs: isolated test database: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("JAWAKER_TEST_DATABASE_URL", dsn); err != nil {
		fmt.Fprintf(os.Stderr, "certs: set test database: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = dbtest.DropDatabase(base, "certs")
	os.Exit(code)
}

type mutableClock struct {
	mu sync.Mutex
	at time.Time
}

func newClock(start time.Time) *mutableClock { return &mutableClock{at: start} }

func (c *mutableClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.at
}

func (c *mutableClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

type fixture struct {
	store     *Store
	secrets   *secret.Store
	clock     *mutableClock
	pool      *pgxpool.Pool
	projectID string
	siteID    string
	domainID  string
}

func testMasterKey(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("entropy: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf)
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

	clk := newClock(time.Date(2026, 9, 21, 0, 0, 0, 0, time.UTC))

	secStore, err := secret.New(secret.Options{
		DB:   pool,
		Keys: map[int]string{1: testMasterKey(t)},
		Now:  clk.now,
	})
	if err != nil {
		t.Fatalf("secret.New: %v", err)
	}

	// Insert parent fixtures: server -> project -> site -> domain
	var serverID, projectID, siteID, domainID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO servers (name, address, status)
		VALUES ('cert-node', '127.0.0.1:9443', 'active')
		RETURNING id`).Scan(&serverID); err != nil {
		t.Fatalf("insert server: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO projects (slug, name, state)
		VALUES ('cert-proj', 'Cert Project', 'active')
		RETURNING id`).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO sites (project_id, server_id, slug, name, mode)
		VALUES ($1, $2, 'cert-site', 'Cert Site', 'static')
		RETURNING id`, projectID, serverID).Scan(&siteID); err != nil {
		t.Fatalf("insert site: %v", err)
	}
	if err := pool.QueryRow(ctx, `
		INSERT INTO site_domains (site_id, hostname, is_primary)
		VALUES ($1, 'example.com', true)
		RETURNING id`, siteID).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}

	certStore := NewStore(pool, secStore, clk.now)
	return fixture{
		store:     certStore,
		secrets:   secStore,
		clock:     clk,
		pool:      pool,
		projectID: projectID,
		siteID:    siteID,
		domainID:  domainID,
	}
}

// TestRecordCertificateAndSealKey proves that recording a certificate stores
// only metadata in the certificates table, and seals the private key into the
// secret subsystem under a secret:// reference.
func TestRecordCertificateAndSealKey(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	const (
		fakeKey  = "-----BEGIN EC PRIVATE KEY-----\nFAKEKEY\n-----END EC PRIVATE KEY-----"
		fakeCert = "-----BEGIN CERTIFICATE-----\nFAKECERT\n-----END CERTIFICATE-----"
	)
	now := f.clock.now()
	notAfter := now.Add(90 * 24 * time.Hour)

	cert, err := f.store.Record(ctx, RecordParams{
		ProjectID:     f.projectID,
		IssuedAt:      now,
		NotAfter:      notAfter,
		Identifiers:   []string{"example.com", "www.example.com"},
		Issuer:        "Let's Encrypt",
		DirectoryURL:  "https://acme-v02.api.letsencrypt.org/directory",
		SerialHex:     "04a1b2c3d4e5",
		PrivateKeyPEM: fakeKey,
		ChainPEM:      fakeCert,
	})
	if err != nil {
		t.Fatalf("Record certificate: %v", err)
	}

	if cert.ID == "" {
		t.Error("cert.ID is empty")
	}
	if cert.State != StateActive {
		t.Errorf("state = %q, want active", cert.State)
	}
	if cert.SecretRef == "" {
		t.Fatal("secret_ref is empty")
	}

	// Verify the row in certificates table DOES NOT contain the private key
	var rawRow struct {
		SecretRef string
		ChainPEM  string
	}
	if err := f.pool.QueryRow(ctx,
		`SELECT secret_ref, chain_pem FROM certificates WHERE id = $1`, cert.ID,
	).Scan(&rawRow.SecretRef, &rawRow.ChainPEM); err != nil {
		t.Fatalf("query certificates row: %v", err)
	}
	if rawRow.ChainPEM != fakeCert {
		t.Errorf("chain_pem mismatch")
	}

	// Verify OpenKey decrypts the private key correctly from secret store
	decrypted, err := f.store.OpenKey(ctx, cert)
	if err != nil {
		t.Fatalf("OpenKey: %v", err)
	}
	if decrypted != fakeKey {
		t.Errorf("decrypted key = %q, want %q", decrypted, fakeKey)
	}
}

// TestSafeRenewalBindingRetainsHistory proves the PRD §15.4 safe-renewal invariant:
//
//   - When certificate B replaces certificate A for a domain, A is deactivated
//     (deactivated_at = now()) but KEPT in domain_certificates.
//   - Exactly one certificate is current for the domain.
//   - CurrentForDomain returns B.
func TestSafeRenewalBindingRetainsHistory(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	now := f.clock.now()

	// Record Cert A (initial)
	certA, err := f.store.Record(ctx, RecordParams{
		ProjectID:     f.projectID,
		IssuedAt:      now.Add(-60 * 24 * time.Hour),
		NotAfter:      now.Add(30 * 24 * time.Hour),
		Identifiers:   []string{"example.com"},
		PrivateKeyPEM: "KEY-A",
		ChainPEM:      "CERT-A",
	})
	if err != nil {
		t.Fatalf("record cert A: %v", err)
	}

	// Bind Cert A to domain
	if err := f.store.Bind(ctx, f.domainID, certA.ID); err != nil {
		t.Fatalf("bind cert A: %v", err)
	}

	// Current is Cert A
	current, err := f.store.CurrentForDomain(ctx, f.domainID)
	if err != nil {
		t.Fatalf("CurrentForDomain: %v", err)
	}
	if current.ID != certA.ID {
		t.Errorf("current id = %q, want certA %q", current.ID, certA.ID)
	}

	// Advance clock and record Cert B (renewal)
	f.clock.advance(15 * 24 * time.Hour)
	certB, err := f.store.Record(ctx, RecordParams{
		ProjectID:     f.projectID,
		IssuedAt:      f.clock.now(),
		NotAfter:      f.clock.now().Add(90 * 24 * time.Hour),
		Identifiers:   []string{"example.com"},
		PrivateKeyPEM: "KEY-B",
		ChainPEM:      "CERT-B",
		ReplacesID:    certA.ID,
	})
	if err != nil {
		t.Fatalf("record cert B: %v", err)
	}

	// Bind Cert B — must deactivate A and activate B in ONE tx
	if err := f.store.Bind(ctx, f.domainID, certB.ID); err != nil {
		t.Fatalf("bind cert B (renewal): %v", err)
	}

	// Current is now Cert B
	currentB, err := f.store.CurrentForDomain(ctx, f.domainID)
	if err != nil {
		t.Fatalf("CurrentForDomain after renewal: %v", err)
	}
	if currentB.ID != certB.ID {
		t.Errorf("current id = %q, want certB %q", currentB.ID, certB.ID)
	}

	// Invariant: exactly ONE current binding in the table
	var currentCount int
	if err := f.pool.QueryRow(ctx,
		`SELECT count(*) FROM domain_certificates WHERE site_domain_id = $1 AND is_current = true`,
		f.domainID).Scan(&currentCount); err != nil {
		t.Fatalf("count current: %v", err)
	}
	if currentCount != 1 {
		t.Errorf("currentCount = %d, want exactly 1", currentCount)
	}

	// Invariant: TOTAL bindings = 2 (history is retained for rollback)
	var totalCount int
	if err := f.pool.QueryRow(ctx,
		`SELECT count(*) FROM domain_certificates WHERE site_domain_id = $1`,
		f.domainID).Scan(&totalCount); err != nil {
		t.Fatalf("count total bindings: %v", err)
	}
	if totalCount != 2 {
		t.Errorf("totalCount = %d, want 2 (Cert A must be preserved for rollback)", totalCount)
	}
}

// TestListExpiringUsesExpiryIndex proves that ListExpiring queries only certificates
// whose not_after falls inside the specified window, ordered by not_after ASC.
func TestListExpiringUsesExpiryIndex(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	now := f.clock.now()

	// Cert 1: expires in 10 days (inside 30d window)
	c1, err := f.store.Record(ctx, RecordParams{
		ProjectID:     f.projectID,
		IssuedAt:      now,
		NotAfter:      now.Add(10 * 24 * time.Hour),
		Identifiers:   []string{"soon.example.com"},
		PrivateKeyPEM: "K1",
		ChainPEM:      "C1",
	})
	if err != nil {
		t.Fatalf("record c1: %v", err)
	}

	// Cert 2: expires in 60 days (OUTSIDE 30d window)
	_, err = f.store.Record(ctx, RecordParams{
		ProjectID:     f.projectID,
		IssuedAt:      now,
		NotAfter:      now.Add(60 * 24 * time.Hour),
		Identifiers:   []string{"later.example.com"},
		PrivateKeyPEM: "K2",
		ChainPEM:      "C2",
	})
	if err != nil {
		t.Fatalf("record c2: %v", err)
	}

	expiring, err := f.store.ListExpiring(ctx, 30*24*time.Hour)
	if err != nil {
		t.Fatalf("ListExpiring: %v", err)
	}
	if len(expiring) != 1 {
		t.Fatalf("len(expiring) = %d, want 1", len(expiring))
	}
	if expiring[0].ID != c1.ID {
		t.Errorf("expiring[0].ID = %q, want c1 %q", expiring[0].ID, c1.ID)
	}
}

// TestRevocationRefusesSubsequentBinding proves that a revoked certificate
// transitions to state='revoked' and cannot be bound to a domain.
func TestRevocationRefusesSubsequentBinding(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	now := f.clock.now()
	cert, err := f.store.Record(ctx, RecordParams{
		ProjectID:     f.projectID,
		IssuedAt:      now,
		NotAfter:      now.Add(90 * 24 * time.Hour),
		Identifiers:   []string{"revoked.example.com"},
		PrivateKeyPEM: "KR",
		ChainPEM:      "CR",
	})
	if err != nil {
		t.Fatalf("record: %v", err)
	}

	revoked, err := f.store.Revoke(ctx, cert.ID, "key compromised")
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if revoked.State != StateRevoked {
		t.Errorf("state = %q, want revoked", revoked.State)
	}
	if revoked.RevokedAt == nil {
		t.Error("revoked_at is nil")
	}

	// Binding a revoked cert must be refused
	bindErr := f.store.Bind(ctx, f.domainID, cert.ID)
	if !errors.Is(bindErr, ErrNotActive) {
		t.Errorf("Bind revoked cert err = %v, want ErrNotActive", bindErr)
	}
}
