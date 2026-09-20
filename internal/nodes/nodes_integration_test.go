//go:build integration

package nodes

import (
	"context"
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
	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
	"github.com/bukansembarangkong/jawaker-panel/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMain gives this package its own database, so parallel packages cannot
// reset the schema underneath it.
func TestMain(m *testing.M) {
	base := dbtest.FixtureURL()
	if base == "" {
		os.Exit(m.Run())
	}
	dsn, err := dbtest.IsolatedDatabase(base, "nodes")
	if err != nil {
		fmt.Fprintf(os.Stderr, "nodes: isolated test database: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("JAWAKER_TEST_DATABASE_URL", dsn); err != nil {
		fmt.Fprintf(os.Stderr, "nodes: set test database: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = dbtest.DropDatabase(base, "nodes")
	os.Exit(code)
}

// mutableClock lets a test move time forward instead of waiting for a token to
// expire. One instance is shared by the authority and the store so both agree on
// the instant, mirroring production where a single clock is injected into both.
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

// harness wires a migrated database, a secret store, an authority and a store
// the way production does. The secret store is exposed because reload tests must
// reuse the SAME key ring: a fresh key ring cannot open roots sealed with
// another key, and generating one per helper was a trap.
type harness struct {
	pool    *pgxpool.Pool
	secrets *secret.Store
	auth    *Authority
	store   *Store
	clock   *mutableClock
	ctx     context.Context
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	ctx := context.Background()

	base := dbtest.FixtureURL()
	if base == "" {
		t.Skip("JAWAKER_TEST_DATABASE_URL not set; skipping nodes integration tests")
	}
	pool := freshPool(t, ctx, base)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := migrate.New(migrations.FS, logger)
	if err != nil {
		t.Fatalf("migrator: %v", err)
	}
	if _, err = m.Up(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// A fresh master key per test, generated rather than written as a literal,
	// so no credential value ever appears in the repository.
	key, err := secret.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	secrets, err := secret.New(secret.Options{DB: pool, Keys: map[int]string{1: key}})
	if err != nil {
		t.Fatalf("secret store: %v", err)
	}

	// Anchored at real current time, not a fixed date: the PKI verifier defaults to
	// time.Now, and a clock pinned in the past would make every issued certificate
	// look expired to it. Tests that need to cross an expiry advance the clock
	// forward from here.
	clock := newClock(time.Now().UTC())
	auth, created, err := EnsureAuthority(ctx, AuthorityOptions{
		DB:      pool,
		Secrets: secrets,
		Now:     clock.now,
	})
	if err != nil {
		t.Fatalf("EnsureAuthority: %v", err)
	}
	if !created {
		t.Fatal("EnsureAuthority reported no creation on a fresh database")
	}
	return &harness{
		pool:    pool,
		secrets: secrets,
		auth:    auth,
		store:   NewStore(pool, clock.now),
		clock:   clock,
		ctx:     ctx,
	}
}

// freshPool connects and resets the schema so each test starts pristine.
func freshPool(t *testing.T, ctx context.Context, dsn string) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	return pool
}

// migrateOnly prepares a bare database without creating roots, for the
// missing-CA case.
func migrateOnly(t *testing.T) (*pgxpool.Pool, *secret.Store) {
	t.Helper()
	base := dbtest.FixtureURL()
	if base == "" {
		t.Skip("JAWAKER_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool := freshPool(t, ctx, base)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	m, err := migrate.New(migrations.FS, logger)
	if err != nil {
		t.Fatalf("migrator: %v", err)
	}
	if _, err = m.Up(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	key, err := secret.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	secrets, err := secret.New(secret.Options{DB: pool, Keys: map[int]string{1: key}})
	if err != nil {
		t.Fatalf("secret store: %v", err)
	}
	return pool, secrets
}

// --- authority ----------------------------------------------------------------

// Reloading the authority must return the SAME roots. If it minted fresh ones,
// every certificate already in the fleet would stop verifying, and the failure
// would look like a mass compromise rather than a restart.
func TestAuthorityIsStableAcrossReload(t *testing.T) {
	h := newHarness(t)

	reloaded, created, err := EnsureAuthority(h.ctx, AuthorityOptions{
		DB: h.pool, Secrets: h.secrets, Now: h.clock.now,
	})
	if err != nil {
		t.Fatalf("EnsureAuthority: %v", err)
	}
	if created {
		t.Error("EnsureAuthority recreated the roots on reload; existing node certificates would be invalidated")
	}
	if reloaded.ControllerFingerprint() != h.auth.ControllerFingerprint() {
		t.Error("controller root changed across reload")
	}
	if reloaded.NodeFingerprint() != h.auth.NodeFingerprint() {
		t.Error("node root changed across reload")
	}
	if reloaded.ControllerID() != h.auth.ControllerID() {
		t.Error("controller identity changed across reload")
	}
}

// Two controllers racing EnsureAuthority must converge on one root, not two.
func TestAuthorityCreationIsRaceSafe(t *testing.T) {
	h := newHarness(t)

	const racers = 6
	results := make(chan *Authority, racers)
	var wg sync.WaitGroup
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			auth, _, err := EnsureAuthority(h.ctx, AuthorityOptions{
				DB: h.pool, Secrets: h.secrets, Now: h.clock.now,
			})
			if err != nil {
				t.Errorf("EnsureAuthority: %v", err)
				return
			}
			results <- auth
		}()
	}
	wg.Wait()
	close(results)

	fingerprints := make(map[string]int)
	for auth := range results {
		fingerprints[auth.NodeFingerprint()]++
	}
	if len(fingerprints) != 1 {
		t.Fatalf("%d distinct node roots after a race, want 1: %v", len(fingerprints), fingerprints)
	}
}

// The two roots must differ, and neither may accept the other's leaf. This is
// the property that stops a node from impersonating the controller.
func TestAuthorityRootsAreSeparate(t *testing.T) {
	h := newHarness(t)
	if h.auth.ControllerFingerprint() == h.auth.NodeFingerprint() {
		t.Fatal("controller and node roots are the same authority")
	}

	controllerLeaf, err := h.auth.IssueControllerLeaf()
	if err != nil {
		t.Fatalf("IssueControllerLeaf: %v", err)
	}
	nodeLeaf, err := h.auth.IssueNodeLeaf("33333333-3333-3333-3333-333333333333")
	if err != nil {
		t.Fatalf("IssueNodeLeaf: %v", err)
	}

	nodeVerifier, err := pki.NewVerifier(pki.VerifierOptions{RootPEM: h.auth.NodeCertPEM(), Kind: pki.KindNode})
	if err != nil {
		t.Fatalf("NewVerifier(node): %v", err)
	}
	if _, err = nodeVerifier.Verify([][]byte{controllerLeaf.Cert().Raw}, nil); err == nil {
		t.Error("the node root accepted a controller certificate")
	}

	controllerVerifier, err := pki.NewVerifier(pki.VerifierOptions{
		RootPEM: h.auth.ControllerCertPEM(), Kind: pki.KindController,
	})
	if err != nil {
		t.Fatalf("NewVerifier(controller): %v", err)
	}
	if _, err := controllerVerifier.Verify([][]byte{nodeLeaf.Cert().Raw}, nil); err == nil {
		t.Error("the controller root accepted a node certificate")
	}
}

// A node CA stored under the controller reference must be refused at load, not
// accepted and then trusted as a controller root.
func TestAuthorityDetectsMisplacedRoot(t *testing.T) {
	h := newHarness(t)

	fresh, err := pki.NewCA("impostor", pki.KindNode, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	encoded, err := fresh.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if err := h.secrets.Set(h.ctx, ControllerCARef, encoded, "wrong root on purpose"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	if _, err := LoadAuthority(h.ctx, AuthorityOptions{DB: h.pool, Secrets: h.secrets, Now: h.clock.now}); err == nil {
		t.Fatal("LoadAuthority accepted a node root at the controller reference")
	}
}

// A missing root is a configuration fact, not something LoadAuthority should fix
// by minting a new one: doing so would invalidate the fleet silently.
func TestLoadAuthorityReportsMissingRoots(t *testing.T) {
	pool, secrets := migrateOnly(t)
	_, err := LoadAuthority(context.Background(), AuthorityOptions{DB: pool, Secrets: secrets})
	if err == nil {
		t.Fatal("LoadAuthority succeeded with no roots configured")
	}
	if !errors.Is(err, ErrNoAuthority) {
		t.Errorf("error = %v, want ErrNoAuthority", err)
	}
}

// The two roots must be stored ENCRYPTED, reached only by reference. A plaintext
// root in the database would mean a dump discloses the installation's signing
// authority.
func TestRootsAreStoredEncrypted(t *testing.T) {
	h := newHarness(t)

	for _, ref := range []string{ControllerCARef, NodeCARef} {
		var ciphertext []byte
		if err := h.pool.QueryRow(h.ctx,
			`SELECT ciphertext FROM secret_values WHERE secret_ref = $1`, ref).Scan(&ciphertext); err != nil {
			t.Fatalf("read stored root %s: %v", ref, err)
		}
		// The stored bytes must not contain the PEM header: if they did, the
		// value is not encrypted.
		if containsBytes(ciphertext, []byte("PRIVATE KEY")) {
			t.Errorf("%s is stored in plaintext", ref)
		}
		if containsBytes(ciphertext, []byte("BEGIN CERTIFICATE")) {
			t.Errorf("%s is stored in plaintext", ref)
		}
		// And it must actually be openable, so "encrypted" does not mean
		// "unreadable".
		if _, err := h.secrets.Open(h.ctx, ref); err != nil {
			t.Errorf("open %s: %v", ref, err)
		}
	}
}

func containsBytes(haystack, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := range needle {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
