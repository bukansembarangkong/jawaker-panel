//go:build integration

// Integration tests for the secret store against real PostgreSQL.
//
// These cover what the pure-unit tests cannot: the actual column types, the
// ON CONFLICT replacement path, rotation across a live key ring, and delete
// semantics.

package secret

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/bukansembarangkong/jawaker-panel/internal/db/migrate"
	"github.com/bukansembarangkong/jawaker-panel/internal/dbtest"
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
	dsn, err := dbtest.IsolatedDatabase(base, "secret")
	if err != nil {
		fmt.Fprintf(os.Stderr, "secret: isolated test database: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("JAWAKER_TEST_DATABASE_URL", dsn); err != nil {
		fmt.Fprintf(os.Stderr, "secret: set test database: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = dbtest.DropDatabase(base, "secret")
	os.Exit(code)
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// setup applies the real migrations and returns a store plus its pool.
func setup(t *testing.T, keys map[int]string) (*Store, *pgxpool.Pool, context.Context) {
	t.Helper()
	ctx := context.Background()

	base := dbtest.FixtureURL()
	if base == "" {
		t.Skip("JAWAKER_TEST_DATABASE_URL not set; skipping secret integration tests")
	}
	pool := newPool(t, ctx, base)

	m, err := migrate.New(migrations.FS, testLogger())
	if err != nil {
		t.Fatalf("migrator: %v", err)
	}
	if _, err := m.Up(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	store, err := New(Options{DB: pool, Keys: keys})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return store, pool, ctx
}

// newPool connects and resets the schema, so each test starts pristine.
func newPool(t *testing.T, ctx context.Context, dsn string) *pgxpool.Pool {
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

func mustKey(t *testing.T) string {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

func TestStoreRoundTrip(t *testing.T) {
	store, pool, ctx := setup(t, map[int]string{1: mustKey(t)})
	// References carry a UUID rather than an email: they appear in config
	// files, logs, and revision payloads, so putting PII in them would spread
	// it, and it would go stale when the address changed.
	const ref = "secret://totp/6f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
	const plaintext = "JBSWY3DPEHPK3PXP"

	if err := store.Set(ctx, ref, plaintext, "TOTP for the owner"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	got, err := store.Open(ctx, ref)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got != plaintext {
		t.Errorf("Open = %q, want %q", got, plaintext)
	}

	// The plaintext must not appear anywhere in the stored bytes; that is the
	// entire point of the subsystem.
	var stored []byte
	if err := pool.QueryRow(ctx,
		`SELECT ciphertext FROM secret_values WHERE secret_ref = $1`, ref).Scan(&stored); err != nil {
		t.Fatalf("query ciphertext: %v", err)
	}
	if bytes.Contains(stored, []byte(plaintext)) {
		t.Fatal("plaintext is recoverable from the stored ciphertext")
	}

	meta, err := store.Describe(ctx, ref)
	if err != nil {
		t.Fatalf("Describe: %v", err)
	}
	if meta.KeyVersion != 1 {
		t.Errorf("key_version = %d, want 1", meta.KeyVersion)
	}
	if meta.Description != "TOTP for the owner" {
		t.Errorf("description = %q", meta.Description)
	}
	if meta.LastReadAt == nil {
		t.Error("last_read_at not stamped by Open; the pruning runbook cannot find unused secrets")
	}
}

func TestOpenMissingSecret(t *testing.T) {
	store, _, ctx := setup(t, map[int]string{1: mustKey(t)})

	if _, err := store.Open(ctx, "secret://nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing secret err = %v, want ErrNotFound", err)
	}
	// A malformed reference is rejected before any query runs.
	if _, err := store.Open(ctx, "not-a-ref"); !errors.Is(err, ErrInvalidRef) {
		t.Errorf("malformed ref err = %v, want ErrInvalidRef", err)
	}
}

// Create must refuse to overwrite, so a caller that meant to generate a new
// credential cannot silently destroy an existing one. Set is the explicit
// rotation path.
func TestCreateRefusesExisting(t *testing.T) {
	store, _, ctx := setup(t, map[int]string{1: mustKey(t)})
	const ref = "secret://db/password"

	if err := store.Create(ctx, ref, "first-value", ""); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := store.Create(ctx, ref, "second-value", ""); !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("second Create err = %v, want ErrAlreadyExists", err)
	}

	got, err := store.Open(ctx, ref)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got != "first-value" {
		t.Errorf("value = %q, want the original untouched", got)
	}

	if err := store.Set(ctx, ref, "third-value", ""); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got, _ := store.Open(ctx, ref); got != "third-value" {
		t.Errorf("value after Set = %q, want third-value", got)
	}

	// The superseded value must not remain readable through any reference.
	if rows := countRows(t, store, ctx, ref); rows != 1 {
		t.Errorf("rows for one reference = %d, want 1", rows)
	}
}

func TestExistsAndDelete(t *testing.T) {
	store, _, ctx := setup(t, map[int]string{1: mustKey(t)})
	const ref = "secret://ephemeral"

	exists, err := store.Exists(ctx, ref)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Error("Exists = true for a missing secret")
	}

	if err := store.Set(ctx, ref, "value", ""); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if exists, _ := store.Exists(ctx, ref); !exists {
		t.Error("Exists = false after Set")
	}

	if err := store.Delete(ctx, ref); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if exists, _ := store.Exists(ctx, ref); exists {
		t.Error("secret survived deletion")
	}
	// Deleting twice reports not-found rather than silently succeeding.
	if err := store.Delete(ctx, ref); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Delete err = %v, want ErrNotFound", err)
	}
}

// Rotation is the operation most likely to destroy data, so it is tested as the
// full three-phase sequence an operator actually performs: add the new key,
// re-encrypt, then drop the old one.
func TestKeyRotationMigratesValues(t *testing.T) {
	oldKey, newKey := mustKey(t), mustKey(t)
	ctx := context.Background()

	base := dbtest.FixtureURL()
	if base == "" {
		t.Skip("JAWAKER_TEST_DATABASE_URL not set")
	}
	pool := newPool(t, ctx, base)
	m, err := migrate.New(migrations.FS, testLogger())
	if err != nil {
		t.Fatalf("migrator: %v", err)
	}
	if _, err := m.Up(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	const ref = "secret://legacy"
	const plaintext = "legacy-secret"

	// Phase 1: only the old key exists.
	before, err := New(Options{DB: pool, Keys: map[int]string{1: oldKey}})
	if err != nil {
		t.Fatalf("New (before): %v", err)
	}
	if err := before.Set(ctx, ref, plaintext, ""); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Phase 2: the new key is added for writes, the old retained for reads.
	rotating, err := New(Options{DB: pool, Keys: map[int]string{1: oldKey, 2: newKey}})
	if err != nil {
		t.Fatalf("New (rotating): %v", err)
	}
	if rotating.CurrentKeyVersion() != 2 {
		t.Fatalf("current version = %d, want 2", rotating.CurrentKeyVersion())
	}

	needs, err := rotating.NeedsRotation(ctx, ref)
	if err != nil {
		t.Fatalf("NeedsRotation: %v", err)
	}
	if !needs {
		t.Error("NeedsRotation = false for a value sealed under the old key")
	}
	if got, err := rotating.Open(ctx, ref); err != nil || got != plaintext {
		t.Errorf("legacy read under the rotating ring = %q, %v", got, err)
	}

	if err := rotating.Reencrypt(ctx, ref); err != nil {
		t.Fatalf("Reencrypt: %v", err)
	}
	if needs, _ := rotating.NeedsRotation(ctx, ref); needs {
		t.Error("NeedsRotation still true after Reencrypt")
	}
	if got, err := rotating.Open(ctx, ref); err != nil || got != plaintext {
		t.Errorf("value after re-encryption = %q, %v", got, err)
	}

	// Phase 3: the old key can now be dropped, which is the point of rotating.
	after, err := New(Options{DB: pool, Keys: map[int]string{2: newKey}})
	if err != nil {
		t.Fatalf("New (after): %v", err)
	}
	if got, err := after.Open(ctx, ref); err != nil || got != plaintext {
		t.Errorf("value after dropping the old key = %q, %v", got, err)
	}
}

// Dropping the old key BEFORE re-encrypting must fail with a distinct "no key"
// error, so an operator can tell "restore the old key" from "the data is
// corrupt". Conflating those two costs hours during an incident.
func TestDroppedKeyReportsMissingKey(t *testing.T) {
	oldKey, newKey := mustKey(t), mustKey(t)
	ctx := context.Background()

	base := dbtest.FixtureURL()
	if base == "" {
		t.Skip("JAWAKER_TEST_DATABASE_URL not set")
	}
	pool := newPool(t, ctx, base)
	m, err := migrate.New(migrations.FS, testLogger())
	if err != nil {
		t.Fatalf("migrator: %v", err)
	}
	if _, err := m.Up(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	before, _ := New(Options{DB: pool, Keys: map[int]string{1: oldKey}})
	const ref = "secret://orphan"
	if err := before.Set(ctx, ref, "value", ""); err != nil {
		t.Fatalf("Set: %v", err)
	}

	after, _ := New(Options{DB: pool, Keys: map[int]string{2: newKey}})
	if _, err := after.Open(ctx, ref); !errors.Is(err, ErrNoKey) {
		t.Errorf("err = %v, want ErrNoKey", err)
	}
}

// Concurrent Set calls on one reference must converge on a single, readable
// value rather than leaving a torn envelope that fails to authenticate.
func TestConcurrentSetConverges(t *testing.T) {
	store, _, ctx := setup(t, map[int]string{1: mustKey(t)})
	const ref = "secret://contended"

	const writers = 8
	done := make(chan error, writers)
	want := make(map[string]struct{}, writers)
	for i := 0; i < writers; i++ {
		value := fmt.Sprintf("value-%d", i)
		want[value] = struct{}{}
		go func(value string) { done <- store.Set(ctx, ref, value, "") }(value)
	}
	for i := 0; i < writers; i++ {
		if err := <-done; err != nil {
			t.Fatalf("concurrent Set: %v", err)
		}
	}

	got, err := store.Open(ctx, ref)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, ok := want[got]; !ok {
		t.Errorf("value = %q, not one of the written values", got)
	}

	if rows := countRows(t, store, ctx, ref); rows != 1 {
		t.Errorf("rows for one reference = %d, want 1", rows)
	}
}

// A reference that reaches SQL must be validated first; the grammar is what keeps
// the namespace predictable and the value safe to interpolate anywhere.
func TestRejectsMalformedReferenceOnWrite(t *testing.T) {
	store, _, ctx := setup(t, map[int]string{1: mustKey(t)})

	for _, bad := range []string{"", "totp/x", "secret://", "secret://../etc", "secret://a b", `secret://a'q`} {
		if err := store.Set(ctx, bad, "value", ""); err == nil {
			t.Errorf("Set(%q) accepted, want rejection", bad)
		} else if !strings.HasPrefix(err.Error(), "secret: invalid reference") {
			t.Errorf("Set(%q) err = %v, want a reference validation error", bad, err)
		}
	}
}

// countRows asserts the number of rows backing one reference. It is a test
// helper rather than a Store method so production code does not carry a
// test-only surface.
func countRows(t *testing.T, s *Store, ctx context.Context, ref string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(ctx,
		`SELECT count(*) FROM secret_values WHERE secret_ref = $1`, ref).Scan(&n); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return n
}
