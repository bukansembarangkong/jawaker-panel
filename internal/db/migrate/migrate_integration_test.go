//go:build integration

// Integration tests for the migration runner against a real PostgreSQL.
//
// Run with:
//
//	JAWAKER_TEST_DATABASE_URL=postgres://... go test -tags integration ./...
//
// The target database is dropped and recreated around each scenario so tests
// are deterministic and mutually independent. CI provisions a postgres
// service container; locally, `make db-up` provides one.

package migrate

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("JAWAKER_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("JAWAKER_TEST_DATABASE_URL not set; skipping migration integration tests")
	}
	return url
}

// freshPool connects to the test database and drops/recreates the public
// schema so every scenario starts from a pristine state.
func freshPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, testDatabaseURL(t))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)

	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}
	return pool
}

func tableExists(ctx context.Context, pool *pgxpool.Pool, name string) bool {
	var n int
	err := pool.QueryRow(ctx,
		`SELECT count(*) FROM information_schema.tables WHERE table_schema='public' AND table_name=$1`,
		name).Scan(&n)
	if err != nil {
		return false
	}
	return n == 1
}

func TestUpAppliesAllMigrationsInOrder(t *testing.T) {
	pool := freshPool(t)
	ctx := context.Background()

	fsys := fstest.MapFS{
		"0001_one.sql":   {Data: []byte(`CREATE TABLE mig_order (step int); INSERT INTO mig_order VALUES (1);`)},
		"0002_two.sql":   {Data: []byte(`INSERT INTO mig_order VALUES (2);`)},
		"0010_three.sql": {Data: []byte(`INSERT INTO mig_order VALUES (10);`)},
	}
	m, err := New(fsys, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	applied, err := m.Up(ctx, pool)
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if len(applied) != 3 {
		t.Fatalf("applied = %v, want 3 migrations", applied)
	}

	rows, err := pool.Query(ctx, `SELECT step FROM mig_order ORDER BY step`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var steps []int
	for rows.Next() {
		var s int
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("scan: %v", err)
		}
		steps = append(steps, s)
	}
	if fmt.Sprint(steps) != "[1 2 10]" {
		t.Errorf("execution order = %v, want [1 2 10]", steps)
	}
}

func TestUpIsIdempotent(t *testing.T) {
	pool := freshPool(t)
	ctx := context.Background()

	m, err := New(testdataFS(t, "testdata/valid"), testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := m.Up(ctx, pool); err != nil {
		t.Fatalf("first Up: %v", err)
	}

	second, err := m.Up(ctx, pool)
	if err != nil {
		t.Fatalf("second Up: %v", err)
	}
	if len(second) != 0 {
		t.Errorf("second Up applied %v, want none", second)
	}
}

func TestUpDetectsTamperedAppliedMigration(t *testing.T) {
	pool := freshPool(t)
	ctx := context.Background()

	original := fstest.MapFS{"0001_init.sql": {Data: []byte(`CREATE TABLE tamper_probe (a int);`)}}
	m1, err := New(original, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := m1.Up(ctx, pool); err != nil {
		t.Fatalf("Up: %v", err)
	}

	// Same version/name, edited content — must be rejected, not re-applied.
	tampered := fstest.MapFS{"0001_init.sql": {Data: []byte(`CREATE TABLE tamper_probe (a int, b text);`)}}
	m2, err := New(tampered, testLogger())
	if err != nil {
		t.Fatalf("New tampered: %v", err)
	}
	_, err = m2.Up(ctx, pool)
	if err == nil {
		t.Fatal("tampered migration accepted, want checksum error")
	}
	if !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("error %q should mention checksum mismatch", err)
	}
}

func TestUpFailsAtomicallyOnBadSQL(t *testing.T) {
	pool := freshPool(t)
	ctx := context.Background()

	fsys := fstest.MapFS{
		"0001_good.sql": {Data: []byte(`CREATE TABLE mig_atomic_ok (a int);`)},
		"0002_bad.sql":  {Data: []byte(`CREATE TABLE mig_atomic_ok (a int); THIS IS NOT SQL;`)},
		"0003_never.sql": {Data: []byte(`CREATE TABLE mig_atomic_never (a int);`)},
	}
	m, err := New(fsys, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := m.Up(ctx, pool); err == nil {
		t.Fatal("bad SQL accepted, want error")
	}

	if !tableExists(ctx, pool, "mig_atomic_ok") {
		t.Error("migration 0001 should have committed before the failure")
	}
	if tableExists(ctx, pool, "mig_atomic_never") {
		t.Error("migration 0003 must not run after 0002 failed")
	}

	// The failed migration must NOT be recorded, so a corrected re-run can
	// apply it — and the successful one is not re-executed.
	var recorded int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM schema_migrations WHERE version = 2`).Scan(&recorded); err != nil {
		t.Fatalf("query schema_migrations: %v", err)
	}
	if recorded != 0 {
		t.Error("failed migration was recorded as applied")
	}
}

func TestConcurrentMigratorsSerializeViaAdvisoryLock(t *testing.T) {
	pool := freshPool(t)
	ctx := context.Background()

	// Each migration inserts its own marker; if two migrators ran the same
	// file concurrently without the lock, the unique insert below would race
	// and one would fail with a duplicate key error.
	fsys := fstest.MapFS{
		"0001_shared.sql": {Data: []byte(
			`CREATE TABLE IF NOT EXISTS mig_race (marker text PRIMARY KEY);` +
				`INSERT INTO mig_race VALUES ('once');`)},
	}
	m, err := New(fsys, testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	const workers = 4
	var wg sync.WaitGroup
	errs := make([]error, workers)
	appliedCounts := make([]int, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			applied, err := m.Up(ctx, pool)
			errs[i] = err
			appliedCounts[i] = len(applied)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("worker %d: Up failed: %v", i, err)
		}
	}
	total := 0
	for _, c := range appliedCounts {
		total += c
	}
	if total != 1 {
		t.Errorf("migration applied %d times across %d workers, want exactly 1", total, workers)
	}
}

func TestUpHonorsContextCancellation(t *testing.T) {
	pool := freshPool(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	m, err := New(testdataFS(t, "testdata/valid"), testLogger())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := m.Up(ctx, pool); err == nil {
		t.Fatal("Up on cancelled context should fail")
	}
}
