//go:build integration

package doctor

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
	"github.com/bukansembarangkong/jawaker-panel/internal/nodes"
	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
	"github.com/bukansembarangkong/jawaker-panel/migrations"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestMain gives this package its OWN database.
//
// The suffix "doctor" is unique across integration packages — each package needs
// one, because go test runs packages in parallel and two suites that each reset
// the public schema of a shared database destroy each other mid-run.
func TestMain(m *testing.M) {
	base := dbtest.FixtureURL()
	if base == "" {
		os.Exit(m.Run())
	}
	dsn, err := dbtest.IsolatedDatabase(base, "doctor")
	if err != nil {
		fmt.Fprintf(os.Stderr, "doctor: isolated test database: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("JAWAKER_TEST_DATABASE_URL", dsn); err != nil {
		fmt.Fprintf(os.Stderr, "doctor: set test database: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	_ = dbtest.DropDatabase(base, "doctor")
	os.Exit(code)
}

// dbFixture is a migrated database plus a secret store, the same wiring the
// controller builds at startup.
type dbFixture struct {
	pool    *pgxpool.Pool
	secrets *secret.Store
	ctx     context.Context
}

// freshFixture connects, resets the schema, migrates, and builds a secret store.
func freshFixture(t *testing.T) *dbFixture {
	t.Helper()
	ctx := context.Background()
	base := dbtest.FixtureURL()
	if base == "" {
		t.Skip("JAWAKER_TEST_DATABASE_URL not set; skipping doctor integration tests")
	}

	pool, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}

	m, err := migrate.New(migrations.FS, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("migrator: %v", err)
	}
	if _, err = m.Up(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// A generated key rather than a literal, so no credential value ever appears
	// in the repository.
	key, err := secret.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	secrets, err := secret.New(secret.Options{DB: pool, Keys: map[int]string{1: key}})
	if err != nil {
		t.Fatalf("secret store: %v", err)
	}
	return &dbFixture{pool: pool, secrets: secrets, ctx: ctx}
}

// THE HEALTHY PATH: a migrated database with the certificate authorities created
// reports healthy, and every check carries concrete evidence rather than a bare
// pass.
func TestControllerReportsAHealthyInstallation(t *testing.T) {
	f := freshFixture(t)

	// Create the authorities the way production does at startup.
	if _, _, err := nodes.EnsureAuthority(f.ctx, nodes.AuthorityOptions{
		DB: f.pool, Secrets: f.secrets, Now: time.Now,
	}); err != nil {
		t.Fatalf("EnsureAuthority: %v", err)
	}

	report := Controller(f.ctx, "test", ControllerOptions{
		DB:      f.pool,
		Secrets: f.secrets,
		// No ListenAddr, so the port probe is skipped rather than binding.
	})
	if !report.Healthy() {
		t.Fatalf("a healthy installation was reported unhealthy:\n%s", report.Text())
	}

	db := statusOf(t, report, "database")
	if db.Status != StatusOK {
		t.Errorf("database = %q (%s), want ok", db.Status, db.Detail)
	}
	if db.Evidence["server_version"] == nil {
		t.Error("the database check reported no server version")
	}

	mig := statusOf(t, report, "migrations")
	if mig.Status != StatusOK {
		t.Errorf("migrations = %q (%s), want ok", mig.Status, mig.Detail)
	}

	ca := statusOf(t, report, "certificate-authorities")
	if ca.Status != StatusOK {
		t.Errorf("certificate-authorities = %q (%s), want ok", ca.Status, ca.Detail)
	}
	// The fingerprints are the point: an operator records which roots an
	// installation is using, and never the keys themselves.
	if ca.Evidence["controller_fingerprint"] == nil || ca.Evidence["node_fingerprint"] == nil {
		t.Errorf("certificate-authorities evidence lacks fingerprints: %+v", ca.Evidence)
	}
	for _, key := range []string{"controller_fingerprint", "node_fingerprint"} {
		if fp, _ := ca.Evidence[key].(string); fp == "" {
			t.Errorf("%s is empty", key)
		}
	}
}

// THE PLAN'S BROKEN-CA CASE: the certificate authority deliberately absent. The
// check must report the concrete finding, and doctor must not CRASH or silently
// repair it by minting a root.
func TestControllerReportsAMissingCertificateAuthority(t *testing.T) {
	f := freshFixture(t)
	// Deliberately NOT calling EnsureAuthority: the roots do not exist.

	report := Controller(f.ctx, "test", ControllerOptions{DB: f.pool, Secrets: f.secrets})

	ca := statusOf(t, report, "certificate-authorities")
	if ca.Status != StatusFail {
		t.Errorf("certificate-authorities = %q (%s), want fail", ca.Status, ca.Detail)
	}
	if !containsAll(ca.Detail, "missing", "invalidate every certificate") {
		t.Errorf("detail = %q, want it to name the missing root and the consequence", ca.Detail)
	}
	if report.Healthy() {
		t.Error("an installation with no certificate authority was reported healthy")
	}

	// The rest of the report must still be present: one missing subsystem must
	// not destroy the report about every other check.
	for _, name := range []string{"build", "database", "migrations", "secret-keys"} {
		if statusOf(t, report, name).Status == "" {
			t.Errorf("the %q check is absent from the report", name)
		}
	}

	// Critically: doctor must NOT have created the roots while checking.
	// If it had, this re-run would find them and pass, and a diagnostic that
	// changes what it diagnoses is worse than no diagnostic at all.
	var count int
	if err := f.pool.QueryRow(f.ctx,
		`SELECT count(*) FROM secret_values WHERE secret_ref = $1`, nodes.ControllerCARef).Scan(&count); err != nil {
		t.Fatalf("count controller CA secret: %v", err)
	}
	if count != 0 {
		t.Error("doctor CREATED the missing certificate authority; a diagnostic must be read-only")
	}
}

// An UNMIGRATED database is a warning naming the remedy, not a crash. This is the
// fresh-install state an operator most often hits.
func TestControllerReportsAnUnmigratedDatabase(t *testing.T) {
	base := dbtest.FixtureURL()
	if base == "" {
		t.Skip("JAWAKER_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, base)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;`); err != nil {
		t.Fatalf("reset schema: %v", err)
	}

	report := Controller(ctx, "test", ControllerOptions{DB: pool})
	mig := statusOf(t, report, "migrations")
	if mig.Status != StatusWarn {
		t.Errorf("migrations = %q (%s), want warn on an unmigrated database", mig.Status, mig.Detail)
	}
	if !containsAll(mig.Detail, "never been migrated", "migrate-only") {
		t.Errorf("detail = %q, want it to state the condition and the remedy", mig.Detail)
	}
	// The CA check cannot run against an unmigrated schema; it must skip, not
	// crash, so the report still explains the migration state to the operator.
	ca := statusOf(t, report, "certificate-authorities")
	if ca.Status == StatusOK {
		t.Error("the certificate-authorities check passed on an unmigrated database")
	}
}

// A TAMPERED migration — released history edited in place — is the most serious
// migration state and must be a hard failure, because running migrations cannot
// fix a checksum the binary and the database disagree about.
func TestControllerReportsTamperedMigrationHistory(t *testing.T) {
	f := freshFixture(t)

	// Corrupt one recorded checksum directly. This is the only way to reach the
	// state without editing a migration FILE, which would change the binary and
	// make the test prove nothing.
	if _, err := f.pool.Exec(f.ctx,
		`UPDATE schema_migrations SET checksum = $1 WHERE version = (SELECT min(version) FROM schema_migrations)`,
		"deadbeef"); err != nil {
		t.Fatalf("tamper with a checksum: %v", err)
	}

	mig := statusOf(t, Controller(f.ctx, "test", ControllerOptions{DB: f.pool}), "migrations")
	if mig.Status != StatusFail {
		t.Errorf("migrations = %q (%s), want fail on tampered history", mig.Status, mig.Detail)
	}
	if !containsAll(mig.Detail, "no longer match", "immutable") {
		t.Errorf("detail = %q, want it to name the tampering and that history is immutable", mig.Detail)
	}
}

// With NO database at all, the database-backed checks must SKIP naming the cause,
// not fail and not crash. This is the graceful-degradation path from
// ARCHITECTURE.md §13, and it is why a report stays useful when half the inputs
// are missing.
func TestControllerSkipsDatabaseChecksWhenNoDatabase(t *testing.T) {
	report := Controller(context.Background(), "test", ControllerOptions{})
	if report.Healthy() {
		// Not unhealthy either: there is nothing measured to have failed. The
		// component reports what it could not check.
		t.Log("no-database report is not unhealthy, which is correct")
	}
	for _, name := range []string{"database", "migrations", "secret-keys", "certificate-authorities"} {
		check := statusOf(t, report, name)
		if check.Status != StatusSkip {
			t.Errorf("%s = %q (%s), want skip with no database", name, check.Status, check.Detail)
		}
	}
	// build must still run: it needs no inputs, so it is never skipped.
	if statusOf(t, report, "build").Status != StatusOK {
		t.Error("the build check did not pass with no inputs")
	}
}
