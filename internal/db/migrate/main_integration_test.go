//go:build integration

package migrate

import (
	"fmt"
	"os"
	"testing"

	"github.com/bukansembarangkong/jawaker-panel/internal/dbtest"
)

// TestMain gives this package its OWN database before any test runs.
//
// go test runs packages in parallel, and both this suite and the identity
// suite reset the public schema. Sharing one database means whichever starts
// second drops the other's tables mid-run — a flake that reproduces in CI.
func TestMain(m *testing.M) {
	base := dbtest.FixtureURL()
	if base == "" {
		// Integration tests are unconfigured; let each test skip itself.
		os.Exit(m.Run())
	}

	dsn, err := dbtest.IsolatedDatabase(base, "migrate")
	if err != nil {
		fmt.Fprintf(os.Stderr, "migrate: isolated test database: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("JAWAKER_TEST_DATABASE_URL", dsn); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: set test database: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()

	// Best-effort cleanup: a leftover database would confuse the next run, but
	// it must not mask the test result.
	_ = dbtest.DropDatabase(base, "migrate")
	os.Exit(code)
}
