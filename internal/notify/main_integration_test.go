//go:build integration

package notify

import (
	"fmt"
	"os"
	"testing"

	"github.com/bukansembarangkong/jawaker-panel/internal/dbtest"
)

// TestMain gives this package its OWN database before any test runs.
//
// go test runs packages in parallel, and every integration suite here resets
// the public schema. Sharing one database means whichever starts second drops
// the other's tables mid-run — a flake that reproduces in CI.
func TestMain(m *testing.M) {
	base := dbtest.FixtureURL()
	if base == "" {
		os.Exit(m.Run())
	}

	dsn, err := dbtest.IsolatedDatabase(base, "notify")
	if err != nil {
		fmt.Fprintf(os.Stderr, "notify: isolated test database: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("JAWAKER_TEST_DATABASE_URL", dsn); err != nil {
		fmt.Fprintf(os.Stderr, "notify: set test database: %v\n", err)
		os.Exit(1)
	}

	code := m.Run()
	_ = dbtest.DropDatabase(base, "notify")
	os.Exit(code)
}
