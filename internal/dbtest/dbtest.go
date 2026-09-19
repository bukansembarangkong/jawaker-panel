// Package dbtest provides isolated PostgreSQL fixtures for integration tests.
//
// go test runs separate PACKAGES in parallel. Two suites that each reset the
// public schema of one shared database destroy each other's tables mid-run, so
// every integration package gets its own database. Isolation is per package,
// not per test: within a package, tests run sequentially unless they opt into
// t.Parallel(), and each one resets the schema itself.
package dbtest

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// envVar names the fixture database the suites derive their own from.
const envVar = "JAWAKER_TEST_DATABASE_URL"

// FixtureURL returns the configured base DSN, or "" when integration tests are
// not configured. Callers skip rather than fail in that case.
func FixtureURL() string { return strings.TrimSpace(os.Getenv(envVar)) }

// IsolatedDatabase drops and recreates a database dedicated to one test
// package and returns its DSN.
//
// suffix must be a lowercase identifier fragment (the calling package's name).
// The base DSN is never modified, so the caller keeps a handle for cleanup.
func IsolatedDatabase(baseURL, suffix string) (string, error) {
	name, err := databaseName(baseURL, suffix)
	if err != nil {
		return "", err
	}
	if err = execute(baseURL, `DROP DATABASE IF EXISTS `+quoteIdent(name)+` WITH (FORCE)`); err != nil {
		return "", fmt.Errorf("dbtest: drop stale %s: %w", name, err)
	}
	if err = execute(baseURL, `CREATE DATABASE `+quoteIdent(name)); err != nil {
		return "", fmt.Errorf("dbtest: create %s: %w", name, err)
	}
	dsn, err := withDatabase(baseURL, name)
	if err != nil {
		return "", err
	}
	return dsn, nil
}

// DropDatabase removes a database created by IsolatedDatabase.
func DropDatabase(baseURL, suffix string) error {
	name, err := databaseName(baseURL, suffix)
	if err != nil {
		return err
	}
	if err := execute(baseURL, `DROP DATABASE IF EXISTS `+quoteIdent(name)+` WITH (FORCE)`); err != nil {
		return fmt.Errorf("dbtest: drop %s: %w", name, err)
	}
	return nil
}

// databaseName derives "<base>_<suffix>", lowercased and truncated to the
// PostgreSQL identifier limit.
func databaseName(baseURL, suffix string) (string, error) {
	if err := validateSuffix(suffix); err != nil {
		return "", err
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("dbtest: parse %s: %w", envVar, err)
	}
	base := strings.TrimPrefix(u.Path, "/")
	if base == "" {
		return "", fmt.Errorf("dbtest: %s names no database", envVar)
	}

	const maxIdentifierLen = 63
	name := strings.ToLower(base + "_" + suffix)
	if len(name) > maxIdentifierLen {
		name = name[:maxIdentifierLen]
	}
	return name, nil
}

// validateSuffix keeps the derived name a plain identifier, so quoteIdent never
// has to defend against injection through a caller-supplied fragment.
func validateSuffix(suffix string) error {
	if suffix == "" {
		return fmt.Errorf("dbtest: suffix is required")
	}
	for _, c := range suffix {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return fmt.Errorf("dbtest: suffix %q must be [a-z0-9_]", suffix)
		}
	}
	return nil
}

// quoteIdent renders a validated name as a quoted identifier.
func quoteIdent(name string) string {
	return `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
}

// withDatabase returns baseURL pointed at a different database.
func withDatabase(baseURL, name string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("dbtest: parse %s: %w", envVar, err)
	}
	u.Path = "/" + name
	return u.String(), nil
}

// execute runs one statement against baseURL with a bounded connection attempt.
func execute(baseURL, statement string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgx.Connect(ctx, baseURL)
	if err != nil {
		return fmt.Errorf("dbtest: connect: %w", err)
	}
	defer conn.Close(ctx)

	if _, err := conn.Exec(ctx, statement); err != nil {
		return err
	}
	return nil
}
