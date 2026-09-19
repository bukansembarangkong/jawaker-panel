package dbtest

import (
	"strings"
	"testing"
)

// The DSNs below carry no userinfo: these helpers derive and swap database
// names, and credentials are irrelevant to that. Keeping fixtures
// credential-free means a secret-scanning finding in this file stays a real
// signal instead of needing a mute.
const (
	testDSN     = "postgres://127.0.0.1:5432/jawaker_test?sslmode=disable"
	testHostDSN = "postgres://db.internal:5432/jawaker_test?sslmode=disable"
)

// Derived names are PostgreSQL identifiers built from a caller-supplied
// fragment, so the validation and truncation rules are the security-relevant
// part of this package and are pinned here without a database.
func TestDatabaseNameDerivation(t *testing.T) {
	got, err := databaseName(testDSN, "migrate")
	if err != nil {
		t.Fatalf("databaseName: %v", err)
	}
	if got != "jawaker_test_migrate" {
		t.Errorf("name = %q, want jawaker_test_migrate", got)
	}

	// Long base names are truncated to the identifier limit rather than
	// rejected, so a verbose fixture database still works.
	long := "postgres://127.0.0.1:5432/" + strings.Repeat("a", 80) + "?sslmode=disable"
	truncated, err := databaseName(long, "identity")
	if err != nil {
		t.Fatalf("databaseName (long): %v", err)
	}
	if len(truncated) != 63 {
		t.Errorf("length = %d, want the 63-byte identifier limit", len(truncated))
	}
}

func TestDatabaseNameRejectsUnsafeSuffix(t *testing.T) {
	// A suffix reaches SQL, so anything outside [a-z0-9_] is refused instead of
	// being escaped-and-hoped-for.
	for _, bad := range []string{"", "up-case", "with space", `quote"`, "semi;colon", "drop db;--"} {
		if _, err := databaseName(testDSN, bad); err == nil {
			t.Errorf("suffix %q accepted, want rejection", bad)
		}
	}
	if _, err := databaseName(testDSN, "ok_name_1"); err != nil {
		t.Errorf("valid suffix rejected: %v", err)
	}
	if err := validateSuffix("ok"); err != nil {
		t.Errorf("validateSuffix: %v", err)
	}
}

func TestDatabaseNameRequiresDatabaseInDSN(t *testing.T) {
	if _, err := databaseName("postgres://127.0.0.1:5432/?sslmode=disable", "x"); err == nil {
		t.Error("DSN naming no database accepted")
	}
}

// Swapping the database must leave host, port, and query parameters alone, or
// an isolated suite would silently connect somewhere else.
func TestWithDatabaseSwapsOnlyTheDatabase(t *testing.T) {
	got, err := withDatabase(testHostDSN+"&x=y", "two")
	if err != nil {
		t.Fatalf("withDatabase: %v", err)
	}
	want := "postgres://db.internal:5432/two?sslmode=disable&x=y"
	if got != want {
		t.Errorf("dsn = %q, want %q", got, want)
	}
	if _, err := withDatabase("not a url ::::", "two"); err == nil {
		t.Error("unparseable DSN accepted")
	}
}

// quoteIdent is the last line of defense if a validated name ever reaches SQL
// as text; doubling embedded quotes is what makes that safe.
func TestQuoteIdentEscapesQuotes(t *testing.T) {
	if got := quoteIdent(`a"b`); got != `"a""b"` {
		t.Errorf("quoteIdent = %s, want \"a\"\"b\"", got)
	}
	if got := quoteIdent("plain"); got != `"plain"` {
		t.Errorf("quoteIdent = %s, want \"plain\"", got)
	}
}
