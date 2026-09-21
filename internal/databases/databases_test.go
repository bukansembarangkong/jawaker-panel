package databases

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateSlug(t *testing.T) {
	cases := []struct {
		slug  string
		valid bool
	}{
		{"db", true},
		{"my_db", true},
		{"my_database_123", true},
		{"d_1", true},
		{"d", false},                     // too short (min 2)
		{strings.Repeat("a", 49), false}, // too long (max 48)
		{"1db", true},                    // digit start ok
		{"_db", false},                   // cannot start with underscore
		{"db_", false},                   // cannot end with underscore
		{"db-name", false},               // hyphens not allowed in db slug
		{"DB", false},                    // uppercase rejected (must be lowercase)
		{"db.name", false},               // dots rejected
	}
	for _, tc := range cases {
		err := validateSlug(tc.slug)
		if (err == nil) != tc.valid {
			t.Errorf("validateSlug(%q): err=%v, want valid=%v", tc.slug, err, tc.valid)
		}
		if err != nil && !errors.Is(err, ErrInvalid) {
			t.Errorf("validateSlug(%q): err should wrap ErrInvalid, got %v", tc.slug, err)
		}
	}
}

func TestValidateEngine(t *testing.T) {
	for _, ok := range []string{EnginePostgreSQL, EngineMariaDB} {
		if err := validateEngine(ok); err != nil {
			t.Errorf("validateEngine(%q): unexpected err %v", ok, err)
		}
	}
	for _, bad := range []string{"mysql", "sqlite", "oracle", "redis", ""} {
		if err := validateEngine(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("validateEngine(%q): want ErrInvalid, got %v", bad, err)
		}
	}
}

func TestValidatePrivileges(t *testing.T) {
	cases := []struct {
		privs []string
		valid bool
	}{
		{[]string{"ALL"}, true},
		{[]string{"SELECT", "INSERT", "UPDATE", "DELETE"}, true},
		{[]string{"select", "insert"}, true}, // case-insensitive
		{[]string{"SUPERUSER"}, false},
		{[]string{"DROP", "GRANT"}, false}, // GRANT not in allowlist
		{[]string{""}, false},
	}
	for _, tc := range cases {
		err := validatePrivileges(tc.privs)
		if (err == nil) != tc.valid {
			t.Errorf("validatePrivileges(%v): err=%v, want valid=%v", tc.privs, err, tc.valid)
		}
	}
}

func TestConnectionString(t *testing.T) {
	pgDB := ManagedDatabase{
		Engine: EnginePostgreSQL,
		DBName: "jw_proj_app",
	}
	mariaDB := ManagedDatabase{
		Engine: EngineMariaDB,
		DBName: "jw_proj_app",
	}

	cases := []struct {
		name     string
		db       ManagedDatabase
		user     string
		pass     string
		contains []string
	}{
		{
			name:     "postgresql clean",
			db:       pgDB,
			user:     "app_user",
			pass:     "secret123",
			contains: []string{"postgresql://app_user:secret123@localhost/jw_proj_app?sslmode=disable"},
		},
		{
			name:     "postgresql special chars in password",
			db:       pgDB,
			user:     "app_user",
			pass:     "p@ss:w/ord",
			contains: []string{"postgresql://app_user:p%40ss%3Aw%2Ford@localhost/jw_proj_app"},
		},
		{
			name:     "mariadb clean",
			db:       mariaDB,
			user:     "app_user",
			pass:     "secret123",
			contains: []string{"mysql://app_user:secret123@unix(/var/run/mysqld/mysqld.sock)/jw_proj_app"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ConnectionString(tc.db, tc.user, tc.pass)
			for _, sub := range tc.contains {
				if !strings.Contains(got, sub) {
					t.Errorf("ConnectionString() = %q, want substring %q", got, sub)
				}
			}
		})
	}
}

func TestLiveAndUsablePredicates(t *testing.T) {
	db := ManagedDatabase{State: StateActive}
	if !db.Live() || !db.Usable() {
		t.Errorf("active database should be Live and Usable")
	}

	db.State = StateSuspended
	if !db.Live() || db.Usable() {
		t.Errorf("suspended database should be Live but NOT Usable")
	}

	now := db.CreatedAt
	db.DeletedAt = &now
	db.State = StateDeleted
	if db.Live() || db.Usable() {
		t.Errorf("deleted database should be neither Live nor Usable")
	}
}
