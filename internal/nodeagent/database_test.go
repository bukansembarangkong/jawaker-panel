package nodeagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// fakeExecutors builds an Executors instance with mock command runner and
// test directories. pg and maria are set AFTER construction to override
// ambient binary detection on CI runners that have postgresql-client installed.
func fakeExecutors(t *testing.T, pg, maria bool) (*Executors, *[]CommandSpec) {
	t.Helper()
	var recorded []CommandSpec
	dumpDir := t.TempDir()

	e := NewExecutors(ExecutorOptions{
		AgentVersion:   "db-test",
		PgAvailable:    pg,
		MariaAvailable: maria,
		DBDumpDir:      dumpDir,
		Now:            func() time.Time { return time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC) },
	})
	// Override detection: ambient binaries on CI (e.g. postgresql-client on ubuntu)
	// must not pollute the test expectations.
	e.pgAvailable = pg
	e.mariaAvailable = maria
	e.cmdRunner = func(_ context.Context, spec CommandSpec) (CommandResult, error) {
		recorded = append(recorded, spec)
		return CommandResult{Stdout: "", ExitCode: 0}, nil
	}
	return e, &recorded
}

func TestDatabaseManageLinuxGate(t *testing.T) {
	if supportedOS() {
		t.Skip("skipping non-Linux assertion on Linux")
	}
	e, _ := fakeExecutors(t, true, true)
	_, err := e.ManageDatabase(context.Background(), nodewire.DatabaseManageInput{
		Engine: "postgresql", DBName: "mydb", Action: "create_db", SocketPath: "/var/run/postgresql",
	})
	if err == nil {
		t.Fatal("manage on non-Linux must fail")
	}
	var nwErr *nodewire.Error
	if !errors.As(err, &nwErr) || nwErr.Code != nodewire.CodeNotAvailable {
		t.Errorf("got %v, want CodeNotAvailable", err)
	}
}

func TestDatabaseManageEngineUnavailable(t *testing.T) {
	// Linux only for this test.
	if !supportedOS() {
		t.Skip("requires Linux")
	}
	e, _ := fakeExecutors(t, false, false) // neither engine available
	_, err := e.ManageDatabase(context.Background(), nodewire.DatabaseManageInput{
		Engine: "postgresql", DBName: "mydb", Action: "create_db", SocketPath: "/var/run/postgresql",
	})
	if err == nil {
		t.Fatal("expected error when PG not available")
	}
	var nwErr *nodewire.Error
	if !errors.As(err, &nwErr) || nwErr.Code != nodewire.CodeNotAvailable {
		t.Errorf("got %v, want CodeNotAvailable", err)
	}
}

func TestDatabaseDumpPathConfinement(t *testing.T) {
	e, _ := fakeExecutors(t, true, true)
	ctx := context.Background()

	for _, bad := range []string{
		"/etc/passwd",
		"../../etc/shadow",
		"/tmp/evil.dump",
	} {
		_, err := e.DumpDatabase(ctx, nodewire.DatabaseDumpInput{
			Engine: "postgresql", DBName: "mydb", DumpPath: bad, SocketPath: "/var/run/postgresql",
		})
		if err == nil {
			t.Errorf("bad path %q accepted", bad)
		}
	}
}

func TestDatabaseRestorePathConfinement(t *testing.T) {
	e, _ := fakeExecutors(t, true, true)
	ctx := context.Background()

	for _, bad := range []string{
		"/etc/passwd",
		"../../etc/shadow",
		"/tmp/evil.dump",
	} {
		_, err := e.RestoreDatabase(ctx, nodewire.DatabaseRestoreInput{
			Engine: "postgresql", DBName: "mydb", DumpPath: bad, SocketPath: "/var/run/postgresql",
		})
		if err == nil {
			t.Errorf("bad path %q accepted for restore", bad)
		}
	}
}

func TestDatabaseUpgradeRequiresPreDumpFile(t *testing.T) {
	// confineDumpPath is OS-agnostic; test the validation layer directly.
	e, _ := fakeExecutors(t, true, true)

	// Empty pre_dump_path: validated by UpgradeDatabase before supportedOS check would matter.
	// On Linux: would hit the ErrInvalidInput from the empty-path check.
	// On non-Linux: hits the supportedOS gate first, which returns CodeNotAvailable.
	// Test the confinement directly instead:
	_, err := e.confineDumpPath("/etc/passwd")
	if err == nil {
		t.Fatal("confineDumpPath must reject path outside dump root")
	}
	if !strings.Contains(err.Error(), "must be inside") {
		t.Errorf("unexpected error: %v", err)
	}

	// Valid path inside dump dir
	good := e.dbDumpDir + "/valid.dump"
	_, err = e.confineDumpPath(good)
	if err != nil {
		t.Errorf("valid path rejected: %v", err)
	}
}

func TestDatabaseUpgradeDumpsBeforeUpgrade(t *testing.T) {
	e, recorded := fakeExecutors(t, true, true)
	ctx := context.Background()

	// Gate 4: empty pre_dump_path must be rejected with CodeInvalidInput
	// before any engine binary runs.
	if !supportedOS() {
		// On non-Linux the OS gate fires first (CodeNotAvailable); still no commands run.
		_, err := e.UpgradeDatabase(ctx, nodewire.DatabaseUpgradeInput{
			Engine:      "mariadb",
			FromVersion: "10.11",
			ToVersion:   "11.4",
			SocketPath:  "/var/run/mysqld/mysqld.sock",
		})
		var nwErr *nodewire.Error
		if !errors.As(err, &nwErr) || nwErr.Code != nodewire.CodeNotAvailable {
			t.Fatalf("got %v, want CodeNotAvailable on non-Linux", err)
		}
		if len(*recorded) != 0 {
			t.Fatal("no command may run when upgrade is gated")
		}
		return
	}

	// Linux: missing pre_dump_path must yield CodeInvalidInput, no commands run.
	_, err := e.UpgradeDatabase(ctx, nodewire.DatabaseUpgradeInput{
		Engine:      "mariadb",
		FromVersion: "10.11",
		ToVersion:   "11.4",
		SocketPath:  "/var/run/mysqld/mysqld.sock",
	})
	var nwErr *nodewire.Error
	if !errors.As(err, &nwErr) || nwErr.Code != nodewire.CodeInvalidInput {
		t.Fatalf("got %v, want CodeInvalidInput for empty pre_dump_path", err)
	}
	if len(*recorded) != 0 {
		t.Fatal("no command may run without a pre-upgrade dump")
	}

	// With a real pre-dump file present, validation passes; the run then
	// reaches require() which fails with CodeUnsupportedOperation when the
	// upgrade binary is absent (normal on CI runners).
	preDump := filepath.Join(e.dbDumpDir, "valid-pre.dump")
	if wErr := os.WriteFile(preDump, []byte("fake-dump"), 0600); wErr != nil {
		t.Fatalf("create temp dump: %v", wErr)
	}
	if _, uErr := e.UpgradeDatabase(ctx, nodewire.DatabaseUpgradeInput{
		Engine:      "mariadb",
		FromVersion: "10.11",
		ToVersion:   "11.4",
		PreDumpPath: preDump,
		SocketPath:  "/var/run/mysqld/mysqld.sock",
	}); uErr != nil {
		var gateErr *nodewire.Error
		if errors.As(uErr, &gateErr) && gateErr.Code != nodewire.CodeUnsupportedOperation {
			t.Errorf("unexpected error past pre-dump gate: %v", uErr)
		}
	}
}

func TestSocketDirHelper(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"/var/run/postgresql/.s.PGSQL.5432", "/var/run/postgresql"},
		{"/var/run/mysqld/mysqld.sock", "/var/run/mysqld"},
		{"/var/run/postgresql", "/var/run/postgresql"},
	}
	for _, tc := range cases {
		got := socketDir(tc.input)
		if got != tc.want {
			t.Errorf("socketDir(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestBuildPGGrantSQL(t *testing.T) {
	// ALL privileges
	sql := buildPGGrantSQL("app_user", []string{"ALL"})
	if !strings.Contains(sql, "ALL PRIVILEGES") || !strings.Contains(sql, "app_user") {
		t.Errorf("unexpected SQL: %s", sql)
	}

	// Specific privileges
	sql2 := buildPGGrantSQL("app_user", []string{"SELECT", "INSERT"})
	if !strings.Contains(sql2, "SELECT, INSERT") {
		t.Errorf("privileges not formatted correctly: %s", sql2)
	}
}
