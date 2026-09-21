package nodewire

import (
	"strings"
	"testing"
)

func TestDatabaseManageInputValidate(t *testing.T) {
	valid := DatabaseManageInput{
		Engine:     "postgresql",
		DBName:     "jw_main_mydb",
		Action:     "create_db",
		SocketPath: "/var/run/postgresql/.s.PGSQL.5432",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}

	cases := []struct {
		name  string
		mut   func(*DatabaseManageInput)
		wants string
	}{
		{"bad engine", func(in *DatabaseManageInput) { in.Engine = "oracle" }, "engine"},
		{"empty db_name", func(in *DatabaseManageInput) { in.DBName = "" }, "db_name"},
		{"db_name with hyphen", func(in *DatabaseManageInput) { in.DBName = "jw-main" }, "db_name"},
		{"db_name with NUL", func(in *DatabaseManageInput) { in.DBName = "jw_main\x00" }, "db_name"},
		{"bad action", func(in *DatabaseManageInput) { in.Action = "run_sql" }, "action"},
		{"user action without username", func(in *DatabaseManageInput) { in.Action = "create_user" }, "username"},
		{"bad username", func(in *DatabaseManageInput) { in.Action = "drop_user"; in.Username = "DROP TABLE" }, "username"},
		{"empty socket_path", func(in *DatabaseManageInput) { in.SocketPath = "" }, "socket_path"},
		{"tcp socket path", func(in *DatabaseManageInput) { in.SocketPath = "/tmp/evil.sock" }, "socket_path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := valid
			tc.mut(&in)
			err := in.Validate()
			if err == nil {
				t.Fatalf("%s: want error, got nil", tc.name)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("%s: error %q does not mention %q", tc.name, err, tc.wants)
			}
		})
	}
}

func TestDatabaseManageGrantsAllowlist(t *testing.T) {
	in := DatabaseManageInput{
		Engine:     "mariadb",
		DBName:     "jw_main_mydb",
		Action:     "set_grants",
		Username:   "app_user",
		Privileges: []string{"SELECT", "SUPER"},
		SocketPath: "/var/run/mysqld/mysqld.sock",
	}
	err := in.Validate()
	if err == nil || !strings.Contains(err.Error(), "SUPER") {
		t.Fatalf("SUPER privilege accepted; want rejection: %v", err)
	}
	in.Privileges = []string{"SELECT", "INSERT", "UPDATE", "DELETE", "CREATE", "DROP", "ALL"}
	if err := in.Validate(); err != nil {
		t.Fatalf("full allowlist rejected: %v", err)
	}
}

func TestDatabaseDumpInputValidate(t *testing.T) {
	valid := DatabaseDumpInput{
		Engine:     "postgresql",
		DBName:     "jw_main_mydb",
		DumpPath:   DatabaseDumpRoot + "/jw_main_mydb-20260921.dump",
		SocketPath: "/var/run/postgresql/.s.PGSQL.5432",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}

	// Path traversal outside the dump root.
	for _, bad := range []string{
		"/etc/passwd",
		DatabaseDumpRoot + "/../../../etc/passwd",
		"",
	} {
		in := valid
		in.DumpPath = bad
		if err := in.Validate(); err == nil {
			t.Errorf("dump_path %q accepted; want confinement error", bad)
		}
	}
}

func TestDatabaseUpgradeRequiresPreDump(t *testing.T) {
	in := DatabaseUpgradeInput{
		Engine:      "postgresql",
		FromVersion: "17.1",
		ToVersion:   "17.2",
		PreDumpPath: "",
		SocketPath:  "/var/run/postgresql/.s.PGSQL.5432",
	}
	err := in.Validate()
	if err == nil || !strings.Contains(err.Error(), "pre_dump_path is required") {
		t.Fatalf("upgrade without pre_dump_path accepted; want refusal (gate: explicit backup plan): %v", err)
	}

	// Outside dump root also refused.
	in.PreDumpPath = "/tmp/evil.dump"
	if err := in.Validate(); err == nil || !strings.Contains(err.Error(), "inside") {
		t.Fatalf("pre_dump_path outside root accepted: %v", err)
	}

	// Same version refused.
	in.PreDumpPath = DatabaseDumpRoot + "/pre.dump"
	in.FromVersion = "17.2"
	if err := in.Validate(); err == nil || !strings.Contains(err.Error(), "different") {
		t.Fatalf("same-version upgrade accepted: %v", err)
	}

	// Valid.
	in.FromVersion = "17.1"
	if err := in.Validate(); err != nil {
		t.Fatalf("valid upgrade rejected: %v", err)
	}
}

func TestDatabaseMetricsInputValidate(t *testing.T) {
	in := DatabaseMetricsInput{Engine: "mariadb", SocketPath: "/var/run/mysqld/mysqld.sock"}
	if err := in.Validate(); err != nil {
		t.Fatalf("valid input rejected: %v", err)
	}
	if err := (DatabaseMetricsInput{Engine: "sqlite", SocketPath: "/x"}).Validate(); err == nil {
		t.Error("bad engine accepted")
	}
	if err := (DatabaseMetricsInput{Engine: "postgresql"}).Validate(); err == nil {
		t.Error("empty socket_path accepted")
	}
}

// TestRegistryHasNoDatabaseShellOperation is the Phase 5 closed-registry guard:
// no database operation may offer a generic SQL or shell execution surface.
func TestRegistryHasNoDatabaseShellOperation(t *testing.T) {
	forbidden := []string{"sql", "shell", "query", "exec", "run", "command", "script"}
	for _, op := range Names() {
		lower := strings.ToLower(string(op))
		if !strings.HasPrefix(lower, "database.") {
			continue
		}
		for _, word := range forbidden {
			if strings.Contains(lower, word) {
				t.Errorf("database operation %q contains %q; the protocol must not expose SQL/shell execution", op, word)
			}
		}
	}
}

// TestDatabaseDescriptorsComplete asserts every database descriptor has a
// rollback statement when mutating and a permission declared (registry
// invariant, proven by ValidateRegistry — but repeated here to localize a
// Phase 5 regression to these five operations).
func TestDatabaseDescriptorsComplete(t *testing.T) {
	ops := []Operation{OpDatabaseManage, OpDatabaseDump, OpDatabaseRestore, OpDatabaseMetrics, OpDatabaseUpgrade}
	for _, op := range ops {
		d, ok := Lookup(op)
		if !ok {
			t.Fatalf("operation %q missing from registry", op)
		}
		if d.Permission == "" {
			t.Errorf("%q has no permission", op)
		}
		if d.Mutating && d.Rollback == "" {
			t.Errorf("%q is mutating but declares no rollback", op)
		}
		if len(d.OSSupport) != 1 || d.OSSupport[0] != "linux" {
			t.Errorf("%q must be linux-only", op)
		}
	}
	// metrics is the only non-mutating database op.
	if d, _ := Lookup(OpDatabaseMetrics); d.Mutating {
		t.Error("database.metrics must not be mutating")
	}
}
