package nodeagent

// database.go implements the Phase 5 database operations.
//
// Authentication to the engine uses OS-level peer auth (PostgreSQL) or
// unix-socket auth (MariaDB). No root credential is stored or transmitted.
//
// Every subprocess uses an absolute path from a fixed candidate list, argv
// only, no shell. Dump paths are confined inside e.dbDumpDir via path.Clean
// (unix semantics regardless of the build host OS).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// Binary candidate paths for PostgreSQL admin tools.
var (
	pgCreateDB   = []string{"/usr/bin/createdb", "/usr/local/bin/createdb"}
	pgDropDB     = []string{"/usr/bin/dropdb", "/usr/local/bin/dropdb"}
	pgCreateUser = []string{"/usr/bin/createuser", "/usr/local/bin/createuser"}
	pgDropUser   = []string{"/usr/bin/dropuser", "/usr/local/bin/dropuser"}
	pgPSQL       = []string{"/usr/bin/psql", "/usr/local/bin/psql"}
	pgDump       = []string{"/usr/bin/pg_dump", "/usr/local/bin/pg_dump"}
	pgRestore    = []string{"/usr/bin/pg_restore", "/usr/local/bin/pg_restore"}
	pgUpgrade    = []string{"/usr/bin/pg_upgrade", "/usr/local/bin/pg_upgrade", "/usr/lib/postgresql/17/bin/pg_upgrade"}
)

// Binary candidate paths for MariaDB/MySQL admin tools.
var (
	mariaClient  = []string{"/usr/bin/mariadb", "/usr/bin/mysql", "/usr/local/bin/mariadb"}
	mariaDump    = []string{"/usr/bin/mariadb-dump", "/usr/bin/mysqldump", "/usr/local/bin/mariadb-dump"}
	mariaUpgrade = []string{"/usr/bin/mariadb-upgrade", "/usr/bin/mysql_upgrade", "/usr/local/bin/mariadb-upgrade"}
)

// confineDumpPath resolves and validates a dump path against the dump root.
func (e *Executors) confineDumpPath(p string) (string, error) {
	clean := path.Clean(p)
	root := strings.TrimRight(e.dbDumpDir, "/")
	if !strings.HasPrefix(clean, root+"/") && clean != root {
		return "", fmt.Errorf("dump path %q must be inside %s", p, e.dbDumpDir)
	}
	return clean, nil
}

// socketDir extracts the directory from a socket path (for -h argument to PG tools).
// /var/run/postgresql/.s.PGSQL.5432 → /var/run/postgresql
// /var/run/postgresql → /var/run/postgresql (already a dir)
func socketDir(socketPath string) string {
	if strings.HasSuffix(socketPath, ".sock") || strings.HasSuffix(socketPath, ".PGSQL.5432") || strings.Contains(path.Base(socketPath), ".") {
		return path.Dir(socketPath)
	}
	return socketPath
}

// require resolves the first existing candidate and returns an error if none.
func require(candidates []string) (string, error) {
	p, ok := resolveProgram(candidates...)
	if !ok {
		return "", &nodewire.Error{
			Code:    nodewire.CodeUnsupportedOperation,
			Message: "required database binary not found on this node",
		}
	}
	return p, nil
}

// ManageDatabase creates or drops a database or user on the local engine.
func (e *Executors) ManageDatabase(ctx context.Context, in nodewire.DatabaseManageInput) (nodewire.DatabaseManageResult, error) {
	if !supportedOS() {
		return nodewire.DatabaseManageResult{}, notAvailable("database management is supported on Linux only")
	}
	switch in.Engine {
	case nodewire.EnginePostgreSQL:
		if !e.pgAvailable {
			return nodewire.DatabaseManageResult{}, notAvailable("postgresql client binaries are not installed on this node")
		}
		return e.managePG(ctx, in)
	case nodewire.EngineMariaDB:
		if !e.mariaAvailable {
			return nodewire.DatabaseManageResult{}, notAvailable("mariadb client binaries are not installed on this node")
		}
		return e.manageMariaDB(ctx, in)
	default:
		return nodewire.DatabaseManageResult{}, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: "unknown engine " + in.Engine}
	}
}

func (e *Executors) managePG(ctx context.Context, in nodewire.DatabaseManageInput) (nodewire.DatabaseManageResult, error) {
	sockDir := socketDir(in.SocketPath)
	run := e.cmdRunner

	switch in.Action {
	case "create_db":
		bin, err := require(pgCreateDB)
		if err != nil {
			return nodewire.DatabaseManageResult{}, err
		}
		if _, err := run(ctx, CommandSpec{
			Path:    bin,
			Args:    []string{"-h", sockDir, "-U", "postgres", "--if-not-exists", in.DBName},
			Timeout: 30 * time.Second,
		}); err != nil {
			return nodewire.DatabaseManageResult{}, wrapDBErr(err, "create database")
		}

	case "drop_db":
		bin, err := require(pgDropDB)
		if err != nil {
			return nodewire.DatabaseManageResult{}, err
		}
		if _, err := run(ctx, CommandSpec{
			Path:    bin,
			Args:    []string{"-h", sockDir, "-U", "postgres", "--if-exists", in.DBName},
			Timeout: 30 * time.Second,
		}); err != nil {
			return nodewire.DatabaseManageResult{}, wrapDBErr(err, "drop database")
		}

	case "create_user":
		bin, err := require(pgCreateUser)
		if err != nil {
			return nodewire.DatabaseManageResult{}, err
		}
		if _, err := run(ctx, CommandSpec{
			Path:    bin,
			Args:    []string{"-h", sockDir, "-U", "postgres", "--no-superuser", "--no-createdb", "--no-createrole", in.Username},
			Timeout: 30 * time.Second,
		}); err != nil {
			return nodewire.DatabaseManageResult{}, wrapDBErr(err, "create user")
		}

	case "drop_user":
		bin, err := require(pgDropUser)
		if err != nil {
			return nodewire.DatabaseManageResult{}, err
		}
		if _, err := run(ctx, CommandSpec{
			Path:    bin,
			Args:    []string{"-h", sockDir, "-U", "postgres", "--if-exists", in.Username},
			Timeout: 30 * time.Second,
		}); err != nil {
			return nodewire.DatabaseManageResult{}, wrapDBErr(err, "drop user")
		}

	case "set_grants":
		bin, err := require(pgPSQL)
		if err != nil {
			return nodewire.DatabaseManageResult{}, err
		}
		sql := buildPGGrantSQL(in.Username, in.Privileges)
		if _, err := run(ctx, CommandSpec{
			Path:    bin,
			Args:    []string{"-h", sockDir, "-U", "postgres", "-d", in.DBName, "-c", sql},
			Timeout: 30 * time.Second,
		}); err != nil {
			return nodewire.DatabaseManageResult{}, wrapDBErr(err, "set grants")
		}
	}

	return nodewire.DatabaseManageResult{OK: true, ObservedAt: time.Now().UTC()}, nil
}

func buildPGGrantSQL(username string, privileges []string) string {
	privList := "ALL PRIVILEGES"
	if len(privileges) > 0 {
		joined := strings.Join(privileges, ", ")
		if joined != "ALL" {
			privList = joined
		}
	}
	return fmt.Sprintf(
		"GRANT %s ON ALL TABLES IN SCHEMA public TO %s; GRANT USAGE ON SCHEMA public TO %s; ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT %s ON TABLES TO %s;",
		privList, username, username, privList, username,
	)
}

func (e *Executors) manageMariaDB(ctx context.Context, in nodewire.DatabaseManageInput) (nodewire.DatabaseManageResult, error) {
	bin, err := require(mariaClient)
	if err != nil {
		return nodewire.DatabaseManageResult{}, err
	}
	run := e.cmdRunner

	var sql string
	switch in.Action {
	case "create_db":
		sql = fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`;", escapeMaria(in.DBName))
	case "drop_db":
		sql = fmt.Sprintf("DROP DATABASE IF EXISTS `%s`;", escapeMaria(in.DBName))
	case "create_user":
		sql = fmt.Sprintf("CREATE USER IF NOT EXISTS '%s'@'localhost';", escapeMaria(in.Username))
	case "drop_user":
		sql = fmt.Sprintf("DROP USER IF EXISTS '%s'@'localhost';", escapeMaria(in.Username))
	case "set_grants":
		privList := "ALL PRIVILEGES"
		if len(in.Privileges) > 0 && (len(in.Privileges) != 1 || strings.ToUpper(in.Privileges[0]) != "ALL") {
			privList = strings.Join(in.Privileges, ", ")
		}
		sql = fmt.Sprintf(
			"GRANT %s ON `%s`.* TO '%s'@'localhost'; FLUSH PRIVILEGES;",
			privList, escapeMaria(in.DBName), escapeMaria(in.Username),
		)
	}

	if _, err := run(ctx, CommandSpec{
		Path:    bin,
		Args:    []string{"--socket=" + in.SocketPath, "-e", sql},
		Timeout: 30 * time.Second,
	}); err != nil {
		return nodewire.DatabaseManageResult{}, wrapDBErr(err, in.Action)
	}
	return nodewire.DatabaseManageResult{OK: true, ObservedAt: time.Now().UTC()}, nil
}

// escapeMaria escapes a MariaDB identifier value (not the backtick wrapper itself).
func escapeMaria(s string) string { return strings.ReplaceAll(s, "'", "\\'") }

// DumpDatabase runs pg_dump or mariadb-dump to a confined path.
func (e *Executors) DumpDatabase(ctx context.Context, in nodewire.DatabaseDumpInput) (nodewire.DatabaseDumpResult, error) {
	if !supportedOS() {
		return nodewire.DatabaseDumpResult{}, notAvailable("database dump is supported on Linux only")
	}
	dumpPath, err := e.confineDumpPath(in.DumpPath)
	if err != nil {
		return nodewire.DatabaseDumpResult{}, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
	}
	// Ensure the dump directory exists.
	if mkErr := os.MkdirAll(path.Dir(dumpPath), 0750); mkErr != nil {
		return nodewire.DatabaseDumpResult{}, fmt.Errorf("dump: create parent dir: %w", mkErr)
	}

	// Remove any partial artifact on failure.
	var ok bool
	defer func() {
		if !ok {
			_ = os.Remove(dumpPath)
		}
	}()

	switch in.Engine {
	case nodewire.EnginePostgreSQL:
		if !e.pgAvailable {
			return nodewire.DatabaseDumpResult{}, notAvailable("postgresql client binaries not installed")
		}
		pgBin, reqErr := require(pgDump)
		if reqErr != nil {
			return nodewire.DatabaseDumpResult{}, reqErr
		}
		if _, runErr := e.cmdRunner(ctx, CommandSpec{
			Path:    pgBin,
			Args:    []string{"-h", socketDir(in.SocketPath), "-U", "postgres", "-F", "c", "-f", dumpPath, in.DBName},
			Timeout: 30 * 60 * time.Second,
		}); runErr != nil {
			return nodewire.DatabaseDumpResult{}, wrapDBErr(runErr, "pg_dump")
		}

	case nodewire.EngineMariaDB:
		if !e.mariaAvailable {
			return nodewire.DatabaseDumpResult{}, notAvailable("mariadb client binaries not installed")
		}
		mBin, reqErr := require(mariaDump)
		if reqErr != nil {
			return nodewire.DatabaseDumpResult{}, reqErr
		}
		if _, runErr := e.cmdRunner(ctx, CommandSpec{
			Path:    mBin,
			Args:    []string{"--socket=" + in.SocketPath, "--single-transaction", "--routines", "--events", "--result-file=" + dumpPath, in.DBName},
			Timeout: 30 * 60 * time.Second,
		}); runErr != nil {
			return nodewire.DatabaseDumpResult{}, wrapDBErr(runErr, "mariadb-dump")
		}

	default:
		return nodewire.DatabaseDumpResult{}, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: "unknown engine " + in.Engine}
	}

	// Compute SHA-256 and size of the completed dump.
	data, err := os.ReadFile(dumpPath) //nolint:gosec // G304: path is confined above
	if err != nil {
		return nodewire.DatabaseDumpResult{}, fmt.Errorf("dump: read completed artifact: %w", err)
	}
	sum := sha256.Sum256(data)
	ok = true
	return nodewire.DatabaseDumpResult{
		DumpPath:   dumpPath,
		SizeBytes:  int64(len(data)),
		SHA256:     hex.EncodeToString(sum[:]),
		ObservedAt: time.Now().UTC(),
	}, nil
}

// RestoreDatabase restores a database from a confined dump file.
func (e *Executors) RestoreDatabase(ctx context.Context, in nodewire.DatabaseRestoreInput) (nodewire.DatabaseRestoreResult, error) {
	if !supportedOS() {
		return nodewire.DatabaseRestoreResult{}, notAvailable("database restore is supported on Linux only")
	}
	dumpPath, err := e.confineDumpPath(in.DumpPath)
	if err != nil {
		return nodewire.DatabaseRestoreResult{}, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
	}

	switch in.Engine {
	case nodewire.EnginePostgreSQL:
		if !e.pgAvailable {
			return nodewire.DatabaseRestoreResult{}, notAvailable("postgresql client binaries not installed")
		}
		bin, err := require(pgRestore)
		if err != nil {
			return nodewire.DatabaseRestoreResult{}, err
		}
		if _, err := e.cmdRunner(ctx, CommandSpec{
			Path:    bin,
			Args:    []string{"-h", socketDir(in.SocketPath), "-U", "postgres", "--clean", "--if-exists", "-d", in.DBName, dumpPath},
			Timeout: 30 * 60 * time.Second,
		}); err != nil {
			return nodewire.DatabaseRestoreResult{}, wrapDBErr(err, "pg_restore")
		}

	case nodewire.EngineMariaDB:
		if !e.mariaAvailable {
			return nodewire.DatabaseRestoreResult{}, notAvailable("mariadb client binaries not installed")
		}
		bin, err := require(mariaClient)
		if err != nil {
			return nodewire.DatabaseRestoreResult{}, err
		}
		// MariaDB restore: pipe the dump file via the mariadb client.
		// Args: --socket=<sock> --database=<db> --execute=source <path>
		// Since we can't use shell redirection, we use --execute with SOURCE.
		if _, err := e.cmdRunner(ctx, CommandSpec{
			Path:    bin,
			Args:    []string{"--socket=" + in.SocketPath, "--database=" + in.DBName, "--execute=source " + dumpPath},
			Timeout: 30 * 60 * time.Second,
		}); err != nil {
			return nodewire.DatabaseRestoreResult{}, wrapDBErr(err, "mariadb restore")
		}

	default:
		return nodewire.DatabaseRestoreResult{}, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: "unknown engine " + in.Engine}
	}

	return nodewire.DatabaseRestoreResult{OK: true, ObservedAt: time.Now().UTC()}, nil
}

// GetDatabaseMetrics collects point-in-time connection counts and slow queries.
func (e *Executors) GetDatabaseMetrics(ctx context.Context, in nodewire.DatabaseMetricsInput) (nodewire.DatabaseMetricsResult, error) {
	if !supportedOS() {
		return nodewire.DatabaseMetricsResult{}, notAvailable("database metrics are supported on Linux only")
	}

	switch in.Engine {
	case nodewire.EnginePostgreSQL:
		if !e.pgAvailable {
			return nodewire.DatabaseMetricsResult{}, notAvailable("postgresql client binaries not installed")
		}
		return e.pgMetrics(ctx, in.SocketPath)

	case nodewire.EngineMariaDB:
		if !e.mariaAvailable {
			return nodewire.DatabaseMetricsResult{}, notAvailable("mariadb client binaries not installed")
		}
		return e.mariaMetrics(ctx, in.SocketPath)

	default:
		return nodewire.DatabaseMetricsResult{}, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: "unknown engine " + in.Engine}
	}
}

func (e *Executors) pgMetrics(ctx context.Context, socketPath string) (nodewire.DatabaseMetricsResult, error) {
	bin, err := require(pgPSQL)
	if err != nil {
		return nodewire.DatabaseMetricsResult{}, err
	}
	sockDir := socketDir(socketPath)

	// Single query returning JSON metrics to avoid multiple round trips.
	// pg_stat_statements may not be installed — COALESCE to empty array.
	sql := `SELECT json_build_object(
		'connections', (SELECT count(*) FROM pg_stat_activity),
		'active', (SELECT count(*) FROM pg_stat_activity WHERE state = 'active'),
		'slow_5m', COALESCE((SELECT count(*) FROM pg_stat_statements WHERE mean_exec_time > 500), 0),
		'top_slow', COALESCE(
			(SELECT json_agg(r) FROM (
				SELECT query, calls, total_exec_time AS total_time_ms, mean_exec_time AS mean_time_ms
				FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 5
			) r), '[]'::json)
		);`

	res, runErr := e.cmdRunner(ctx, CommandSpec{
		Path:    bin,
		Args:    []string{"-h", sockDir, "-U", "postgres", "-d", "postgres", "--no-psqlrc", "--tuples-only", "--no-align", "-c", sql},
		Timeout: 15 * time.Second,
	})
	if runErr != nil {
		// Degrade gracefully: return zeroed metrics rather than an error.
		return nodewire.DatabaseMetricsResult{ObservedAt: time.Now().UTC()}, nil
	}

	var raw struct {
		Connections int                  `json:"connections"`
		Active      int                  `json:"active"`
		Slow5m      int                  `json:"slow_5m"`
		TopSlow     []nodewire.SlowQuery `json:"top_slow"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(res.Stdout)), &raw); err != nil {
		return nodewire.DatabaseMetricsResult{ObservedAt: time.Now().UTC()}, nil
	}
	return nodewire.DatabaseMetricsResult{
		Connections:       raw.Connections,
		ActiveQueries:     raw.Active,
		SlowQueriesLast5m: raw.Slow5m,
		TopSlowQueries:    raw.TopSlow,
		ObservedAt:        time.Now().UTC(),
	}, nil
}

func (e *Executors) mariaMetrics(ctx context.Context, socketPath string) (nodewire.DatabaseMetricsResult, error) {
	bin, err := require(mariaClient)
	if err != nil {
		return nodewire.DatabaseMetricsResult{}, err
	}

	res, _ := e.cmdRunner(ctx, CommandSpec{
		Path:    bin,
		Args:    []string{"--socket=" + socketPath, "--batch", "--skip-column-names", "-e", "SHOW GLOBAL STATUS LIKE 'Threads_connected'"},
		Timeout: 15 * time.Second,
	})

	connections := 0
	for _, line := range strings.Split(res.Stdout, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "Threads_connected" {
			connections, _ = strconv.Atoi(fields[1])
		}
	}

	return nodewire.DatabaseMetricsResult{
		Connections: connections,
		ObservedAt:  time.Now().UTC(),
	}, nil
}

// UpgradeDatabase performs a safe engine version upgrade with a pre-dump gate.
func (e *Executors) UpgradeDatabase(ctx context.Context, in nodewire.DatabaseUpgradeInput) (nodewire.DatabaseUpgradeResult, error) {
	if !supportedOS() {
		return nodewire.DatabaseUpgradeResult{}, notAvailable("database upgrade is supported on Linux only")
	}

	// Gate: pre_dump_path is required and must be confined (Validate already
	// checks this, but enforce here too so the guarantee is a property of the
	// executor and not only of the dispatch path).
	if in.PreDumpPath == "" {
		return nodewire.DatabaseUpgradeResult{}, &nodewire.Error{
			Code:    nodewire.CodeInvalidInput,
			Message: "pre_dump_path is required: upgrade cannot run without a pre-upgrade backup",
		}
	}
	preDump, err := e.confineDumpPath(in.PreDumpPath)
	if err != nil {
		return nodewire.DatabaseUpgradeResult{}, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
	}

	switch in.Engine {
	case nodewire.EnginePostgreSQL:
		if !e.pgAvailable {
			return nodewire.DatabaseUpgradeResult{}, notAvailable("postgresql client binaries not installed")
		}
		return e.pgUpgrade(ctx, in, preDump)
	case nodewire.EngineMariaDB:
		if !e.mariaAvailable {
			return nodewire.DatabaseUpgradeResult{}, notAvailable("mariadb client binaries not installed")
		}
		return e.mariaUpgrade(ctx, in, preDump)
	default:
		return nodewire.DatabaseUpgradeResult{}, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: "unknown engine " + in.Engine}
	}
}

func (e *Executors) pgUpgrade(ctx context.Context, in nodewire.DatabaseUpgradeInput, preDump string) (nodewire.DatabaseUpgradeResult, error) {
	// Verify the pre-dump exists.
	if _, err := os.Stat(preDump); err != nil {
		return nodewire.DatabaseUpgradeResult{}, &nodewire.Error{
			Code:    nodewire.CodeInvalidInput,
			Message: fmt.Sprintf("pre_dump_path %q does not exist or is not accessible", preDump),
		}
	}

	upgradeBin, err := require(pgUpgrade)
	if err != nil {
		return nodewire.DatabaseUpgradeResult{}, err
	}

	// pg_upgrade is version-specific; --old-bindir and --new-bindir are inferred
	// from the installed packages. Provide sensible defaults.
	oldBinDir := fmt.Sprintf("/usr/lib/postgresql/%s/bin", in.FromVersion)
	newBinDir := fmt.Sprintf("/usr/lib/postgresql/%s/bin", in.ToVersion)
	oldDataDir := fmt.Sprintf("/var/lib/postgresql/%s/main", in.FromVersion)
	newDataDir := fmt.Sprintf("/var/lib/postgresql/%s/main", in.ToVersion)

	if _, err := e.cmdRunner(ctx, CommandSpec{
		Path: upgradeBin,
		Args: []string{
			"--old-bindir=" + oldBinDir,
			"--new-bindir=" + newBinDir,
			"--old-datadir=" + oldDataDir,
			"--new-datadir=" + newDataDir,
			"--link", // hard-link mode: fastest, requires old data dir to be on same filesystem
		},
		Timeout: 60 * 60 * time.Second,
	}); err != nil {
		// Upgrade failed: the pre_dump_path is left intact for operator inspection.
		return nodewire.DatabaseUpgradeResult{
			OK:             false,
			RolledBack:     false, // pg_upgrade does not write to new cluster on failure; operator must run restore manually
			RollbackReason: fmt.Sprintf("pg_upgrade failed: %v; restore from pre_dump_path %s manually", err, preDump),
		}, nil
	}

	return nodewire.DatabaseUpgradeResult{OK: true, ObservedAt: time.Now().UTC()}, nil
}

func (e *Executors) mariaUpgrade(ctx context.Context, in nodewire.DatabaseUpgradeInput, preDump string) (nodewire.DatabaseUpgradeResult, error) {
	if _, err := os.Stat(preDump); err != nil {
		return nodewire.DatabaseUpgradeResult{}, &nodewire.Error{
			Code:    nodewire.CodeInvalidInput,
			Message: fmt.Sprintf("pre_dump_path %q does not exist", preDump),
		}
	}

	upgradeBin, err := require(mariaUpgrade)
	if err != nil {
		return nodewire.DatabaseUpgradeResult{}, err
	}

	if _, err := e.cmdRunner(ctx, CommandSpec{
		Path:    upgradeBin,
		Args:    []string{"--socket=" + in.SocketPath},
		Timeout: 60 * 60 * time.Second,
	}); err != nil {
		return nodewire.DatabaseUpgradeResult{
			OK:             false,
			RolledBack:     false,
			RollbackReason: fmt.Sprintf("mariadb-upgrade failed: %v; restore from pre_dump_path %s manually", err, preDump),
		}, nil
	}
	return nodewire.DatabaseUpgradeResult{OK: true, ObservedAt: time.Now().UTC()}, nil
}

// wrapDBErr converts a runCommand error into a typed nodewire.Error.
func wrapDBErr(err error, op string) error {
	if err == nil {
		return nil
	}
	if nwErr, ok := err.(*nodewire.Error); ok { //nolint:errorlint // exact type, not wrap
		return nwErr
	}
	return &nodewire.Error{
		Code:    nodewire.CodeExecutionFailed,
		Message: fmt.Sprintf("database %s: %v", op, err),
	}
}
