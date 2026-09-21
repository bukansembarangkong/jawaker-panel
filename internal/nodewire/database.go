package nodewire

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"
)

// Engine names for Phase 5 database operations.
const (
	EnginePostgreSQL = "postgresql"
	EngineMariaDB    = "mariadb"
)

// AllowedDatabaseEngines is the closed set of database engines.
var AllowedDatabaseEngines = map[string]bool{
	"postgresql": true,
	"mariadb":    true,
}

// AllowedDatabaseActions is the closed set of database management actions.
// There is deliberately no generic SQL execution path (PRD.md §12.4).
var AllowedDatabaseActions = map[string]bool{
	"create_db":   true,
	"drop_db":     true,
	"create_user": true,
	"drop_user":   true,
	"set_grants":  true,
}

// AllowedDatabasePrivileges is the allowlist of SQL privileges.
var AllowedDatabasePrivileges = map[string]bool{
	"SELECT": true, "INSERT": true, "UPDATE": true, "DELETE": true,
	"CREATE": true, "DROP": true, "ALL": true,
}

// DatabaseDumpRoot is the path-confinement root for database dumps.
const DatabaseDumpRoot = "/var/lib/jawaker/db-dumps"

// DatabaseManageInput is the payload for OpDatabaseManage.
type DatabaseManageInput struct {
	Engine     string   `json:"engine"`
	DBName     string   `json:"db_name"`
	Action     string   `json:"action"`
	Username   string   `json:"username,omitempty"`
	Privileges []string `json:"privileges,omitempty"`
	SocketPath string   `json:"socket_path"`
}

// Validate checks DatabaseManageInput before execution.
func (in DatabaseManageInput) Validate() error {
	var errs []error
	if !AllowedDatabaseEngines[in.Engine] {
		errs = append(errs, fmt.Errorf("engine %q must be postgresql or mariadb", in.Engine))
	}
	if in.DBName == "" {
		errs = append(errs, errors.New("db_name is required"))
	} else if !dbNameWireRE.MatchString(in.DBName) {
		errs = append(errs, fmt.Errorf("db_name %q must match ^[a-z0-9_]{2,63}$", in.DBName))
	}
	if !AllowedDatabaseActions[in.Action] {
		errs = append(errs, fmt.Errorf("action %q is not allowed", in.Action))
	}
	switch in.Action {
	case "create_user", "drop_user", "set_grants":
		if in.Username == "" {
			errs = append(errs, errors.New("username is required for user actions"))
		} else if !usernameWireRE.MatchString(in.Username) {
			errs = append(errs, fmt.Errorf("username %q contains invalid characters", in.Username))
		}
	}
	if in.Action == "set_grants" {
		for _, p := range in.Privileges {
			if !AllowedDatabasePrivileges[strings.ToUpper(p)] {
				errs = append(errs, fmt.Errorf("privilege %q is not allowed", p))
			}
		}
	}
	if in.SocketPath == "" {
		errs = append(errs, errors.New("socket_path is required"))
	} else if !strings.HasPrefix(in.SocketPath, "/var/run/postgresql") && !strings.HasPrefix(in.SocketPath, "/var/run/mysqld") {
		errs = append(errs, fmt.Errorf("socket_path %q must be under /var/run/postgresql or /var/run/mysqld", in.SocketPath))
	}
	if strings.ContainsRune(in.DBName, 0) || strings.ContainsRune(in.Username, 0) || strings.ContainsRune(in.SocketPath, 0) {
		errs = append(errs, errors.New("input contains a NUL byte"))
	}
	return errors.Join(errs...)
}

// DatabaseManageResult is the reply to OpDatabaseManage.
type DatabaseManageResult struct {
	OK         bool      `json:"ok"`
	ObservedAt time.Time `json:"observed_at"`
}

// DatabaseDumpInput is the payload for OpDatabaseDump.
type DatabaseDumpInput struct {
	Engine     string `json:"engine"`
	DBName     string `json:"db_name"`
	DumpPath   string `json:"dump_path"`
	SocketPath string `json:"socket_path"`
}

// Validate checks DatabaseDumpInput before execution.
func (in DatabaseDumpInput) Validate() error {
	var errs []error
	if !AllowedDatabaseEngines[in.Engine] {
		errs = append(errs, fmt.Errorf("engine %q must be postgresql or mariadb", in.Engine))
	}
	if in.DBName == "" {
		errs = append(errs, errors.New("db_name is required"))
	}
	clean := path.Clean(in.DumpPath)
	if !strings.HasPrefix(clean, DatabaseDumpRoot+"/") && clean != DatabaseDumpRoot {
		errs = append(errs, fmt.Errorf("dump_path %q must be inside %s", in.DumpPath, DatabaseDumpRoot))
	}
	if in.SocketPath == "" {
		errs = append(errs, errors.New("socket_path is required"))
	}
	if strings.ContainsRune(in.DBName, 0) || strings.ContainsRune(in.DumpPath, 0) {
		errs = append(errs, errors.New("input contains a NUL byte"))
	}
	return errors.Join(errs...)
}

// DatabaseDumpResult is the reply to OpDatabaseDump.
type DatabaseDumpResult struct {
	DumpPath   string    `json:"dump_path"`
	SizeBytes  int64     `json:"size_bytes"`
	SHA256     string    `json:"sha256"`
	ObservedAt time.Time `json:"observed_at"`
}

// DatabaseRestoreInput is the payload for OpDatabaseRestore.
type DatabaseRestoreInput struct {
	Engine     string `json:"engine"`
	DBName     string `json:"db_name"`
	DumpPath   string `json:"dump_path"`
	SocketPath string `json:"socket_path"`
}

// Validate checks DatabaseRestoreInput before execution.
func (in DatabaseRestoreInput) Validate() error {
	var errs []error
	if !AllowedDatabaseEngines[in.Engine] {
		errs = append(errs, fmt.Errorf("engine %q must be postgresql or mariadb", in.Engine))
	}
	if in.DBName == "" {
		errs = append(errs, errors.New("db_name is required"))
	}
	clean := path.Clean(in.DumpPath)
	if !strings.HasPrefix(clean, DatabaseDumpRoot+"/") {
		errs = append(errs, fmt.Errorf("dump_path %q must be inside %s", in.DumpPath, DatabaseDumpRoot))
	}
	if in.SocketPath == "" {
		errs = append(errs, errors.New("socket_path is required"))
	}
	if strings.ContainsRune(in.DBName, 0) || strings.ContainsRune(in.DumpPath, 0) {
		errs = append(errs, errors.New("input contains a NUL byte"))
	}
	return errors.Join(errs...)
}

// DatabaseRestoreResult is the reply to OpDatabaseRestore.
type DatabaseRestoreResult struct {
	OK         bool      `json:"ok"`
	ObservedAt time.Time `json:"observed_at"`
}

// DatabaseMetricsInput is the payload for OpDatabaseMetrics.
type DatabaseMetricsInput struct {
	Engine     string `json:"engine"`
	SocketPath string `json:"socket_path"`
}

// Validate checks DatabaseMetricsInput before execution.
func (in DatabaseMetricsInput) Validate() error {
	if !AllowedDatabaseEngines[in.Engine] {
		return fmt.Errorf("engine %q must be postgresql or mariadb", in.Engine)
	}
	if in.SocketPath == "" {
		return errors.New("socket_path is required")
	}
	return nil
}

// SlowQuery describes one slow query snapshot.
type SlowQuery struct {
	Query     string  `json:"query"`
	Calls     int64   `json:"calls"`
	TotalTime float64 `json:"total_time_ms"`
	MeanTime  float64 `json:"mean_time_ms"`
}

// DatabaseMetricsResult is the reply to OpDatabaseMetrics.
type DatabaseMetricsResult struct {
	Connections       int         `json:"connections"`
	ActiveQueries     int         `json:"active_queries"`
	SlowQueriesLast5m int         `json:"slow_queries_last_5m"`
	TopSlowQueries    []SlowQuery `json:"top_slow_queries,omitempty"`
	ObservedAt        time.Time   `json:"observed_at"`
}

// DatabaseUpgradeInput is the payload for OpDatabaseUpgrade.
type DatabaseUpgradeInput struct {
	Engine      string `json:"engine"`
	FromVersion string `json:"from_version"`
	ToVersion   string `json:"to_version"`
	PreDumpPath string `json:"pre_dump_path"`
	SocketPath  string `json:"socket_path"`
}

// Validate checks DatabaseUpgradeInput before execution.
func (in DatabaseUpgradeInput) Validate() error {
	var errs []error
	if !AllowedDatabaseEngines[in.Engine] {
		errs = append(errs, fmt.Errorf("engine %q must be postgresql or mariadb", in.Engine))
	}
	if in.FromVersion == "" {
		errs = append(errs, errors.New("from_version is required"))
	}
	if in.ToVersion == "" {
		errs = append(errs, errors.New("to_version is required"))
	}
	if in.FromVersion == in.ToVersion {
		errs = append(errs, errors.New("from_version and to_version must be different"))
	}
	// PreDumpPath must be present and path-confined — Gate: upgrades have explicit backup plan.
	if in.PreDumpPath == "" {
		errs = append(errs, errors.New("pre_dump_path is required: an upgrade cannot run without a pre-upgrade backup"))
	} else {
		clean := path.Clean(in.PreDumpPath)
		if !strings.HasPrefix(clean, DatabaseDumpRoot+"/") {
			errs = append(errs, fmt.Errorf("pre_dump_path %q must be inside %s", in.PreDumpPath, DatabaseDumpRoot))
		}
	}
	if in.SocketPath == "" {
		errs = append(errs, errors.New("socket_path is required"))
	}
	return errors.Join(errs...)
}

// DatabaseUpgradeResult is the reply to OpDatabaseUpgrade.
type DatabaseUpgradeResult struct {
	OK             bool      `json:"ok"`
	RolledBack     bool      `json:"rolled_back,omitempty"`
	RollbackReason string    `json:"rollback_reason,omitempty"`
	ObservedAt     time.Time `json:"observed_at"`
}

// dbNameWireRE validates the db_name field in wire payloads.
// Matches the schema CHECK: ^[a-z0-9_]{2,63}$
var dbNameWireRE = regexp.MustCompile(`^[a-z0-9_]{2,63}$`)

// usernameWireRE validates the username field in wire payloads.
// Matches the schema CHECK: ^[a-z0-9_]{2,32}$
var usernameWireRE = regexp.MustCompile(`^[a-z0-9_]{2,32}$`)
