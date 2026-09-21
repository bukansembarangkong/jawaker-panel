package nodewire

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The registry is closed by construction: it is a package-level map built once
// from literal descriptors, and Lookup is the only way in.
//
// There is no Register function. A registry that modules could add to would mean
// the set of privileged operations on a node changes at runtime and is not
// knowable by reading the code — which is the opposite of what a security review
// of a node agent needs. When a later phase adds operations, they are added
// here, in review.

// Operations is the complete protocol surface.
var Operations = map[Operation]Descriptor{
	OpNodeCapabilities: {
		Operation:   OpNodeCapabilities,
		Permission:  "server.read",
		InputSchema: "{} (no input)",
		Validation:  "no input to validate; the agent reports only what it detected",
		OSSupport:   []string{"linux"},
		Scope: Scope{
			FilesystemRead: []string{"/etc/os-release", "/proc/version"},
			Network:        "none",
		},
		Timeout:     10 * time.Second,
		AuditAction: "node.capabilities.read",
		Retry:       RetryPolicy{Idempotent: true, MaxAttempts: 2},
		Mutating:    false,
	},

	OpNodeHeartbeat: {
		Operation:   OpNodeHeartbeat,
		Permission:  "server.read",
		InputSchema: "{observed_at, uptime_seconds, load1_milli, mem_total_bytes, mem_used_bytes, workload_count}",
		Validation:  "all counters must be non-negative and used ≤ total; a violation is refused rather than clamped",
		OSSupport:   []string{"linux"},
		Scope: Scope{
			FilesystemRead: []string{"/proc/loadavg", "/proc/meminfo", "/proc/uptime"},
			Network:        "none",
		},
		Timeout:     10 * time.Second,
		AuditAction: "node.heartbeat.received",
		Retry:       RetryPolicy{Idempotent: true, MaxAttempts: 3},
		Mutating:    false,
	},

	OpServiceInspect: {
		Operation:   OpServiceInspect,
		Permission:  "server.read",
		InputSchema: "{unit: string} — target is the unit name",
		Validation:  "unit name must match the unit-name pattern and be in this node's declared scope",
		OSSupport:   []string{"linux"},
		Scope: Scope{
			// The units a node may inspect. The list is deliberately explicit:
			// "inspect anything" would let a caller enumerate the host's entire
			// service inventory, which is reconnaissance.
			Services: []string{"nginx", "php-fpm", "postgresql", "mariadb", "docker"},
			Network:  "none",
		},
		Timeout:     15 * time.Second,
		AuditAction: "service.inspect",
		Retry:       RetryPolicy{Idempotent: true, MaxAttempts: 2},
		Mutating:    false,
	},

	OpServiceRestart: {
		Operation:   OpServiceRestart,
		Permission:  "server.manage",
		InputSchema: "{unit: string} — target is the unit name",
		Validation:  "unit name must match the unit-name pattern and be in this node's declared scope; the unit must exist before a restart is attempted",
		OSSupport:   []string{"linux"},
		Scope: Scope{
			Services: []string{"nginx", "php-fpm", "postgresql", "mariadb", "docker"},
			Network:  "none",
		},
		// A restart briefly stops serving. The lock key is per-unit so two
		// restarts of the SAME unit serialize while restarts of different units
		// proceed concurrently.
		LockKeys:    []string{"service.restart"},
		Timeout:     60 * time.Second,
		AuditAction: "service.restart",
		// A restart is NOT idempotent in the sense that matters: repeating it
		// drops the service again and interrupts whatever it was serving. It is
		// therefore given no automatic retry, and the descriptor rule refuses
		// the combination outright.
		Retry:    RetryPolicy{Idempotent: false, MaxAttempts: 0},
		Rollback: "none: a restart is its own recovery. If the unit fails to come back, the failure is reported and the previous state is not restorable from here.",
		Mutating: true,
	},

	OpWebConfigValidate: {
		Operation: OpWebConfigValidate,
		// site.read, not site.manage: this operation cannot change what any live
		// site serves, so it belongs with the permissions that let someone LOOK
		// at a site. Requiring a management permission to see whether a config
		// is valid would push the check to the moment of apply, which is exactly
		// where a validation failure is most expensive.
		Permission: "site.read",
		InputSchema: "{config: string, filename: string} — the candidate config text and " +
			"the file name to stage it under; target is the site id",
		Validation: "config must be non-empty, below the size ceiling, and contain no NUL " +
			"byte; filename must be a bare file name (one path segment, no separators, no " +
			"leading dot) so it cannot address a directory; the staged path is resolved " +
			"through the agent's path confinement and refused unless it lands strictly " +
			"inside the staging root",
		OSSupport: []string{"linux"},
		Scope: Scope{
			// The READ scope is the live tree, so the validator can check whether
			// the host actually includes JAWAKER's directory. The WRITE scope is
			// the staging root alone. These are deliberately different roots: an
			// operation whose read and write scope were the same tree could be
			// one edit away from writing what it was only supposed to inspect.
			FilesystemRead:  []string{"/etc/nginx/jawaker", "/etc/nginx/nginx.conf"},
			FilesystemWrite: []string{"/etc/nginx/jawaker/staging"},
			Network:         "none",
		},
		// Longer than a service inspect: a cold nginx -t parses the whole
		// configuration, including included files.
		Timeout:     30 * time.Second,
		AuditAction: "web.config.validate",
		// Idempotent in the sense that matters: re-validating the same text
		// produces the same verdict and the same staged file. Safe to retry.
		Retry: RetryPolicy{Idempotent: true, MaxAttempts: 2},
		// Mutating is TRUE and not an oversight. It writes a candidate file to
		// disk, which is a state change, and marking it false to make the
		// descriptor simpler would be the kind of lie this registry exists to
		// prevent. The rollback below is what makes it safe to call freely.
		Rollback: "the staged candidate file is removed on completion, success or failure. " +
			"The LIVE configuration is never written by this operation, so there is nothing " +
			"to restore: an invalid candidate is discarded and the running site is untouched.",
		Mutating: true,
	},

	OpSiteLogsTail: {
		Operation: OpSiteLogsTail,
		// site.logs.read, not logs.read: D-006 defines this as the
		// project-scoped permission for reading a site's own logs. The
		// server-scoped logs.read is a different authorization boundary and
		// must not be conflated with this one.
		Permission: "site.logs.read",
		InputSchema: "{project_slug: string, site_slug: string, log_type: \"access\"|\"error\", " +
			"lines: int} — caller names the site and log type; the agent derives the " +
			"filesystem path itself using the fixed convention " +
			"/var/log/nginx/<project_slug>--<site_slug>-<log_type>.log",
		Validation: "project_slug and site_slug must match the slug alphabet; log_type must " +
			"be \"access\" or \"error\"; lines must be 0 or between 1 and " +
			"MaxSiteLogsTailLines; the derived path is resolved through the agent's " +
			"path confinement and refused unless it lands strictly inside /var/log/nginx",
		OSSupport: []string{"linux"},
		Scope: Scope{
			FilesystemRead: []string{"/var/log/nginx"},
			Network:        "none",
		},
		// 15 seconds: a large log file read with a bounded buffer is fast on
		// local disk. This is deliberately shorter than a restart and the same
		// order as a service inspect.
		Timeout:     15 * time.Second,
		AuditAction: "site.logs.read",
		// Idempotent: reading the same file tail twice yields the same result
		// (modulo concurrent writes). Safe to retry on a transient failure.
		Retry:    RetryPolicy{Idempotent: true, MaxAttempts: 2},
		Mutating: false,
	},

	OpWebConfigApply: {
		Operation: OpWebConfigApply,
		// site.manage: this changes what a live site serves. Unlike validate
		// (site.read), apply is a management action and requires step-up at
		// the controller's RBAC layer.
		Permission: "site.manage",
		InputSchema: "{config: string, filename: string} — the VALIDATED candidate config " +
			"text and the bare file name it is installed as under sites-enabled; " +
			"target must be \"nginx\"",
		Validation: "config must be non-empty, below MaxWebConfigBytes, and contain no NUL " +
			"byte; filename must be a bare file name (one path segment, no separators, no " +
			"leading dot); the live path is resolved through the agent's path confinement " +
			"and refused unless it lands strictly inside the sites-enabled root; the " +
			"candidate is re-validated with nginx -t against the FULL configuration " +
			"BEFORE the reload, and the previous file is restored on any failure",
		OSSupport: []string{"linux"},
		Scope: Scope{
			// Read covers the live tree and the main config because nginx -t
			// parses the full configuration including every include.
			FilesystemRead:  []string{"/etc/nginx/jawaker/sites-enabled", "/etc/nginx/nginx.conf"},
			FilesystemWrite: []string{"/etc/nginx/jawaker/sites-enabled"},
			// The reload target. Declared so validateTarget enforces that the
			// envelope says exactly which unit gets reloaded — "nginx", never
			// anything else, never empty.
			Services: []string{"nginx"},
			Network:  "none",
		},
		// Per-site serialization: two concurrent applies to one site would race
		// on the backup file. The controller's job lock (site:<id>) is the
		// primary serializer; this is the node-side statement of the same need.
		LockKeys: []string{"web.config.apply"},
		// nginx -t on the full config plus a graceful reload. Longer than
		// validate because the reload waits for worker handoff.
		Timeout:     60 * time.Second,
		AuditAction: "web.config.apply",
		// NOT idempotent: repeating an apply reloads the server again, which
		// interrupts in-flight connections each time. No automatic retry; the
		// job engine's own retry policy (with a fresh validate) is the retry
		// path, not blind repetition here.
		Retry: RetryPolicy{Idempotent: false, MaxAttempts: 0},
		Rollback: "the previous live file is backed up before the candidate is written. " +
			"If nginx -t rejects the full configuration, or the reload fails, the backup " +
			"is restored and nginx is reloaded again, returning the site to the active " +
			"known-good configuration. The backup is removed only after a fully " +
			"successful apply.",
		Mutating: true,
	},

	OpAppDeploy: {
		Operation: OpAppDeploy,
		// deployment.create: this changes what an application serves, creates a
		// release directory on disk, and writes a systemd unit. Controller-side
		// RBAC must confirm the caller is a developer or owner before dispatching.
		Permission: "deployment.create",
		InputSchema: "{app: {project_slug, app_slug, runtime_type, port?, health_path?}, " +
			"git: {repo_url, commit_sha, credential_kind: \"ssh_key\"|\"none\", ssh_key_pem?}, " +
			"build: {program, args[]}, " +
			"start: {program, args[]}, " +
			"env: [{name, value}], " +
			"working_dir}",
		Validation: "commit_sha must be 7..40 lowercase hex; program names must be in the " +
			"runtime allowlist detected at agent startup (e.g. node, npm, bun, python3, pip3); " +
			"args must be non-empty strings without NUL; port must be 1024..65535 or absent; " +
			"env names must match ^[A-Za-z_][A-Za-z0-9_]*$; env values must not contain NUL; " +
			"ssh_key_pem, when present, must be a PEM block and is held in memory only; " +
			"the release directory is resolved through path confinement under " +
			"/var/www/jawaker/<project_slug>/<app_slug>/releases; " +
			"the systemd unit path is confined under /etc/systemd/system; " +
			"no argument is interpreted by a shell",
		OSSupport: []string{"linux"},
		Scope: Scope{
			FilesystemRead: []string{"/var/www/jawaker"},
			FilesystemWrite: []string{
				"/var/www/jawaker",
				"/etc/systemd/system",
			},
			// No Services declared. The agent manages the per-app unit via
			// systemctl with a fixed unit name derived from project+app slug, not
			// via the target mechanism. validateTarget therefore requires Target=""
			// and the dispatcher sends no target.
			Network: "outbound-git",
		},
		LockKeys: []string{"app.deploy"},
		// Git clone/fetch, npm/bun/pip install, daemon-reload, and a health probe
		// can all take substantial time. 15 minutes is generous but bounded.
		Timeout:     15 * 60 * time.Second,
		AuditAction: "app.deploy",
		// NOT idempotent: a re-run creates a new release directory and restarts
		// the service again. No automatic retry; the job engine drives retries
		// at the controller layer after a fresh deploy record.
		Retry: RetryPolicy{Idempotent: false, MaxAttempts: 0},
		Rollback: "a new release directory is created and the 'current' symlink is switched " +
			"atomically only after the build and unit generation succeed. If the health check " +
			"fails after the switch, the symlink is restored to the previous release and the " +
			"service restarted. The failed release directory is left on disk for diagnosis and " +
			"pruned by the next successful deploy. If no previous release exists (first deploy), " +
			"a health failure removes the symlink and marks the deploy as failed.",
		Mutating: true,
	},

	OpDatabaseManage: {
		Operation: OpDatabaseManage,
		// database.manage: creates or drops databases and users. The controller
		// RBAC layer must confirm the caller holds this project-scoped permission
		// and has completed step-up re-authentication before dispatching.
		Permission: "database.manage",
		InputSchema: "{engine: \"postgresql\"|\"mariadb\", db_name: string, " +
			"action: \"create_db\"|\"drop_db\"|\"create_user\"|\"drop_user\"|\"set_grants\", " +
			"username?: string, privileges?: [\"SELECT\"|\"INSERT\"|\"UPDATE\"|\"DELETE\"|\"CREATE\"|\"DROP\"|\"ALL\"], " +
			"socket_path: string}",
		Validation: "engine must be postgresql or mariadb; action must be one of the enumerated values; " +
			"username must match ^[a-z0-9_]{2,32}$ when present; privileges must be a subset of the " +
			"allowlist; socket_path must be a valid unix socket path under /var/run/postgresql or " +
			"/var/run/mysqld; no field may contain a NUL byte; there is no generic SQL execution path",
		OSSupport: []string{"linux"},
		Scope: Scope{
			// Unix sockets only — the agent never opens a TCP connection to the engine.
			FilesystemRead: []string{"/var/run/postgresql", "/var/run/mysqld"},
			// create_db/drop_db/create_user mutate the engine's own data directory
			// through the socket-authenticated admin command; declare it so the scope
			// is honest about what the operation reaches.
			FilesystemWrite: []string{"/var/lib/postgresql", "/var/lib/mysql"},
			Network:         "unix-socket-only",
		},
		// Per-database serialization: two concurrent creates/drops on the same
		// database_id would race. The controller job lock serializes at the
		// controller level; this LockKey is the node-side statement.
		LockKeys:    []string{"database.manage"},
		Timeout:     60 * time.Second,
		AuditAction: "database.manage",
		// create_db and create_user are idempotent (IF NOT EXISTS semantics);
		// drop_db and drop_user are also idempotent (IF EXISTS). set_grants
		// replaces the grant set atomically. MaxAttempts=2 is safe.
		Retry: RetryPolicy{Idempotent: true, MaxAttempts: 2},
		Rollback: "create_db failure leaves no database; create_user failure leaves no user; " +
			"drop_db and drop_user are their own recovery (idempotent). set_grants failure " +
			"leaves the previous grant set in force. No separate rollback step is required.",
		Mutating: true,
	},

	OpDatabaseDump: {
		Operation:  OpDatabaseDump,
		Permission: "database.manage",
		InputSchema: "{engine: \"postgresql\"|\"mariadb\", db_name: string, " +
			"dump_path: string, socket_path: string}",
		Validation: "engine must be postgresql or mariadb; db_name must match ^[a-z0-9_]{2,63}$; " +
			"dump_path must be an absolute path confined strictly inside /var/lib/jawaker/db-dumps/ " +
			"(path traversal refused); socket_path must be under /var/run/postgresql or /var/run/mysqld; " +
			"no field may contain a NUL byte",
		OSSupport: []string{"linux"},
		Scope: Scope{
			FilesystemRead:  []string{"/var/run/postgresql", "/var/run/mysqld"},
			FilesystemWrite: []string{"/var/lib/jawaker/db-dumps"},
			Network:         "unix-socket-only",
		},
		LockKeys:    []string{"database.dump"},
		Timeout:     30 * 60 * time.Second, // large databases may take time
		AuditAction: "database.dump",
		Retry:       RetryPolicy{Idempotent: true, MaxAttempts: 2},
		Rollback: "dump failure leaves a partial file which the agent removes before returning the " +
			"error, so the caller never sees a partial artifact. The source database is untouched.",
		Mutating: true, // writes a file to disk
	},

	OpDatabaseRestore: {
		Operation:  OpDatabaseRestore,
		Permission: "database.manage",
		InputSchema: "{engine: \"postgresql\"|\"mariadb\", db_name: string, " +
			"dump_path: string, socket_path: string}",
		Validation: "engine must be postgresql or mariadb; db_name must match ^[a-z0-9_]{2,63}$; " +
			"dump_path must already exist and be confined inside /var/lib/jawaker/db-dumps/; " +
			"socket_path must be under /var/run/postgresql or /var/run/mysqld; " +
			"no field may contain a NUL byte",
		OSSupport: []string{"linux"},
		Scope: Scope{
			FilesystemRead: []string{"/var/lib/jawaker/db-dumps", "/var/run/postgresql", "/var/run/mysqld"},
			// pg_restore --clean --if-exists and the mariadb client rewrite the
			// target database's contents through the engine; the engine writes its
			// own data directory. Declared so the scope is honest.
			FilesystemWrite: []string{"/var/lib/postgresql", "/var/lib/mysql"},
			Network:         "unix-socket-only",
		},
		LockKeys:    []string{"database.restore"},
		Timeout:     30 * 60 * time.Second,
		AuditAction: "database.restore",
		// Idempotent: applying the same dump file twice leaves the same database state
		// because pg_restore uses --clean --if-exists and mariadb recreates from scratch.
		Retry: RetryPolicy{Idempotent: true, MaxAttempts: 1},
		Rollback: "restore failure leaves the database in an indeterminate state. The caller " +
			"must create the database fresh and retry the restore, or recover from a different " +
			"backup. The dump file is NOT removed on failure (the caller decides retention).",
		Mutating: true,
	},

	OpDatabaseMetrics: {
		Operation:   OpDatabaseMetrics,
		Permission:  "database.read",
		InputSchema: "{engine: \"postgresql\"|\"mariadb\", socket_path: string}",
		Validation: "engine must be postgresql or mariadb; socket_path must be under " +
			"/var/run/postgresql or /var/run/mysqld; no field may contain a NUL byte",
		OSSupport: []string{"linux"},
		Scope: Scope{
			FilesystemRead: []string{"/var/run/postgresql", "/var/run/mysqld"},
			Network:        "unix-socket-only",
		},
		// No LockKeys: read-only; multiple concurrent metric polls are safe.
		Timeout:     15 * time.Second,
		AuditAction: "database.metrics.read",
		Retry:       RetryPolicy{Idempotent: true, MaxAttempts: 2},
		Mutating:    false,
	},

	OpDatabaseUpgrade: {
		Operation:  OpDatabaseUpgrade,
		Permission: "database.manage",
		InputSchema: "{engine: \"postgresql\"|\"mariadb\", from_version: string, to_version: string, " +
			"pre_dump_path: string, socket_path: string}",
		Validation: "engine must be postgresql or mariadb; from_version and to_version must be " +
			"non-empty strings matching the engine's version format; pre_dump_path must be non-empty " +
			"and confined inside /var/lib/jawaker/db-dumps/ — an empty pre_dump_path is refused to " +
			"prevent upgrade without a safety checkpoint; socket_path must be under " +
			"/var/run/postgresql or /var/run/mysqld",
		OSSupport: []string{"linux"},
		Scope: Scope{
			FilesystemRead:  []string{"/var/lib/jawaker/db-dumps", "/var/run/postgresql", "/var/run/mysqld"},
			FilesystemWrite: []string{"/var/lib/jawaker/db-dumps"},
			Network:         "unix-socket-only",
		},
		LockKeys:    []string{"database.upgrade"},
		Timeout:     60 * 60 * time.Second, // pg_upgrade on a large cluster can take tens of minutes
		AuditAction: "database.upgrade",
		Retry:       RetryPolicy{Idempotent: false, MaxAttempts: 0},
		Rollback: "if the upgrade binary fails, the agent restores from the pre_dump_path (a full " +
			"database restore) and returns RolledBack=true. The pre_dump_path is retained after " +
			"rollback so the operator can inspect it. A successful upgrade removes nothing — " +
			"old data directories are left for the operator to remove once satisfied.",
		Mutating: true,
	},
}

// Lookup returns the descriptor for an operation. The second result is false for
// any name not in the registry, which is what makes an unknown operation
// unrepresentable rather than merely rejected.
func Lookup(op Operation) (Descriptor, bool) {
	d, ok := Operations[op]
	return d, ok
}

// Names returns every registered operation name, sorted.
//
// Sorted rather than map-ordered so logs, diagnostics and tests are stable: an
// unsorted listing makes a diff of two runs show spurious differences.
func Names() []Operation {
	out := make([]Operation, 0, len(Operations))
	for op := range Operations {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Served is the set of operations a given build implements. It mirrors the
// registry for now; keeping it a separate value means a build that omits an
// operation (a minimal agent, say) has somewhere to say so without editing the
// protocol.
func Served() map[Operation]bool {
	out := make(map[Operation]bool, len(Operations))
	for op := range Operations {
		out[op] = true
	}
	return out
}

// ValidateRegistry checks every descriptor is complete.
//
// It is called by a test rather than at init: a panic in an init function takes
// down a process for a programming error that a test can report far more
// usefully, and a node agent crashing on startup because of one malformed
// descriptor would be worse than refusing to serve that one operation.
func ValidateRegistry() error {
	var errs []error
	for name, desc := range Operations {
		if name != desc.Operation {
			errs = append(errs, fmt.Errorf("registry key %q does not match descriptor operation %q", name, desc.Operation))
		}
		if err := desc.validate(); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
		// A mutating operation with no rollback statement is a gap: SECURITY.md
		// §7 requires recovery behavior to be declared, and "we did not think
		// about it" must not be expressible as an empty string.
		if desc.Mutating && desc.Rollback == "" {
			errs = append(errs, fmt.Errorf("%s: a mutating operation must declare its rollback behavior", name))
		}
	}
	return errors.Join(errs...)
}

// --- operation payloads -------------------------------------------------------

// Capability states. A node reports what it can ACTUALLY do, which is not the
// same as what is installed: a package present but unusable is "degraded", and
// something recognized but not serviceable here is "unsupported".
const (
	CapabilityAvailable   = "available"
	CapabilityDegraded    = "degraded"
	CapabilityUnsupported = "unsupported"
)

// Capability is one detected capability.
type Capability struct {
	// Kind buckets the capability, e.g. "os", "init", "service".
	Kind string `json:"kind"`
	// Name is the specific capability, e.g. "systemd", "nginx".
	Name string `json:"name"`
	// Version is the detected version, empty when not applicable.
	Version string `json:"version,omitempty"`
	// State is one of the Capability* constants.
	State string `json:"state"`
	// Detail carries non-secret evidence for the state: a resolved path, a
	// reason for degradation. It must never contain credentials.
	Detail map[string]any `json:"detail,omitempty"`
}

// CapabilitiesResult is the reply to node.capabilities.
type CapabilitiesResult struct {
	// OSFamily and OSVersion are the detected host identity. They are reported
	// as observed, not as certified: certification is a separate claim that this
	// build does not make (see the Phase 2 plan, Q3).
	OSFamily  string `json:"os_family"`
	OSVersion string `json:"os_version"`
	// Kernel is the reported kernel version.
	Kernel string `json:"kernel,omitempty"`
	// Architecture is the reported machine architecture.
	Architecture string `json:"architecture,omitempty"`
	// AgentVersion is this agent's own build version.
	AgentVersion string `json:"agent_version"`
	// Capabilities is the full inventory.
	Capabilities []Capability `json:"capabilities"`
	// ObservedAt is when the scan ran.
	ObservedAt time.Time `json:"observed_at"`
}

// HeartbeatInput is the payload the agent sends with a heartbeat.
type HeartbeatInput struct {
	// ObservedAt is when the NODE took these readings. Kept distinct from the
	// controller's receipt time because clock skew is a real operational fact
	// and collapsing the two would hide the evidence for it.
	ObservedAt time.Time `json:"observed_at"`
	// UptimeSeconds is the host uptime.
	UptimeSeconds int64 `json:"uptime_seconds"`
	// Load1Milli is the 1-minute load average scaled by 1000, so the value stays
	// an integer and needs no rounding decision in the application.
	Load1Milli int64 `json:"load1_milli"`
	// MemTotalBytes and MemUsedBytes are host memory figures.
	MemTotalBytes int64 `json:"mem_total_bytes"`
	MemUsedBytes  int64 `json:"mem_used_bytes"`
	// WorkloadCount is how many workloads the agent is responsible for. The
	// "node survives a controller outage" gate is about these staying untouched,
	// so the number travels with every observation and a change is visible.
	WorkloadCount int `json:"workload_count"`
}

// Validate refuses impossible readings rather than clamping them.
//
// Clamping would turn a bug in the collector into plausible-looking numbers in
// the time series, and a time series that quietly lies is worse than one with a
// gap.
func (h HeartbeatInput) Validate() error {
	var errs []error
	if h.ObservedAt.IsZero() {
		errs = append(errs, errors.New("observed_at is required"))
	}
	if h.UptimeSeconds < 0 {
		errs = append(errs, fmt.Errorf("uptime_seconds is negative (%d)", h.UptimeSeconds))
	}
	if h.Load1Milli < 0 {
		errs = append(errs, fmt.Errorf("load1_milli is negative (%d)", h.Load1Milli))
	}
	if h.MemTotalBytes < 0 || h.MemUsedBytes < 0 {
		errs = append(errs, errors.New("memory figures cannot be negative"))
	}
	if h.MemTotalBytes > 0 && h.MemUsedBytes > h.MemTotalBytes {
		errs = append(errs, fmt.Errorf("mem_used_bytes (%d) exceeds mem_total_bytes (%d)",
			h.MemUsedBytes, h.MemTotalBytes))
	}
	if h.WorkloadCount < 0 {
		errs = append(errs, fmt.Errorf("workload_count is negative (%d)", h.WorkloadCount))
	}
	return errors.Join(errs...)
}

// HeartbeatPath is the controller endpoint a heartbeat is posted to.
//
// It is a controller route rather than a registered Operation, and the reason is
// the DIRECTION: for every operation the controller is the client and the node
// answers, whereas a heartbeat is the node calling the controller. Reusing the
// operation envelope would give one direction of traffic two shapes, and one of
// them would eventually be forgotten.
//
// It is defined here, beside the payload, so the agent's client and the
// controller's handler cannot disagree about the URL.
const HeartbeatPath = "/api/v1/node/heartbeat"

// HeartbeatPayload is what a heartbeat carries.
type HeartbeatPayload struct {
	// ServerID is the node's own claim about which server it is. The controller
	// treats it as a claim and not as identity: what identifies the peer is the
	// certificate, and a body field is what the peer chose to say.
	ServerID string `json:"server_id"`
	// Reported is the reading itself, validated by the same rules on both ends.
	Reported HeartbeatInput `json:"report"`
	// AgentVersion is sent on every beat so a controller that never received the
	// enrollment facts still learns which build a node runs.
	AgentVersion string `json:"agent_version"`
}

// Validate checks a heartbeat payload at either end.
//
// It is the SAME validator the controller applies, so an impossible reading is
// refused in one place with one message rather than accepted here and rejected
// there — which would produce a time series whose shape depends on which end
// happened to parse it.
func (h HeartbeatPayload) Validate() error {
	var errs []error
	if h.ServerID == "" {
		errs = append(errs, errors.New("server_id is required"))
	}
	if err := h.Reported.Validate(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// ServiceState is the observed state of one unit.
//
// Per OBSERVABILITY.md §10, a service can be RUNNING yet DEGRADED. A single
// boolean would force one of those to be lost.
type ServiceState struct {
	// Unit is the unit name.
	Unit string `json:"unit"`
	// LoadState is systemd's LoadState: "loaded", "not-found", "masked".
	LoadState string `json:"load_state"`
	// ActiveState is systemd's ActiveState: "active", "inactive", "failed".
	ActiveState string `json:"active_state"`
	// SubState is systemd's SubState: "running", "dead", "exited".
	SubState string `json:"sub_state"`
	// Description is the unit's description, useful in a UI.
	Description string `json:"description,omitempty"`
	// MainPID is the unit's main process id, 0 when not running.
	MainPID int `json:"main_pid"`
	// ObservedAt is when the state was read.
	ObservedAt time.Time `json:"observed_at"`
}

// Running reports whether the unit's main process is up.
func (s ServiceState) Running() bool {
	return s.ActiveState == "active" && s.SubState == "running"
}

// Healthy reports whether the unit is in the state a restart is meant to
// produce. A unit that is active but "exited" (a oneshot) is not unhealthy; a
// failed unit is.
func (s ServiceState) Healthy() bool {
	return s.LoadState == "loaded" && s.ActiveState != "failed"
}

// ServiceInspectInput is the payload for service.inspect.
type ServiceInspectInput struct {
	// Unit mirrors the envelope target. It is duplicated so a stored payload is
	// self-describing, and the two must agree — a mismatch is refused rather
	// than resolved, because resolving it would mean one of two stated intents
	// is silently discarded.
	Unit string `json:"unit"`
}

// ValidateInspectInput checks the payload against the envelope target.
func ValidateInspectInput(in ServiceInspectInput, target string) error {
	if in.Unit == "" {
		return fmt.Errorf("%w: unit is required", ErrInvalidInput)
	}
	if target != "" && in.Unit != target {
		return fmt.Errorf("%w: unit %q does not match target %q", ErrInvalidInput, in.Unit, target)
	}
	if !ValidServiceName(in.Unit) {
		return fmt.Errorf("%w: unit %q is not a valid unit name", ErrInvalidInput, in.Unit)
	}
	return nil
}

// ServiceRestartInput is the payload for service.restart.
type ServiceRestartInput struct {
	// Unit mirrors the envelope target, for the same reason as above.
	Unit string `json:"unit"`
}

// ValidateRestartInput checks the restart payload against the envelope target.
func ValidateRestartInput(in ServiceRestartInput, target string) error {
	if in.Unit == "" {
		return fmt.Errorf("%w: unit is required", ErrInvalidInput)
	}
	if target != "" && in.Unit != target {
		return fmt.Errorf("%w: unit %q does not match target %q", ErrInvalidInput, in.Unit, target)
	}
	if !ValidServiceName(in.Unit) {
		return fmt.Errorf("%w: unit %q is not a valid unit name", ErrInvalidInput, in.Unit)
	}
	return nil
}

// RestartResult is the reply to service.restart.
type RestartResult struct {
	// Before and After bracket the change, so a caller can prove the restart
	// happened rather than assume it.
	Before ServiceState `json:"before"`
	After  ServiceState `json:"after"`
}

// --- web.config.validate ------------------------------------------------------

// MaxWebConfigBytes bounds the candidate configuration text.
//
// Exported because it is part of the protocol contract, not an implementation
// detail: the controller must respect it before spending a round trip on a
// candidate that cannot be sent, and the agent enforces it on receipt. Two
// copies of the number would be two things that can drift.
//
// The envelope cap is 64 KiB (maxInputBytes), but a config is TEXT and JSON
// escaping inflates text: every newline becomes two characters, and a config
// dense with quotes or backslashes can nearly double in size on the way into the
// envelope. Setting the ceiling at the envelope cap would mean a configuration
// that passes this check and then fails to encode — a refusal that arrives as a
// transport error rather than as a validation verdict the operator can act on.
//
// Sixteen KiB is roughly four times a real nginx site block, so this is not a
// practical limit; it exists so the failure mode is a clear "too large" rather
// than an inexplicable protocol error.
const MaxWebConfigBytes = 16 * 1024

// WebConfigValidateInput is the payload for web.config.validate.
//
// The configuration travels as TEXT, never as a command. There is no field here
// that could carry something to execute: what the node runs is nginx with -t and
// a path the agent derived itself, and the caller has no way to influence either.
// That is the difference between this and a generic execution primitive, and it is
// why a field called Config is safe where a field called Command would not be.
type WebConfigValidateInput struct {
	// Config is the candidate configuration text.
	Config string `json:"config"`
	// Filename is the bare file name to stage the candidate under. It is NOT a
	// path: a caller that could choose the destination directory could write
	// outside the staging root, which is why the name is constrained to a single
	// segment and the directory is chosen by the agent.
	Filename string `json:"filename"`
}

// Validate checks the payload. The filename rules are load-bearing rather than
// cosmetic: this value becomes part of a filesystem path, and every way of making
// it address something other than one new file in the staging directory is refused
// here, in addition to the confinement check the agent applies when it resolves
// the resulting path.
func (in WebConfigValidateInput) Validate() error {
	return validateConfigAndFilename(in.Config, in.Filename)
}

// validateConfigAndFilename holds the rules shared by the validate and apply
// payloads: both carry a config text and a bare file name that becomes part of a
// filesystem path. One definition, so the two operations cannot drift on what a
// safe file name is.
func validateConfigAndFilename(config, filename string) error {
	var errs []error

	if config == "" {
		errs = append(errs, errors.New("config is required"))
	}
	if len(config) > MaxWebConfigBytes {
		errs = append(errs, fmt.Errorf("config is %d bytes, limit is %d", len(config), MaxWebConfigBytes))
	}
	// A NUL byte in the text would truncate the file as seen by the syscall
	// layer, so what is staged would not be what was validated.
	if strings.ContainsRune(config, 0) {
		errs = append(errs, errors.New("config contains a NUL byte"))
	}

	switch {
	case filename == "":
		errs = append(errs, errors.New("filename is required"))
	case strings.ContainsRune(filename, 0):
		errs = append(errs, errors.New("filename contains a NUL byte"))
	case filename != filepath.Base(filename):
		// Covers every separator and the traversal shapes "." and "..": if the
		// value is not its own base name, it was naming something other than a
		// single file in a single directory.
		errs = append(errs, fmt.Errorf("filename %q is not a bare file name", filename))
	case strings.HasPrefix(filename, "."):
		// A dot-prefixed name is a hidden file, which on a config tree means a
		// file an operator is not going to find. It also covers "." and ".."
		// explicitly, which the base-name check above would already have caught.
		errs = append(errs, fmt.Errorf("filename %q must not begin with a dot", filename))
	case !validWebConfigFilename.MatchString(filename):
		errs = append(errs, fmt.Errorf("filename %q contains a character outside [a-zA-Z0-9._-]", filename))
	}

	return errors.Join(errs...)
}

// validWebConfigFilename is an allowlist for the staged file name.
//
// An allowlist rather than a blocklist because the value ends up in a path passed
// to a privileged program and written to a directory the operator reads. A
// blocklist invites the next bypass to be discovered by someone else.
var validWebConfigFilename = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// WebConfigValidateResult is the reply to web.config.validate.
//
// Valid is the verdict, and Output is the evidence for it. The distinction
// matters: an operator deciding whether to apply a configuration needs to know
// WHAT nginx said, not merely that it said no. PRD.md §41 requires a useful error
// to carry the validation output, and a bare boolean cannot satisfy that.
type WebConfigValidateResult struct {
	// Valid reports whether the web server accepted the candidate.
	Valid bool `json:"valid"`
	// Output is the web server's own report, bounded. It is truncated rather
	// than dropped when long, and Truncated says so.
	Output string `json:"output"`
	// Truncated reports that Output was cut short to fit the wire. Stating it is
	// what keeps a truncated verdict from looking like a complete one.
	Truncated bool `json:"truncated,omitempty"`
	// Tool is the program that produced the verdict, e.g. "nginx". Recorded so a
	// host with an unexpected web server is visible in the reply rather than
	// inferred from the output's shape.
	Tool string `json:"tool"`
	// ToolVersion is the detected version of that tool.
	ToolVersion string `json:"tool_version,omitempty"`
	// Staged is the path the candidate was written to and then removed. Exposed
	// so the controller's audit trail and a human reader can see exactly which
	// file was involved; the value is agent-derived and never caller-chosen.
	Staged string `json:"staged"`
	// ObservedAt is when the check ran, on the NODE's clock. Kept distinct from
	// receipt time for the same reason a heartbeat does it.
	ObservedAt time.Time `json:"observed_at"`
}

// --- site.logs.tail -----------------------------------------------------------

// MaxSiteLogsTailLines bounds how many log lines a single request may ask for.
// A client asking for more gets clamped or refused; unbounded lines is a DoS
// primitive against the node agent and control plane.
const MaxSiteLogsTailLines = 500

// DefaultSiteLogsTailLines is the line count when none is specified.
const DefaultSiteLogsTailLines = 100

// MaxSiteLogsTailBytes bounds what the agent will read and return over the wire.
// It is smaller than maxInputBytes (64 KiB) to leave plenty of envelope headroom.
const MaxSiteLogsTailBytes = 48 * 1024

// LogTypeAccess and LogTypeError are the allowed log types.
const (
	LogTypeAccess = "access"
	LogTypeError  = "error"
)

// SiteLogsTailInput is the payload for site.logs.tail.
//
// The caller identifies the site by its project slug and site slug, and specifies
// which log to read. The node agent constructs the path itself using the canonical
// layout `/var/log/nginx/<project_slug>--<site_slug>-<log_type>.log`. The caller
// has no way to choose a directory or an arbitrary file name, closing the path
// traversal attack surface before confinement even runs.
type SiteLogsTailInput struct {
	// ProjectSlug is the site's parent project slug.
	ProjectSlug string `json:"project_slug"`
	// SiteSlug is the site's slug within that project.
	SiteSlug string `json:"site_slug"`
	// LogType is either "access" or "error".
	LogType string `json:"log_type"`
	// Lines is how many trailing lines to return. 0 means DefaultSiteLogsTailLines.
	// Clamped to MaxSiteLogsTailLines.
	Lines int `json:"lines,omitempty"`
}

// Validate checks the payload before it reaches the executor.
func (in SiteLogsTailInput) Validate() error {
	var errs []error
	if in.ProjectSlug == "" {
		errs = append(errs, errors.New("project_slug is required"))
	} else if !validSlugPattern.MatchString(in.ProjectSlug) {
		errs = append(errs, fmt.Errorf("project_slug %q is not a valid slug", in.ProjectSlug))
	}

	if in.SiteSlug == "" {
		errs = append(errs, errors.New("site_slug is required"))
	} else if !validSlugPattern.MatchString(in.SiteSlug) {
		errs = append(errs, fmt.Errorf("site_slug %q is not a valid slug", in.SiteSlug))
	}

	switch in.LogType {
	case LogTypeAccess, LogTypeError:
	case "":
		errs = append(errs, errors.New("log_type is required"))
	default:
		errs = append(errs, fmt.Errorf("log_type %q must be \"access\" or \"error\"", in.LogType))
	}

	if in.Lines < 0 {
		errs = append(errs, errors.New("lines cannot be negative"))
	} else if in.Lines > MaxSiteLogsTailLines {
		errs = append(errs, fmt.Errorf("lines (%d) exceeds the maximum of %d", in.Lines, MaxSiteLogsTailLines))
	}

	return errors.Join(errs...)
}

// validSlugPattern matches a safe slug: lowercase alphanumerics with optional internal hyphens.
var validSlugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// SiteLogsTailResult is the reply to site.logs.tail.
//
// D-005: Site logs are read from the node on demand and never stored in PostgreSQL.
// Lines are returned as an array of strings in chronological order.
type SiteLogsTailResult struct {
	// Lines holds the tail log entries.
	Lines []string `json:"lines"`
	// Truncated reports whether lines were dropped because the total size
	// exceeded MaxSiteLogsTailBytes or the requested line count was hit.
	Truncated bool `json:"truncated,omitempty"`
	// LogType echoes the requested log type.
	LogType string `json:"log_type"`
	// ObservedAt is when the file was read, on the NODE's clock.
	ObservedAt time.Time `json:"observed_at"`
}

// --- web.config.apply ---------------------------------------------------------

// WebConfigApplyInput is the payload for web.config.apply.
//
// The shape is intentionally identical to WebConfigValidateInput: the candidate
// is validated on the controller side before this operation is called, and the
// input travels unchanged from the controller's job payload to the node. Having
// two distinct types rather than one shared one avoids collapsing two different
// operations into one type, which would make the validate/apply distinction
// invisible to a reader of the descriptor or the agent.
type WebConfigApplyInput struct {
	// Config is the candidate configuration text, already validated.
	Config string `json:"config"`
	// Filename is the bare file name to install the config as under sites-enabled.
	Filename string `json:"filename"`
}

// Validate checks the payload. The same rules as WebConfigValidateInput.
func (in WebConfigApplyInput) Validate() error {
	return validateConfigAndFilename(in.Config, in.Filename)
}

// WebConfigApplyResult is the reply to web.config.apply.
//
// Both Applied and RolledBack can be false: if the full-config nginx -t passes
// but the reload fails after a restore attempt, neither flag is set and the node
// reports execution_failed. That signals the controller to investigate rather
// than assume the site is healthy.
type WebConfigApplyResult struct {
	// Applied reports whether the candidate is now live.
	Applied bool `json:"applied"`
	// RolledBack reports whether a failure was caught and the backup restored,
	// leaving the previous known-good config in force. It is mutually exclusive
	// with Applied.
	RolledBack bool `json:"rolled_back,omitempty"`
	// Output is the nginx -t output on the full configuration, whether or not the
	// apply succeeded.
	Output string `json:"output,omitempty"`
	// Truncated reports that Output was cut short to fit the wire.
	Truncated bool `json:"truncated,omitempty"`
	// Tool names the web server program that ran the verification.
	Tool string `json:"tool"`
	// ToolVersion is the detected version.
	ToolVersion string `json:"tool_version,omitempty"`
	// LivePath is the path the config was written to (or restored to, if rolled
	// back). Exposed so the audit trail and a human reader can see exactly which
	// file was involved; the value is agent-derived and never caller-chosen.
	LivePath string `json:"live_path"`
	// BackupPath is where the previous config was backed up before the write. It
	// is the same directory as LivePath and is removed on success.
	BackupPath string `json:"backup_path,omitempty"`
	// ObservedAt is when the operation completed, on the NODE's clock.
	ObservedAt time.Time `json:"observed_at"`
}

// --- app.deploy ---------------------------------------------------------------

// AppSpec identifies the application on the node.
type AppSpec struct {
	ProjectSlug string `json:"project_slug"`
	AppSlug     string `json:"app_slug"`
	RuntimeType string `json:"runtime_type"`
	Port        *int   `json:"port,omitempty"`
	HealthPath  string `json:"health_path,omitempty"`
}

// GitSpec identifies the source repository and credentials.
type GitSpec struct {
	RepoURL        string `json:"repo_url"`
	CommitSHA      string `json:"commit_sha"`
	CredentialKind string `json:"credential_kind"` // "ssh_key" or "none"
	// SSHKeyPEM is the raw PEM-encoded private key held ONLY in memory.
	// It is written to a 0600 temp file for the git subprocess and immediately deleted.
	SSHKeyPEM string `json:"ssh_key_pem,omitempty"`
}

// CommandSpecWire specifies an allowlisted program and its argv slice.
type CommandSpecWire struct {
	Program string   `json:"program"`
	Args    []string `json:"args"`
}

// EnvEntryWire is a single environment variable key-value pair.
type EnvEntryWire struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// AppDeployInput is the payload for app.deploy.
type AppDeployInput struct {
	App        AppSpec         `json:"app"`
	Git        GitSpec         `json:"git"`
	Build      CommandSpecWire `json:"build"`
	Start      CommandSpecWire `json:"start"`
	Env        []EnvEntryWire  `json:"env,omitempty"`
	WorkingDir string          `json:"working_dir,omitempty"`
}

// AppDeployResult is the reply to app.deploy.
type AppDeployResult struct {
	Deployed       bool      `json:"deployed"`
	CommitSHA      string    `json:"commit_sha"`
	ReleasePath    string    `json:"release_path"`
	CurrentPath    string    `json:"current_path"`
	BuildOutput    string    `json:"build_output,omitempty"`
	BuildTruncated bool      `json:"build_truncated,omitempty"`
	HealthState    string    `json:"health_state"`
	RolledBack     bool      `json:"rolled_back,omitempty"`
	RollbackReason string    `json:"rollback_reason,omitempty"`
	ObservedAt     time.Time `json:"observed_at"`
}

// commitSHARegex matches full (40-char) or short (7..39-char) lowercase hex SHAs.
var commitSHARegex = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// envWireNameRE mirrors the schema check: ^[A-Za-z_][A-Za-z0-9_]*$
var envWireNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Validate checks the deployment input before execution.
func (in AppDeployInput) Validate() error {
	var errs []error

	if in.App.ProjectSlug == "" {
		errs = append(errs, errors.New("app.project_slug is required"))
	} else if !validSlugPattern.MatchString(in.App.ProjectSlug) {
		errs = append(errs, fmt.Errorf("app.project_slug %q is not a valid slug", in.App.ProjectSlug))
	}

	if in.App.AppSlug == "" {
		errs = append(errs, errors.New("app.app_slug is required"))
	} else if !validSlugPattern.MatchString(in.App.AppSlug) {
		errs = append(errs, fmt.Errorf("app.app_slug %q is not a valid slug", in.App.AppSlug))
	}

	switch in.App.RuntimeType {
	case "node", "bun", "python", "php", "static":
	default:
		errs = append(errs, fmt.Errorf("app.runtime_type %q is not supported", in.App.RuntimeType))
	}

	if in.App.Port != nil && (*in.App.Port < 1024 || *in.App.Port > 65535) {
		errs = append(errs, fmt.Errorf("app.port %d is out of range 1024..65535", *in.App.Port))
	}

	if in.Git.RepoURL == "" {
		errs = append(errs, errors.New("git.repo_url is required"))
	}

	if in.Git.CommitSHA == "" {
		errs = append(errs, errors.New("git.commit_sha is required"))
	} else if !commitSHARegex.MatchString(in.Git.CommitSHA) {
		errs = append(errs, fmt.Errorf("git.commit_sha %q must be 7..40 hex characters", in.Git.CommitSHA))
	}

	switch in.Git.CredentialKind {
	case "none", "ssh_key", "":
	default:
		errs = append(errs, fmt.Errorf("git.credential_kind %q must be 'none' or 'ssh_key'", in.Git.CredentialKind))
	}

	// Build program can be empty (static apps or apps that need no build step)
	if in.Build.Program != "" {
		if strings.ContainsRune(in.Build.Program, 0) {
			errs = append(errs, errors.New("build.program contains a NUL byte"))
		}
		for _, arg := range in.Build.Args {
			if strings.ContainsRune(arg, 0) {
				errs = append(errs, errors.New("build.args contains a NUL byte"))
				break
			}
		}
	}

	// Start program is required for non-static apps
	if in.App.RuntimeType != "static" && in.Start.Program == "" {
		errs = append(errs, errors.New("start.program is required for non-static runtime"))
	}
	if in.Start.Program != "" {
		if strings.ContainsRune(in.Start.Program, 0) {
			errs = append(errs, errors.New("start.program contains a NUL byte"))
		}
		for _, arg := range in.Start.Args {
			if strings.ContainsRune(arg, 0) {
				errs = append(errs, errors.New("start.args contains a NUL byte"))
				break
			}
		}
	}

	for _, e := range in.Env {
		if !envWireNameRE.MatchString(e.Name) {
			errs = append(errs, fmt.Errorf("env var name %q must match ^[A-Za-z_][A-Za-z0-9_]*$", e.Name))
		}
		if strings.ContainsRune(e.Value, 0) {
			errs = append(errs, fmt.Errorf("env var %q value contains a NUL byte", e.Name))
		}
	}

	return errors.Join(errs...)
}
