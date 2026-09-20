package nodewire

import (
	"errors"
	"fmt"
	"sort"
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
