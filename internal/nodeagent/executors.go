package nodeagent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// The operation executors: the only code in JAWAKER that acts on a managed host.
//
// Two rules hold throughout this file.
//
// FIRST, an executor returns a nodewire error code for every foreseeable refusal,
// never a bare Go error. The controller branches on those codes, and a refusal
// that arrives as an opaque internal error is indistinguishable from the agent
// being broken — which is exactly how "unsupported" becomes "the panel is lying".
//
// SECOND, nothing pretends. If systemd is absent the node reports
// service.restart as unsupported and REFUSES it, rather than falling back to
// something that looks similar. A capability claim the node cannot honor is
// worse than an honest gap, because the operator acts on it.

// systemdBinary is resolved at startup. The candidate list is fixed and is not
// derived from PATH — see resolveProgram for why.
var systemdCandidates = []string{"/usr/bin/systemctl", "/bin/systemctl", "/usr/sbin/systemctl"}

// Executors holds what the agent can actually do, decided once at startup.
//
// Detection happens at construction rather than per request so that a capability
// report and an operation refusal can never disagree: both read the same field.
type Executors struct {
	// agentVersion is this build's version, reported in capabilities.
	agentVersion string
	// systemctlPath is the resolved systemctl, empty when absent.
	systemctlPath string
	// hasSystemd reports whether systemd is the running init.
	hasSystemd bool
	// now supplies the clock.
	now func() time.Time
	// workloadCount reports how many workloads this agent is responsible for.
	workloadCount func() int
	// spawns counts every privileged process this node started. It exists so the
	// outage gate can assert "nothing was started" as a number rather than as the
	// absence of an error: an agent that took an action during a controller outage
	// is the failure the whole design exists to prevent.
	spawns atomic.Int64
	// webServer is the detected web server and staging directory, resolved once
	// at startup for the same reason the systemd path is: the capability report
	// and the refusal of web.config.validate must not disagree.
	webServer WebServer
}

// ExecutorOptions configures detection.
type ExecutorOptions struct {
	AgentVersion string
	Now          func() time.Time
	// WorkloadCount supplies the heartbeat's workload figure. Nil means zero,
	// which in Phase 2 is the truth: the agent manages no workloads yet.
	WorkloadCount func() int
	// SystemctlPath overrides detection, for tests.
	SystemctlPath string
	// NginxPath overrides web-server detection, for tests.
	NginxPath string
	// StagingDir overrides where candidates are staged, for tests. It must
	// already exist; detection reports the web server as unavailable otherwise.
	StagingDir string
}

// NewExecutors detects what this node can do.
func NewExecutors(opts ExecutorOptions) *Executors {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	e := &Executors{
		agentVersion:  opts.AgentVersion,
		now:           now,
		workloadCount: opts.WorkloadCount,
	}
	// Web-server detection happens here, BEFORE the systemd branch, because a
	// host may well have nginx and no systemd. Detecting it after the early
	// returns would make the web capability silently depend on an unrelated one.
	e.webServer = detectWebServer(opts.NginxPath, opts.StagingDir)

	path := opts.SystemctlPath
	if path == "" {
		var found bool
		path, found = resolveProgram(systemdCandidates...)
		if !found {
			return e
		}
	}
	// The binary existing is not enough: systemd must be the running init, or
	// systemctl will fail at request time with a message about D-Bus. Checking
	// here means the capability report says "unsupported" up front instead of
	// the operator learning it from a failed restart.
	if !systemdRunning() {
		return e
	}
	e.systemctlPath = path
	e.hasSystemd = true
	return e
}

// SystemctlPath reports the resolved binary, empty when systemd is unavailable.
func (e *Executors) SystemctlPath() string { return e.systemctlPath }

// WebServer reports the detected web server and its staging directory. It is
// derived from the same detection the capability report reads, so an operation
// and the inventory cannot disagree about whether this host can validate a
// configuration.
func (e *Executors) WebServer() WebServer { return e.webServer }

// Spawns reports how many privileged commands this node has started. The outage
// gate asserts this stays zero while the controller is unreachable, so "the agent
// did nothing on its own" is a number rather than an assumption.
func (e *Executors) Spawns() int64 { return e.spawns.Load() }

// systemdRunning reports whether systemd is the running init.
//
// /run/systemd/system is the check systemd itself documents for this question:
// it exists exactly while systemd is up, and its absence on a container or a
// sysvinit host is the distinction that matters. Checking for the binary instead
// would report systemd on a container that has the client installed but no init.
func systemdRunning() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	info, err := os.Stat("/run/systemd/system")
	return err == nil && info.IsDir()
}

// supportedOS reports whether this build may perform mutating operations.
//
// Only Linux is supported, and that is a statement about the code rather than
// about ambition: the process-group supervision in this package uses POSIX
// process groups, and the service backend is systemd. A non-Linux build refuses
// mutating work instead of performing it with weaker guarantees.
func supportedOS() bool { return runtime.GOOS == "linux" }

// --- node.capabilities --------------------------------------------------------

// Capabilities reports what this node can actually do, right now.
func (e *Executors) Capabilities() (nodewire.CapabilitiesResult, error) {
	osFamily, osVersion, kernel, arch := detectOS()
	caps := []nodewire.Capability{
		{
			Kind: "os", Name: osFamily, Version: osVersion, State: nodewire.CapabilityAvailable,
		},
	}

	// systemd: available only when it is BOTH installed and running.
	if e.hasSystemd {
		caps = append(caps, nodewire.Capability{
			Kind: "init", Name: "systemd", State: nodewire.CapabilityAvailable,
			Detail: map[string]any{"systemctl": e.systemctlPath},
		})
	} else {
		// Degraded vs unsupported: systemd is RECOGNIZED as the service backend
		// this agent understands, but it is not usable here. That is
		// "unsupported", and service.* operations are refused to match.
		reason := "systemd is not the running init on this host"
		if runtime.GOOS != "linux" {
			reason = fmt.Sprintf("the node agent supports service management on Linux only (this host is %s)", runtime.GOOS)
		}
		caps = append(caps, nodewire.Capability{
			Kind: "init", Name: "systemd", State: nodewire.CapabilityUnsupported,
			Detail: map[string]any{"reason": reason},
		})
	}

	// web: a web server AND a staging directory are both required, because
	// validation stages a candidate before asking the server about it. Reporting
	// the capability from the binary alone would let a node advertise a check it
	// cannot perform — the same defect the honest-advertisement rule for
	// service.* exists to prevent.
	if e.webServer.Available() {
		caps = append(caps, nodewire.Capability{
			Kind: "web", Name: "nginx", Version: e.webServer.Version,
			State: nodewire.CapabilityAvailable,
			Detail: map[string]any{
				"binary":      e.webServer.Path,
				"staging_dir": e.webServer.StagingDir,
			},
		})
	} else {
		// The reason names which half is missing, because the two have different
		// remedies: install nginx, or provision the directory. The directory is
		// not named here because on the failure path detection returned without
		// recording it, and naming the default would be wrong for a node
		// configured with a different one.
		reason := "no web server was found on this host"
		if e.webServer.Path != "" {
			reason = "the staging directory for candidate configurations does not exist, so a candidate cannot be validated"
		}
		caps = append(caps, nodewire.Capability{
			Kind: "web", Name: "nginx", State: nodewire.CapabilityUnsupported,
			Detail: map[string]any{"reason": reason},
		})
	}

	// The kernel and architecture are reported as observed. They are not a
	// certification claim: this build has not been tested against any specific
	// distribution, and the capability report says so rather than implying a
	// support matrix.
	return nodewire.CapabilitiesResult{
		OSFamily:     osFamily,
		OSVersion:    osVersion,
		Kernel:       kernel,
		Architecture: arch,
		AgentVersion: e.agentVersion,
		Capabilities: caps,
		ObservedAt:   e.now().UTC(),
	}, nil
}

// detectOS reads the host identity from fixed paths that the operation descriptor
// declares.
//
// Every failure degrades to an empty field rather than an error. A host that
// cannot report its version should still be able to enroll and be managed; an
// empty cell is honest where a fabricated one is not.
func detectOS() (family, version, kernel, arch string) {
	if raw, err := os.ReadFile("/etc/os-release"); err == nil {
		family, version = parseOSRelease(string(raw))
	}
	if raw, err := os.ReadFile("/proc/version"); err == nil {
		kernel = firstField(trimSpace(string(raw)))
	}
	if raw, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		// Prefer the bare release string when present: /proc/version is a free
		// text line whose shape varies by distribution.
		kernel = trimSpace(string(raw))
	}
	arch = runtime.GOARCH
	return family, version, kernel, arch
}

// parseOSRelease extracts ID and VERSION_ID from os-release(5).
//
// It is a hand-rolled parser for the two fields needed rather than a dependency,
// and it deliberately does not shell out to source the file: os-release content
// is data, and sourcing it would execute whatever a compromised host put there.
func parseOSRelease(content string) (family, version string) {
	for _, line := range strings.Split(content, "\n") {
		line = trimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(trimSpace(value), `"'`)
		switch trimSpace(key) {
		case "ID":
			family = value
		case "VERSION_ID":
			version = value
		}
	}
	return family, version
}

// firstField returns the first whitespace-separated token.
func firstField(s string) string {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

// --- node.heartbeat ----------------------------------------------------------

// Heartbeat collects the readings a heartbeat carries.
//
// A zero value is returned with an error for any reading that cannot be taken:
// reporting 0 for an unreadable value would enter a plausible-looking zero into
// the time series, and a time series that quietly lies is worse than one with a
// visible gap.
func (e *Executors) Heartbeat(ctx context.Context) (nodewire.HeartbeatInput, error) {
	var (
		out  nodewire.HeartbeatInput
		errs []error
	)

	if uptime, err := os.ReadFile("/proc/uptime"); err == nil {
		// The file is "<uptime> <idle>", both in seconds with two decimals.
		if seconds, parseErr := strconv.ParseFloat(firstField(trimSpace(string(uptime))), 64); parseErr == nil {
			out.UptimeSeconds = int64(seconds)
		} else {
			errs = append(errs, fmt.Errorf("parse /proc/uptime: %w", parseErr))
		}
	} else {
		errs = append(errs, fmt.Errorf("read /proc/uptime: %w", err))
	}

	if load, err := os.ReadFile("/proc/loadavg"); err == nil {
		// Milliseconds as an integer, so no rounding decision is made here and
		// the value survives JSON without a float.
		if value, parseErr := strconv.ParseFloat(firstField(trimSpace(string(load))), 64); parseErr == nil {
			if value < 0 {
				errs = append(errs, fmt.Errorf("load average is negative (%v)", value))
			} else {
				out.Load1Milli = int64(value * 1000)
			}
		} else {
			errs = append(errs, fmt.Errorf("parse /proc/loadavg: %w", parseErr))
		}
	} else {
		errs = append(errs, fmt.Errorf("read /proc/loadavg: %w", err))
	}

	if total, used, err := readMemInfo(); err == nil {
		out.MemTotalBytes, out.MemUsedBytes = total, used
	} else {
		errs = append(errs, err)
	}

	out.ObservedAt = e.now().UTC()
	if e.workloadCount != nil {
		out.WorkloadCount = e.workloadCount()
	}

	// The shared validator decides whether the readings are possible. Running it
	// here means a collector bug is caught at the source rather than rejected by
	// the controller, where the message would name the wire format instead of the
	// file that was misread.
	if err := out.Validate(); err != nil {
		errs = append(errs, err)
	}
	return out, errors.Join(errs...)
}

// readMemInfo returns total and used memory in bytes.
//
// "Used" is computed as MemTotal minus MemAvailable, which is the figure that
// answers "how much can I still use". MemFree alone excludes reclaimable page
// cache and would report a healthy host as nearly full.
func readMemInfo() (total, used int64, err error) {
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0, fmt.Errorf("read /proc/meminfo: %w", err)
	}
	var availableKB int64
	var haveTotal, haveAvailable bool
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		fields := strings.Fields(trimSpace(value))
		if len(fields) == 0 {
			continue
		}
		kb, parseErr := strconv.ParseInt(fields[0], 10, 64)
		if parseErr != nil {
			continue
		}
		switch key {
		case "MemTotal":
			total, haveTotal = kb*1024, true
		case "MemAvailable":
			availableKB, haveAvailable = kb*1024, true
		}
	}
	if !haveTotal || !haveAvailable {
		return 0, 0, errors.New("read /proc/meminfo: MemTotal or MemAvailable is missing")
	}
	used = total - availableKB
	if used < 0 {
		// A negative "used" is not a reading to clamp: it means the file
		// disagreed with itself, and the honest report is a gap.
		return 0, 0, errors.New("read /proc/meminfo: available memory exceeds total")
	}
	return total, used, nil
}

// --- service.inspect ---------------------------------------------------------

// InspectService reports one unit's state.
//
// The unit name has ALREADY been validated against the operation descriptor's
// scope by nodewire.DecodeRequest before this is reached, so it is a literal from
// a closed allowlist by the time it arrives. It is still passed as its own argv
// element — validation and quoting are independent defenses and neither is
// relied on to make the other unnecessary.
func (e *Executors) InspectService(ctx context.Context, unit string) (nodewire.ServiceState, error) {
	if !supportedOS() {
		return nodewire.ServiceState{}, notAvailable("service inspection is supported on Linux only")
	}
	if !e.hasSystemd {
		return nodewire.ServiceState{}, notAvailable("systemd is not the running init on this host")
	}
	// Every service command passes through here, so this is the one place the
	// counter needs incrementing. It counts DECISIONS to act on the host, which is
	// what "did the agent do anything on its own?" means.
	e.spawns.Add(1)
	// The journal-style output is a fixed key=value list, which is stable across
	// systemd versions in a way that the human-readable output is not.
	result, err := runCommand(ctx, CommandSpec{
		Path: e.systemctlPath,
		Args: []string{"show", "--no-pager", "--property=LoadState,ActiveState,SubState,MainPID,Description", "--", unit},
	})
	if err != nil {
		return nodewire.ServiceState{}, classifyCommandError(err, unit)
	}

	state := parseSystemctlShow(result.Stdout)
	state.Unit = unit
	state.ObservedAt = e.now().UTC()
	if state.LoadState == "not-found" {
		return nodewire.ServiceState{}, &nodewire.Error{
			Code:    nodewire.CodeNotFound,
			Message: fmt.Sprintf("unit %q is not present on this host", unit),
		}
	}
	return state, nil
}

// parseSystemctlShow reads the key=value output of systemctl show.
func parseSystemctlShow(out string) nodewire.ServiceState {
	var state nodewire.ServiceState
	for _, line := range strings.Split(out, "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = trimSpace(value)
		switch key {
		case "LoadState":
			state.LoadState = value
		case "ActiveState":
			state.ActiveState = value
		case "SubState":
			state.SubState = value
		case "Description":
			state.Description = value
		case "MainPID":
			if pid, err := strconv.Atoi(value); err == nil {
				state.MainPID = pid
			}
		}
	}
	return state
}

// --- service.restart ---------------------------------------------------------

// RestartService restarts one unit and reports the state before and after.
//
// The before/after pair is the point: a restart that returns "ok" without
// evidence is a claim, and the caller needs to be able to prove the unit came
// back. If it does not come back, that is reported as a failure even though the
// restart COMMAND succeeded — the honest answer to "is it running now?" is no.
func (e *Executors) RestartService(ctx context.Context, unit string) (nodewire.RestartResult, error) {
	if !supportedOS() {
		return nodewire.RestartResult{}, notAvailable("service management is supported on Linux only")
	}
	if !e.hasSystemd {
		return nodewire.RestartResult{}, notAvailable("systemd is not the running init on this host")
	}

	before, err := e.InspectService(ctx, unit)
	if err != nil {
		return nodewire.RestartResult{}, err
	}

	e.spawns.Add(1)
	if _, err = runCommand(ctx, CommandSpec{
		Path: e.systemctlPath,
		Args: []string{"restart", "--", unit},
	}); err != nil {
		// A failed restart is not retried: the descriptor forbids it, because
		// repeating a restart drops the service again and interrupts whatever it
		// was serving.
		return nodewire.RestartResult{Before: before}, classifyCommandError(err, unit)
	}

	after, err := e.InspectService(ctx, unit)
	if err != nil {
		return nodewire.RestartResult{Before: before}, err
	}
	if !after.Healthy() {
		return nodewire.RestartResult{Before: before, After: after}, &nodewire.Error{
			Code:    nodewire.CodeExecutionFailed,
			Message: fmt.Sprintf("unit %q was restarted but is not healthy afterwards", unit),
			Details: map[string]any{
				"active_state": after.ActiveState,
				"sub_state":    after.SubState,
				"load_state":   after.LoadState,
			},
		}
	}
	return nodewire.RestartResult{Before: before, After: after}, nil
}

// --- error classification ----------------------------------------------------

// notAvailable builds the error for a facility this node lacks.
func notAvailable(reason string) *nodewire.Error {
	return &nodewire.Error{
		Code:    nodewire.CodeNotAvailable,
		Message: reason,
		Details: map[string]any{"reason": reason},
	}
}

// classifyCommandError maps a failed command onto a wire error code.
//
// The mapping is explicit rather than a generic wrap because the codes are what
// the controller branches on: "deadline exceeded" is retryable and "unit not
// found" is not, and collapsing both into execution_failed would make the panel
// offer a retry that cannot work.
func classifyCommandError(err error, unit string) error {
	if errors.Is(err, ErrOutputLimit) {
		return &nodewire.Error{
			Code:      nodewire.CodeExecutionFailed,
			Message:   fmt.Sprintf("inspecting unit %q produced more output than the agent will read", unit),
			Retryable: false,
		}
	}
	var failed *ErrCommandFailed
	if errors.As(err, &failed) {
		if failed.TimedOut {
			return &nodewire.Error{
				Code:      nodewire.CodeDeadlineExceeded,
				Message:   fmt.Sprintf("the operation on unit %q did not finish before its deadline", unit),
				Retryable: true,
			}
		}
		return &nodewire.Error{
			Code:      nodewire.CodeExecutionFailed,
			Message:   fmt.Sprintf("the operation on unit %q failed", unit),
			Retryable: false,
			Details:   map[string]any{"exit_code": failed.Code},
		}
	}
	// A canceled context is reported as a deadline rather than a distinct code:
	// from the caller's side both mean "this did not complete and trying again
	// is reasonable", and giving them separate codes would invite a caller to
	// treat one as retryable and the other as a bug.
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return &nodewire.Error{
			Code:      nodewire.CodeDeadlineExceeded,
			Message:   fmt.Sprintf("the operation on unit %q did not complete", unit),
			Retryable: true,
		}
	}
	return &nodewire.Error{
		Code:    nodewire.CodeExecutionFailed,
		Message: fmt.Sprintf("the operation on unit %q could not be performed", unit),
	}
}
