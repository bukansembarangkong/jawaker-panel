package nodeagent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// --- the command runner -------------------------------------------------------

// helperProcess is the test binary re-invoked as a child, so the runner is
// exercised against a REAL process rather than a stub. That matters here more
// than usual: the properties under test — a NUL-free argv, a controlled
// environment, a bounded read, a killed process group — are properties of the
// operating system's process model, and a fake would assert nothing.
func helperProcess(t *testing.T, args ...string) CommandSpec {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test binary: %v", err)
	}
	// -test.run names a test that does nothing; the helper is selected by the
	// environment the runner deliberately does NOT pass through, so it is set on
	// this spec's own argv instead.
	argv := append([]string{"-test.run=TestHelperProcessEntry", "--"}, args...)
	return CommandSpec{Path: exe, Args: argv}
}

// TestHelperProcessEntry is the child side of the runner tests. It is inert
// during a normal run and activates only when invoked with the "--" sentinel
// that helperProcess adds — never via an environment variable, because the whole
// point of the runner is that it does NOT pass the environment through.
func TestHelperProcessEntry(t *testing.T) {
	args := os.Args
	marker := -1
	for i, a := range args {
		if a == "--" {
			marker = i
			break
		}
	}
	if marker < 0 {
		// A normal `go test` invocation has no sentinel; do nothing.
		return
	}
	args = args[marker+1:]
	if len(args) == 0 {
		os.Exit(2)
	}
	switch args[0] {
	case "echo":
		_, _ = os.Stdout.WriteString(strings.Join(args[1:], " "))
	case "stderr-and-fail":
		_, _ = os.Stderr.WriteString("something went wrong")
		os.Exit(3)
	case "flood":
		// Write far more than the limit, then exit successfully. A runner that
		// stops READING at the limit deadlocks here, which is the failure mode
		// the bounded buffer exists to avoid.
		blob := strings.Repeat("x", 8192)
		for range 64 {
			_, _ = os.Stdout.WriteString(blob)
		}
	case "sleep":
		time.Sleep(time.Duration(len(args[1])) * time.Second)
	case "printenv":
		_, _ = os.Stdout.WriteString(os.Getenv(args[1]))
	case "cwd":
		wd, _ := os.Getwd()
		_, _ = os.Stdout.WriteString(wd)
	}
	os.Exit(0)
}

func TestRunCommandCapturesOutput(t *testing.T) {
	spec := helperProcess(t, "echo", "hello", "world")
	result, err := runCommand(context.Background(), spec)
	if err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if got := trimSpace(result.Stdout); got != "hello world" {
		t.Errorf("stdout = %q, want %q", got, "hello world")
	}
}

// A non-zero exit is an error carrying the code and the child's stderr, so a
// caller can tell "the unit does not exist" from "the command is missing".
func TestRunCommandReportsExitCodeAndStderr(t *testing.T) {
	spec := helperProcess(t, "stderr-and-fail")
	_, err := runCommand(context.Background(), spec)
	if err == nil {
		t.Fatal("a non-zero exit was reported as success")
	}
	var failed *ErrCommandFailed
	if !errors.As(err, &failed) {
		t.Fatalf("error = %v, want *ErrCommandFailed", err)
	}
	if failed.Code != 3 {
		t.Errorf("exit code = %d, want 3", failed.Code)
	}
	if !strings.Contains(failed.Stderr, "something went wrong") {
		t.Errorf("stderr = %q, want the child's message", failed.Stderr)
	}
}

// THE POINT OF THE BOUNDED BUFFER. A child that writes far past the limit must
// still FINISH: io.LimitReader would stop reading, the pipe would fill, and the
// child would block forever while the agent waited for a deadline. The limit is
// enforced by discarding, not by not reading.
func TestRunCommandRefusesOversizedOutputWithoutDeadlocking(t *testing.T) {
	spec := helperProcess(t, "flood")
	spec.Timeout = 20 * time.Second

	done := make(chan error, 1)
	go func() {
		_, err := runCommand(context.Background(), spec)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrOutputLimit) {
			t.Fatalf("error = %v, want ErrOutputLimit", err)
		}
	case <-time.After(25 * time.Second):
		t.Fatal("the runner deadlocked on a child that wrote past the limit; the buffer is not draining")
	}
}

// A deadline must actually cancel the child, and the error must say so.
func TestRunCommandTimeoutCancelsChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process-group cancellation is POSIX-only")
	}
	spec := helperProcess(t, "sleep", "30")
	spec.Timeout = 500 * time.Millisecond

	start := time.Now()
	_, err := runCommand(context.Background(), spec)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a child that outlived its deadline was reported as successful")
	}
	var failed *ErrCommandFailed
	if !errors.As(err, &failed) || !failed.TimedOut {
		t.Fatalf("error = %v, want a timed-out *ErrCommandFailed", err)
	}
	if elapsed > 10*time.Second {
		t.Errorf("cancellation took %s; the child was not killed promptly", elapsed)
	}
}

// The child's environment is the fixed set, so nothing inherited leaks in and
// nothing a request carries can extend it.
func TestRunCommandEnvironmentIsControlled(t *testing.T) {
	t.Setenv("JAWAKER_LEAK_CANARY", "should-not-appear")

	spec := helperProcess(t, "printenv", "JAWAKER_LEAK_CANARY")
	result, err := runCommand(context.Background(), spec)
	if err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if strings.TrimSpace(result.Stdout) != "" {
		t.Errorf("the child inherited JAWAKER_LEAK_CANARY=%q; the environment is not controlled",
			strings.TrimSpace(result.Stdout))
	}

	// And the pinned locale is present, so parsed output does not vary by host.
	spec = helperProcess(t, "printenv", "LC_ALL")
	if result, err = runCommand(context.Background(), spec); err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	if got := strings.TrimSpace(result.Stdout); got != "C" {
		t.Errorf("LC_ALL = %q, want C", got)
	}
}

// The child's working directory is fixed, not whatever the agent was started in.
func TestRunCommandWorkingDirectoryIsFixed(t *testing.T) {
	spec := helperProcess(t, "cwd")
	result, err := runCommand(context.Background(), spec)
	if err != nil {
		t.Fatalf("runCommand: %v", err)
	}
	got := strings.TrimSpace(result.Stdout)
	if got == "" {
		t.Fatal("the child reported an empty working directory")
	}

	// The property that matters is that the child does NOT run in the agent's own
	// directory, which is whatever the agent's service file or an operator's
	// shell happened to be. On Windows os.Stat("/") succeeds and resolves to the
	// current drive root, so comparing against safeWorkingDir there would assert
	// a coincidence rather than the property; comparing against our own cwd holds
	// on every platform.
	own, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if samePath(got, own) {
		t.Errorf("the child ran in the agent's own working directory (%q); it must be fixed", got)
	}
	if runtime.GOOS != "windows" && got != safeWorkingDir() {
		t.Errorf("child cwd = %q, want %q", got, safeWorkingDir())
	}
}

// samePath compares two paths case-insensitively on platforms where that matters.
func samePath(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// --- spec validation ---------------------------------------------------------

// A relative path is refused: the program the agent runs must not depend on the
// process's working directory or PATH.
func TestCommandSpecRejectsRelativePath(t *testing.T) {
	spec := CommandSpec{Path: "systemctl", Args: []string{"status"}}
	if err := spec.Validate(); err == nil {
		t.Fatal("a relative program path was accepted")
	}
	spec = CommandSpec{Path: ""}
	if err := spec.Validate(); err == nil {
		t.Fatal("an empty program path was accepted")
	}
}

// A NUL in an argument is refused, because execve cannot represent it and the
// alternative is a silently truncated argument.
func TestCommandSpecRejectsNULArgument(t *testing.T) {
	spec := CommandSpec{Path: "/bin/echo", Args: []string{"ok", "bad\x00tail"}}
	if err := spec.Validate(); err == nil {
		t.Fatal("an argument containing a NUL byte was accepted")
	}
}

// --- program resolution ------------------------------------------------------

// resolveProgram picks the first executable candidate and ignores a
// non-executable one, so a present-but-unusable binary is reported as absent
// rather than claimed as available.
func TestResolveProgramSkipsNonExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executable permission bits are not meaningful on windows")
	}
	dir := t.TempDir()
	notExec := filepath.Join(dir, "not-executable")
	if err := os.WriteFile(notExec, []byte("#!/bin/sh\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	executable := filepath.Join(dir, "executable")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o700); err != nil { //nolint:gosec // G306: the file must be executable for this test to mean anything
		t.Fatalf("write: %v", err)
	}

	got, ok := resolveProgram(notExec, executable)
	if !ok {
		t.Fatal("resolveProgram found nothing")
	}
	if got != executable {
		t.Errorf("resolved %q, want the executable candidate %q", got, executable)
	}

	if _, ok := resolveProgram(filepath.Join(dir, "absent")); ok {
		t.Error("resolveProgram reported success for a nonexistent path")
	}
}

// --- the closed registry, as seen by the agent --------------------------------

// A node without systemd must not advertise service operations. A capability
// claim the node cannot honor is worse than an honest gap: the operator would be
// offered a control that always fails.
func TestServedOperationsReflectDetectedCapabilities(t *testing.T) {
	withSystemd := &Executors{hasSystemd: true, systemctlPath: "/usr/bin/systemctl"}
	served := servedOperations(withSystemd)

	// On a non-Linux host the OS gate refuses service operations regardless of
	// what was detected, so the expectation depends on the build's target.
	if supportedOS() {
		if !served[nodewire.OpServiceInspect] || !served[nodewire.OpServiceRestart] {
			t.Error("systemd was detected but service operations are not advertised")
		}
	} else if served[nodewire.OpServiceRestart] {
		t.Error("service.restart is advertised on a host this build does not support")
	}

	withoutSystemd := &Executors{}
	served = servedOperations(withoutSystemd)
	if served[nodewire.OpServiceInspect] || served[nodewire.OpServiceRestart] {
		t.Error("service operations are advertised on a node with no systemd")
	}
	// The read-only operations are always available: they are how the panel
	// learns anything about the node at all.
	if !served[nodewire.OpNodeCapabilities] || !served[nodewire.OpNodeHeartbeat] {
		t.Error("the read-only operations are not advertised")
	}
}

// The refusal must be the same code as the capability report: a node that says
// "unsupported" must also refuse with not_available.
func TestServiceOperationsRefuseWithoutSystemd(t *testing.T) {
	e := &Executors{}
	_, err := e.InspectService(context.Background(), "nginx")
	var wireErr *nodewire.Error
	if !errors.As(err, &wireErr) {
		t.Fatalf("error = %v, want a *nodewire.Error", err)
	}
	if wireErr.Code != nodewire.CodeNotAvailable && wireErr.Code != nodewire.CodeUnsupportedOS {
		t.Errorf("code = %q, want not_available or unsupported_os", wireErr.Code)
	}
}

// The capability report must not claim certified support for any distribution.
// It reports what it observed and marks systemd unsupported when absent.
func TestCapabilitiesReportHonestState(t *testing.T) {
	e := &Executors{agentVersion: "test", now: func() time.Time { return time.Unix(0, 0).UTC() }}
	result, err := e.Capabilities()
	if err != nil {
		t.Fatalf("Capabilities: %v", err)
	}
	if result.AgentVersion != "test" {
		t.Errorf("agent version = %q, want test", result.AgentVersion)
	}
	if len(result.Capabilities) == 0 {
		t.Fatal("the capability report is empty")
	}

	var sawSystemd bool
	for _, c := range result.Capabilities {
		if c.Name == "systemd" {
			sawSystemd = true
			if e.hasSystemd && c.State != nodewire.CapabilityAvailable {
				t.Errorf("systemd state = %q, want available", c.State)
			}
			if !e.hasSystemd && c.State != nodewire.CapabilityUnsupported {
				t.Errorf("systemd state = %q, want unsupported when it is not running", c.State)
			}
		}
		// Nothing may claim certification: this build is not tested against any
		// distribution, and the report is the place that would otherwise imply it.
		if strings.Contains(strings.ToLower(c.Name), "certified") {
			t.Errorf("capability %q implies certification", c.Name)
		}
	}
	if !sawSystemd {
		t.Error("the capability report does not mention systemd at all")
	}
}

// --- heartbeat collection ----------------------------------------------------

// The heartbeat collector must produce a value the shared validator accepts, so
// the agent never sends something the controller will refuse.
func TestHeartbeatProducesValidReading(t *testing.T) {
	e := NewExecutors(ExecutorOptions{AgentVersion: "test"})
	report, err := e.Heartbeat(context.Background())
	if err != nil {
		// On a host with no /proc this is expected, and the error must name the
		// file rather than the wire format.
		t.Skipf("heartbeat collection unavailable on this host: %v", err)
	}
	if err := report.Validate(); err != nil {
		t.Errorf("the collected heartbeat does not satisfy the shared validator: %v", err)
	}
	if report.ObservedAt.IsZero() {
		t.Error("observed_at is zero")
	}
	if report.MemTotalBytes > 0 && report.MemUsedBytes > report.MemTotalBytes {
		t.Errorf("used (%d) exceeds total (%d)", report.MemUsedBytes, report.MemTotalBytes)
	}
}

// os-release parsing must not execute its contents: the file is data on a host
// that may be compromised, and sourcing it would run whatever is in it.
func TestParseOSReleaseDoesNotExecuteOrCrash(t *testing.T) {
	cases := map[string]struct{ family, version string }{
		`ID=debian
VERSION_ID="12"`: {"debian", "12"},
		`# comment
ID='ubuntu'
VERSION_ID=24.04`: {"ubuntu", "24.04"},
		`ID=$(touch /tmp/pwned)`: {"$(touch /tmp/pwned)", ""},
		``:                       {"", ""},
		"garbage without equals": {"", ""},
		`PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"`: {"", ""},
	}
	for input, want := range cases {
		family, version := parseOSRelease(input)
		if family != want.family || version != want.version {
			t.Errorf("parseOSRelease(%q) = (%q, %q), want (%q, %q)",
				input, family, version, want.family, want.version)
		}
	}
}

// restrictedStateDir returns a temporary directory at mode 0700.
//
// t.TempDir() is os.Mkdir(dir, 0o777), which the process umask reduces — to 0755
// on a typical Linux runner. EnsureStateDir REFUSES a directory that group or
// others can reach, and it refuses to repair one silently, because the key inside
// may already have been exposed. So a test that hands a bare t.TempDir() to the
// agent's save path fails on Linux and passes on Windows, where the POSIX mode
// check is skipped — which is exactly the split-brain this helper removes.
func restrictedStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, dirMode); err != nil {
		t.Fatalf("restrict the state directory: %v", err)
	}
	return dir
}

// --- state directory safety --------------------------------------------------

// A state directory readable by group or others is a HARD failure: the key inside
// may already have been copied, and no later action can undo that.
func TestEnsureStateDirRefusesPermissiveDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not meaningful on windows")
	}
	// The directory must ALREADY be restrictive: t.TempDir() is 0755 on a
	// typical Linux runner, and EnsureStateDir is meant to refuse that, not
	// adopt it.
	dir := restrictedStateDir(t)
	if err := EnsureStateDir(dir); err != nil {
		t.Fatalf("EnsureStateDir on a fresh 0700 directory: %v", err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: widening the mode IS the subject of this test
		t.Fatalf("chmod: %v", err)
	}
	if err := EnsureStateDir(dir); err == nil {
		t.Fatal("a group/world-accessible state directory was accepted")
	}
}

// --- enrollment request validation, at the agent's own boundary ---------------

// A misconfigured agent must fail locally, naming the field, instead of receiving
// an opaque 400 from the controller.
func TestEnrollOptionsValidateLocally(t *testing.T) {
	base := EnrollOptions{
		ControllerURL:                 "https://controller.example:8443",
		Token:                         "jwenroll_x",
		StateDir:                      restrictedStateDir(t),
		NodeAddress:                   "10.0.0.5:9443",
		ExpectedControllerFingerprint: strings.Repeat("ab", 32),
	}
	if err := base.validate(); err != nil {
		t.Fatalf("a complete configuration was rejected: %v", err)
	}

	// A bearer token must not travel in plaintext.
	insecure := base
	insecure.ControllerURL = "http://controller.example:8443"
	if err := insecure.validate(); err == nil {
		t.Fatal("an http controller URL was accepted for enrollment")
	}

	for name, mutate := range map[string]func(*EnrollOptions){
		"no token":        func(o *EnrollOptions) { o.Token = "" },
		"no state dir":    func(o *EnrollOptions) { o.StateDir = "" },
		"no node address": func(o *EnrollOptions) { o.NodeAddress = "" },
		"unparseable URL": func(o *EnrollOptions) { o.ControllerURL = "://bad" },
	} {
		opts := base
		mutate(&opts)
		if err := opts.validate(); err == nil {
			t.Errorf("%s: the configuration was accepted", name)
		}
	}
}

// --- the fingerprint pin is mandatory ----------------------------------------

// WITHOUT the pin, whoever answers the enrollment request becomes this node's
// permanently trusted controller. The requirement lives in the library, so it is
// tested there: a check that lived only in the command would leave any other
// caller able to enroll unpinned.
func TestEnrollRequiresFingerprintPin(t *testing.T) {
	base := EnrollOptions{
		ControllerURL: "https://controller.example:8443",
		Token:         testEnrollToken,
		StateDir:      restrictedStateDir(t),
		NodeAddress:   "10.0.0.5:9443",
	}
	if err := base.validate(); err == nil {
		t.Fatal("enrollment was accepted with no pinned fingerprint: the node would trust whoever answered")
	}

	// Whitespace is not a pin either.
	padded := base
	padded.ExpectedControllerFingerprint = "   "
	if err := padded.validate(); err == nil {
		t.Fatal("whitespace was accepted as a pinned fingerprint")
	}

	pinned := base
	pinned.ExpectedControllerFingerprint = strings.Repeat("ab", 32)
	if err := pinned.validate(); err != nil {
		t.Fatalf("a complete configuration with a pin was rejected: %v", err)
	}
}

// A controller that presents a root other than the pinned one must be refused,
// and NOTHING may be written to the state directory: a partially-written identity
// would fail at the next start with a message that names the symptom rather than
// the substitution that caused it.
func TestEnrollRefusesMismatchedFingerprint(t *testing.T) {
	stateDir := restrictedStateDir(t)

	// The response carries a root whose fingerprint differs from the pin. The
	// check runs before anything is persisted, so serving the request is enough
	// to exercise it.
	server := newEnrollStub(t)
	_, err := Enroll(context.Background(), EnrollOptions{
		ControllerURL:                 server.url,
		Token:                         testEnrollToken,
		ExpectedControllerFingerprint: strings.Repeat("00", 32),
		StateDir:                      stateDir,
		NodeAddress:                   "127.0.0.1:9443",
		AgentVersion:                  "test",
		HTTPClient:                    server.client,
	})
	if err == nil {
		t.Fatal("enrollment succeeded against a controller that did not match the pin")
	}
	if !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("error = %v, want ErrFingerprintMismatch", err)
	}

	// Nothing was written: no identity, no config, no pinned root.
	for _, name := range []string{identityFile, configFile, controllerCAFile} {
		if _, statErr := os.Stat(filepath.Join(stateDir, name)); statErr == nil {
			t.Errorf("%s was written despite the fingerprint mismatch", name)
		}
	}
}
