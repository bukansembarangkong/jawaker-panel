package nodewire

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// --- registry integrity -------------------------------------------------------

// The registry is a security artifact. A malformed descriptor is a programming
// error that must fail the build's test run rather than ship as an operation
// nobody reviewed.
func TestRegistryIsWellFormed(t *testing.T) {
	if err := ValidateRegistry(); err != nil {
		t.Fatalf("ValidateRegistry: %v", err)
	}
}

// Every declared operation must exist. Adding an operation means adding it HERE
// too, so a rename cannot silently drop one and an addition cannot be silent.
func TestRegistryContainsExactlyTheDeclaredOperations(t *testing.T) {
	want := []Operation{
		OpNodeCapabilities,
		OpNodeHeartbeat,
		OpServiceInspect,
		OpServiceRestart,
		OpWebConfigValidate,
	}
	if len(Operations) != len(want) {
		t.Errorf("registry has %d operations %v, want %d", len(Operations), Names(), len(want))
	}
	for _, op := range want {
		if _, ok := Lookup(op); !ok {
			t.Errorf("operation %q is missing from the registry", op)
		}
	}
}

// There must be no way to obtain a generic execution operation. The check is a
// search over every registered descriptor for anything that would accept an
// arbitrary command: a "shell", "exec", "run", or "command" operation name, or a
// scope that reaches a filesystem path for writing without a service context.
//
// This is a regression guard on the protocol shape itself. It is cheap and it
// fails loudly if someone adds a passthrough by another name.
func TestRegistryHasNoGenericExecutionOperation(t *testing.T) {
	forbidden := []string{"shell", "exec", "run", "command", "script", "arbitrary", "passthrough"}
	for _, op := range Names() {
		lower := strings.ToLower(string(op))
		for _, word := range forbidden {
			if strings.Contains(lower, word) {
				t.Errorf("operation %q contains %q; the protocol must not expose generic execution", op, word)
			}
		}
	}
	// No descriptor may accept an unbounded filesystem write scope. A mutating
	// operation may write only under an explicit, reviewed path; "/" or an empty
	// string would be unbounded.
	for op, desc := range Operations {
		for _, path := range desc.Scope.FilesystemWrite {
			if path == "/" || path == "" || path == "/*" {
				t.Errorf("operation %q declares an unbounded write scope %q", op, path)
			}
		}
	}
}

// A mutating operation must name the resources it may touch, and none of them may
// be a wildcard — "restart anything" is generic execution with extra steps.
//
// Phase 2 asserted this for SERVICE scope, because every mutating operation then
// acted on a unit. Phase 3 adds one that writes a file, so the requirement is
// stated in terms of scope generally: a mutation must reach some declared
// resource, whichever kind. The checks that matter are unchanged — no wildcards,
// no retries on a non-idempotent mutation, and a declared rollback — because those
// are what stop a mutating operation from being reviewed as one thing and acting
// as another.
func TestMutatingOperationsDeclareBoundedScope(t *testing.T) {
	for op, desc := range Operations {
		if !desc.Mutating {
			continue
		}
		if len(desc.Scope.Services) == 0 && len(desc.Scope.FilesystemWrite) == 0 {
			t.Errorf("mutating operation %q declares neither a service nor a filesystem scope", op)
		}
		for _, unit := range desc.Scope.Services {
			if unit == "*" || unit == "" || strings.Contains(unit, "*") {
				t.Errorf("operation %q declares a wildcard unit %q", op, unit)
			}
		}
		for _, path := range desc.Scope.FilesystemWrite {
			if path == "/" || path == "" || strings.ContainsAny(path, "*?") {
				t.Errorf("operation %q declares a wildcard write path %q", op, path)
			}
		}
		// Non-idempotent side effects must not declare automatic retries; the
		// descriptor rule already forbids it, so assert it holds in practice.
		if !desc.Retry.Idempotent && desc.Retry.MaxAttempts > 0 {
			t.Errorf("operation %q is non-idempotent but declares %d automatic retries", op, desc.Retry.MaxAttempts)
		}
		if desc.Rollback == "" {
			t.Errorf("mutating operation %q declares no rollback behavior", op)
		}
	}
}

// Every operation must carry an RBAC permission and an audit action, so no
// operation can be reached without authorization or recorded without a trail.
func TestEveryOperationDeclaresPermissionAndAudit(t *testing.T) {
	for op, desc := range Operations {
		if desc.Permission == "" {
			t.Errorf("operation %q has no permission", op)
		}
		if desc.AuditAction == "" {
			t.Errorf("operation %q has no audit action", op)
		}
		if desc.Timeout <= 0 {
			t.Errorf("operation %q has no timeout", op)
		}
		if len(desc.OSSupport) == 0 {
			t.Errorf("operation %q declares no supported OS", op)
		}
	}
}

func TestNamesIsSorted(t *testing.T) {
	names := Names()
	for i := 1; i < len(names); i++ {
		if names[i-1] > names[i] {
			t.Fatalf("Names() is not sorted: %v", names)
		}
	}
}

// --- service name validation --------------------------------------------------

// This is the injection boundary. Every value here reaches a privileged program
// as an argv element, so the pattern must refuse anything that could be read as
// a path, a separator, or shell syntax.
func TestValidServiceName(t *testing.T) {
	accepted := []string{
		"nginx",
		"php-fpm",
		"postgresql",
		"docker",
		"systemd-networkd",
		"nginx.service",
		"getty@tty1",
		"postgresql@17-main",
		"my_service.v2:main",
	}
	for _, name := range accepted {
		if !ValidServiceName(name) {
			t.Errorf("ValidServiceName(%q) = false, want true", name)
		}
	}

	// Each rejection is a distinct attack shape, not a style preference.
	rejected := map[string]string{
		"empty":          "",
		"path traversal": "../../etc/passwd",
		"absolute path":  "/etc/passwd",
		"shell chain":    "nginx; rm -rf /",
		"pipe":           "nginx | cat",
		"subshell":       "$(id)",
		"backtick":       "`id`",
		"redirect":       "nginx > /tmp/x",
		"space":          "nginx arg",
		"newline":        "nginx\nreboot",
		"tab":            "nginx\targ",
		"slash":          "nginx/foo",
		"backslash":      "nginx\\foo",
		"leading dash":   "-rf",
		"leading dot":    ".hidden",
		"quote":          "nginx'",
		"double quote":   `nginx"`,
		"null-ish brace": "nginx${IFS}x",
		"very long":      strings.Repeat("a", 200),
	}
	for label, name := range rejected {
		if ValidServiceName(name) {
			t.Errorf("ValidServiceName(%q) = true, want false (%s)", name, label)
		}
	}
}

// --- encode/decode ------------------------------------------------------------

func validRequest(op Operation, target string) Request {
	return Request{
		Operation: op,
		RequestID: "req_test_1",
		Deadline:  time.Now().Add(30 * time.Second),
		Target:    target,
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	in := validRequest(OpServiceInspect, "nginx")
	in.Input = json.RawMessage(`{"unit":"nginx"}`)

	encoded, err := EncodeRequest(in)
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	decoded, desc, err := DecodeRequest(encoded, Served())
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	if decoded.Operation != in.Operation {
		t.Errorf("operation = %q, want %q", decoded.Operation, in.Operation)
	}
	if decoded.Target != in.Target {
		t.Errorf("target = %q, want %q", decoded.Target, in.Target)
	}
	if desc.Permission != "server.read" {
		t.Errorf("descriptor permission = %q, want server.read", desc.Permission)
	}
	if decoded.ProtocolVersion != ProtocolVersion {
		t.Errorf("protocol version = %d, want %d", decoded.ProtocolVersion, ProtocolVersion)
	}
}

// A name that is not in the registry cannot even be encoded, which is the first
// half of "the controller cannot send unsupported generic commands": the sender
// refuses its own unsupported request.
func TestEncodeRefusesUnregisteredOperation(t *testing.T) {
	req := validRequest(Operation("shell.exec"), "")
	_, err := EncodeRequest(req)
	if err == nil {
		t.Fatal("EncodeRequest accepted an unregistered operation, want refusal")
	}
	if !errors.Is(err, ErrUnknownOperation) {
		t.Errorf("error = %v, want ErrUnknownOperation", err)
	}
}

// The second half: even a hand-crafted envelope naming an unknown operation is
// refused at decode, with the correct wire code.
func TestDecodeRefusesUnknownOperation(t *testing.T) {
	// Build the JSON by hand so it bypasses EncodeRequest entirely.
	body := []byte(`{"protocol_version":1,"operation":"shell.exec","request_id":"req_x",` +
		`"deadline":"2030-01-01T00:00:00Z","input":{"command":"id"}}`)
	_, _, err := DecodeRequest(body, Served())
	if err == nil {
		t.Fatal("DecodeRequest accepted an unknown operation, want refusal")
	}
	if !errors.Is(err, ErrUnknownOperation) {
		t.Errorf("error = %v, want ErrUnknownOperation", err)
	}
	if code := CodeFor(err); code != CodeUnsupportedOperation {
		t.Errorf("CodeFor = %q, want %q", code, CodeUnsupportedOperation)
	}
}

// A build that does not implement an operation refuses it identically to an
// unknown one, so the registry and the served set are both load-bearing.
func TestDecodeRefusesUnservedOperation(t *testing.T) {
	body := []byte(`{"protocol_version":1,"operation":"service.restart","request_id":"req_x",` +
		`"deadline":"2030-01-01T00:00:00Z","target":"nginx"}`)
	_, _, err := DecodeRequest(body, map[Operation]bool{OpServiceInspect: true})
	if err == nil {
		t.Fatal("DecodeRequest accepted an operation the node does not serve, want refusal")
	}
	if !errors.Is(err, ErrUnknownOperation) {
		t.Errorf("error = %v, want ErrUnknownOperation", err)
	}
}

func TestDecodeRefusesProtocolMismatch(t *testing.T) {
	body := []byte(`{"protocol_version":99,"operation":"node.heartbeat","request_id":"req_x",` +
		`"deadline":"2030-01-01T00:00:00Z"}`)
	_, _, err := DecodeRequest(body, Served())
	if err == nil {
		t.Fatal("DecodeRequest accepted a different protocol version, want refusal")
	}
	if !errors.Is(err, ErrProtocolMismatch) {
		t.Errorf("error = %v, want ErrProtocolMismatch", err)
	}
}

// Unknown JSON fields must be refused: silently ignoring a field would mean
// applying a partially-understood instruction, which is how a payload grows a
// meaning nobody reviewed.
func TestDecodeRefusesUnknownFields(t *testing.T) {
	body := []byte(`{"protocol_version":1,"operation":"node.heartbeat","request_id":"req_x",` +
		`"deadline":"2030-01-01T00:00:00Z","command":"id"}`)
	_, _, err := DecodeRequest(body, Served())
	if err == nil {
		t.Fatal("DecodeRequest accepted an unknown field, want refusal")
	}
	if !strings.Contains(err.Error(), "unknown field") {
		t.Errorf("error = %v, want an unknown-field refusal", err)
	}
}

// A second JSON value in one body would be parsed and discarded; the node must
// not accept a request carrying something it never inspects.
func TestDecodeRefusesTrailingValue(t *testing.T) {
	body := []byte(`{"protocol_version":1,"operation":"node.heartbeat","request_id":"req_x",` +
		`"deadline":"2030-01-01T00:00:00Z"}{"protocol_version":1,"operation":"service.restart",` +
		`"request_id":"req_y","deadline":"2030-01-01T00:00:00Z","target":"nginx"}`)
	_, _, err := DecodeRequest(body, Served())
	if err == nil {
		t.Fatal("DecodeRequest accepted two JSON values, want refusal")
	}
}

func TestDecodeRefusesMissingRequestIDAndDeadline(t *testing.T) {
	noID := []byte(`{"protocol_version":1,"operation":"node.heartbeat","deadline":"2030-01-01T00:00:00Z"}`)
	if _, _, err := DecodeRequest(noID, Served()); err == nil {
		t.Error("DecodeRequest accepted a missing request id, want refusal")
	}
	noDeadline := []byte(`{"protocol_version":1,"operation":"node.heartbeat","request_id":"req_x"}`)
	if _, _, err := DecodeRequest(noDeadline, Served()); err == nil {
		t.Error("DecodeRequest accepted a missing deadline, want refusal")
	}
}

func TestEncodeRefusesOversizedInput(t *testing.T) {
	req := validRequest(OpNodeHeartbeat, "")
	req.Input = json.RawMessage(strings.Repeat("a", maxInputBytes+1))
	if _, err := EncodeRequest(req); err == nil {
		t.Error("EncodeRequest accepted an oversized input, want refusal")
	}
}

// --- scope enforcement --------------------------------------------------------

// A restart with no target is refused rather than defaulted to "everything".
func TestScopeRejectsRestartWithoutTarget(t *testing.T) {
	req := validRequest(OpServiceRestart, "")
	if _, err := EncodeRequest(req); err == nil {
		t.Fatal("EncodeRequest accepted a restart with no target, want refusal")
	}
}

// A restart naming a unit outside the declared scope is refused.
func TestScopeRejectsOutOfScopeUnit(t *testing.T) {
	// systemd-journald is a real unit that the descriptor does not list.
	req := validRequest(OpServiceRestart, "systemd-journald")
	_, err := EncodeRequest(req)
	if err == nil {
		t.Fatal("EncodeRequest accepted an out-of-scope unit, want refusal")
	}
	if !errors.Is(err, ErrScopeViolation) {
		t.Errorf("error = %v, want ErrScopeViolation", err)
	}
}

func TestScopeRejectsInvalidUnitName(t *testing.T) {
	req := validRequest(OpServiceRestart, "nginx;reboot")
	_, err := EncodeRequest(req)
	if err == nil {
		t.Fatal("EncodeRequest accepted an invalid unit name, want refusal")
	}
	if !errors.Is(err, ErrScopeViolation) {
		t.Errorf("error = %v, want ErrScopeViolation", err)
	}
}

// A whole-node operation must not accept a target, or a caller could smuggle a
// unit name through a field the handler never validates.
func TestScopeRejectsTargetOnNodeWideOperation(t *testing.T) {
	req := validRequest(OpNodeHeartbeat, "nginx")
	_, err := EncodeRequest(req)
	if err == nil {
		t.Fatal("EncodeRequest accepted a target on node.heartbeat, want refusal")
	}
	if !errors.Is(err, ErrScopeViolation) {
		t.Errorf("error = %v, want ErrScopeViolation", err)
	}
}

// Scope is enforced at BOTH ends: a hand-crafted envelope bypasses
// EncodeRequest, so DecodeRequest must refuse the same things.
func TestDecodeEnforcesScopeIndependently(t *testing.T) {
	body := []byte(`{"protocol_version":1,"operation":"service.restart","request_id":"req_x",` +
		`"deadline":"2030-01-01T00:00:00Z","target":"sshd"}`)
	_, _, err := DecodeRequest(body, Served())
	if err == nil {
		t.Fatal("DecodeRequest accepted an out-of-scope unit, want refusal")
	}
	if !errors.Is(err, ErrScopeViolation) {
		t.Errorf("error = %v, want ErrScopeViolation", err)
	}
}

// --- payload decode -----------------------------------------------------------

func TestDecodeInputRefusesUnknownFields(t *testing.T) {
	req := validRequest(OpServiceInspect, "nginx")
	req.Input = json.RawMessage(`{"unit":"nginx","as_root":true}`)
	if _, err := DecodeInput[ServiceInspectInput](req); err == nil {
		t.Fatal("DecodeInput accepted an unknown field, want refusal")
	}
}

func TestDecodeInputRejectsMismatchWithTarget(t *testing.T) {
	in := ServiceInspectInput{Unit: "php-fpm"}
	if err := ValidateInspectInput(in, "nginx"); err == nil {
		t.Error("ValidateInspectInput accepted a payload that disagrees with the envelope target, want refusal")
	}
	if err := ValidateInspectInput(ServiceInspectInput{}, "nginx"); err == nil {
		t.Error("ValidateInspectInput accepted an empty unit, want refusal")
	}
	if err := ValidateInspectInput(ServiceInspectInput{Unit: "nginx;reboot"}, "nginx;reboot"); err == nil {
		t.Error("ValidateInspectInput accepted an invalid unit name, want refusal")
	}
	if err := ValidateInspectInput(ServiceInspectInput{Unit: "nginx"}, "nginx"); err != nil {
		t.Errorf("ValidateInspectInput rejected a valid request: %v", err)
	}
}

func TestValidateRestartInputMatchesInspect(t *testing.T) {
	if err := ValidateRestartInput(ServiceRestartInput{Unit: "nginx"}, "nginx"); err != nil {
		t.Errorf("ValidateRestartInput rejected a valid request: %v", err)
	}
	if err := ValidateRestartInput(ServiceRestartInput{Unit: "nginx"}, "php-fpm"); err == nil {
		t.Error("ValidateRestartInput accepted a target mismatch, want refusal")
	}
	if err := ValidateRestartInput(ServiceRestartInput{Unit: "../etc"}, "../etc"); err == nil {
		t.Error("ValidateRestartInput accepted a traversal unit name, want refusal")
	}
}

// --- heartbeat validation -----------------------------------------------------

// Impossible readings are refused, not clamped: a time series that quietly lies
// is worse than one with a gap.
func TestHeartbeatValidateRejectsImpossibleReadings(t *testing.T) {
	now := time.Now()
	cases := map[string]HeartbeatInput{
		"missing observed_at": {UptimeSeconds: 10},
		"negative uptime":     {ObservedAt: now, UptimeSeconds: -1},
		"negative load":       {ObservedAt: now, Load1Milli: -1},
		"negative total":      {ObservedAt: now, MemTotalBytes: -1},
		"negative used":       {ObservedAt: now, MemUsedBytes: -1},
		"negative workload":   {ObservedAt: now, WorkloadCount: -1},
		"used over total":     {ObservedAt: now, MemTotalBytes: 100, MemUsedBytes: 200},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			if err := h.Validate(); err == nil {
				t.Error("Validate accepted an impossible reading, want refusal")
			}
		})
	}

	valid := HeartbeatInput{
		ObservedAt:    now,
		UptimeSeconds: 3600,
		Load1Milli:    150,
		MemTotalBytes: 1 << 30,
		MemUsedBytes:  1 << 29,
		WorkloadCount: 3,
	}
	if err := valid.Validate(); err != nil {
		t.Errorf("Validate rejected a valid heartbeat: %v", err)
	}
	// Zero total with zero used is legitimate: a node that could not read memory
	// reports zeros rather than a fabricated number.
	if err := (HeartbeatInput{ObservedAt: now}).Validate(); err != nil {
		t.Errorf("Validate rejected an all-zero heartbeat: %v", err)
	}
}

// --- service state ------------------------------------------------------------

func TestServiceStatePredicates(t *testing.T) {
	running := ServiceState{LoadState: "loaded", ActiveState: "active", SubState: "running"}
	if !running.Running() || !running.Healthy() {
		t.Error("a running unit should be Running and Healthy")
	}
	failed := ServiceState{LoadState: "loaded", ActiveState: "failed", SubState: "dead"}
	if failed.Running() || failed.Healthy() {
		t.Error("a failed unit should be neither Running nor Healthy")
	}
	// A oneshot that exited successfully is not running but is not unhealthy.
	exited := ServiceState{LoadState: "loaded", ActiveState: "active", SubState: "exited"}
	if exited.Running() {
		t.Error("an exited unit is not Running")
	}
	if !exited.Healthy() {
		t.Error("a successfully exited oneshot is Healthy")
	}
	missing := ServiceState{LoadState: "not-found"}
	if missing.Healthy() {
		t.Error("a unit that is not found is not Healthy")
	}
}

// --- response -----------------------------------------------------------------

func TestResponseRoundTripAndConsistency(t *testing.T) {
	result, err := EncodeResult(ServiceState{Unit: "nginx", ActiveState: "active", SubState: "running"})
	if err != nil {
		t.Fatalf("EncodeResult: %v", err)
	}
	resp := Response{Operation: OpServiceInspect, RequestID: "req_x", OK: true, Result: result}
	encoded, err := EncodeResponse(resp, time.Now())
	if err != nil {
		t.Fatalf("EncodeResponse: %v", err)
	}
	decoded, err := DecodeResponse(encoded)
	if err != nil {
		t.Fatalf("DecodeResponse: %v", err)
	}
	if !decoded.OK || decoded.CompletedAt.IsZero() {
		t.Errorf("decoded response = %+v, want ok with a completion time", decoded)
	}
}

// ok and error must not both be set, and must not both be absent. A response
// whose meaning is ambiguous is how a failure gets read as a success.
func TestResponseRejectsAmbiguousState(t *testing.T) {
	both := []byte(`{"protocol_version":1,"operation":"service.inspect","request_id":"r","ok":true,` +
		`"error":{"code":"execution_failed","message":"x","retryable":false},"completed_at":"2030-01-01T00:00:00Z"}`)
	if _, err := DecodeResponse(both); err == nil {
		t.Error("DecodeResponse accepted ok=true with an error, want refusal")
	}
	neither := []byte(`{"protocol_version":1,"operation":"service.inspect","request_id":"r","ok":false,` +
		`"completed_at":"2030-01-01T00:00:00Z"}`)
	if _, err := DecodeResponse(neither); err == nil {
		t.Error("DecodeResponse accepted ok=false with no error, want refusal")
	}
}

func TestResponseRejectsProtocolMismatch(t *testing.T) {
	body := []byte(`{"protocol_version":99,"operation":"node.heartbeat","request_id":"r","ok":true,` +
		`"completed_at":"2030-01-01T00:00:00Z"}`)
	_, err := DecodeResponse(body)
	if !errors.Is(err, ErrProtocolMismatch) {
		t.Errorf("error = %v, want ErrProtocolMismatch", err)
	}
}

// --- error mapping ------------------------------------------------------------

func TestCodeForMapsSentinels(t *testing.T) {
	cases := map[string]struct {
		err  error
		want string
	}{
		"unknown":   {fmt.Errorf("wrapped: %w", ErrUnknownOperation), CodeUnsupportedOperation},
		"protocol":  {ErrProtocolMismatch, CodeProtocolMismatch},
		"input":     {ErrInvalidInput, CodeInvalidInput},
		"malformed": {ErrMalformedRequest, CodeInvalidInput},
		"scope":     {ErrScopeViolation, CodeScopeViolation},
		"nil":       {nil, ""},
		"other":     {errors.New("something else"), CodeExecutionFailed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := CodeFor(tc.err); got != tc.want {
				t.Errorf("CodeFor = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNodeErrorImplementsError(t *testing.T) {
	e := NewError(CodeScopeViolation, "unit not in scope", false, nil)
	if !strings.Contains(e.Error(), CodeScopeViolation) {
		t.Errorf("Error() = %q, want it to name the code", e.Error())
	}
	var nilErr *Error
	if nilErr.Error() == "" {
		t.Error("a nil node error must still render something")
	}
}
