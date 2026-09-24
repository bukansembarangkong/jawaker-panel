// Package nodewire defines the controller↔node protocol.
//
// It exists so that "the controller cannot send unsupported generic commands" is
// true BY CONSTRUCTION rather than by validation. There is no passthrough here:
// an operation is a value in a closed registry, its input is a typed struct, and
// an agent that receives a name it does not implement refuses before any process
// is started. AGENTS.md §9 is explicit that a generic RunShell(any_string) RPC
// must not exist, and the surest way to honor that is for the protocol to have
// no way to express one.
//
// # Why a hand-rolled envelope instead of gRPC
//
// ARCHITECTURE.md §4 and PRD.md §32.5 name gRPC. This package implements the
// same properties — typed operations, deadlines, correlation, mutual identity —
// over HTTP/2 with stdlib crypto/tls and net/http. The reasoning is recorded in
// the Phase 2 plan and supersedes that line:
//
//   - gRPC brings roughly thirty transitive dependencies into a module whose
//     only current dependency is pgx;
//   - codegen requires protoc plus two plugins, and CI must then detect
//     generated-code drift — a second toolchain to keep pinned;
//   - nothing in Phase 2 needs streaming: every operation is a short
//     request/response with a deadline;
//   - the security properties the spec asks for come from the closed registry
//     and the pinned-root verifier in internal/pki. Those have to be written
//     either way, gRPC or not.
//
// The envelope carries an explicit protocol version so a future move to protobuf
// or a real gRPC service does not break the domain layer: only this package's
// encode/decode would change.
package nodewire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

// ProtocolVersion is the wire protocol version. A peer that does not speak this
// version is refused rather than parsed leniently: a protocol that silently
// tolerates an unknown version cannot be changed safely later.
const ProtocolVersion = 1

// VersionHeader carries the protocol version on every request and response. It
// is a header as well as a body field so a peer can reject an incompatible
// request before reading a body it may not understand.
const VersionHeader = "X-Jawaker-Node-Protocol"

// Operation names. These are the ONLY operations that exist.
//
// Each name is spelled once. A name that is not in this list has no descriptor,
// so it cannot be encoded, and an agent decoding it finds no handler and refuses.
type Operation string

const (
	// OpNodeCapabilities reports the node's OS and capability inventory.
	OpNodeCapabilities Operation = "node.capabilities"
	// OpNodeHeartbeat reports liveness and coarse resource facts.
	OpNodeHeartbeat Operation = "node.heartbeat"
	// OpNodeMetrics samples host-level CPU, memory, disk and load from /proc
	// and statfs. Unlike the heartbeat's coarse snapshot it is a bounded,
	// time-stamped sample the controller stores for trend evaluation and
	// alerting (Phase 7 observability). Read-only.
	OpNodeMetrics Operation = "node.metrics" //nolint:gosec // G101: an operation wire name, not a credential
	// OpServiceInspect reports the state of one service unit.
	OpServiceInspect Operation = "service.inspect"
	// OpServiceRestart restarts one service unit.
	OpServiceRestart Operation = "service.restart"
	// OpWebConfigValidate stages a candidate web-server configuration and asks
	// the real web server whether it is valid.
	//
	// It is the first operation whose input names a PATH, which is why it is
	// also the first to exercise the agent's path confinement. Validation
	// necessarily writes — nginx -t must be pointed at a file — so the write is
	// confined to a staging root the descriptor declares, and the LIVE
	// configuration is never touched. That distinction is the whole safety
	// story of this operation: it cannot break a running site.
	OpWebConfigValidate Operation = "web.config.validate" //nolint:gosec // G101: an operation wire name, not a credential
	// OpSiteLogsTail returns a bounded tail of one site's access or error log,
	// read from the node on demand. Per docs/decisions.md D-005 no log content is
	// ever copied into the control-plane database; this is a read-through to the
	// host that serves the site. It is read-only and touches no subprocess: the
	// agent opens a confined path and reads its final bytes.
	OpSiteLogsTail Operation = "site.logs.tail" //nolint:gosec // G101: an operation wire name, not a credential
	// OpWebConfigApply writes a validated candidate to the LIVE site config path
	// and reloads the web server. It is the most dangerous operation in the
	// registry: unlike web.config.validate, it touches what a running site serves.
	//
	// The safety story is the six-step order inside the executor: back up the
	// current known-good file, write the candidate, run nginx -t against the FULL
	// configuration, and only then reload. Any failure restores the backup and
	// reloads again, so an invalid candidate can never replace the active
	// known-good configuration (Phase 3 gate, IMPLEMENTATION_PLAN.md L87).
	OpWebConfigApply Operation = "web.config.apply" //nolint:gosec // G101: an operation wire name, not a credential
	// OpAppDeploy fetches a Git revision, builds it, writes a managed systemd
	// service unit, switches the atomic symlink to the new release directory, and
	// verifies the application is healthy. On any failure after the symlink
	// already existed the previous release is restored.
	//
	// It is the first operation whose build step runs a user-configured program
	// on the node. The program must come from the per-runtime allowlist the agent
	// detects at startup; an unrecognized program name is refused before any
	// process starts. Arguments are passed as an argv slice, never interpreted by
	// a shell.
	OpAppDeploy Operation = "app.deploy" //nolint:gosec // G101: an operation wire name, not a credential

	// OpDatabaseManage creates or drops a database or database user on the local
	// engine (PostgreSQL or MariaDB). Authentication uses the OS-level peer/socket
	// auth for the jawaker system user — no root credential is stored or sent
	// (SECURITY.md §6, PRD.md §12.4).
	//
	// There is deliberately no generic SQL execution path: every action is an
	// enumerated value (create_db, drop_db, create_user, drop_user, set_grants)
	// and the agent refuses any action not in the allowlist.
	OpDatabaseManage Operation = "database.manage" //nolint:gosec // G101: an operation wire name, not a credential

	// OpDatabaseDump runs pg_dump or mariadb-dump to a path confined inside
	// /var/lib/jawaker/db-dumps/. The result includes the SHA-256 and byte size
	// so the controller can verify receipt without re-reading the file.
	OpDatabaseDump Operation = "database.dump" //nolint:gosec // G101: an operation wire name, not a credential

	// OpDatabaseRestore runs pg_restore or mariadb from a dump file confined
	// inside /var/lib/jawaker/db-dumps/. It is idempotent: applying the same
	// dump file twice leaves the database in the same final state.
	OpDatabaseRestore Operation = "database.restore" //nolint:gosec // G101: an operation wire name, not a credential

	// OpDatabaseMetrics collects point-in-time connection counts and slow-query
	// snapshots. It is read-only: no process is spawned, no file is written.
	// PostgreSQL uses pg_stat_activity + pg_stat_statements; MariaDB uses
	// information_schema.PROCESSLIST and slow-query log tail.
	OpDatabaseMetrics Operation = "database.metrics" //nolint:gosec // G101: an operation wire name, not a credential

	// OpDatabaseUpgrade performs a safe engine version bump (pg_upgrade /
	// mariadb-upgrade). It MUST write a pre-upgrade dump before touching the
	// engine — the upgrade is refused if the pre-dump path is empty. Rollback
	// uses the pre-upgrade dump to restore the database if the upgrade fails.
	OpDatabaseUpgrade Operation = "database.upgrade" //nolint:gosec // G101: an operation wire name, not a credential

	// OpFileArchive packs a closed set of source paths into a tar.gz archive
	// under /var/lib/jawaker/backups. Sources are confined to reviewed roots
	// (app releases and the nginx config tree); there is no way to name an
	// arbitrary path, which is what keeps this from being a read-anything
	// primitive.
	OpFileArchive Operation = "file.archive" //nolint:gosec // G101: an operation wire name, not a credential

	// OpFileRestore extracts a previously created archive into a destination
	// directory under the same reviewed roots. Extraction never follows
	// absolute paths or ".." members out of the destination (tar refuses them
	// by default; the archive path itself is confined before tar runs).
	OpFileRestore Operation = "file.restore" //nolint:gosec // G101: an operation wire name, not a credential

	// OpContainerList reports the containers running on this node, filtered
	// to those belonging to the requested project. It invokes 'docker ps'
	// with a fixed argument vector; no shell is involved.
	OpContainerList Operation = "container.list" //nolint:gosec // G101: an operation wire name, not a credential

	// OpContainerInspect reports the full state of one container identified
	// by its name. The name must match the container.name-safe pattern so it
	// cannot be used to inject arguments into the docker CLI.
	OpContainerInspect Operation = "container.inspect" //nolint:gosec // G101: an operation wire name, not a credential

	// OpContainerLogs returns a bounded, redacted tail of one container's
	// stdout/stderr. Secret values from the container's environment are
	// stripped before the tail leaves the agent; the gate is enforced at the
	// agent, not the caller, because the agent is the only party with access
	// to the raw log stream.
	OpContainerLogs Operation = "container.logs" //nolint:gosec // G101: an operation wire name, not a credential

	// OpNetFirewallList reads the current iptables/nftables ruleset from the
	// node and returns it as a structured chain/rule list. It is read-only:
	// no process is spawned that changes state, and the output path is
	// /proc/net (procfs, not a user-writable path).
	OpNetFirewallList Operation = "net.firewall.list" //nolint:gosec // G101: an operation wire name, not a credential

	// OpNetPortInventory runs 'ss -tlunp' (socket statistics) and returns the
	// set of bound TCP/UDP ports with their owning process. Read-only.
	OpNetPortInventory Operation = "net.port.inventory" //nolint:gosec // G101: an operation wire name, not a credential

	// OpNetDiag runs a confined ping or traceroute to a validated target.
	// The target is validated against a strict character allowlist before any
	// process is spawned; it is passed as a single argv element. The mode
	// enum limits the operation to known diagnostic tools; no shell is used.
	OpNetDiag Operation = "net.diag" //nolint:gosec // G101: an operation wire name, not a credential

	// OpSecHardeningScan runs a hardening check suite on the node and returns
	// structured findings with severity, status, and remediation hints.
	// The scan reads configuration files only; it never writes or executes
	// arbitrary commands.
	OpSecHardeningScan Operation = "sec.hardening.scan"

	// OpSecSSHPosture reads the sshd_config and active-session data to assess
	// the SSH attack surface. Read-only; no sshd is restarted.
	OpSecSSHPosture Operation = "sec.ssh.posture"

	// OpSecBanList reads the current ban list from fail2ban or crowdsec.
	// The source adapter is selected by the Source field; both are read-only.
	OpSecBanList Operation = "sec.ban.list"
)

// Scope describes what an operation may touch. It is part of the descriptor, not
// documentation: it is what a reviewer checks to answer "what can this operation
// reach?" without reading the implementation.
type Scope struct {
	// FilesystemRead and FilesystemWrite are paths the operation may touch.
	// Empty means none.
	FilesystemRead  []string
	FilesystemWrite []string
	// Services are the unit names the operation may act on. A wildcard is NOT
	// accepted: an operation that can restart "any unit" is a generic remote
	// execution primitive with extra steps.
	Services []string
	// Network describes listening/connecting behavior, for review purposes.
	Network string
}

// RetryPolicy states whether an operation may be retried and, if so, how.
type RetryPolicy struct {
	// Idempotent reports that repeating the operation produces the same state.
	Idempotent bool
	// MaxAttempts bounds automatic retries. Zero means no automatic retry.
	MaxAttempts int
}

// Descriptor describes one operation completely.
//
// SECURITY.md §7 requires each privileged operation to declare capability, input
// schema, validation, OS support, scope, lock requirements, timeout, audit
// event, retry semantics, and rollback behavior. Every one of those is a field
// here, so an operation cannot be registered without answering them.
type Descriptor struct {
	// Operation is the wire name.
	Operation Operation
	// Permission is the RBAC permission the CONTROLLER requires of the human or
	// token that triggered this. It is enforced controller-side; the agent
	// enforces scope, not RBAC, because the agent has no notion of users.
	Permission string
	// InputSchema describes the accepted input, for error messages and docs.
	InputSchema string
	// Validation describes how the agent re-validates input locally. An agent
	// must never trust controller-side validation alone (ARCHITECTURE.md §3.4:
	// "validates input again locally").
	Validation string
	// OSSupport names the OS families this operation works on, e.g. "linux".
	OSSupport []string
	// Scope is what the operation may touch.
	Scope Scope
	// LockKeys are per-resource lock names the controller must hold while the
	// operation runs, so two jobs cannot mutate one resource concurrently.
	LockKeys []string
	// Timeout bounds the operation.
	Timeout time.Duration
	// AuditAction is the audit event action string.
	AuditAction string
	// Retry states idempotency and retry bounds.
	Retry RetryPolicy
	// Rollback describes recovery if the operation fails partway. Empty means
	// there is nothing to undo: a read, or a restart that is its own recovery.
	Rollback string
	// Mutating reports whether the operation changes state.
	Mutating bool
}

// validate checks a descriptor is complete. Every field is required except the
// ones documented as optional, because a descriptor is a security artifact: an
// operation shipped with an unstated scope is an operation whose blast radius
// nobody reviewed.
func (d Descriptor) validate() error {
	var errs []error
	if d.Operation == "" {
		errs = append(errs, errors.New("operation name is required"))
	}
	if !permissionPattern.MatchString(d.Permission) {
		errs = append(errs, fmt.Errorf("permission %q is not a dotted permission name", d.Permission))
	}
	if strings.TrimSpace(d.InputSchema) == "" {
		errs = append(errs, errors.New("input schema is required"))
	}
	if strings.TrimSpace(d.Validation) == "" {
		errs = append(errs, errors.New("validation description is required"))
	}
	if len(d.OSSupport) == 0 {
		errs = append(errs, errors.New("at least one supported OS family is required"))
	}
	if d.Timeout <= 0 {
		errs = append(errs, errors.New("timeout must be positive"))
	}
	if strings.TrimSpace(d.AuditAction) == "" {
		errs = append(errs, errors.New("audit action is required"))
	}
	if d.Retry.MaxAttempts < 0 {
		errs = append(errs, errors.New("retry attempts cannot be negative"))
	}
	// A retried non-idempotent operation is a correctness bug waiting for a
	// network blip, so the combination is refused outright rather than left to
	// the scheduler to get right.
	if !d.Retry.Idempotent && d.Retry.MaxAttempts > 0 {
		errs = append(errs, errors.New("a non-idempotent operation cannot declare automatic retries"))
	}
	// A mutating operation must declare what it touches. A read with no scope is
	// harmless; a write with none has not been reviewed.
	if d.Mutating && len(d.Scope.FilesystemWrite) == 0 && len(d.Scope.Services) == 0 && d.Scope.Network == "" {
		errs = append(errs, errors.New("a mutating operation must declare its scope"))
	}
	for _, name := range d.Scope.Services {
		if !ValidServiceName(name) {
			errs = append(errs, fmt.Errorf("scope service name %q is not a valid unit name", name))
		}
	}
	return errors.Join(errs...)
}

// permissionPattern matches the catalog's dotted permission keys.
var permissionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`)

// serviceNamePattern constrains a service unit name.
//
// This is an input-validation boundary, not a nicety. The value is passed to a
// privileged program as an argv element, so a name containing a path separator,
// whitespace, or a shell metacharacter is an injection vector if the executor
// ever changes shape. Being strict here means the executor cannot be attacked
// through this field no matter how it is refactored.
//
// systemd accepts `/` in template instance names; it is deliberately excluded
// here. Allowing a path separator in a value that reaches a privileged program
// is not worth the convenience, and the units JAWAKER manages do not need it.
var serviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._:-]{0,127}$`)

// ValidServiceName reports whether a unit name is acceptable.
//
// Exported so the controller validates at its own boundary too: refusing bad
// input at the edge gives a clear 400, while the agent's refusal is the backstop
// that matters if the edge check is ever removed.
func ValidServiceName(name string) bool {
	return serviceNamePattern.MatchString(name)
}

// Request is the envelope for a controller→node operation.
type Request struct {
	ProtocolVersion int       `json:"protocol_version"`
	Operation       Operation `json:"operation"`
	// RequestID correlates this call with the HTTP request and the audit trail.
	RequestID string `json:"request_id"`
	// JobID and RevisionID correlate with the job engine and change history.
	JobID      string `json:"job_id,omitempty"`
	RevisionID string `json:"revision_id,omitempty"`
	// Deadline is when the node must abandon the operation. An absolute instant
	// rather than a duration, because a duration means different things to two
	// machines whose clocks differ.
	Deadline time.Time `json:"deadline"`
	// Target names the scoped object the operation acts on, e.g. a unit name.
	// It is separate from Input so the scope check runs before the payload is
	// decoded: the controller states WHAT it wants to touch before saying HOW.
	Target string `json:"target,omitempty"`
	// Input is the operation-specific payload, raw so the envelope stays
	// operation-agnostic. The agent decodes it into the operation's typed struct
	// with unknown fields refused.
	Input json.RawMessage `json:"input,omitempty"`
}

// Response is the envelope for the node's reply.
type Response struct {
	ProtocolVersion int       `json:"protocol_version"`
	Operation       Operation `json:"operation"`
	RequestID       string    `json:"request_id"`
	OK              bool      `json:"ok"`
	// Result is the operation's structured output when OK.
	Result json.RawMessage `json:"result,omitempty"`
	// Error describes a failure. Nil when OK.
	Error *Error `json:"error,omitempty"`
	// CompletedAt is when the node finished, for latency accounting.
	CompletedAt time.Time `json:"completed_at"`
}

// Error is the node's structured failure. It mirrors the API's error shape so a
// node fault reaches a user without translating two vocabularies.
type Error struct {
	// Code is a stable machine code, e.g. "unsupported_operation".
	Code string `json:"code"`
	// Message is a safe human description. It must never contain node-internal
	// paths or credentials.
	Message string `json:"message"`
	// Retryable reports whether repeating the same request could succeed.
	Retryable bool `json:"retryable"`
	// Details carries non-secret structured context.
	Details map[string]any `json:"details,omitempty"`
}

// Error codes. These are stable: a controller branches on them.
const (
	// CodeUnsupportedOperation means the agent does not serve this operation.
	// This is the refusal that makes the closed registry real.
	CodeUnsupportedOperation = "unsupported_operation"
	// CodeInvalidInput means the payload did not match the operation's schema.
	CodeInvalidInput = "invalid_input"
	// CodeScopeViolation means the target is outside the operation's scope.
	CodeScopeViolation = "scope_violation"
	// CodeDeadlineExceeded means the operation ran past its deadline.
	CodeDeadlineExceeded = "deadline_exceeded"
	// CodeUnsupportedOS means the operation is not available on this OS family.
	CodeUnsupportedOS = "unsupported_os"
	// CodeNotAvailable means a required facility is missing (no systemd, binary
	// absent). Distinct from unsupported_os: the OS may be fine while the
	// facility is not installed.
	CodeNotAvailable = "not_available"
	// CodeExecutionFailed means the operation ran and failed.
	CodeExecutionFailed = "execution_failed"
	// CodeProtocolMismatch means the peer speaks a different protocol version.
	CodeProtocolMismatch = "protocol_mismatch"
	// CodeNotFound means the target does not exist.
	CodeNotFound = "not_found"
)

// Error implements the error interface so a decoded node error can be returned
// as an ordinary Go error.
func (e *Error) Error() string {
	if e == nil {
		return "nodewire: nil error"
	}
	return fmt.Sprintf("nodewire: %s: %s", e.Code, e.Message)
}

// NewError builds a node error.
func NewError(code, message string, retryable bool, details map[string]any) *Error {
	return &Error{Code: code, Message: message, Retryable: retryable, Details: details}
}

// maxInputBytes bounds a request payload. A node accepts small typed payloads; an
// unbounded body on a privileged daemon is a denial-of-service surface.
const maxInputBytes = 64 * 1024

// EncodeRequest validates a request against the registry and serializes it.
//
// Validating here is not politeness: encoding a request for an operation with no
// descriptor produces a payload no agent can serve, and failing at the sender
// with a clear cause beats a confusing refusal on the far side.
func EncodeRequest(req Request) ([]byte, error) {
	desc, ok := Lookup(req.Operation)
	if !ok {
		return nil, fmt.Errorf("%w: %q has no descriptor", ErrUnknownOperation, req.Operation)
	}
	if req.RequestID == "" {
		return nil, fmt.Errorf("%w: request id is required", ErrMalformedRequest)
	}
	if req.Deadline.IsZero() {
		return nil, fmt.Errorf("%w: deadline is required", ErrMalformedRequest)
	}
	if len(req.Input) > maxInputBytes {
		return nil, fmt.Errorf("%w: input is %d bytes, limit is %d", ErrMalformedRequest, len(req.Input), maxInputBytes)
	}
	if err := validateTarget(desc, req.Target); err != nil {
		return nil, err
	}
	req.ProtocolVersion = ProtocolVersion
	return json.Marshal(req)
}

// DecodeRequest parses a request and confirms the operation is one this node
// serves.
//
// served is the set of operations the caller implements. Passing it in rather
// than treating the registry as the answer matters: the registry describes the
// protocol, while a given build may implement a subset, and the refusal must
// reflect what THIS node can do.
func DecodeRequest(body []byte, served map[Operation]bool) (Request, Descriptor, error) {
	var req Request
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return Request{}, Descriptor{}, fmt.Errorf("%w: %v", ErrMalformedRequest, err)
	}
	// A trailing value would otherwise be silently ignored, letting a request
	// carry something the node never sees.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Request{}, Descriptor{}, fmt.Errorf("%w: body contains more than one JSON value", ErrMalformedRequest)
	}

	if req.ProtocolVersion != ProtocolVersion {
		return Request{}, Descriptor{}, fmt.Errorf("%w: peer speaks version %d, this node speaks %d",
			ErrProtocolMismatch, req.ProtocolVersion, ProtocolVersion)
	}

	desc, ok := Lookup(req.Operation)
	if !ok {
		// Unknown to the protocol entirely.
		return Request{}, Descriptor{}, fmt.Errorf("%w: %q", ErrUnknownOperation, req.Operation)
	}
	if !served[req.Operation] {
		// Known to the protocol, unimplemented in this build. Refused the same
		// way: from the caller's perspective the operation is not available, and
		// distinguishing the two would leak build details.
		return Request{}, Descriptor{}, fmt.Errorf("%w: %q is not served by this node",
			ErrUnknownOperation, req.Operation)
	}
	if req.RequestID == "" {
		return Request{}, Descriptor{}, fmt.Errorf("%w: request id is required", ErrMalformedRequest)
	}
	if req.Deadline.IsZero() {
		return Request{}, Descriptor{}, fmt.Errorf("%w: deadline is required", ErrMalformedRequest)
	}
	if len(req.Input) > maxInputBytes {
		return Request{}, Descriptor{}, fmt.Errorf("%w: input exceeds %d bytes", ErrMalformedRequest, maxInputBytes)
	}
	if err := validateTarget(desc, req.Target); err != nil {
		return Request{}, Descriptor{}, err
	}
	return req, desc, nil
}

// validateTarget checks a request's target against the descriptor's scope.
//
// An operation that declares no services accepts no target at all, so a
// whole-node operation cannot be tricked into naming one. An operation that
// declares services REQUIRES a target and only the listed ones: a restart with
// no named unit is not a meaningful request, and defaulting to "all" would be
// catastrophic.
func validateTarget(desc Descriptor, target string) error {
	if len(desc.Scope.Services) == 0 {
		if target != "" {
			return fmt.Errorf("%w: operation %q does not accept a target", ErrScopeViolation, desc.Operation)
		}
		return nil
	}
	if target == "" {
		return fmt.Errorf("%w: operation %q requires a target", ErrScopeViolation, desc.Operation)
	}
	if !ValidServiceName(target) {
		return fmt.Errorf("%w: target %q is not a valid unit name", ErrScopeViolation, target)
	}
	for _, allowed := range desc.Scope.Services {
		if allowed == target {
			return nil
		}
	}
	return fmt.Errorf("%w: target %q is not in the scope of %q", ErrScopeViolation, target, desc.Operation)
}

// DecodeInput decodes an operation's typed payload, refusing unknown fields.
//
// DisallowUnknownFields is the point: a caller sending a field the operation
// does not define is either out of date or probing, and silently ignoring it
// would mean applying a partially-understood instruction.
func DecodeInput[T any](req Request) (T, error) {
	var out T
	if len(req.Input) == 0 {
		return out, nil
	}
	dec := json.NewDecoder(bytes.NewReader(req.Input))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("%w: %v", ErrInvalidInput, err)
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return out, fmt.Errorf("%w: input contains more than one JSON value", ErrInvalidInput)
	}
	return out, nil
}

// EncodeResult serializes an operation's output for a Response.
func EncodeResult(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("nodewire: encode result: %w", err)
	}
	return b, nil
}

// EncodeResponse serializes a response, stamping the protocol version and the
// completion time so no caller has to add either itself.
func EncodeResponse(resp Response, now time.Time) ([]byte, error) {
	resp.ProtocolVersion = ProtocolVersion
	if resp.CompletedAt.IsZero() {
		resp.CompletedAt = now.UTC()
	}
	return json.Marshal(resp)
}

// DecodeResponse parses a node's reply.
func DecodeResponse(body []byte) (Response, error) {
	var resp Response
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrMalformedRequest, err)
	}
	if resp.ProtocolVersion != ProtocolVersion {
		return Response{}, fmt.Errorf("%w: node speaks version %d, this controller speaks %d",
			ErrProtocolMismatch, resp.ProtocolVersion, ProtocolVersion)
	}
	// ok and error must agree. A response that is both, or neither, is
	// ambiguous, and resolving that ambiguity in the caller is how a failure
	// becomes a success.
	switch {
	case resp.OK && resp.Error != nil:
		return Response{}, fmt.Errorf("%w: response is both ok and an error", ErrMalformedRequest)
	case !resp.OK && resp.Error == nil:
		return Response{}, fmt.Errorf("%w: response is neither ok nor an error", ErrMalformedRequest)
	}
	return resp, nil
}

// Sentinel errors, for the transport layer to map onto the wire codes above.
var (
	// ErrUnknownOperation means the operation has no descriptor or is not served
	// by this node.
	ErrUnknownOperation = errors.New("unknown operation")
	// ErrMalformedRequest means the envelope could not be parsed.
	ErrMalformedRequest = errors.New("malformed request")
	// ErrProtocolMismatch means the peer speaks a different protocol version.
	ErrProtocolMismatch = errors.New("protocol version mismatch")
	// ErrInvalidInput means the payload did not match the operation's schema.
	ErrInvalidInput = errors.New("invalid input")
	// ErrScopeViolation means the target is outside the operation's scope.
	ErrScopeViolation = errors.New("scope violation")
)

// CodeFor maps a sentinel error onto the wire error code a caller branches on.
func CodeFor(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrUnknownOperation):
		return CodeUnsupportedOperation
	case errors.Is(err, ErrProtocolMismatch):
		return CodeProtocolMismatch
	case errors.Is(err, ErrInvalidInput), errors.Is(err, ErrMalformedRequest):
		return CodeInvalidInput
	case errors.Is(err, ErrScopeViolation):
		return CodeScopeViolation
	default:
		return CodeExecutionFailed
	}
}
