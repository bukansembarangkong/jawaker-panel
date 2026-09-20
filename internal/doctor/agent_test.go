package doctor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodeagent"
	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
)

// --- the agent checks ---------------------------------------------------------
//
// These are NOT integration tests against a live controller: the connectivity
// probe is skipped, so the report is deterministic on any platform and no network
// is required. What they do prove is that each check reports the CONDITION it
// found rather than a generic failure, which is the whole requirement a
// diagnostic has to meet.

// enrolledState writes a real, mutually-consistent node identity to disk, the way
// enrollment does. Using the production save path rather than hand-writing JSON
// is what makes these assertions meaningful: a state directory this helper built
// is one LoadState accepts.
//
// The leaf lives 20 days — long enough to sit outside the 7-day renewal window
// so the healthy path reports ok — and the authorities live 10 years, matching
// production. Tests that need expiry inject a clock rather than rebuilding this.
func enrolledState(t *testing.T) string {
	t.Helper()
	const (
		serverID      = "44444444-4444-4444-4444-444444444444"
		controllerID  = "55555555-5555-5555-5555-555555555555"
		address       = "127.0.0.1:9443"
		authorityLife = 10 * 365 * 24 * time.Hour
		identityLife  = 20 * 24 * time.Hour
	)

	// TWO authorities, matching the controller: the root the node pins is the
	// CONTROLLER root, and the certificate it holds is signed by the NODE
	// authority. One authority for both would be refused by pki.
	controllerCA, err := pki.NewCA("JAWAKER Controller CA (doctor test)", pki.KindController,
		time.Now().Add(authorityLife))
	if err != nil {
		t.Fatalf("NewCA(controller): %v", err)
	}
	nodeCA, err := pki.NewCA("JAWAKER Node CA (doctor test)", pki.KindNode,
		time.Now().Add(authorityLife))
	if err != nil {
		t.Fatalf("NewCA(node): %v", err)
	}
	leaf, err := nodeCA.IssueLeaf(pki.LeafParams{
		Identity: pki.Identity{Kind: pki.KindNode, ID: serverID},
		NotAfter: time.Now().Add(identityLife),
	})
	if err != nil {
		t.Fatalf("issue node leaf: %v", err)
	}

	dir := restrictedStateDir(t)
	if err := nodeagent.SaveIdentity(dir, leaf, controllerCA.CertPEM()); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	if err := nodeagent.SaveConfig(dir, nodeagent.Config{
		ServerID:              serverID,
		ControllerAddress:     address,
		ControllerID:          controllerID,
		ControllerFingerprint: controllerCA.Fingerprint(),
		EnrolledAt:            time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}
	return dir
}

// restrictedStateDir returns a temporary directory at mode 0700.
//
// t.TempDir() is os.Mkdir(dir, 0o777), which the umask reduces to 0755 on a
// Linux runner — and EnsureStateDir refuses a directory that group or others can
// reach, because the key inside may already have been exposed. Without this, every
// test below would fail on CI while passing on Windows.
func restrictedStateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: the agent requires 0700; this is the restrictive direction
		t.Fatalf("restrict the state directory: %v", err)
	}
	return dir
}

// agentReport runs the agent checks with the connectivity probe omitted.
func agentReport(t *testing.T, dir string) Report {
	t.Helper()
	return Agent(context.Background(), "test", AgentOptions{
		StateDir:         dir,
		SkipConnectivity: true,
	})
}

func statusOf(t *testing.T, r Report, name string) Check {
	t.Helper()
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no check named %q in the report", name)
	return Check{}
}

// THE HEALTHY PATH: a properly enrolled node reports healthy.
func TestAgentReportsAHealthyInstallation(t *testing.T) {
	report := agentReport(t, enrolledState(t))
	if !report.Healthy() {
		t.Fatalf("a properly enrolled node was reported unhealthy:\n%s", report.Text())
	}

	identity := statusOf(t, report, "node-identity")
	if identity.Status != StatusOK {
		t.Errorf("node-identity = %q (%s), want ok", identity.Status, identity.Detail)
	}
	// The evidence is the point: an operator must learn WHICH node and until
	// WHEN, not merely that the check passed.
	if identity.Evidence["server_id"] == nil || identity.Evidence["not_after"] == nil {
		t.Errorf("node-identity evidence is missing facts: %+v", identity.Evidence)
	}

	pin := statusOf(t, report, "pinned-controller")
	if pin.Status != StatusOK {
		t.Errorf("pinned-controller = %q (%s), want ok", pin.Status, pin.Detail)
	}
	if pin.Evidence["pinned_fingerprint"] == nil {
		t.Error("the pinned fingerprint is not reported, so an operator cannot compare it")
	}
}

// A MISSING state directory is reported as not enrolled, which is the actionable
// fact, rather than as a generic load failure.
func TestAgentReportsAMissingStateDirectory(t *testing.T) {
	report := agentReport(t, filepath.Join(t.TempDir(), "never-existed"))

	dir := statusOf(t, report, "state-directory")
	if dir.Status != StatusFail {
		t.Errorf("state-directory = %q, want fail", dir.Status)
	}
	if !containsAll(dir.Detail, "does not exist", "has not been enrolled") {
		t.Errorf("detail = %q, want it to say the host is not enrolled", dir.Detail)
	}
	// The dependent checks must SKIP rather than fail: the pin cannot be checked
	// when there is no identity, and reporting that as a second failure would
	// tell an operator to fix two things when there is one.
	if got := statusOf(t, report, "pinned-controller"); got.Status != StatusSkip {
		t.Errorf("pinned-controller = %q, want skip when there is no identity", got.Status)
	}
	if report.Healthy() {
		t.Error("a node with no identity was reported healthy")
	}
}

// A PERMISSIVE state directory is a hard failure, because the private key may
// already have been copied and nothing later can undo that.
func TestAgentReportsAPermissiveStateDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not meaningful on Windows")
	}
	dir := restrictedStateDir(t)
	if err := os.Chmod(dir, 0o755); err != nil { //nolint:gosec // G302: widening the mode IS the subject of this test
		t.Fatalf("chmod: %v", err)
	}

	check := statusOf(t, agentReport(t, dir), "state-directory")
	if check.Status != StatusFail {
		t.Errorf("state-directory = %q (%s), want fail", check.Status, check.Detail)
	}
	if !containsAll(check.Detail, "0755", "re-enroll") {
		t.Errorf("detail = %q, want it to name the mode and the remedy", check.Detail)
	}
}

// An EXPIRED node certificate is a failure, and a nearly-expired one a warning
// with a countdown: the two need different responses, and the distinction is the
// check's whole value.
//
// The clock is injected rather than the certificate backdated, because pki
// REFUSES to issue a leaf whose NotAfter is already in the past — a fabricated
// expired certificate is not constructible, and pretending otherwise would test
// something the system cannot produce.
func TestAgentReportsCertificateExpiry(t *testing.T) {
	dir := enrolledState(t)

	// Past the certificate's expiry. The fixture's leaf lives 20 days, so a
	// 21-day advance is beyond it.
	expired := Agent(context.Background(), "test", AgentOptions{
		StateDir:         dir,
		SkipConnectivity: true,
		Now:              func() time.Time { return time.Now().Add(21 * 24 * time.Hour) },
	})
	check := statusOf(t, expired, "node-identity")
	if check.Status != StatusFail {
		t.Errorf("expired certificate = %q (%s), want fail", check.Status, check.Detail)
	}
	if !containsAll(check.Detail, "expired") {
		t.Errorf("detail = %q, want it to say the certificate expired", check.Detail)
	}

	// Not yet expired but inside the 7-day renewal window: 20 days minus 14
	// leaves 6, so this is a warning with a countdown rather than a failure.
	soon := Agent(context.Background(), "test", AgentOptions{
		StateDir:         dir,
		SkipConnectivity: true,
		Now:              func() time.Time { return time.Now().Add(14 * 24 * time.Hour) },
	})
	check = statusOf(t, soon, "node-identity")
	if check.Status != StatusWarn {
		t.Errorf("expiring certificate = %q (%s), want warn", check.Status, check.Detail)
	}
	if !containsAll(check.Detail, "expires in", "re-enroll") {
		t.Errorf("detail = %q, want a countdown and the remedy", check.Detail)
	}
}

// A pinned root from the WRONG TRUST DOMAIN must be reported. This is the fault an
// operator cannot otherwise explain: a valid identity that refuses every
// connection, because a node authority was pinned where a controller authority
// belongs.
//
// What is deliberately NOT asserted here is an id mismatch with the root
// unchanged. pki compares a peer's identity at HANDSHAKE time, which needs a live
// peer, and LoadState already refuses a stored state whose certificate name
// disagrees with its configuration. So a wrong-kind root is the failure doctor can
// actually detect offline, and the test asserts the detectable one rather than an
// equality the design does not claim.
func TestAgentReportsAPinnedRootFromTheWrongTrustDomain(t *testing.T) {
	dir := restrictedStateDir(t)
	serverID := "77777777-7777-7777-7777-777777777777"

	// TWO authorities: the node certificate is signed by the node authority, and
	// the NODE root is pinned where the CONTROLLER root belongs.
	controllerCA, err := pki.NewCA("JAWAKER Controller CA (doctor test)", pki.KindController,
		time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("NewCA(controller): %v", err)
	}
	nodeCA, err := pki.NewCA("JAWAKER Node CA (doctor test)", pki.KindNode, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("NewCA(node): %v", err)
	}
	leaf, err := nodeCA.IssueLeaf(pki.LeafParams{
		Identity: pki.Identity{Kind: pki.KindNode, ID: serverID},
		NotAfter: time.Now().Add(12 * time.Hour),
	})
	if err != nil {
		t.Fatalf("issue node leaf: %v", err)
	}

	// SaveIdentity writes the pinned root, so passing the NODE root here is the
	// wrong-domain pin. LoadState builds a verifier while loading and refuses it,
	// which is why every dependent check reports a skip or failure naming the
	// cause rather than a misleading success.
	if err := nodeagent.SaveIdentity(dir, leaf, nodeCA.CertPEM()); err != nil {
		t.Fatalf("SaveIdentity: %v", err)
	}
	if err := nodeagent.SaveConfig(dir, nodeagent.Config{
		ServerID:              serverID,
		ControllerAddress:     "127.0.0.1:9443",
		ControllerID:          controllerCA.Fingerprint(),
		ControllerFingerprint: controllerCA.Fingerprint(),
		EnrolledAt:            time.Now().UTC(),
	}); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	report := agentReport(t, dir)
	if report.Healthy() {
		t.Fatalf("a node pinning the wrong trust domain was reported healthy:\n%s", report.Text())
	}
	// The identity check is where LoadState's refusal surfaces, and it must name
	// the pinned-root problem rather than merely "could not load".
	identity := statusOf(t, report, "node-identity")
	if identity.Status != StatusFail {
		t.Errorf("node-identity = %q (%s), want fail", identity.Status, identity.Detail)
	}
	if !containsAll(identity.Detail, "pinned controller root does not match") {
		t.Errorf("detail = %q, want it to name the pinned root as the cause", identity.Detail)
	}
}

// An identity with no private key cannot complete a handshake at all. That is a
// distinct fault from an expired certificate and is reported as its own.
func TestAgentReportsAnIdentityWithoutAKey(t *testing.T) {
	dir := enrolledState(t)
	identityPath := filepath.Join(dir, "node-identity.pem")
	raw, err := os.ReadFile(identityPath) //nolint:gosec // G304: path is this test's own fixture
	if err != nil {
		t.Fatalf("read identity: %v", err)
	}
	// Strip the PRIVATE KEY block, leaving the certificate. The file is then
	// well-formed and LoadState parses it, so the check exercises the key's
	// absence rather than a decode error.
	trimmed := stripPrivateKeyBlock(raw)
	if err := os.WriteFile(identityPath, []byte(trimmed), 0o600); err != nil { //nolint:gosec // G306: test fixture
		t.Fatalf("write identity: %v", err)
	}

	check := statusOf(t, agentReport(t, dir), "node-identity")
	if check.Status != StatusFail {
		t.Errorf("node-identity = %q (%s), want fail", check.Status, check.Detail)
	}
	if !containsAll(check.Detail, "no private key") {
		t.Errorf("detail = %q, want it to name the missing key", check.Detail)
	}
}

// stripPrivateKeyBlock removes the PRIVATE KEY PEM block from an identity file.
func stripPrivateKeyBlock(raw []byte) string {
	const beginKey = "-----BEGIN PRIVATE KEY-----"
	const endKey = "-----END PRIVATE KEY-----"
	s := string(raw)
	start := strings.Index(s, beginKey)
	end := strings.Index(s, endKey)
	if start < 0 || end < 0 || end < start {
		return s
	}
	return s[:start] + s[end+len(endKey):]
}

// Operation support must state what this host CAN do. Reporting green on a host
// where the agent will refuse every service operation is how a panel button ends
// up broken with no explanation.
func TestAgentReportsOperationSupportHonestly(t *testing.T) {
	check := statusOf(t, agentReport(t, enrolledState(t)), "operation-support")
	switch runtime.GOOS {
	case "linux":
		// Either systemd is present (ok) or it is not (warn). Both are honest;
		// what is not acceptable is a failure, because service management being
		// unavailable is a capability, not a fault.
		if check.Status == StatusFail {
			t.Errorf("operation-support = %q (%s), want ok or warn on linux", check.Status, check.Detail)
		}
	default:
		if check.Status != StatusWarn {
			t.Errorf("operation-support = %q (%s) on %s, want warn", check.Status, check.Detail, runtime.GOOS)
		}
		if !containsAll(check.Detail, runtime.GOOS, "unsupported") {
			t.Errorf("detail = %q, want it to name the platform and the consequence", check.Detail)
		}
	}
}

// The disk check must SKIP off Linux rather than report a fabricated number: a
// made-up figure in a diagnostic gets acted upon.
func TestAgentSkipsDiskOffLinux(t *testing.T) {
	check := statusOf(t, agentReport(t, enrolledState(t)), "disk")
	if runtime.GOOS == "linux" {
		if check.Status != StatusOK && check.Status != StatusWarn {
			t.Errorf("disk = %q (%s) on linux, want a real measurement", check.Status, check.Detail)
		}
		return
	}
	if check.Status != StatusSkip {
		t.Errorf("disk = %q (%s), want skip off linux", check.Status, check.Detail)
	}
}

// JSON output must carry the same facts the text does, so a monitoring system can
// consume it without scraping.
func TestAgentJSONReportIsComplete(t *testing.T) {
	report := agentReport(t, enrolledState(t))
	raw, err := report.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}
	for _, want := range []string{"node-identity", "pinned-controller", "server_id", "controller_id"} {
		if !containsAll(string(raw), want) {
			t.Errorf("JSON report is missing %q", want)
		}
	}
}

// containsAll reports whether s contains every needle, so assertions read as the
// facts they check rather than as a chain of boolean operators.
func containsAll(s string, needles ...string) bool {
	for _, n := range needles {
		if !strings.Contains(s, n) {
			return false
		}
	}
	return true
}
