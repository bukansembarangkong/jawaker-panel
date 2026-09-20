//go:build integration

package nodes

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
)

// The heartbeat endpoint over REAL mutual TLS.
//
// A handler test that called handleHeartbeat directly would prove nothing about
// the property that matters here: the peer identity must come from the VERIFIED
// CERTIFICATE, not from the body. A direct call has no certificate, so it would
// either fail for the wrong reason or be written to fake one — and the check under
// test is precisely that the certificate and the claim must agree.

// heartbeatServer is a real node listener plus a client that can present a node
// certificate.
type heartbeatServer struct {
	harness  *harness
	address  string
	serveErr chan error
	cancel   context.CancelFunc
}

// newNodeListenerHarness starts the controller's node-facing listener as
// production wires it: the same Handlers, the same TLS configuration, a real
// socket.
func newNodeListenerHarness(t *testing.T) *heartbeatServer {
	t.Helper()
	h := newHarness(t)

	handlers, err := NewHandlers(HandlerOptions{
		Store:     h.store,
		Authority: h.auth,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:       h.clock.now,
	})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	listener, err := NewNodeListener(NodeListenerOptions{
		Handlers: handlers,
		Logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:      h.clock.now,
	})
	if err != nil {
		t.Fatalf("NewNodeListener: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveErr := make(chan error, 1)
	go func() { serveErr <- listener.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-serveErr:
		case <-time.After(5 * time.Second):
			t.Error("the node listener did not shut down within 5 seconds")
		}
	})

	return &heartbeatServer{
		harness:  h,
		address:  ln.Addr().String(),
		serveErr: serveErr,
		cancel:   cancel,
	}
}

// clientFor builds an mTLS client presenting one node's certificate, pinning the
// NODE root the way a real agent does.
func (s *heartbeatServer) clientFor(t *testing.T, leaf *pki.Leaf) *http.Client {
	t.Helper()
	// The agent verifies the CONTROLLER on this connection: it pins the
	// controller root and expects a controller identity. Pinning the node root
	// here would be checking the wrong side of the mesh.
	verifier, err := pki.NewVerifier(pki.VerifierOptions{
		RootPEM: s.harness.auth.ControllerCertPEM(),
		Kind:    pki.KindController,
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tlsConfig, err := pki.NewTLSClientConfig(pki.TLSClientOptions{
		CertPEM:  leaf.CertPEM(),
		KeyPEM:   leaf.KeyPEM(),
		Verifier: verifier,
	})
	if err != nil {
		t.Fatalf("NewTLSClientConfig: %v", err)
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig}}
}

// enrollNode creates a server row and returns its id, plus a leaf for it.
func (s *heartbeatServer) enrollNode(t *testing.T, name string) (string, *pki.Leaf) {
	t.Helper()
	token := makeToken(t, s.harness, name)
	result, err := redeemToken(t, s.harness, token)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	// IssueNodeLeaf generates the key pair, which is what a test needs: the
	// client side must hold a private key to complete a handshake. Enrollment
	// itself uses the key-based path, so this is a deliberate shortcut for the
	// client's credential, not a change to how enrollment works.
	leaf, err := s.harness.auth.IssueNodeLeaf(result.Server.ID)
	if err != nil {
		t.Fatalf("IssueNodeLeaf: %v", err)
	}
	// The certificate must be recorded, or the revocation check refuses it.
	if _, err := s.harness.pool.Exec(s.harness.ctx, `
		INSERT INTO node_certificates (serial, server_id, fingerprint, not_before, not_after)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (serial) DO NOTHING`,
		leaf.SerialHex(), result.Server.ID, leaf.Fingerprint(),
		leaf.Cert().NotBefore, leaf.Cert().NotAfter); err != nil {
		t.Fatalf("record certificate: %v", err)
	}
	return result.Server.ID, leaf
}

// postHeartbeat sends a heartbeat and returns the status.
func (s *heartbeatServer) postHeartbeat(t *testing.T, client *http.Client, payload nodewire.HeartbeatPayload) int {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	resp, err := client.Post("https://"+s.address+nodewire.HeartbeatPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST heartbeat: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func validHeartbeat(serverID string) nodewire.HeartbeatPayload {
	return nodewire.HeartbeatPayload{
		ServerID: serverID,
		Reported: nodewire.HeartbeatInput{
			ObservedAt:    time.Now().UTC(),
			UptimeSeconds: 3600,
			Load1Milli:    125,
			MemTotalBytes: 8 << 30,
			MemUsedBytes:  2 << 30,
			WorkloadCount: 3,
		},
		AgentVersion: "test-agent",
	}
}

// --- the positive path --------------------------------------------------------

// A node reporting as ITSELF over mutual TLS is accepted, and the observation is
// recorded.
func TestHeartbeatAcceptedFromMatchingCertificate(t *testing.T) {
	s := newNodeListenerHarness(t)
	serverID, leaf := s.enrollNode(t, "hb-ok")
	client := s.clientFor(t, leaf)

	if status := s.postHeartbeat(t, client, validHeartbeat(serverID)); status != http.StatusOK {
		t.Fatalf("status = %d, want 200", status)
	}

	// The observation landed, and the server rollup followed it.
	var count int
	if err := s.harness.pool.QueryRow(s.harness.ctx,
		`SELECT count(*) FROM node_heartbeats WHERE server_id = $1`, serverID).Scan(&count); err != nil {
		t.Fatalf("count heartbeats: %v", err)
	}
	if count != 1 {
		t.Errorf("%d heartbeat rows, want 1", count)
	}
	server, err := s.harness.store.GetServer(s.harness.ctx, serverID)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if server.LastSeenAt == nil {
		t.Error("last_seen_at is still null after an accepted heartbeat")
	}
}

// --- the check that matters ---------------------------------------------------

// A node must NOT be able to report as a DIFFERENT node.
//
// This is the assertion that a mutation removing the certificate-vs-claim
// comparison fails, and it is the reason the check exists: without it any enrolled
// node could mark a colleague offline, or feed it a load figure that trips an
// alert nobody can explain.
func TestHeartbeatRefusesClaimedIdentityThatIsNotTheCertificate(t *testing.T) {
	s := newNodeListenerHarness(t)

	victimID, _ := s.enrollNode(t, "hb-victim")
	attackerID, attackerLeaf := s.enrollNode(t, "hb-attacker")

	client := s.clientFor(t, attackerLeaf)

	// The attacker's certificate is valid and its own server exists. The ONLY
	// thing wrong with this request is that it claims to be the victim.
	status := s.postHeartbeat(t, client, validHeartbeat(victimID))
	if status == http.StatusOK {
		t.Fatal("a node reported a heartbeat as a DIFFERENT node; the certificate is not what decides identity")
	}
	if status < 400 {
		t.Errorf("status = %d, want a client error", status)
	}

	// And the victim's own last_seen_at must be untouched: the refusal has to
	// leave no trace of the attacker's reading.
	victim, err := s.harness.store.GetServer(s.harness.ctx, victimID)
	if err != nil {
		t.Fatalf("GetServer(victim): %v", err)
	}
	if victim.LastSeenAt != nil {
		t.Error("a refused heartbeat still updated the victim's last_seen_at")
	}
	var rows int
	if err := s.harness.pool.QueryRow(s.harness.ctx,
		`SELECT count(*) FROM node_heartbeats WHERE server_id = $1`, victimID).Scan(&rows); err != nil {
		t.Fatalf("count heartbeats: %v", err)
	}
	if rows != 0 {
		t.Errorf("%d heartbeat rows were written for the victim, want 0", rows)
	}

	// The attacker's OWN identity still works, so the refusal is about the
	// mismatch rather than about the certificate being rejected outright.
	if status := s.postHeartbeat(t, client, validHeartbeat(attackerID)); status != http.StatusOK {
		t.Errorf("the attacker's own heartbeat was refused too: status %d", status)
	}
}

// A heartbeat with IMPOSSIBLE readings is refused rather than clamped: a clamped
// value in a time series is a lie nobody can discover afterwards.
func TestHeartbeatRefusesImpossibleReadings(t *testing.T) {
	s := newNodeListenerHarness(t)
	serverID, leaf := s.enrollNode(t, "hb-impossible")
	client := s.clientFor(t, leaf)

	cases := map[string]func(*nodewire.HeartbeatPayload){
		"used exceeds total": func(p *nodewire.HeartbeatPayload) {
			p.Reported.MemTotalBytes = 1 << 20
			p.Reported.MemUsedBytes = 2 << 20
		},
		"negative uptime":   func(p *nodewire.HeartbeatPayload) { p.Reported.UptimeSeconds = -1 },
		"negative load":     func(p *nodewire.HeartbeatPayload) { p.Reported.Load1Milli = -1 },
		"missing timestamp": func(p *nodewire.HeartbeatPayload) { p.Reported.ObservedAt = time.Time{} },
		"negative memory":   func(p *nodewire.HeartbeatPayload) { p.Reported.MemTotalBytes = -1 },
	}
	for name, mutate := range cases {
		payload := validHeartbeat(serverID)
		mutate(&payload)
		if status := s.postHeartbeat(t, client, payload); status == http.StatusOK {
			t.Errorf("%s: an impossible reading was accepted", name)
		}
	}

	// Nothing was written for any of them.
	var rows int
	if err := s.harness.pool.QueryRow(s.harness.ctx,
		`SELECT count(*) FROM node_heartbeats WHERE server_id = $1`, serverID).Scan(&rows); err != nil {
		t.Fatalf("count heartbeats: %v", err)
	}
	if rows != 0 {
		t.Errorf("%d heartbeat rows were written for impossible readings, want 0", rows)
	}
}

// A heartbeat from an anonymous peer must not reach the handler at all: the
// listener requires a client certificate.
func TestHeartbeatRefusesAnonymousPeer(t *testing.T) {
	s := newNodeListenerHarness(t)
	serverID, _ := s.enrollNode(t, "hb-anon")

	// A pool that trusts the controller's serving certificate, so the handshake
	// gets far enough to be refused for the MISSING CLIENT CERTIFICATE rather
	// than for the server's own name.
	rootCert, err := pki.DecodeCertPEM(string(s.harness.auth.ControllerCertPEM()))
	if err != nil {
		t.Fatalf("decode controller root: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(rootCert)
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
	body, err := json.Marshal(validHeartbeat(serverID))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := client.Post("https://"+s.address+nodewire.HeartbeatPath,
		"application/json", bytes.NewReader(body)); err == nil {
		t.Fatal("an anonymous peer completed a heartbeat; the listener did not require a client certificate")
	}
}

// A PLAINTEXT request must fail.
//
// This is a regression guard, and it guards a bug that actually happened: Serve
// set http.Server.TLSConfig and then called Serve, which IGNORES that field — so
// the listener served plaintext and the required-client-certificate verifier never
// ran. Every other test in this file speaks TLS, so none of them could notice;
// this one is the only assertion that the handshake happens at all.
func TestHeartbeatListenerRefusesPlaintext(t *testing.T) {
	s := newNodeListenerHarness(t)

	conn, err := net.DialTimeout("tcp", s.address, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := "POST " + nodewire.HeartbeatPath + " HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}"
	_, _ = conn.Write([]byte(req))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	got := string(buf[:n])

	// Go's TLS server answers a plaintext HTTP request with a specific sentinel
	// and NOTHING from the mux. That sentinel is PROOF the handshake is enforced:
	// a listener serving plaintext would have routed this to the handler and
	// returned a JSON body. The bug this guards against served exactly that.
	if strings.Contains(got, `"status":"ok"`) || strings.Contains(got, `"request_id"`) {
		t.Fatalf("the node listener served a plaintext request through its handler:\n%s", got)
	}
	if !strings.Contains(got, "Client sent an HTTP request to an HTTPS server") &&
		!strings.Contains(got, "HTTP/1.0 400") {
		t.Fatalf("expected the TLS plaintext sentinel, got:\n%q", got)
	}
}

// A heartbeat with an unknown field is refused, so a request cannot carry
// something the controller never inspects.
func TestHeartbeatRefusesUnknownField(t *testing.T) {
	s := newNodeListenerHarness(t)
	serverID, leaf := s.enrollNode(t, "hb-unknown")
	client := s.clientFor(t, leaf)

	raw := `{"server_id":"` + serverID + `","agent_version":"test","report":{` +
		`"observed_at":"` + time.Now().UTC().Format(time.RFC3339) + `","uptime_seconds":1,` +
		`"load1_milli":0,"mem_total_bytes":0,"mem_used_bytes":0,"workload_count":0,` +
		`"skip_validation":true}}`
	resp, err := client.Post("https://"+s.address+nodewire.HeartbeatPath, "application/json", bytes.NewReader([]byte(raw)))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusOK {
		t.Fatal("a heartbeat with an unknown field was accepted")
	}
}

// --- revocation takes effect --------------------------------------------------

// A revoked certificate must be refused, even though the handshake succeeded: the
// serial is re-checked at the handler so a revocation that lands between the
// handshake and the request still takes effect.
func TestHeartbeatRefusesRevokedCertificate(t *testing.T) {
	s := newNodeListenerHarness(t)
	serverID, leaf := s.enrollNode(t, "hb-revoked")
	client := s.clientFor(t, leaf)

	if status := s.postHeartbeat(t, client, validHeartbeat(serverID)); status != http.StatusOK {
		t.Fatalf("setup heartbeat failed: status %d", status)
	}

	// Revoke the certificate the client is holding.
	if err := s.harness.store.RevokeCertificate(s.harness.ctx, serverID, leaf.SerialHex(), "test revocation"); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}

	// The SAME TLS session is reused by the transport (keep-alive), which is the
	// case the handler's own check exists for: the handshake already happened.
	if status := s.postHeartbeat(t, client, validHeartbeat(serverID)); status == http.StatusOK {
		t.Fatal("a revoked certificate was still able to report a heartbeat")
	}
}
