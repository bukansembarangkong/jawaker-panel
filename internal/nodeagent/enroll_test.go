package nodeagent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
)

// testEnrollToken is a placeholder enrollment token, not a credential. It is a
// single shared constant so the gosec G101 suppression lives in exactly one
// place instead of at every call site.
const testEnrollToken = "jwenroll_placeholder" //nolint:gosec // G101: placeholder test value, never a real token
// enrollStub is a controller that answers the enrollment endpoint.
//
// It serves over TLS and returns a REAL controller root minted by pki, so the
// fingerprint the agent computes is a fingerprint of an actual certificate. A
// stub that returned arbitrary bytes would let the pinning check pass for the
// wrong reason — fingerprintPEM falls back to digesting raw bytes when the PEM
// does not parse, and that fallback would then be what the test exercised.
type enrollStub struct {
	url    string
	client *http.Client
	// rootPEM is the root the stub hands back, for a test that wants to pin it.
	rootPEM     []byte
	fingerprint string
}

// newEnrollStub starts a TLS enrollment endpoint with a genuine controller root.
func newEnrollStub(t *testing.T) *enrollStub {
	t.Helper()

	// TWO authorities, mirroring the real controller. The response returns the
	// CONTROLLER root for the agent to pin, while the certificate it issues is
	// signed by the NODE authority. Using one authority for both would be
	// refused by pki — the two trust domains may not cross — and the stub would
	// be exercising a configuration the controller cannot produce.
	controllerCA, err := pki.NewCA("JAWAKER Controller CA (test)", pki.KindController, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("NewCA(controller): %v", err)
	}
	nodeCA, err := pki.NewCA("JAWAKER Node CA (test)", pki.KindNode, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("NewCA(node): %v", err)
	}

	// httptest.NewTLSServer mints its own serving certificate, so no server
	// keypair is built here. The authorities are still real, because the
	// response's ROOT must be a genuine certificate for the fingerprint pin to
	// be exercised: fingerprintPEM falls back to digesting raw bytes when the PEM
	// does not parse, and that fallback would let the test pass for the wrong
	// reason.
	rootPEM := controllerCA.CertPEM()
	fingerprint := fingerprintPEM(rootPEM)
	serverID := "22222222-2222-2222-2222-222222222222"
	controllerID := "11111111-1111-1111-1111-111111111111"

	// The node's public key is unknown until the request arrives, so the issued
	// certificate is built per request from what the agent sent.
	mux := http.NewServeMux()
	mux.HandleFunc(nodewire.EnrollmentPath, func(w http.ResponseWriter, r *http.Request) {
		var req nodewire.EnrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, `{"error":{"code":"invalid_request"}}`, http.StatusBadRequest)
			return
		}
		pub, err := pki.DecodePublicKeyPEM(string(req.PublicKeyPEM))
		if err != nil {
			http.Error(w, `{"error":{"code":"invalid_request"}}`, http.StatusBadRequest)
			return
		}
		issued, err := nodeCA.IssueLeafForKey(pki.LeafParams{
			Identity: pki.Identity{Kind: pki.KindNode, ID: serverID},
			NotAfter: time.Now().Add(12 * time.Hour),
		}, pub)
		if err != nil {
			http.Error(w, `{"error":{"code":"internal"}}`, http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"server_id":              serverID,
			"node_uri":               pki.Identity{Kind: pki.KindNode, ID: serverID}.String(),
			"cert_pem":               issued.CertPEM(),
			"serial":                 issued.SerialHex(),
			"not_before":             issued.Cert().NotBefore,
			"not_after":              issued.Cert().NotAfter,
			"controller_id":          controllerID,
			"controller_root_pem":    rootPEM,
			"controller_fingerprint": fingerprint,
			"node_listener_address":  req.NodeAddress,
		})
	})

	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)

	// The agent verifies the controller the way an HTTPS client would at
	// enrollment (it has no pinned root yet), so the test client trusts the
	// stub's own certificate.
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())

	return &enrollStub{
		url:         strings.TrimSuffix(server.URL, "/"),
		rootPEM:     rootPEM,
		fingerprint: fingerprint,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					RootCAs:    pool,
					MinVersion: tls.VersionTLS12,
				},
			},
		},
	}
}

// TestEnrollSucceedsAgainstAPinnedController is the positive case for the same
// path: with the right pin, the identity is written and pairs with the key the
// agent generated.
func TestEnrollSucceedsAgainstAPinnedController(t *testing.T) {
	stateDir := t.TempDir()
	stub := newEnrollStub(t)

	state, err := Enroll(t.Context(), EnrollOptions{
		ControllerURL:                 stub.url,
		Token:                         testEnrollToken,
		ExpectedControllerFingerprint: stub.fingerprint,
		StateDir:                      stateDir,
		NodeAddress:                   "127.0.0.1:9443",
		AgentVersion:                  "test-agent",
		OSFamily:                      "linux",
		OSVersion:                     "test 1",
		HTTPClient:                    stub.client,
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if state.ServerID == "" {
		t.Error("the enrolled state has no server id")
	}
	if len(state.ControllerRootPEM) == 0 {
		t.Error("the pinned root was not stored")
	}
	if state.Identity == nil || !state.Identity.HasPrivateKey() {
		t.Fatal("the stored identity has no private key, so the node could not authenticate")
	}

	// The stored identity must RELOAD and still be valid: the on-disk form is
	// what the agent uses on the next start, and an identity that only exists in
	// memory is not an enrollment.
	reloaded, err := LoadState(stateDir)
	if err != nil {
		t.Fatalf("LoadState after enrollment: %v", err)
	}
	if reloaded.ServerID != state.ServerID {
		t.Errorf("reloaded server id = %q, want %q", reloaded.ServerID, state.ServerID)
	}
}

// An unpinned enrollment must be refused before any request is made, so a
// misconfigured agent cannot reach a hostile endpoint at all.
func TestEnrollRefusesToEvenContactAnUnpinnedController(t *testing.T) {
	var contacted bool
	stub := newEnrollStub(t)
	client := *stub.client
	client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		contacted = true
		return nil, errStubUnreachable
	})

	_, err := Enroll(t.Context(), EnrollOptions{
		ControllerURL: stub.url,
		Token:         testEnrollToken,
		StateDir:      t.TempDir(),
		NodeAddress:   "127.0.0.1:9443",
		HTTPClient:    &client,
		// No fingerprint.
	})
	if err == nil {
		t.Fatal("enrollment without a pin succeeded")
	}
	if contacted {
		t.Error("the agent contacted the controller before validating that it had a fingerprint to pin")
	}
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

var errStubUnreachable = &stubError{"the stub must not be reached"}

type stubError struct{ msg string }

func (e *stubError) Error() string { return e.msg }
