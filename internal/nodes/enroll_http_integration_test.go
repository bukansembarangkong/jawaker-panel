//go:build integration

package nodes

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
	"github.com/bukansembarangkong/jawaker-panel/internal/ratelimit"
)

// enrollHarness is a real HTTP surface: the mux, the routes, the middleware-free
// handler set. The point is to exercise the endpoint as a node reaches it, not to
// call the handler function directly.
type enrollHarness struct {
	*harness
	server *httptest.Server
}

func newEnrollHarness(t *testing.T, rate ratelimit.Options) *enrollHarness {
	t.Helper()
	h := newHarness(t)
	handlers, err := NewHandlers(HandlerOptions{
		Store:      h.store,
		Authority:  h.auth,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Now:        h.clock.now,
		EnrollRate: rate,
	})
	if err != nil {
		t.Fatalf("NewHandlers: %v", err)
	}
	mux := http.NewServeMux()
	handlers.Routes(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return &enrollHarness{harness: h, server: server}
}

// enrollBody builds a valid request body with a fresh node public key.
func enrollBody(t *testing.T, token string) (body []byte, key *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	req := nodewire.EnrollmentRequest{
		Token:        token,
		PublicKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
		AgentVersion: "test-agent-1.0.0",
		OSFamily:     "linux",
		OSVersion:    "test 1",
		NodeAddress:  "127.0.0.1:9443",
	}
	body, err = json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return body, key
}

// postEnroll sends a body to the enrollment endpoint with no session, no cookie
// and no CSRF token — which is exactly how a node arrives.
func (e *enrollHarness) postEnroll(t *testing.T, body []byte) (*http.Response, []byte) {
	t.Helper()
	resp, err := http.Post(e.server.URL+nodewire.EnrollmentPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", nodewire.EnrollmentPath, err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp, data
}

// --- the happy path -----------------------------------------------------------

// A node with a valid token, no session and no certificate must be able to enroll
// and receive a certificate that pairs with the key IT generated.
func TestEnrollEndpointIssuesCertificateForNodeKey(t *testing.T) {
	e := newEnrollHarness(t, ratelimit.Options{})
	token := makeToken(t, e.harness, "http-enroll-01")
	body, key := enrollBody(t, token)

	resp, data := e.postEnroll(t, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, want 201: %s", resp.StatusCode, data)
	}

	var out nodewire.EnrollmentResponse
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("decode response: %v\n%s", err, data)
	}
	if err := out.Validate(); err != nil {
		t.Fatalf("response is not structurally valid: %v", err)
	}
	// The controller must have returned its own root and fingerprint: without
	// them the node has nothing to pin, and the one step that cannot use mutual
	// TLS would be unprotected.
	if out.ControllerFingerprint != e.auth.ControllerFingerprint() {
		t.Errorf("controller fingerprint = %q, want %q",
			out.ControllerFingerprint, e.auth.ControllerFingerprint())
	}

	// THE PROPERTY: the certificate pairs with the key the NODE generated and the
	// private half never travelled.
	leaf, err := pki.DecodeLeaf(string(out.CertPEM) + privateKeyPEM(t, key))
	if err != nil {
		t.Fatalf("issued certificate does not pair with the node's own key: %v", err)
	}
	id, err := leaf.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if id.ID != out.ServerID || id.Kind != pki.KindNode {
		t.Errorf("certificate identity = %+v, want node %s", id, out.ServerID)
	}

	// And the raw response must NOT contain the private key.
	if bytes.Contains(data, []byte("PRIVATE KEY")) {
		t.Error("the enrollment response contains private key material")
	}

	// The server row exists with the reported facts.
	stored, err := e.store.GetServer(e.ctx, out.ServerID)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if stored.Status != "active" || stored.Address != "127.0.0.1:9443" {
		t.Errorf("stored server = %+v, want active with the reported address", stored)
	}
}

// --- refusal shape ------------------------------------------------------------

// Every refusal reason must be indistinguishable to the caller. A caller holding
// a guessed token must not learn whether it was unknown, expired or already used.
func TestEnrollRefusalsAreIndistinguishable(t *testing.T) {
	e := newEnrollHarness(t, ratelimit.Options{})

	type attempt struct {
		name  string
		token string
	}
	var attempts []attempt

	attempts = append(attempts, attempt{
		name:  "unknown",
		token: "jwenroll_" + strings.Repeat("A", 43),
	})

	expired := makeToken(t, e.harness, "http-expired")
	e.clock.advance(TokenLifetime + time.Minute)
	attempts = append(attempts, attempt{name: "expired", token: expired})

	// Redeeming spends the token; the same one is then "used".
	used := makeToken(t, e.harness, "http-used")
	body, _ := enrollBody(t, used)
	if resp, data := e.postEnroll(t, body); resp.StatusCode != http.StatusCreated {
		t.Fatalf("setup enrollment failed: %d %s", resp.StatusCode, data)
	}
	attempts = append(attempts, attempt{name: "used", token: used})

	var (
		firstStatus int
		firstBody   string
	)
	for i, a := range attempts {
		body, _ := enrollBody(t, a.token)
		resp, data := e.postEnroll(t, body)
		if resp.StatusCode < 400 {
			t.Errorf("%s: status = %d, want a refusal", a.name, resp.StatusCode)
			continue
		}
		// Normalise the request id, which is per-request by design and must not
		// be compared.
		normalised := stripRequestID(t, data)
		if i == 0 {
			firstStatus, firstBody = resp.StatusCode, normalised
			continue
		}
		if resp.StatusCode != firstStatus {
			t.Errorf("%s: status = %d, want %d (must be indistinguishable)", a.name, resp.StatusCode, firstStatus)
		}
		if normalised != firstBody {
			t.Errorf("%s: body differs from the first refusal:\n got %s\nwant %s",
				a.name, normalised, firstBody)
		}
	}
}

// stripRequestID removes the request id from a JSON error body so two refusals
// can be compared for everything else.
func stripRequestID(t *testing.T, data []byte) string {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		return string(data)
	}
	delete(v, "request_id")
	delete(v, "requestId")
	cleaned, err := json.Marshal(v)
	if err != nil {
		return string(data)
	}
	return string(cleaned)
}

// --- input validation ---------------------------------------------------------

// The public key field is a trust boundary. A stream carrying a private key must
// be refused rather than trimmed: a node sending one has broken the exact
// property this flow exists to establish.
func TestEnrollRefusesPrivateKeyInPublicKeyField(t *testing.T) {
	e := newEnrollHarness(t, ratelimit.Options{})
	token := makeToken(t, e.harness, "http-privkey")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}
	body, err := json.Marshal(nodewire.EnrollmentRequest{
		Token:        token,
		PublicKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		NodeAddress:  "127.0.0.1:9443",
		AgentVersion: "test",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	resp, data := e.postEnroll(t, body)
	if resp.StatusCode == http.StatusCreated {
		t.Fatal("the endpoint accepted a private key in the public-key field")
	}
	// And the token must be untouched, so the node can retry correctly.
	if _, err := e.store.Redeem(e.ctx, e.auth, RedeemRequest{
		Token:       token,
		PublicKey:   key.Public(),
		NodeAddress: "127.0.0.1:9443",
	}); err != nil {
		t.Errorf("the refused attempt consumed the token: %v\n%s", err, data)
	}
}

// A body with an unknown field is refused rather than partly honored, so a
// request cannot carry something the server never inspects.
func TestEnrollRefusesUnknownFields(t *testing.T) {
	e := newEnrollHarness(t, ratelimit.Options{})
	token := makeToken(t, e.harness, "http-unknown")
	body, _ := enrollBody(t, token)

	var asMap map[string]any
	if err := json.Unmarshal(body, &asMap); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	asMap["skip_validation"] = true
	tampered, err := json.Marshal(asMap)
	if err != nil {
		t.Fatalf("re-encode body: %v", err)
	}

	resp, data := e.postEnroll(t, tampered)
	if resp.StatusCode == http.StatusCreated {
		t.Fatalf("the endpoint accepted an unknown field: %s", data)
	}
}

// A cross-kind key must not produce a node certificate, and a malformed body must
// not crash the handler.
func TestEnrollRejectsMalformedBodies(t *testing.T) {
	e := newEnrollHarness(t, ratelimit.Options{})
	for _, body := range []string{
		``,
		`not json`,
		`{}`,
		`{"token":"x"}`,
		`{"token":"x","public_key_pem":"bm90LWEta2V5"}`,
		`{"token":"x","public_key_pem":"bm90LWEta2V5"} trailing`,
	} {
		resp, data := e.postEnroll(t, []byte(body))
		if resp.StatusCode == http.StatusCreated {
			t.Errorf("body %q was accepted: %s", body, data)
		}
		if resp.StatusCode >= 500 {
			t.Errorf("body %q produced a %d; malformed input is a caller error: %s",
				body, resp.StatusCode, data)
		}
	}
}

// --- rate limiting ------------------------------------------------------------

// The endpoint is the one unauthenticated write on the controller, so attempts
// must cost something. The limiter is per client address.
func TestEnrollIsRateLimited(t *testing.T) {
	e := newEnrollHarness(t, ratelimit.Options{Limit: 3, Interval: time.Minute})

	token := makeToken(t, e.harness, "http-rate")
	body, _ := enrollBody(t, token)

	var rateLimited bool
	for range 10 {
		resp, _ := e.postEnroll(t, body)
		if resp.StatusCode == http.StatusTooManyRequests {
			rateLimited = true
			if resp.Header.Get("Retry-After") == "" {
				t.Error("a 429 carried no Retry-After header")
			}
			break
		}
	}
	if !rateLimited {
		t.Fatal("ten enrollment attempts from one address were never rate limited")
	}
}

// The fleet-install case: several nodes enrolling from one address in a burst
// must not be blocked by the default allowance. It is generous for exactly this
// reason, and a regression that tightened it would break a rollout.
func TestEnrollDefaultRateAllowsAFleetBurst(t *testing.T) {
	e := newEnrollHarness(t, ratelimit.Options{})

	for i := range 10 {
		token := makeToken(t, e.harness, "http-burst-"+string(rune('a'+i)))
		body, _ := enrollBody(t, token)
		resp, data := e.postEnroll(t, body)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("node %d of a burst was refused: %d %s", i, resp.StatusCode, data)
		}
	}
}
