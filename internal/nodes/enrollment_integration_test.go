//go:build integration

package nodes

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
)

// makeToken mints a token for a named node and returns its plaintext.
func makeToken(t *testing.T, h *harness, name string) string {
	t.Helper()
	_, plaintext, err := h.store.CreateToken(h.ctx, h.auth.ControllerID(), CreateTokenParams{NodeName: name})
	if err != nil {
		t.Fatalf("CreateToken(%s): %v", name, err)
	}
	return plaintext
}

// testNodeKey generates a node key pair and returns BOTH halves.
//
// Tests need the private half for the same reason a node does: to pair it with
// the certificate the controller issues. The controller never sees it, which is
// the property under test.
func testNodeKey(t *testing.T) (*ecdsa.PrivateKey, crypto.PublicKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate node key: %v", err)
	}
	return key, key.Public()
}

// privateKeyPEM encodes a node key the way the agent's state directory holds it.
func privateKeyPEM(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal node key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// redeemWith exercises Redeem with a caller-chosen authority and a fresh node
// key, mirroring what an agent does.
func redeemWith(t *testing.T, h *harness, auth *Authority, token string, publicKey crypto.PublicKey) (EnrollmentResult, error) {
	t.Helper()
	return h.store.Redeem(h.ctx, auth, RedeemRequest{
		Token:        token,
		PublicKey:    publicKey,
		NodeAddress:  "127.0.0.1:9443",
		AgentVersion: "test-agent-1.0.0",
		OSFamily:     "linux",
		OSVersion:    "test-distro 1",
	})
}

// redeemToken redeems against the harness's own authority, generating the node
// key inline. It is the stand-in for the twenty-odd call sites that care about
// the token's fate and not about the key material.
func redeemToken(t *testing.T, h *harness, token string) (EnrollmentResult, error) {
	t.Helper()
	_, publicKey := testNodeKey(t)
	return redeemWith(t, h, h.auth, token, publicKey)
}

// --- the happy path -----------------------------------------------------------

func TestRedeemIssuesIdentityAndCertificate(t *testing.T) {
	h := newHarness(t)
	token := makeToken(t, h, "web-01")
	nodeKey, publicKey := testNodeKey(t)

	result, err := redeemWith(t, h, h.auth, token, publicKey)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if result.Server.Name != "web-01" {
		t.Errorf("server name = %q, want web-01", result.Server.Name)
	}
	if result.Server.Status != "active" {
		t.Errorf("server status = %q, want active", result.Server.Status)
	}
	if result.Server.EnrolledAt == nil {
		t.Error("enrolled_at is null after a successful enrollment")
	}
	if result.Server.CertStatus != "active" {
		t.Errorf("cert status = %q, want active", result.Server.CertStatus)
	}
	if result.NodeURI != NodeIdentity(result.Server.ID).String() {
		t.Errorf("node URI = %q, want the server's identity", result.NodeURI)
	}

	// THE PROPERTY THIS TEST EXISTS FOR: the controller returned a certificate
	// and no key material. EnrollmentResult has no private-key field at all, so
	// this is structural rather than a value check — but the pairing below proves
	// the certificate is for the key the NODE generated, not one the controller
	// made up.
	if result.CertPEM == nil || len(result.CertPEM) == 0 {
		t.Fatal("no certificate was issued")
	}
	leaf, err := pki.DecodeLeaf(string(result.CertPEM) + privateKeyPEM(t, nodeKey))
	if err != nil {
		t.Fatalf("issued certificate does not pair with the node's own key: %v", err)
	}
	if !leaf.HasPrivateKey() {
		t.Error("the decoded leaf has no private key; the test key did not round-trip")
	}
	id, err := leaf.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if id != NodeIdentity(result.Server.ID) {
		t.Errorf("certificate identity = %+v, want the server identity", id)
	}
	verifier, err := pki.NewVerifier(pki.VerifierOptions{RootPEM: h.auth.NodeCertPEM(), Kind: pki.KindNode})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := verifier.Verify([][]byte{leaf.Cert().Raw}, nil); err != nil {
		t.Errorf("issued certificate does not verify against the node root: %v", err)
	}
	if leaf.SerialHex() != result.Serial {
		t.Errorf("serial = %q, want %q", leaf.SerialHex(), result.Serial)
	}
	if result.Fingerprint == "" {
		t.Error("the enrollment result carries no certificate fingerprint")
	}
}

// Enrollment must record what the agent reported about itself. The columns
// existed before this and were never populated, so a server row was "active" with
// no address to dial and no idea what ran on it.
func TestRedeemRecordsHostFacts(t *testing.T) {
	h := newHarness(t)
	token := makeToken(t, h, "facts-01")
	_, publicKey := testNodeKey(t)

	result, err := h.store.Redeem(h.ctx, h.auth, RedeemRequest{
		Token:        token,
		PublicKey:    publicKey,
		NodeAddress:  "10.1.2.3:9443",
		AgentVersion: "jawaker-agent 2.4.1",
		OSFamily:     "debian",
		OSVersion:    "12.7",
	})
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if result.Server.Address != "10.1.2.3:9443" {
		t.Errorf("address = %q, want 10.1.2.3:9443", result.Server.Address)
	}
	if result.Server.AgentVersion != "jawaker-agent 2.4.1" {
		t.Errorf("agent version = %q, want jawaker-agent 2.4.1", result.Server.AgentVersion)
	}
	if result.Server.OSFamily != "debian" || result.Server.OSVersion != "12.7" {
		t.Errorf("os = %q/%q, want debian/12.7", result.Server.OSFamily, result.Server.OSVersion)
	}

	// And it survives the round trip through the database, so the columns were
	// written and not merely set on the returned struct.
	stored, err := h.store.GetServer(h.ctx, result.Server.ID)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if stored.Address != "10.1.2.3:9443" || stored.OSFamily != "debian" {
		t.Errorf("stored server = %+v, want the reported facts", stored)
	}
}

// The address the controller will later dial is a trust-boundary value, so it is
// validated here rather than left to net.Dial discovering something odd at
// connection time.
func TestRedeemRefusesBadNodeAddress(t *testing.T) {
	h := newHarness(t)
	for i, address := range []string{
		"",                     // nothing to dial
		"   ",                  // whitespace only
		"localhost",            // no port
		":9443",                // no host
		"http://10.0.0.1:9443", // a URL is not an address
		"10.0.0.1:9443:extra",  // ambiguous about where the port begins
		"10.0.0.1:9443",        // valid: the control case below
	} {
		// The server name comes from the TOKEN and must be a valid name, so it
		// cannot be derived from the address under test — that would fail CreateToken
		// first and the test would pass for the wrong reason.
		token := makeToken(t, h, fmt.Sprintf("addr-%02d", i))
		_, publicKey := testNodeKey(t)
		_, err := h.store.Redeem(h.ctx, h.auth, RedeemRequest{
			Token:        token,
			PublicKey:    publicKey,
			NodeAddress:  address,
			AgentVersion: "test",
		})
		wantValid := address == "10.0.0.1:9443"
		if wantValid && err != nil {
			t.Errorf("Redeem(address=%q) = %v, want success", address, err)
			continue
		}
		if !wantValid && !errors.Is(err, ErrInvalid) {
			t.Errorf("Redeem(address=%q) error = %v, want ErrInvalid", address, err)
		}
	}
}

// A nil public key is refused before any database work: enrollment without a key
// would create a server row that can never authenticate.
func TestRedeemRefusesMissingPublicKey(t *testing.T) {
	h := newHarness(t)
	token := makeToken(t, h, "nokey-01")
	_, err := h.store.Redeem(h.ctx, h.auth, RedeemRequest{
		Token:       token,
		NodeAddress: "127.0.0.1:9443",
	})
	if !errors.Is(err, ErrInvalid) {
		t.Errorf("error = %v, want ErrInvalid", err)
	}
	// The token must still be usable, since nothing was claimed.
	if _, err := redeemToken(t, h, token); err != nil {
		t.Errorf("the token was consumed by the refused attempt: %v", err)
	}
}

// --- single-use ---------------------------------------------------------------

// The Phase 2 gate: a reused token must be rejected. The first redemption wins,
// the second is refused, and it is the DATABASE's conditional UPDATE that decides.
func TestRedeemRefusesReusedToken(t *testing.T) {
	h := newHarness(t)
	token := makeToken(t, h, "web-02")

	if _, err := redeemToken(t, h, token); err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	_, err := redeemToken(t, h, token)
	if err == nil {
		t.Fatal("second redemption of the same token succeeded, want refusal")
	}
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("error = %v, want ErrTokenInvalid", err)
	}

	// Exactly one server exists, so the refused retry left no partial state.
	servers, _, err := h.store.ListServers(h.ctx, 50, 0, "")
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}
	if len(servers) != 1 {
		t.Errorf("%d servers after one enrollment plus one refused retry, want 1", len(servers))
	}
}

// Concurrent redemption: exactly one of many racers may win. A sequential test
// cannot prove this, because it would also pass if the guard lived in application
// code — which is what the design forbids.
func TestRedeemIsSingleUseUnderConcurrency(t *testing.T) {
	h := newHarness(t)
	token := makeToken(t, h, "web-race")

	const racers = 8
	start := make(chan struct{})
	results := make(chan error, racers)
	var wg sync.WaitGroup
	for range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := redeemToken(t, h, token)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	winners, losers := 0, 0
	for err := range results {
		if err == nil {
			winners++
			continue
		}
		if !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("loser error = %v, want ErrTokenInvalid", err)
		}
		losers++
	}
	if winners != 1 {
		t.Fatalf("%d racers redeemed one token, want exactly 1", winners)
	}
	if losers != racers-1 {
		t.Errorf("%d losers, want %d", losers, racers-1)
	}

	// And exactly one server was created.
	servers, _, err := h.store.ListServers(h.ctx, 50, 0, "")
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}
	if len(servers) != 1 {
		t.Errorf("%d servers after a concurrent race, want 1", len(servers))
	}
}

// --- expiry -------------------------------------------------------------------

// An expired token is refused, and the clock is moved rather than the test
// waiting fifteen minutes.
func TestRedeemRefusesExpiredToken(t *testing.T) {
	h := newHarness(t)
	token := makeToken(t, h, "web-03")

	h.clock.advance(TokenLifetime + time.Minute)

	_, err := redeemToken(t, h, token)
	if err == nil {
		t.Fatal("an expired token was redeemed, want refusal")
	}
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("error = %v, want ErrTokenInvalid", err)
	}
}

// A token must remain usable right up to its expiry: an off-by-one that refuses
// a token a second early is a support ticket, not a security win.
func TestRedeemAcceptsTokenJustBeforeExpiry(t *testing.T) {
	h := newHarness(t)
	token := makeToken(t, h, "web-04")

	h.clock.advance(TokenLifetime - time.Second)

	if _, err := redeemToken(t, h, token); err != nil {
		t.Fatalf("a token one second before expiry was refused: %v", err)
	}
}

// --- revocation ---------------------------------------------------------------

func TestRedeemRefusesRevokedToken(t *testing.T) {
	h := newHarness(t)
	created, plaintext, err := h.store.CreateToken(h.ctx, h.auth.ControllerID(), CreateTokenParams{NodeName: "web-05"})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if err := h.store.RevokeToken(h.ctx, created.ID, ""); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if _, err := redeemToken(t, h, plaintext); !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("error = %v, want ErrTokenInvalid", err)
	}
}

// A token that was already spent cannot be revoked: the schema makes the two
// states mutually exclusive, and a caller attempting it is confused or probing.
func TestRevokeRefusesAlreadyUsedToken(t *testing.T) {
	h := newHarness(t)
	created, plaintext, err := h.store.CreateToken(h.ctx, h.auth.ControllerID(), CreateTokenParams{NodeName: "web-06"})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	if _, err := redeemToken(t, h, plaintext); err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if err := h.store.RevokeToken(h.ctx, created.ID, ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound for an already-spent token", err)
	}
}

func TestRevokeUnknownTokenIsNotFound(t *testing.T) {
	h := newHarness(t)
	err := h.store.RevokeToken(h.ctx, "00000000-0000-0000-0000-000000000000", "")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("error = %v, want ErrNotFound", err)
	}
}

// --- controller binding -------------------------------------------------------

// A token minted for a DIFFERENT controller must not enroll here. The token is
// genuine and unexpired; only its controller binding makes it inapplicable.
//
// The binding is exercised by handing Redeem an authority that claims another
// controller id, because the schema's singleton constraint means a second
// controller identity cannot coexist in one database — which is itself the
// stronger guarantee, asserted separately below.
func TestRedeemRefusesTokenBoundToAnotherController(t *testing.T) {
	h := newHarness(t)
	token := makeToken(t, h, "web-foreign")

	// Same roots, different claimed identity. Every other field is untouched, so
	// the ONLY reason for refusal can be the binding.
	impostor := &Authority{
		controller:   h.auth.controller,
		node:         h.auth.node,
		controllerID: "00000000-0000-0000-0000-0000000000ff",
		clock:        h.clock.now,
	}

	_, publicKey := testNodeKey(t)
	_, err := redeemWith(t, h, impostor, token, publicKey)
	if err == nil {
		t.Fatal("a token bound to another controller was redeemed, want refusal")
	}
	if !errors.Is(err, ErrTokenInvalid) {
		t.Errorf("error = %v, want ErrTokenInvalid", err)
	}

	// The refusal must ROLL BACK, or the token would be spent on a failed
	// attempt and the node could never enroll at all.
	var unspent int
	if err = h.pool.QueryRow(h.ctx, `
		SELECT count(*) FROM enrollment_tokens WHERE used_at IS NULL`).Scan(&unspent); err != nil {
		t.Fatalf("count unspent tokens: %v", err)
	}
	if unspent != 1 {
		t.Errorf("%d unspent tokens after a refused binding, want 1", unspent)
	}
	servers, _, err := h.store.ListServers(h.ctx, 50, 0, "")
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}
	if len(servers) != 0 {
		t.Errorf("%d servers created by a refused redemption, want 0", len(servers))
	}

	// The genuine controller can still use it, which is the point of the
	// rollback.
	if _, err := redeemToken(t, h, token); err != nil {
		t.Errorf("the genuine controller could not redeem the token afterwards: %v", err)
	}
}

// The singleton constraint is the reason a second controller identity cannot
// exist in this database at all, which is what makes the binding meaningful
// rather than merely checked.
func TestControllerIdentityIsSingletonInDatabase(t *testing.T) {
	h := newHarness(t)
	_, err := h.pool.Exec(h.ctx, `INSERT INTO controller_identity (name) VALUES ('second')`)
	if err == nil {
		t.Fatal("a second controller identity was inserted, want refusal")
	}
	if !isUniqueViolation(err) {
		t.Errorf("error = %v, want a unique violation", err)
	}
}

// --- opaque refusal -----------------------------------------------------------

// Every refusal reason must produce the SAME error, so a caller holding a guessed
// token cannot learn whether it was merely expired or structurally valid.
func TestRedeemRejectionIsIndistinguishable(t *testing.T) {
	h := newHarness(t)

	unknown := "jwenroll_" + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	_, errUnknown := redeemToken(t, h, unknown)

	expiredToken := makeToken(t, h, "web-07")
	h.clock.advance(TokenLifetime + time.Minute)
	_, errExpired := redeemToken(t, h, expiredToken)

	usedToken := makeToken(t, h, "web-08")
	if _, err := redeemToken(t, h, usedToken); err != nil {
		t.Fatalf("setup redemption: %v", err)
	}
	_, errUsed := redeemToken(t, h, usedToken)

	for name, err := range map[string]error{
		"unknown": errUnknown,
		"expired": errExpired,
		"used":    errUsed,
	} {
		if !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("%s: error = %v, want ErrTokenInvalid", name, err)
		}
	}
	// The rendered messages must be identical: a caller comparing them must not
	// be able to tell the cases apart.
	if errUnknown.Error() != errExpired.Error() || errExpired.Error() != errUsed.Error() {
		t.Errorf("refusal messages differ across reasons: %q / %q / %q",
			errUnknown.Error(), errExpired.Error(), errUsed.Error())
	}
}

// A malformed value must be refused the same opaque way, so the token's SHAPE is
// not a signal either.
func TestRedeemRefusesMalformedToken(t *testing.T) {
	h := newHarness(t)
	for _, bad := range []string{"", "   ", "not-a-token", "jwenroll_", "jwsess_abcdefghijklmnop"} {
		if _, err := redeemToken(t, h, bad); !errors.Is(err, ErrTokenInvalid) {
			t.Errorf("Redeem(%q) error = %v, want ErrTokenInvalid", bad, err)
		}
	}
}

// --- name handling ------------------------------------------------------------

// The server name comes from the TOKEN, not from the caller, so a caller cannot
// choose a name. This is asserted by enrolling twice with tokens that name the
// same server: the second must fail on the name, and the first must own it.
func TestDuplicateServerNameIsRefused(t *testing.T) {
	h := newHarness(t)
	first := makeToken(t, h, "dup-host")
	if _, err := redeemToken(t, h, first); err != nil {
		t.Fatalf("first redemption: %v", err)
	}

	second := makeToken(t, h, "dup-host")
	_, err := redeemToken(t, h, second)
	if err == nil {
		t.Fatal("two servers were created with the same name, want refusal")
	}
	if !errors.Is(err, ErrNameTaken) {
		t.Errorf("error = %v, want ErrNameTaken", err)
	}

	// The failed redemption must ROLL BACK, leaving the token unspent so an
	// operator can retry with a corrected name. A half-consumed token that can
	// never succeed is the worst outcome of the transaction design, so this
	// asserts the opposite.
	var unspent int
	query := `SELECT count(*) FROM enrollment_tokens WHERE node_name = 'dup-host' AND used_at IS NULL`
	if err := h.pool.QueryRow(h.ctx, query).Scan(&unspent); err != nil {
		t.Fatalf("count unspent tokens: %v", err)
	}
	if unspent != 1 {
		t.Errorf("%d unspent tokens after a failed redemption, want 1 (the retry must still be possible)", unspent)
	}

	// And a server was created only once, by the first successful enrollment.
	var servers int
	if err := h.pool.QueryRow(h.ctx, `SELECT count(*) FROM servers WHERE name = 'dup-host'`).Scan(&servers); err != nil {
		t.Fatalf("count servers: %v", err)
	}
	if servers != 1 {
		t.Errorf("%d servers named dup-host, want 1", servers)
	}
}

func TestTokenNameValidation(t *testing.T) {
	h := newHarness(t)
	// Each rejected name is a distinct problem, not a style preference.
	rejected := []string{
		"",                          // empty
		"has space",                 // whitespace
		"has/slash",                 // path separator
		"has;semicolon",             // shell metacharacter
		"$(id)",                     // command substitution
		"new\nline",                 // newline would spoof a list row
		"<script>alert(1)</script>", // markup
		"name\u00e9",                // non-ASCII
		strings.Repeat("a", 101),    // overlong
	}
	for _, name := range rejected {
		_, _, err := h.store.CreateToken(h.ctx, h.auth.ControllerID(), CreateTokenParams{NodeName: name})
		if err == nil {
			t.Errorf("CreateToken accepted node name %q, want refusal", name)
		}
	}
	// Reasonable names are accepted: letters, digits, dash, dot, underscore, and
	// exactly the 100-character boundary.
	accepted := []string{
		"web-01",
		"web-01.example",
		"db_primary",
		"NodeA",
		strings.Repeat("a", 100),
	}
	for _, name := range accepted {
		if _, _, err := h.store.CreateToken(h.ctx, h.auth.ControllerID(), CreateTokenParams{NodeName: name}); err != nil {
			t.Errorf("CreateToken rejected a valid name %q: %v", name, err)
		}
	}

	// A substring must not be accepted either, so a caller cannot smuggle one
	// through by embedding it.
	if !ValidServerName("web-01") {
		t.Error("ValidServerName rejected a valid name")
	}
	if ValidServerName("web 01") {
		t.Error("ValidServerName accepted a name with a space")
	}
}

// --- token listing ------------------------------------------------------------

// The list must never expose a usable token: plaintexts were never stored, so
// there is nothing to leak.
func TestListTokensExposesNoSecret(t *testing.T) {
	h := newHarness(t)
	plaintext := makeToken(t, h, "listed-01")

	tokens, err := h.store.ListTokens(h.ctx, 50)
	if err != nil {
		t.Fatalf("ListTokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("%d tokens, want 1", len(tokens))
	}
	if tokens[0].NodeName != "listed-01" {
		t.Errorf("node name = %q, want listed-01", tokens[0].NodeName)
	}
	// Holding the plaintext and knowing the token id, the digest must still be
	// the only thing stored: assert the column count of a plaintext query.
	var count int
	if err := h.pool.QueryRow(h.ctx, `
		SELECT count(*) FROM enrollment_tokens WHERE encode(token_hash, 'escape') = $1`,
		plaintext).Scan(&count); err != nil {
		t.Fatalf("query by plaintext: %v", err)
	}
	if count != 0 {
		t.Error("the plaintext token appears in the stored data")
	}
}

// --- certificate revocation ---------------------------------------------------

// Revoking a certificate must take effect immediately, and the reason is
// mandatory: a revocation without one is an audit gap.
func TestRevokeCertificateTakesEffectImmediately(t *testing.T) {
	h := newHarness(t)
	token := makeToken(t, h, "revoke-01")
	result, err := redeemToken(t, h, token)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}

	revoked, err := h.store.IsRevoked(h.ctx, result.Serial)
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Fatal("a freshly issued certificate reports as revoked")
	}

	// A revocation with no reason must be refused.
	if err = h.store.RevokeCertificate(h.ctx, result.Server.ID, result.Serial, "   "); err == nil {
		t.Error("RevokeCertificate accepted an empty reason")
	}

	if err = h.store.RevokeCertificate(h.ctx, result.Server.ID, result.Serial, "node compromised"); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	revoked, err = h.store.IsRevoked(h.ctx, result.Serial)
	if err != nil {
		t.Fatalf("IsRevoked after revocation: %v", err)
	}
	if !revoked {
		t.Error("a revoked certificate does not report as revoked")
	}

	// The server rollup must reflect it, so a list view is not stale.
	server, err := h.store.GetServer(h.ctx, result.Server.ID)
	if err != nil {
		t.Fatalf("GetServer: %v", err)
	}
	if server.CertStatus != "revoked" {
		t.Errorf("cert status = %q, want revoked", server.CertStatus)
	}

	// Revoking twice must not silently succeed.
	if err := h.store.RevokeCertificate(h.ctx, result.Server.ID, result.Serial, "again"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second revocation error = %v, want ErrNotFound", err)
	}
}

// A serial the installation never issued is not "revoked", it is unknown.
// Refusing it is chain validation's job, not this query's.
func TestIsRevokedForUnknownSerial(t *testing.T) {
	h := newHarness(t)
	revoked, err := h.store.IsRevoked(h.ctx, "deadbeef")
	if err != nil {
		t.Fatalf("IsRevoked: %v", err)
	}
	if revoked {
		t.Error("an unknown serial reports as revoked")
	}
}

func TestActiveCertificateAfterRevocation(t *testing.T) {
	h := newHarness(t)
	token := makeToken(t, h, "active-cert")
	result, err := redeemToken(t, h, token)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}

	serial, fingerprint, _, err := h.store.ActiveCertificate(h.ctx, result.Server.ID)
	if err != nil {
		t.Fatalf("ActiveCertificate: %v", err)
	}
	if serial != result.Serial || fingerprint == "" {
		t.Errorf("active certificate = (%q, %q), want the issued one", serial, fingerprint)
	}

	if err := h.store.RevokeCertificate(h.ctx, result.Server.ID, result.Serial, "rotation"); err != nil {
		t.Fatalf("RevokeCertificate: %v", err)
	}
	if _, _, _, err := h.store.ActiveCertificate(h.ctx, result.Server.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("ActiveCertificate after revocation = %v, want ErrNotFound", err)
	}
}

// --- inventory ----------------------------------------------------------------

func TestServerListFiltersAndPaginates(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{"list-a", "list-b", "list-c"} {
		token := makeToken(t, h, name)
		if _, err := redeemToken(t, h, token); err != nil {
			t.Fatalf("Redeem(%s): %v", name, err)
		}
	}

	all, total, err := h.store.ListServers(h.ctx, 50, 0, "")
	if err != nil {
		t.Fatalf("ListServers: %v", err)
	}
	if len(all) != 3 || total != 3 {
		t.Fatalf("list = %d items / total %d, want 3/3", len(all), total)
	}

	page, total, err := h.store.ListServers(h.ctx, 2, 0, "")
	if err != nil {
		t.Fatalf("ListServers(page): %v", err)
	}
	if len(page) != 2 || total != 3 {
		t.Errorf("page = %d items / total %d, want 2/3", len(page), total)
	}

	// A tombstoned server leaves the list but the total agrees.
	if err = h.store.SetStatus(h.ctx, all[0].ID, "deleted"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	remaining, total, err := h.store.ListServers(h.ctx, 50, 0, "")
	if err != nil {
		t.Fatalf("ListServers after delete: %v", err)
	}
	if len(remaining) != 2 || total != 2 {
		t.Errorf("after delete: %d items / total %d, want 2/2", len(remaining), total)
	}

	// Filters are an allowlist.
	if _, _, err := h.store.ListServers(h.ctx, 50, 0, "'; DROP TABLE servers; --"); err == nil {
		t.Error("ListServers accepted an arbitrary status filter")
	}
	if _, _, err := h.store.ListServers(h.ctx, 0, 0, ""); err == nil {
		t.Error("ListServers accepted a zero limit")
	}
	if _, _, err := h.store.ListServers(h.ctx, 50, -1, ""); err == nil {
		t.Error("ListServers accepted a negative offset")
	}
}

func TestGetServerHidesTombstoned(t *testing.T) {
	h := newHarness(t)
	token := makeToken(t, h, "gone-01")
	result, err := redeemToken(t, h, token)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if err := h.store.SetStatus(h.ctx, result.Server.ID, "deleted"); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if _, err := h.store.GetServer(h.ctx, result.Server.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("GetServer for a tombstoned server = %v, want ErrNotFound", err)
	}
}

func TestSetStatusRejectsUnknownStatus(t *testing.T) {
	h := newHarness(t)
	token := makeToken(t, h, "status-01")
	result, err := redeemToken(t, h, token)
	if err != nil {
		t.Fatalf("Redeem: %v", err)
	}
	if err := h.store.SetStatus(h.ctx, result.Server.ID, "exploded"); err == nil {
		t.Error("SetStatus accepted an unknown status")
	}
	if err := h.store.SetStatus(h.ctx, result.Server.ID, "suspended"); err != nil {
		t.Errorf("SetStatus(suspended): %v", err)
	}
}
