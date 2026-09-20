// Package pki tests. No mocks anywhere: certificates are generated, signed, and
// verified with the real crypto/x509 and crypto/tls stacks, and the TLS cases
// open real sockets to a real tls.Listener.
//
// The cases here exist to prove NEGATIVE properties — the ones that are easy to
// claim and hard to guarantee:
//
//   - a node certificate cannot be believed to be the controller;
//   - a certificate signed by a different authority of the same kind is refused;
//   - a leaf with the right chain but the wrong name is refused;
//   - an authority cannot be smuggled in as a peer;
//   - a peer with no certificate cannot connect at all.
package pki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"
)

const (
	controllerID = "11111111-1111-1111-1111-111111111111"
	nodeID       = "22222222-2222-2222-2222-222222222222"
	otherNodeID  = "33333333-3333-3333-3333-333333333333"
)

// newCAFor is the one place tests create an authority, so every test exercises
// the same kind-binding path production uses.
func newCAFor(t *testing.T, kind Kind) *CA {
	t.Helper()
	ca, err := NewCA("JAWAKER "+string(kind)+" test CA", kind, time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("NewCA(%s): %v", kind, err)
	}
	return ca
}

func issueLeaf(t *testing.T, ca *CA, id Identity) *Leaf {
	t.Helper()
	leaf, err := ca.IssueLeaf(LeafParams{Identity: id, NotAfter: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatalf("IssueLeaf(%s): %v", id, err)
	}
	return leaf
}

// --- identity -----------------------------------------------------------------

func TestIdentityURIRoundTrips(t *testing.T) {
	for _, id := range []Identity{
		{Kind: KindController, ID: controllerID},
		{Kind: KindNode, ID: nodeID},
	} {
		parsed, err := ParseIdentity(id.URI())
		if err != nil {
			t.Fatalf("ParseIdentity(%s): %v", id, err)
		}
		if parsed != id {
			t.Errorf("round trip = %+v, want %+v", parsed, id)
		}
	}
}

func TestIdentityURIString(t *testing.T) {
	got := Identity{Kind: KindNode, ID: nodeID}.String()
	want := "spiffe://jawaker/node/" + nodeID
	if got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

// A URI carrying extra components would give one identity two spellings, so a
// verifier comparing strings could disagree with one comparing parsed values.
func TestParseIdentityRejectsExtraURIComponents(t *testing.T) {
	cases := map[string]string{
		"query":     "spiffe://jawaker/node/" + nodeID + "?x=1",
		"fragment":  "spiffe://jawaker/node/" + nodeID + "#x",
		"userinfo":  "spiffe://user@jawaker/node/" + nodeID,
		"scheme":    "https://jawaker/node/" + nodeID,
		"domain":    "spiffe://elsewhere/node/" + nodeID,
		"noslash":   "spiffe://jawaker/node",
		"kind":      "spiffe://jawaker/robot/" + nodeID,
		"traversal": "spiffe://jawaker/node/../controller/" + controllerID,
		"emptyid":   "spiffe://jawaker/node/",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("test URI %q is not parseable: %v", raw, err)
			}
			if _, err := ParseIdentity(u); err == nil {
				t.Errorf("ParseIdentity(%q) succeeded, want rejection", raw)
			}
		})
	}
}

func TestParseIdentityRejectsNil(t *testing.T) {
	if _, err := ParseIdentity(nil); err == nil {
		t.Error("ParseIdentity(nil) succeeded, want rejection")
	}
}

// --- authority kind binding ---------------------------------------------------

// The load-bearing property of the whole package: the Controller CA cannot mint
// a node certificate. Without this, one authority would let a node present a
// certificate the controller root signed, which is precisely the forgery the
// two-authority split exists to prevent.
func TestAuthorityRefusesToSignOtherKind(t *testing.T) {
	controllerCA := newCAFor(t, KindController)
	nodeCA := newCAFor(t, KindNode)

	cases := []struct {
		name string
		ca   *CA
		id   Identity
	}{
		{"controller CA signing a node", controllerCA, Identity{Kind: KindNode, ID: nodeID}},
		{"node CA signing a controller", nodeCA, Identity{Kind: KindController, ID: controllerID}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.ca.IssueLeaf(LeafParams{Identity: tc.id, NotAfter: time.Now().Add(time.Hour)})
			if err == nil {
				t.Fatal("IssueLeaf succeeded across kinds, want refusal")
			}
			if !strings.Contains(err.Error(), "cannot issue") {
				t.Errorf("error = %v, want a cross-kind refusal", err)
			}
		})
	}
}

// An authority that issued for the wrong kind is not merely refused at issue
// time; its kind travels inside the certificate, so a caller cannot decode the
// Node CA and then assert it is the Controller CA.
func TestAuthorityKindIsRecoveredFromTheCertificate(t *testing.T) {
	for _, kind := range []Kind{KindController, KindNode} {
		ca := newCAFor(t, kind)
		if ca.Kind() != kind {
			t.Errorf("Kind() = %q, want %q", ca.Kind(), kind)
		}
		encoded, err := ca.Encode()
		if err != nil {
			t.Fatalf("Encode: %v", err)
		}
		decoded, err := DecodeCA(encoded)
		if err != nil {
			t.Fatalf("DecodeCA: %v", err)
		}
		if decoded.Kind() != kind {
			t.Errorf("decoded Kind() = %q, want %q", decoded.Kind(), kind)
		}
	}
}

func TestNewCARejectsUnknownKind(t *testing.T) {
	if _, err := NewCA("bad", Kind("robot"), time.Now().Add(time.Hour)); err == nil {
		t.Error("NewCA accepted an unknown kind, want rejection")
	}
}

func TestNewCARequiresCommonName(t *testing.T) {
	if _, err := NewCA("   ", KindNode, time.Now().Add(time.Hour)); err == nil {
		t.Error("NewCA accepted a blank common name, want rejection")
	}
}

// --- encode/decode ------------------------------------------------------------

func TestCAEncodeDecodePreservesFingerprintAndFunction(t *testing.T) {
	original := newCAFor(t, KindNode)
	encoded, err := original.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	decoded, err := DecodeCA(encoded)
	if err != nil {
		t.Fatalf("DecodeCA: %v", err)
	}
	if decoded.Fingerprint() != original.Fingerprint() {
		t.Error("fingerprint changed across encode/decode")
	}
	// The decoded authority must actually be able to sign, or the round trip
	// would be preserving bytes while losing function.
	if _, err := decoded.IssueLeaf(LeafParams{
		Identity: Identity{Kind: KindNode, ID: nodeID},
		NotAfter: time.Now().Add(time.Hour),
	}); err != nil {
		t.Errorf("decoded authority cannot sign: %v", err)
	}
}

func TestLeafEncodeDecodeRoundTrips(t *testing.T) {
	leaf := issueLeaf(t, newCAFor(t, KindNode), Identity{Kind: KindNode, ID: nodeID})

	decoded, err := DecodeLeaf(leaf.Encode())
	if err != nil {
		t.Fatalf("DecodeLeaf: %v", err)
	}
	if decoded.SerialHex() != leaf.SerialHex() {
		t.Errorf("serial = %q, want %q", decoded.SerialHex(), leaf.SerialHex())
	}
	if decoded.Fingerprint() != leaf.Fingerprint() {
		t.Error("fingerprint changed across encode/decode")
	}
	id, err := decoded.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if id != (Identity{Kind: KindNode, ID: nodeID}) {
		t.Errorf("identity = %+v, want the node identity", id)
	}
}

func TestLeafIdentityMatchesRequested(t *testing.T) {
	leaf := issueLeaf(t, newCAFor(t, KindController), Identity{Kind: KindController, ID: controllerID})
	id, err := leaf.Identity()
	if err != nil {
		t.Fatalf("Identity: %v", err)
	}
	if id.Kind != KindController || id.ID != controllerID {
		t.Errorf("identity = %+v, want controller/%s", id, controllerID)
	}
}

func TestIssueLeafRejectsEmptyIDAndPastExpiry(t *testing.T) {
	ca := newCAFor(t, KindNode)
	if _, err := ca.IssueLeaf(LeafParams{Identity: Identity{Kind: KindNode}, NotAfter: time.Now().Add(time.Hour)}); err == nil {
		t.Error("IssueLeaf accepted an empty id, want rejection")
	}
	if _, err := ca.IssueLeaf(LeafParams{
		Identity: Identity{Kind: KindNode, ID: nodeID},
		NotAfter: time.Now().Add(-time.Hour),
	}); err == nil {
		t.Error("IssueLeaf accepted an expiry in the past, want rejection")
	}
}

// A certificate and a key that do not correspond produce signature failures at
// handshake time with no hint of the cause, so the mismatch is caught at decode.
func TestDecodeLeafRejectsMismatchedKey(t *testing.T) {
	ca := newCAFor(t, KindNode)
	first := issueLeaf(t, ca, Identity{Kind: KindNode, ID: nodeID})
	second := issueLeaf(t, ca, Identity{Kind: KindNode, ID: otherNodeID})

	mixed := string(first.CertPEM()) + string(second.KeyPEM())
	_, err := DecodeLeaf(mixed)
	if err == nil {
		t.Fatal("DecodeLeaf accepted a mismatched key, want refusal")
	}
	if !errors.Is(err, ErrKeyMismatch) {
		t.Errorf("error = %v, want ErrKeyMismatch", err)
	}
}

func TestDecodeLeafRequiresKey(t *testing.T) {
	leaf := issueLeaf(t, newCAFor(t, KindNode), Identity{Kind: KindNode, ID: nodeID})
	if _, err := DecodeLeaf(string(leaf.CertPEM())); err == nil {
		t.Error("DecodeLeaf accepted a certificate with no key, want refusal")
	}
}

// A leaf decoded as an authority would let a caller who then issued with it
// produce certificates signed by a key that is not the stored root.
func TestDecodeCARejectsLeaf(t *testing.T) {
	leaf := issueLeaf(t, newCAFor(t, KindNode), Identity{Kind: KindNode, ID: nodeID})
	_, err := DecodeCA(leaf.Encode())
	if err == nil {
		t.Fatal("DecodeCA accepted a leaf, want refusal")
	}
	if !errors.Is(err, ErrNotCA) {
		t.Errorf("error = %v, want ErrNotCA", err)
	}
}

// An expired root can sign nothing, and discovering that mid-enrollment is a
// poor place to learn it, so decode fails instead.
func TestDecodeCARejectsExpiredAuthority(t *testing.T) {
	// NotBefore is skewed five minutes into the past, so a notAfter one hour
	// back yields a certificate whose validity window has already closed.
	expired, err := NewCA("expired node CA", KindNode, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("NewCA with a past notAfter: %v", err)
	}
	encoded, err := expired.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if _, err := DecodeCA(encoded); !errors.Is(err, ErrExpired) {
		t.Errorf("DecodeCA error = %v, want ErrExpired", err)
	}
}

func TestDecodeCertPEMRejectsPrivateKey(t *testing.T) {
	leaf := issueLeaf(t, newCAFor(t, KindNode), Identity{Kind: KindNode, ID: nodeID})
	_, err := DecodeCertPEM(leaf.Encode())
	if err == nil {
		t.Fatal("DecodeCertPEM accepted a stream containing a private key, want refusal")
	}
	if !strings.Contains(err.Error(), "private key") {
		t.Errorf("error = %v, want a private-key refusal", err)
	}
}

func TestDecodeCertPEMAcceptsCertOnly(t *testing.T) {
	ca := newCAFor(t, KindController)
	cert, err := DecodeCertPEM(string(ca.CertPEM()))
	if err != nil {
		t.Fatalf("DecodeCertPEM: %v", err)
	}
	if cert.Subject.CommonName != ca.Cert().Subject.CommonName {
		t.Error("decoded certificate does not match the authority")
	}
}

// DecodeCertPEM is PEM-only by contract and by name: it is used for a pinned
// root an operator pastes from a file. Accepting raw bytes here would blur the
// boundary that NewVerifier deliberately owns.
func TestDecodeCertPEMRejectsDER(t *testing.T) {
	ca := newCAFor(t, KindController)
	if _, err := DecodeCertPEM(string(ca.Cert().Raw)); err == nil {
		t.Error("DecodeCertPEM accepted raw DER, want rejection")
	}
}

// NewVerifier, by contrast, accepts either encoding: operators paste PEM and
// machines transmit DER, so the discrimination happens at that one boundary
// instead of in every caller.
func TestNewVerifierAcceptsDERRoot(t *testing.T) {
	ca := newCAFor(t, KindNode)
	v, err := NewVerifier(VerifierOptions{RootPEM: ca.Cert().Raw, Kind: KindNode})
	if err != nil {
		t.Fatalf("NewVerifier(DER root): %v", err)
	}
	leaf := issueLeaf(t, ca, Identity{Kind: KindNode, ID: nodeID})
	if _, err := v.Verify([][]byte{leaf.Cert().Raw}, nil); err != nil {
		t.Errorf("Verify against a DER root: %v", err)
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	garbage := []string{
		"",
		"not pem at all",
		"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
	}
	for _, input := range garbage {
		if _, err := DecodeCA(input); err == nil {
			t.Errorf("DecodeCA(%q) succeeded, want rejection", input)
		}
		if _, err := DecodeLeaf(input); err == nil {
			t.Errorf("DecodeLeaf(%q) succeeded, want rejection", input)
		}
	}
}

// --- verification -------------------------------------------------------------

func TestVerifyAcceptsOwnLeaf(t *testing.T) {
	ca := newCAFor(t, KindNode)
	leaf := issueLeaf(t, ca, Identity{Kind: KindNode, ID: nodeID})
	v := newVerifier(t, ca.CertPEM(), KindNode, "")

	id, err := v.Verify([][]byte{leaf.Cert().Raw}, nil)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id != (Identity{Kind: KindNode, ID: nodeID}) {
		t.Errorf("identity = %+v, want the node identity", id)
	}
}

// A leaf signed by a DIFFERENT authority of the SAME kind must be refused: two
// installations each have their own Node CA, and neither may accept the other's
// nodes. This is the "compromised node trying to impersonate another node" case
// in SECURITY.md §2.
func TestVerifyRefusesForeignAuthority(t *testing.T) {
	ours := newCAFor(t, KindNode)
	theirs := newCAFor(t, KindNode)
	foreignLeaf := issueLeaf(t, theirs, Identity{Kind: KindNode, ID: nodeID})

	v := newVerifier(t, ours.CertPEM(), KindNode, "")
	_, err := v.Verify([][]byte{foreignLeaf.Cert().Raw}, nil)
	if err == nil {
		t.Fatal("Verify accepted a leaf from a foreign authority, want refusal")
	}
	if !errors.Is(err, ErrUntrustedRoot) {
		t.Errorf("error = %v, want ErrUntrustedRoot", err)
	}
}

// Same chain, wrong name: the certificate is genuine but belongs to another node.
func TestVerifyRefusesWrongID(t *testing.T) {
	ca := newCAFor(t, KindNode)
	leaf := issueLeaf(t, ca, Identity{Kind: KindNode, ID: otherNodeID})

	v := newVerifier(t, ca.CertPEM(), KindNode, nodeID)
	_, err := v.Verify([][]byte{leaf.Cert().Raw}, nil)
	if err == nil {
		t.Fatal("Verify accepted a leaf for a different node, want refusal")
	}
	if !errors.Is(err, ErrIdentity) {
		t.Errorf("error = %v, want ErrIdentity", err)
	}
}

// An authority presented as a peer would let a holder of the root key open
// connections without a leaf certificate at all.
func TestVerifyRefusesAuthorityAsPeer(t *testing.T) {
	ca := newCAFor(t, KindNode)
	v := newVerifier(t, ca.CertPEM(), KindNode, "")
	if _, err := v.Verify([][]byte{ca.Cert().Raw}, nil); err == nil {
		t.Fatal("Verify accepted a CA certificate as a peer, want refusal")
	}
}

func TestVerifyRefusesNoCertificate(t *testing.T) {
	v := newVerifier(t, newCAFor(t, KindNode).CertPEM(), KindNode, "")
	if _, err := v.Verify(nil, nil); err == nil {
		t.Fatal("Verify accepted an empty certificate list, want refusal")
	}
}

// A certificate issued by a CA that is not self-signed, presented where a
// two-certificate chain is expected, must not slip through.
func TestVerifyRefusesUnparseableCertificate(t *testing.T) {
	v := newVerifier(t, newCAFor(t, KindNode).CertPEM(), KindNode, "")
	if _, err := v.Verify([][]byte{{0x00, 0x01, 0x02}}, nil); err == nil {
		t.Fatal("Verify accepted unparseable DER, want refusal")
	}
}

func TestVerifyRefusesExpiredLeaf(t *testing.T) {
	ca := newCAFor(t, KindNode)
	// Issue with a short life, then verify with the clock moved past it. The
	// clock is injected so the test does not have to wait for calendar time.
	leaf, err := ca.IssueLeaf(LeafParams{
		Identity: Identity{Kind: KindNode, ID: nodeID},
		NotAfter: time.Now().Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	v, err := NewVerifier(VerifierOptions{
		RootPEM: ca.CertPEM(),
		Kind:    KindNode,
		Now:     func() time.Time { return time.Now().Add(2 * time.Hour) },
	})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if _, err := v.Verify([][]byte{leaf.Cert().Raw}, nil); err == nil {
		t.Fatal("Verify accepted an expired leaf, want refusal")
	}
}

// A certificate with no URI SAN has no identity in this mesh, and one with
// several could claim whichever suits the check being performed.
func TestIdentityOfRejectsMissingAndAmbiguousSANs(t *testing.T) {
	if _, err := IdentityOf(&x509.Certificate{}); err == nil {
		t.Error("IdentityOf accepted a certificate with no URI SAN, want refusal")
	}
	if _, err := IdentityOf(nil); err == nil {
		t.Error("IdentityOf accepted a nil certificate, want refusal")
	}

	leaf := issueLeaf(t, newCAFor(t, KindNode), Identity{Kind: KindNode, ID: nodeID})
	ambiguous := *leaf.Cert()
	ambiguous.URIs = []*url.URL{leaf.Cert().URIs[0], leaf.Cert().URIs[0]}
	if _, err := IdentityOf(&ambiguous); err == nil {
		t.Error("IdentityOf accepted two URI SANs, want refusal")
	}
}

func TestNewVerifierRequiresRoot(t *testing.T) {
	if _, err := NewVerifier(VerifierOptions{Kind: KindNode}); err == nil {
		t.Error("NewVerifier accepted an empty root, want rejection")
	}
}

// Pinning the Node CA while asking for controller peers is a wiring mistake, and
// refusing it at construction is what keeps the two trust domains from being
// accidentally merged by a typo.
func TestNewVerifierRejectsRootOfWrongKind(t *testing.T) {
	nodeCA := newCAFor(t, KindNode)
	if _, err := NewVerifier(VerifierOptions{RootPEM: nodeCA.CertPEM(), Kind: KindController}); err == nil {
		t.Error("NewVerifier accepted a node root for controller peers, want rejection")
	}
	controllerCA := newCAFor(t, KindController)
	if _, err := NewVerifier(VerifierOptions{RootPEM: controllerCA.CertPEM(), Kind: KindNode}); err == nil {
		t.Error("NewVerifier accepted a controller root for node peers, want rejection")
	}
}

func TestNewVerifierRejectsUnknownKind(t *testing.T) {
	ca := newCAFor(t, KindNode)
	if _, err := NewVerifier(VerifierOptions{RootPEM: ca.CertPEM(), Kind: Kind("robot")}); err == nil {
		t.Error("NewVerifier accepted an unknown kind, want rejection")
	}
}

func TestNewVerifierRejectsLeafAsRoot(t *testing.T) {
	leaf := issueLeaf(t, newCAFor(t, KindNode), Identity{Kind: KindNode, ID: nodeID})
	if _, err := NewVerifier(VerifierOptions{RootPEM: leaf.CertPEM(), Kind: KindNode}); err == nil {
		t.Error("NewVerifier accepted a leaf as the pinned root, want rejection")
	}
}

// A TLS config that verifies nothing must not be constructible by omission: the
// verifier is required, not defaulted.
func TestTLSConfigsRequireVerifier(t *testing.T) {
	leaf := issueLeaf(t, newCAFor(t, KindNode), Identity{Kind: KindNode, ID: nodeID})
	if _, err := NewTLSClientConfig(TLSClientOptions{CertPEM: leaf.CertPEM(), KeyPEM: leaf.KeyPEM()}); err == nil {
		t.Error("NewTLSClientConfig accepted a nil verifier, want rejection")
	}
	if _, err := NewTLSServerConfig(TLSServerOptions{CertPEM: leaf.CertPEM(), KeyPEM: leaf.KeyPEM()}); err == nil {
		t.Error("NewTLSServerConfig accepted a nil verifier, want rejection")
	}
}

func TestTLSConfigsRequireUsableKeyPair(t *testing.T) {
	v := newVerifier(t, newCAFor(t, KindNode).CertPEM(), KindNode, "")
	if _, err := NewTLSServerConfig(TLSServerOptions{CertPEM: []byte("x"), KeyPEM: []byte("y"), Verifier: v}); err == nil {
		t.Error("NewTLSServerConfig accepted an unusable keypair, want rejection")
	}
	if _, err := NewTLSClientConfig(TLSClientOptions{CertPEM: []byte("x"), KeyPEM: []byte("y"), Verifier: v}); err == nil {
		t.Error("NewTLSClientConfig accepted an unusable keypair, want rejection")
	}
}

// --- real TLS handshakes ------------------------------------------------------

// These cases open real sockets. A handshake test that never completes a
// handshake proves nothing, and the failures being guarded against â€” a wrong
// ClientAuth mode, an unchecked peer â€” only appear on the wire.
//
// Each refusal is asserted on the SERVER side, because that is where our
// Verifier runs. The client is deliberately built WITHOUT server verification
// (see rawClient) so the handshake proceeds far enough for the server to judge
// the client credential. If the client also verified the server, a mismatch
// there would abort the handshake first and the server would merely see "remote
// error: bad certificate" â€” the test would pass while asserting nothing about
// the property it names. That exact mistake made an earlier version of this
// suite pass vacuously.

// The full mesh, mutually authenticated in both directions: agent dials
// controller and controller dials agent, each pinning the other's root.
func TestTLSHandshakeSucceedsBetweenPinnedPeers(t *testing.T) {
	controllerCA := newCAFor(t, KindController)
	nodeCA := newCAFor(t, KindNode)

	controllerLeaf := issueLeaf(t, controllerCA, Identity{Kind: KindController, ID: controllerID})
	nodeLeaf := issueLeaf(t, nodeCA, Identity{Kind: KindNode, ID: nodeID})

	// Agent side: serves, and accepts controllers only, pinned to the
	// controller root and the one controller id.
	serverCfg := serverConfig(t, nodeLeaf, controllerCA.CertPEM(), KindController, controllerID)
	// Controller side: dials the agent, pinned to the node root.
	clientCfg := clientConfig(t, controllerLeaf, nodeCA.CertPEM(), KindNode, "")

	const payload = "typed-operation"
	if got := roundTrip(t, serverCfg, clientCfg, payload); got != payload {
		t.Errorf("round trip = %q, want %q", got, payload)
	}
}

// An anonymous client must not reach the server at all. This is the case that
// silently regresses if ClientAuth is downgraded to RequestClientCert.
func TestTLSHandshakeRefusesAnonymousClient(t *testing.T) {
	controllerCA := newCAFor(t, KindController)
	nodeLeaf := issueLeaf(t, newCAFor(t, KindNode), Identity{Kind: KindNode, ID: nodeID})

	serverCfg := serverConfig(t, nodeLeaf, controllerCA.CertPEM(), KindController, controllerID)
	anonymous := &tls.Config{
		//nolint:gosec // presenting no client certificate IS the subject of this test
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	err := serverHandshake(t, serverCfg, anonymous)
	if err == nil {
		t.Fatal("an anonymous client completed the handshake, want refusal")
	}
	if !strings.Contains(err.Error(), "didn't provide a certificate") {
		t.Errorf("server error = %v, want a missing-client-certificate refusal", err)
	}
}

// A client presenting a leaf from a DIFFERENT trust domain: genuine, signed by
// a real JAWAKER CA, but not one the server pinned.
func TestTLSHandshakeRefusesWrongTrustDomain(t *testing.T) {
	controllerCA := newCAFor(t, KindController)
	nodeCA := newCAFor(t, KindNode)

	serverLeaf := issueLeaf(t, nodeCA, Identity{Kind: KindNode, ID: nodeID})
	// Server pins this installation's controller root; the client presents a
	// controller leaf signed by a foreign controller CA.
	foreignControllerCA := newCAFor(t, KindController)
	foreignLeaf := issueLeaf(t, foreignControllerCA, Identity{Kind: KindController, ID: controllerID})

	serverCfg := serverConfig(t, serverLeaf, controllerCA.CertPEM(), KindController, controllerID)
	err := serverHandshake(t, serverCfg, rawClient(t, foreignLeaf))
	if err == nil {
		t.Fatal("a foreign-trust-domain client completed the handshake, want refusal")
	}
	if !errors.Is(err, ErrUntrustedRoot) {
		t.Errorf("server error = %v, want ErrUntrustedRoot", err)
	}
}

// Same root, genuine leaf, but not the pinned participant: a second controller
// cannot take the place of the one the agent pinned.
func TestTLSHandshakeRefusesWrongID(t *testing.T) {
	controllerCA := newCAFor(t, KindController)
	nodeCA := newCAFor(t, KindNode)

	serverLeaf := issueLeaf(t, nodeCA, Identity{Kind: KindNode, ID: nodeID})
	otherController := issueLeaf(t, controllerCA, Identity{Kind: KindController, ID: otherNodeID})

	serverCfg := serverConfig(t, serverLeaf, controllerCA.CertPEM(), KindController, controllerID)
	err := serverHandshake(t, serverCfg, rawClient(t, otherController))
	if err == nil {
		t.Fatal("a client with an unexpected id completed the handshake, want refusal")
	}
	if !errors.Is(err, ErrIdentity) {
		t.Errorf("server error = %v, want ErrIdentity", err)
	}
}

// A node leaf presented at an endpoint that pins the controller root. The leaf
// is genuine and signed by a real JAWAKER authority; it fails on trust, which is
// the guarantee that matters. The complementary property â€” that a node
// authority cannot even MINT a controller certificate â€” is covered by
// TestAuthorityRefusesToSignOtherKind.
func TestTLSHandshakeRefusesNodeLeafAtControllerEndpoint(t *testing.T) {
	controllerCA := newCAFor(t, KindController)
	nodeCA := newCAFor(t, KindNode)

	serverLeaf := issueLeaf(t, controllerCA, Identity{Kind: KindController, ID: controllerID})
	nodeLeaf := issueLeaf(t, nodeCA, Identity{Kind: KindNode, ID: nodeID})

	serverCfg := serverConfig(t, serverLeaf, controllerCA.CertPEM(), KindController, controllerID)
	err := serverHandshake(t, serverCfg, rawClient(t, nodeLeaf))
	if err == nil {
		t.Fatal("a node leaf completed a handshake at a controller-pinned endpoint, want refusal")
	}
	if !errors.Is(err, ErrUntrustedRoot) {
		t.Errorf("server error = %v, want ErrUntrustedRoot", err)
	}
}

// A CA certificate presented as a peer: it chains to the pinned root, so only
// the "an authority is not a peer" rule stops it.
func TestTLSHandshakeRefusesAuthorityAsPeer(t *testing.T) {
	controllerCA := newCAFor(t, KindController)
	nodeCA := newCAFor(t, KindNode)

	serverLeaf := issueLeaf(t, nodeCA, Identity{Kind: KindNode, ID: nodeID})
	serverCfg := serverConfig(t, serverLeaf, controllerCA.CertPEM(), KindController, controllerID)

	caAsClient := &tls.Config{
		Certificates: []tls.Certificate{keyPairFromCA(t, controllerCA)},
		//nolint:gosec // isolating the server-side "an authority is not a peer" rule
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
	err := serverHandshake(t, serverCfg, caAsClient)
	if err == nil {
		t.Fatal("an authority certificate completed a handshake as a peer, want refusal")
	}
	if !errors.Is(err, ErrIdentity) {
		t.Errorf("server error = %v, want ErrIdentity", err)
	}
}

// --- TLS helpers --------------------------------------------------------------

func newVerifier(t *testing.T, rootPEM []byte, kind Kind, id string) *Verifier {
	t.Helper()
	v, err := NewVerifier(VerifierOptions{RootPEM: rootPEM, Kind: kind, ID: id})
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

// serverConfig builds a server TLS config that verifies clients against the
// given pinned root, kind, and optional id.
func serverConfig(t *testing.T, leaf *Leaf, rootPEM []byte, kind Kind, id string) *tls.Config {
	t.Helper()
	cfg, err := NewTLSServerConfig(TLSServerOptions{
		CertPEM:  leaf.CertPEM(),
		KeyPEM:   leaf.KeyPEM(),
		Verifier: newVerifier(t, rootPEM, kind, id),
	})
	if err != nil {
		t.Fatalf("server config: %v", err)
	}
	return cfg
}

// clientConfig builds a fully-verifying client: it presents its own leaf AND
// verifies the server against a pinned root. Used for the mutual-auth success
// path, where both sides must judge each other.
func clientConfig(t *testing.T, leaf *Leaf, rootPEM []byte, kind Kind, id string) *tls.Config {
	t.Helper()
	cfg, err := NewTLSClientConfig(TLSClientOptions{
		CertPEM:  leaf.CertPEM(),
		KeyPEM:   leaf.KeyPEM(),
		Verifier: newVerifier(t, rootPEM, kind, id),
	})
	if err != nil {
		t.Fatalf("client config: %v", err)
	}
	return cfg
}

// rawClient presents a leaf but does NOT verify the server. This isolates the
// server-side verifier: the handshake reaches the point where the server judges
// the client credential, and the error observed is ours rather than a client
// rejecting the server first.
func rawClient(t *testing.T, leaf *Leaf) *tls.Config {
	t.Helper()
	cert, err := tls.X509KeyPair(leaf.CertPEM(), leaf.KeyPEM())
	if err != nil {
		t.Fatalf("client keypair: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		//nolint:gosec // server verification is intentionally out of scope here
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS12,
	}
}

// keyPairFromCA loads an authority's own certificate and key as a TLS keypair,
// so a test can present a CA where a leaf is expected.
func keyPairFromCA(t *testing.T, ca *CA) tls.Certificate {
	t.Helper()
	encoded, err := ca.Encode()
	if err != nil {
		t.Fatalf("encode CA: %v", err)
	}
	leaf, err := DecodeLeaf(encoded)
	if err != nil {
		t.Fatalf("decode CA as leaf: %v", err)
	}
	cert, err := tls.X509KeyPair(leaf.CertPEM(), leaf.KeyPEM())
	if err != nil {
		t.Fatalf("CA keypair: %v", err)
	}
	return cert
}

// serverHandshake runs one handshake and returns the error the SERVER observed,
// which is where our Verifier runs. A nil result means the server accepted the
// client. The client's own view is discarded on purpose: these cases assert
// what the server decides.
func serverHandshake(t *testing.T, serverCfg, clientCfg *tls.Config) error {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		defer func() { _ = conn.Close() }()
		// Complete the handshake so the server-side verifier actually runs and
		// its verdict is what we capture, rather than a connection closed before
		// verification happened.
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		serverDone <- conn.(*tls.Conn).HandshakeContext(ctx)
	}()

	// Drive the client side to completion; its error is not the subject here,
	// but the connection must be attempted for the server to reach its verifier.
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	dialer := &tls.Dialer{Config: clientCfg}
	if conn, dialErr := dialer.DialContext(dialCtx, "tcp", ln.Addr().String()); dialErr == nil {
		_ = conn.Close()
	}

	select {
	case err := <-serverDone:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("server handshake did not complete within the timeout")
		return nil
	}
}

// roundTrip serves one echo over a real, mutually-authenticated TLS connection
// and returns what came back.
func roundTrip(t *testing.T, serverCfg, clientCfg *tls.Config, payload string) string {
	t.Helper()

	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	accepted := make(chan error, 1)
	go func() {
		conn, acceptErr := ln.Accept()
		if acceptErr != nil {
			accepted <- acceptErr
			return
		}
		defer func() { _ = conn.Close() }()
		buf := make([]byte, 256)
		n, readErr := conn.Read(buf)
		if readErr != nil {
			accepted <- readErr
			return
		}
		if _, writeErr := conn.Write(buf[:n]); writeErr != nil {
			accepted <- writeErr
			return
		}
		accepted <- nil
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	dialer := &tls.Dialer{Config: clientCfg}
	conn, err := dialer.DialContext(dialCtx, "tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if _, err := conn.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 256)
	n, readErr := conn.Read(buf)
	if readErr != nil {
		t.Fatalf("read: %v", readErr)
	}
	if err := <-accepted; err != nil {
		t.Fatalf("server side: %v", err)
	}
	return string(buf[:n])
}
