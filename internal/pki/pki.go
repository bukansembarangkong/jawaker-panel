// Package pki implements JAWAKER's internal certificate authority.
//
// This is the INTERNAL PKI (PRD.md §15.5), deliberately separate from public
// website certificates. It exists to give the controller↔node channel an
// identity that is not an IP address (SECURITY.md §6: "IP address alone is not
// identity").
//
// # Two authorities, not one
//
// The controller and the nodes are signed by DIFFERENT root keys:
//
//	Controller CA ──signs──> controller leaf   (spiffe://jawaker/controller/<id>)
//	Node CA       ──signs──> node leaf         (spiffe://jawaker/node/<id>)
//
// A single shared CA would mean any node's certificate chains to the root that
// nodes use to authenticate the controller. A compromised node could then
// present its own certificate to another node and be believed to be the
// controller — exactly the "forged controller commands" case in SECURITY.md §2.
// Two roots make that structurally impossible: a node leaf simply does not
// verify against the pinned Controller CA.
//
// Identity is carried in a URI SAN (spiffe://jawaker/<kind>/<id>) rather than a
// DNS name. The DNS SAN present on every leaf is a fixed constant per kind; it
// exists only so the TLS stack's hostname check has something to match, and it
// carries no meaning. The real identity is the URI, and the CA that signed it.
//
// # Key custody
//
// CA private keys are encoded by [CA.Encode] and are intended to be stored
// through internal/secret, which encrypts at rest and audits access. The
// encoded form CONTAINS A PRIVATE KEY. It must never be logged, returned to a
// browser, or written to a Git-backed location.
//
// Node private keys never leave the node: they are written to the agent's state
// directory and are not transmitted at enrollment.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// Kind distinguishes the two participants in the mesh. It is part of the
// certificate's identity, so a value here is wire-visible and must never be
// renamed casually: renaming it orphans every already-issued certificate.
type Kind string

const (
	// KindController identifies the control plane.
	KindController Kind = "controller"
	// KindNode identifies a managed server's agent.
	KindNode Kind = "node"
)

// TrustDomain is the SPIFFE trust domain for this installation. It is a
// constant rather than configuration: there is one mesh per installation, and
// making it configurable would create a way for two installations to accept
// each other's certificates.
const TrustDomain = "jawaker"

// Fixed DNS SANs, one per kind.
//
// These are constants on purpose. A leaf's DNS SAN has to match whatever the
// peer dials, and the peer dials by address — which changes when a node is
// re-IP'd, moved, or reached over a different network. Binding the certificate
// to an address would force a reissue for a network change that does not change
// WHO the participant is. Using a constant keeps the certificate valid across
// address changes while the URI SAN continues to carry the identity.
//
// The names are unresolvable by design. Nothing should ever look them up in
// DNS; if a name like this resolved, that would be a sign of confusion, not a
// working deployment.
const (
	dnsController = "controller.jawaker.internal"
	dnsNode       = "node.jawaker.internal"
)

// Default lifetimes.
//
// The CA is long-lived because rotating it means re-enrolling every node — a
// fleet-wide operation, not a maintenance task. Leaves are short-lived so that
// the cost of a stolen leaf is bounded in time even if revocation is somehow
// missed, and so that renewal is exercised continuously rather than only in a
// once-a-decade emergency.
const (
	DefaultCALifetime   = 10 * 365 * 24 * time.Hour
	DefaultLeafLifetime = 30 * 24 * time.Hour
)

// notBeforeSkew starts certificates slightly in the past. Controllers and nodes
// are different machines with different clocks, and a certificate that is not
// yet valid on a node whose clock runs a few seconds behind the controller
// would fail the handshake for a reason no operator can see. Five minutes is
// enough to absorb realistic NTP drift and far too small to matter for
// lifetime accounting.
const notBeforeSkew = 5 * time.Minute

// serialBytes is the width of a generated serial number. RFC 5280 requires
// uniqueness per CA and no more than 20 octets; 16 random octets gives a value
// that is unique with overwhelming probability and, unlike a counter, reveals
// nothing about how many certificates have been issued.
const serialBytes = 16

var (
	// ErrNotCA is returned when a decoded keypair is not a usable authority.
	ErrNotCA = errors.New("pki: not a certificate authority")
	// ErrExpired is returned when a decoded keypair is no longer valid.
	ErrExpired = errors.New("pki: certificate is not currently valid")
	// ErrKeyMismatch is returned when a decoded private key does not
	// correspond to its certificate.
	ErrKeyMismatch = errors.New("pki: private key does not match certificate")
	// ErrMalformed is returned for PEM that cannot be parsed into the expected
	// shape.
	ErrMalformed = errors.New("pki: malformed keypair")
)

// Identity names one participant in the mesh.
//
// The ID is the opaque UUID from the control-plane database (controller_identity.id
// or servers.id). Using the database identifier means an identity can always be
// resolved back to the row that governs it — its permissions, its revocation
// state, and its audit history — without a second mapping table.
type Identity struct {
	Kind Kind
	ID   string
}

// URI renders the identity as its SPIFFE URI SAN.
func (id Identity) URI() *url.URL {
	return &url.URL{
		Scheme: "spiffe",
		Host:   TrustDomain,
		Path:   "/" + string(id.Kind) + "/" + id.ID,
	}
}

// String renders the identity for logs. It contains no secret material.
func (id Identity) String() string { return id.URI().String() }

// ParseIdentity extracts an identity from a URI SAN.
//
// Every component is checked. A URI is attacker-influenced data from the point
// of view of the verifier: the certificate presenting it may itself be the
// forgery, so the parse must not assume shape.
func ParseIdentity(u *url.URL) (Identity, error) {
	if u == nil {
		return Identity{}, fmt.Errorf("%w: nil URI", ErrMalformed)
	}
	if u.Scheme != "spiffe" {
		return Identity{}, fmt.Errorf("%w: scheme %q is not spiffe", ErrMalformed, u.Scheme)
	}
	if u.Host != TrustDomain {
		return Identity{}, fmt.Errorf("%w: trust domain %q is not %q", ErrMalformed, u.Host, TrustDomain)
	}
	// A SPIFFE URI carries no query, fragment, or credentials. Accepting them
	// would create two spellings of one identity.
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return Identity{}, fmt.Errorf("%w: URI carries query, fragment, or userinfo", ErrMalformed)
	}

	path := strings.TrimPrefix(u.Path, "/")
	kindStr, id, found := strings.Cut(path, "/")
	if !found {
		return Identity{}, fmt.Errorf("%w: path %q is not /<kind>/<id>", ErrMalformed, u.Path)
	}
	var kind Kind
	switch Kind(kindStr) {
	case KindController:
		kind = KindController
	case KindNode:
		kind = KindNode
	default:
		return Identity{}, fmt.Errorf("%w: unknown kind %q", ErrMalformed, kindStr)
	}
	// Reject an empty id and any id that could re-introduce a path segment or a
	// parent traversal, which would make one identity spellable two ways.
	if id == "" || strings.ContainsAny(id, "/\\") || strings.Contains(id, "..") {
		return Identity{}, fmt.Errorf("%w: id %q is not a single opaque segment", ErrMalformed, id)
	}
	return Identity{Kind: kind, ID: id}, nil
}

// dnsNameFor returns the fixed DNS SAN for a kind.
func dnsNameFor(kind Kind) (string, error) {
	switch kind {
	case KindController:
		return dnsController, nil
	case KindNode:
		return dnsNode, nil
	default:
		return "", fmt.Errorf("pki: unknown kind %q", kind)
	}
}

// CA is a signing authority: its own certificate plus the private key that
// signs leaves.
//
// An authority is bound to exactly ONE kind. That binding is not decoration: it
// is what makes the two-authority design structural rather than aspirational.
// The Controller CA physically cannot sign a node certificate, so no future
// caller can collapse the separation by reaching for the wrong root.
type CA struct {
	cert    *x509.Certificate
	key     crypto.Signer
	kind    Kind
	certPEM []byte
}

// Kind reports which participants this authority may sign.
func (ca *CA) Kind() Kind { return ca.kind }

// NewCA generates a fresh self-signed authority for one kind.
//
// The subject common name is human-facing only — it appears in operator
// tooling and certificate dumps. Trust decisions are made from IsCA, the key
// usage, and which root is pinned, never from the name. The kind, by contrast,
// IS load-bearing: it decides which leaves this authority can ever sign.
func NewCA(commonName string, kind Kind, notAfter time.Time) (*CA, error) {
	if strings.TrimSpace(commonName) == "" {
		return nil, errors.New("pki: CA common name is required")
	}
	if _, err := dnsNameFor(kind); err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate CA key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"JAWAKER"},
		},
		NotBefore: now.Add(-notBeforeSkew),
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		// The bound kind is stamped into the authority's OWN URI SAN. It has to
		// live inside the certificate rather than only in Go memory, because a
		// CA is stored as an encoded secret and re-decoded on every controller
		// restart: a binding that had to be passed back in by the caller would
		// be a binding a caller could pass in wrongly.
		URIs: []*url.URL{{
			Scheme: "spiffe",
			Host:   TrustDomain,
			Path:   "/" + string(kind) + "/ca",
		}},
		// Explicitly a CA, and explicitly unable to sign further CAs. The mesh
		// is two levels deep; allowing an intermediate would create a path to
		// issue node certificates from a key that is not the stored root.
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		return nil, fmt.Errorf("pki: sign CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: reparse CA certificate: %w", err)
	}
	return &CA{cert: cert, key: key, kind: kind, certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}

// Cert exposes the authority's own certificate. It is public material and is
// what gets pinned by the other side.
func (ca *CA) Cert() *x509.Certificate { return ca.cert }

// CertPEM returns the authority's certificate as PEM, suitable for pinning.
// It contains no secret material.
func (ca *CA) CertPEM() []byte { return ca.certPEM }

// Fingerprint returns the SHA-256 of the authority certificate's DER encoding,
// as lowercase hex. This is what an operator compares when checking that a
// pinned root is the root they think it is.
func (ca *CA) Fingerprint() string { return fingerprint(ca.cert.Raw) }

// LeafParams describes a certificate to issue.
type LeafParams struct {
	// Identity is stamped into the URI SAN and is the participant's real name.
	Identity Identity
	// NotAfter bounds the leaf's validity. Leaves are short-lived by policy.
	NotAfter time.Time
}

// Leaf is an issued certificate plus its private key.
type Leaf struct {
	cert    *x509.Certificate
	key     crypto.Signer
	certPEM []byte
	keyPEM  []byte
}

// IssueLeaf signs a leaf certificate for the given identity.
//
// The CA's own kind determines what it may sign: the Controller CA signs
// controllers and the Node CA signs nodes. That binding is recorded on the CA
// at construction so a caller cannot accidentally cross the two trust domains
// by passing the wrong identity to the wrong authority.
func (ca *CA) IssueLeaf(params LeafParams) (*Leaf, error) {
	dnsName, err := dnsNameFor(params.Identity.Kind)
	if err != nil {
		return nil, err
	}
	// The load-bearing check: an authority signs only its own kind. Without it,
	// handing the Controller CA a node identity would produce a node leaf that
	// chains to the controller root — collapsing the two trust domains into one
	// and reopening the impersonation path the split was designed to close.
	if params.Identity.Kind != ca.kind {
		return nil, fmt.Errorf("pki: %s CA cannot issue a %s certificate", ca.kind, params.Identity.Kind)
	}
	if params.Identity.ID == "" {
		return nil, errors.New("pki: leaf identity requires an id")
	}
	if !params.NotAfter.After(time.Now()) {
		return nil, errors.New("pki: leaf notAfter must be in the future")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("pki: generate leaf key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			// The common name mirrors the URI so a human reading `openssl x509
			// -text` sees the identity without decoding the SAN extension.
			CommonName:   params.Identity.String(),
			Organization: []string{"JAWAKER"},
		},
		NotBefore: now.Add(-notBeforeSkew),
		NotAfter:  params.NotAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		// Both usages, because each participant both serves and dials: the
		// agent listens for controller-initiated operations AND pushes
		// heartbeats to the controller. Issuing two certificates per
		// participant would double the renewal surface for no security gain —
		// the trust decision comes from which CA signed it and which URI it
		// carries, not from which direction the socket was opened.
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{dnsName},
		URIs:     []*url.URL{params.Identity.URI()},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, key.Public(), ca.key)
	if err != nil {
		return nil, fmt.Errorf("pki: sign leaf certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: reparse leaf certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: encode leaf key: %w", err)
	}
	return &Leaf{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// Cert exposes the leaf certificate. Public material.
func (l *Leaf) Cert() *x509.Certificate { return l.cert }

// CertPEM returns the leaf certificate as PEM. Public material; safe to send
// to a peer during enrollment.
func (l *Leaf) CertPEM() []byte { return l.certPEM }

// KeyPEM returns the leaf private key as PEM.
//
// This is SECRET MATERIAL. It is written only to the owning participant's
// state directory and is never logged, never returned over the API, and never
// stored in the control-plane database.
func (l *Leaf) KeyPEM() []byte { return l.keyPEM }

// SerialHex returns the certificate serial as lowercase hex. This is the value
// recorded in node_certificates.serial and checked on every handshake.
func (l *Leaf) SerialHex() string { return serialHex(l.cert.SerialNumber) }

// Fingerprint returns the SHA-256 of the leaf's DER encoding as lowercase hex.
func (l *Leaf) Fingerprint() string { return fingerprint(l.cert.Raw) }

// Identity extracts the URI SAN identity from this leaf.
func (l *Leaf) Identity() (Identity, error) { return identityOf(l.cert) }

// Encode renders the keypair as a single PEM stream: certificate block followed
// by private key block.
//
// The output CONTAINS A PRIVATE KEY.
func (l *Leaf) Encode() string {
	return string(l.certPEM) + string(l.keyPEM)
}

// DecodeLeaf parses a PEM stream produced by [Leaf.Encode].
//
// The private key is required to match the certificate's public key. Accepting
// a mismatched pair would produce signature failures at handshake time with no
// indication of the actual cause, so the mismatch is caught here instead.
func DecodeLeaf(s string) (*Leaf, error) {
	cert, key, err := decodePair(s)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("pki: re-encode leaf key: %w", err)
	}
	return &Leaf{
		cert:    cert,
		key:     key,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	}, nil
}

// Encode renders the authority as a single PEM stream: certificate block
// followed by private key block.
//
// The output CONTAINS THE ROOT PRIVATE KEY. It is stored only through
// internal/secret and must never reach a log line, an HTTP response, or a
// Git-backed file.
//
// It returns an error rather than an empty string on failure: an empty value
// would be stored as if it were a valid keypair, and the installation would
// later fail to enroll nodes with no indication that the root was never written.
func (ca *CA) Encode() (string, error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(ca.key)
	if err != nil {
		return "", fmt.Errorf("pki: encode CA key: %w", err)
	}
	return string(ca.certPEM) + string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})), nil
}

// DecodeCA parses a PEM stream produced by [CA.Encode] and validates that it is
// a usable, currently-valid authority whose key matches its certificate.
//
// Each check here prevents a specific confusing failure later:
//   - not a CA: a leaf decoded as an authority could sign further leaves if the
//     caller then used it to issue, so it is refused outright;
//   - expired: an expired authority cannot sign anything, and discovering that
//     during an enrollment is a poor place to learn it;
//   - key mismatch: produces opaque handshake failures instead of a clear cause.
func DecodeCA(s string) (*CA, error) {
	cert, key, err := decodePair(s)
	if err != nil {
		return nil, err
	}
	if !cert.IsCA {
		return nil, fmt.Errorf("%w: certificate is not a CA", ErrNotCA)
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("%w: certificate lacks the certSign key usage", ErrNotCA)
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, fmt.Errorf("%w: CA valid from %s to %s, now %s",
			ErrExpired, cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339),
			now.Format(time.RFC3339))
	}
	kind, err := kindFromCA(cert)
	if err != nil {
		return nil, err
	}
	return &CA{
		cert:    cert,
		key:     key,
		kind:    kind,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
	}, nil
}

// kindFromCA recovers an authority's bound kind from its own URI SAN.
//
// Reading it from the certificate rather than accepting it as a parameter is
// the whole point: a caller cannot decode the Node CA and then claim it is the
// Controller CA. The binding travels with the key material.
func kindFromCA(cert *x509.Certificate) (Kind, error) {
	if len(cert.URIs) != 1 {
		return "", fmt.Errorf("%w: authority certificate must carry exactly one URI SAN, has %d",
			ErrMalformed, len(cert.URIs))
	}
	id, err := ParseIdentity(cert.URIs[0])
	if err != nil {
		return "", fmt.Errorf("%w: authority URI SAN is not readable: %v", ErrMalformed, err)
	}
	// NewCA stamps the authority segment as the literal "ca". Anything else
	// means this certificate was not produced by this package's NewCA, and
	// trusting its kind would mean trusting unvalidated input.
	if id.ID != "ca" {
		return "", fmt.Errorf("%w: authority URI SAN segment %q is not %q", ErrMalformed, id.ID, "ca")
	}
	return id.Kind, nil
}

// DecodeCertPEM parses a PEM stream containing only a certificate. It is used
// for the pinned root a node stores, which must never include a private key.
//
// A private key block in the input is rejected rather than ignored: a node that
// received a key it should not have is a misconfiguration worth failing loudly,
// not silently trimming.
func DecodeCertPEM(s string) (*x509.Certificate, error) {
	certPEM, keyPEM, err := splitPair(s)
	if err != nil {
		return nil, err
	}
	if keyPEM != nil {
		return nil, fmt.Errorf("%w: expected a certificate only, but the stream contains a private key", ErrMalformed)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("%w: no PEM block found", ErrMalformed)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: parse certificate: %v", ErrMalformed, err)
	}
	return cert, nil
}

// splitPair separates a PEM stream into its certificate bytes and, if present,
// its private key block.
func splitPair(s string) (certPEM []byte, keyBlock *pem.Block, err error) {
	rest := []byte(s)
	var certBlocks [][]byte
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			certBlocks = append(certBlocks, pem.EncodeToMemory(block))
		case "PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY":
			if keyBlock != nil {
				return nil, nil, fmt.Errorf("%w: stream contains more than one private key", ErrMalformed)
			}
			keyBlock = block
		default:
			// Unknown blocks are ignored so that a future field (an
			// intermediate certificate, say) does not break older readers.
		}
	}
	if len(certBlocks) == 0 {
		return nil, nil, fmt.Errorf("%w: stream contains no certificate", ErrMalformed)
	}
	if len(certBlocks) > 1 {
		// The mesh is exactly two levels deep, so a chain here is unexpected.
		// Refusing is safer than picking one: the wrong choice would produce a
		// certificate that verifies against the wrong root.
		return nil, nil, fmt.Errorf("%w: stream contains %d certificates, expected 1", ErrMalformed, len(certBlocks))
	}
	return certBlocks[0], keyBlock, nil
}

// decodePair parses a certificate+key stream and verifies the key matches.
func decodePair(s string) (*x509.Certificate, crypto.Signer, error) {
	certPEM, keyBlock, err := splitPair(s)
	if err != nil {
		return nil, nil, err
	}
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("%w: stream contains no private key", ErrMalformed)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, fmt.Errorf("%w: certificate block is not decodable", ErrMalformed)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: parse certificate: %v", ErrMalformed, err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Fall back to the SEC1 encoding, which older tooling still emits.
		ecKey, ecErr := x509.ParseECPrivateKey(keyBlock.Bytes)
		if ecErr != nil {
			return nil, nil, fmt.Errorf("%w: parse private key: %v", ErrMalformed, err)
		}
		parsed = ecKey
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("%w: private key is not a signer", ErrMalformed)
	}
	if !publicKeysEqual(signer.Public(), cert.PublicKey) {
		return nil, nil, fmt.Errorf("%w: certificate public key differs from the private key", ErrKeyMismatch)
	}
	return cert, signer, nil
}

// publicKeysEqual compares two public keys without assuming a concrete type, so
// a future move to Ed25519 does not silently break the comparison.
func publicKeysEqual(a, b crypto.PublicKey) bool {
	typeEqualer, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	if !ok {
		return false
	}
	return typeEqualer.Equal(b)
}

// newSerial returns a random positive serial number.
func newSerial() (*big.Int, error) {
	buf := make([]byte, serialBytes)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("pki: read entropy for serial: %w", err)
	}
	// Clear the high bit so the value is positive; a negative serial is invalid
	// in DER and would fail to encode.
	buf[0] &= 0x7f
	serial := new(big.Int).SetBytes(buf)
	if serial.Sign() == 0 {
		// A zero serial is invalid per RFC 5280. The probability of drawing all
		// zero bytes is 2^-127, so this is a guard rather than a retry loop.
		return nil, errors.New("pki: generated serial is zero")
	}
	return serial, nil
}

// serialHex renders a serial as the lowercase hex string stored in the database.
func serialHex(serial *big.Int) string {
	return hex.EncodeToString(serial.Bytes())
}

// fingerprint returns the SHA-256 of a DER encoding as lowercase hex.
func fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// identityOf extracts the single URI SAN identity from a certificate.
//
// A certificate with zero URIs has no identity in this mesh. One with several
// is ambiguous, and choosing among them would let a certificate claim whichever
// identity is convenient for the check being performed — so both are refused.
func identityOf(cert *x509.Certificate) (Identity, error) {
	if len(cert.URIs) == 0 {
		return Identity{}, fmt.Errorf("%w: certificate has no URI SAN", ErrMalformed)
	}
	if len(cert.URIs) > 1 {
		return Identity{}, fmt.Errorf("%w: certificate has %d URI SANs, expected exactly 1",
			ErrMalformed, len(cert.URIs))
	}
	return ParseIdentity(cert.URIs[0])
}

// IdentityOf extracts the identity from a certificate that has ALREADY been
// verified.
//
// It performs no chain validation: calling it on an unverified certificate and
// trusting the result would be an authentication bypass. The verifier callback
// is what establishes trust; this only reads the name off a certificate that
// trust was already established for.
func IdentityOf(cert *x509.Certificate) (Identity, error) {
	if cert == nil {
		return Identity{}, fmt.Errorf("%w: nil certificate", ErrMalformed)
	}
	return identityOf(cert)
}
