package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// Verification is where trust is actually decided. Issuance only creates
// credentials; nothing here can be weakened by a bug in issuance, because the
// verifier never consults the issuing code — it consults the pinned root.
//
// Two properties are checked on every handshake, in this order:
//
//	1. CHAIN:   the peer's certificate is signed, directly, by the pinned root.
//	2. IDENTITY: the chain's leaf carries a URI SAN whose KIND matches the one
//	            this verifier pins, and whose ID matches when one is expected.
//
// Checking only (1) authenticates "a JAWAKER participant of some kind". That is
// insufficient: a legitimate node certificate chains to the Node CA, and the
// Node CA is not the root the node is told to pin for its controller. The
// reverse — a controller connecting with a leaf that chains to the Node CA —
// fails (1) directly. Both halves are load-bearing.
//
// # Why the hostname check is disabled
//
// Peers dial by address (host:port from the servers table), and a leaf's DNS
// SAN is a per-kind constant. Standard hostname verification would therefore
// fail on every connection, so it is disabled and this verifier takes its
// place. Disabling it WITHOUT replacing it — that is, setting
// InsecureSkipVerify with no callback — is the single most dangerous mistake
// available in Go's TLS API, so the callback is not optional here: a Config
// cannot be built without a Verifier.

// ErrUntrustedRoot reports a chain that does not terminate at the pinned root.
var ErrUntrustedRoot = errors.New("pki: certificate chain is not signed by the pinned authority")

// ErrIdentity reports a chain that verifies but whose identity is not the one
// expected: wrong kind, wrong id, missing SAN, or ambiguous SANs.
var ErrIdentity = errors.New("pki: certificate identity is not the expected one")

// Verifier authenticates a peer by pinned root and expected identity.
//
// A Verifier is immutable after construction and is safe for concurrent use:
// the TLS stack calls it on every handshake from potentially many goroutines.
type Verifier struct {
	roots    *x509.CertPool
	kind     Kind
	id       string
	notAfter time.Time
	// now is injectable so tests can exercise an expired root without waiting
	// for calendar time to pass.
	now func() time.Time
}

// VerifierOptions configures a [Verifier].
type VerifierOptions struct {
	// RootPEM is the pinned authority certificate, PEM or DER. This is the ONLY
	// trust anchor consulted: the operating system trust store is deliberately
	// excluded, because a publicly trusted CA must never be able to mint a
	// certificate that this mesh accepts.
	RootPEM []byte
	// Kind is the participant class expected on the other end. Required.
	Kind Kind
	// ID further restricts the peer to one specific participant. Empty accepts
	// any id of the expected kind, which is the right setting for a controller
	// accepting connections from the fleet.
	ID string
	// Now supplies the clock. Nil means time.Now.
	Now func() time.Time
}

// NewVerifier builds a peer verifier from a pinned root.
//
// The pinned certificate is required to be a CA: pinning a leaf and verifying
// chains against it would silently accept nothing, and the failure would show
// up much later as an unexplainable enrollment outage.
func NewVerifier(opts VerifierOptions) (*Verifier, error) {
	if len(opts.RootPEM) == 0 {
		return nil, errors.New("pki: a pinned root certificate is required")
	}
	if _, err := dnsNameFor(opts.Kind); err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	rootCert, err := parseCertAnyEncoding(opts.RootPEM)
	if err != nil {
		return nil, err
	}
	if !rootCert.IsCA {
		return nil, fmt.Errorf("%w: pinned root is not a certificate authority", ErrNotCA)
	}
	// The root's own URI SAN declares which kind it is authoritative for. If the
	// caller asks a Node-root verifier to accept controllers, that is a wiring
	// mistake, and wiring mistakes are what this package exists to make
	// impossible.
	rootKind, err := kindFromCA(rootCert)
	if err != nil {
		return nil, err
	}
	if rootKind != opts.Kind {
		return nil, fmt.Errorf("%w: pinned root is a %s authority, but %s peers were expected",
			ErrIdentity, rootKind, opts.Kind)
	}

	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	return &Verifier{
		roots:    roots,
		kind:     opts.Kind,
		id:       opts.ID,
		notAfter: rootCert.NotAfter,
		now:      now,
	}, nil
}

// Kind reports the participant class this verifier accepts.
func (v *Verifier) Kind() Kind { return v.kind }

// Verify validates a peer's presented certificates and returns its identity.
//
// verifiedChains is what the TLS stack hands a VerifyPeerCertificate callback.
// When the stack performed its own (unpinned) verification this slice is
// populated; when InsecureSkipVerify is set it is empty, which is why the
// fallback below re-verifies against the pinned pool rather than trusting the
// argument's presence.
func (v *Verifier) Verify(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) (Identity, error) {
	if len(rawCerts) == 0 && len(verifiedChains) == 0 {
		return Identity{}, fmt.Errorf("%w: peer presented no certificate", ErrUntrustedRoot)
	}

	leaf, err := v.chainToRoot(rawCerts, verifiedChains)
	if err != nil {
		return Identity{}, err
	}

	// Chain validation covers signature and validity window. It does NOT cover
	// what the certificate is ALLOWED to be used for, which is the difference
	// between "a certificate that chains to our root" and "a certificate that
	// may authenticate this endpoint". A CA certificate presented as a peer, or
	// a leaf signed for a different purpose, is rejected here.
	if leaf.IsCA {
		return Identity{}, fmt.Errorf("%w: a certificate authority cannot act as a peer", ErrIdentity)
	}
	if usageErr := v.checkUsage(leaf); usageErr != nil {
		return Identity{}, usageErr
	}

	id, err := identityOf(leaf)
	if err != nil {
		return Identity{}, fmt.Errorf("%w: %v", ErrIdentity, err)
	}
	if id.Kind != v.kind {
		return Identity{}, fmt.Errorf("%w: peer is a %s, expected a %s", ErrIdentity, id.Kind, v.kind)
	}
	if v.id != "" && id.ID != v.id {
		return Identity{}, fmt.Errorf("%w: peer is %q, expected %q", ErrIdentity, id.ID, v.id)
	}
	return id, nil
}

// VerifyConnection validates an already-negotiated connection state and returns
// the peer identity.
//
// This exists because VerifyPeerCertificate is NOT called on a resumed session:
// a peer that was accepted once could replay its session ticket and reconnect
// without its certificate being re-examined. VerifyConnection IS called on every
// handshake, resumed or not, so it is the hook that actually guarantees identity
// is checked each time. Both callbacks are wired in the TLS configs; this one is
// the authoritative gate.
func (v *Verifier) VerifyConnection(cs tls.ConnectionState) (Identity, error) {
	raw := make([][]byte, 0, len(cs.PeerCertificates))
	for _, cert := range cs.PeerCertificates {
		raw = append(raw, cert.Raw)
	}
	// verifiedChains is nil on the resumption path, so Verify falls back to
	// validating against the pinned pool. That is the intended behavior: a
	// resumed session must still be proven to chain to the pinned root.
	return v.Verify(raw, nil)
}

// chainToRoot resolves the presented certificates into a leaf verified against
// the pinned root.
//
// The chain is required to be exactly [leaf, root]. Longer chains mean an
// intermediate, and the mesh has none — so accepting one would mean accepting a
// certificate signed by a key that is not the stored root but chains to it via
// some other authority.
func (v *Verifier) chainToRoot(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) (*x509.Certificate, error) {
	if len(verifiedChains) == 1 && len(verifiedChains[0]) >= 1 {
		chain := verifiedChains[0]
		if err := v.shapeOK(chain); err != nil {
			return nil, err
		}
		return chain[0], nil
	}

	parsed := make([]*x509.Certificate, 0, len(rawCerts))
	for _, der := range rawCerts {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("%w: peer presented an unparseable certificate: %v", ErrUntrustedRoot, err)
		}
		parsed = append(parsed, cert)
	}
	if len(parsed) == 0 {
		return nil, fmt.Errorf("%w: peer presented no parsable certificate", ErrUntrustedRoot)
	}

	intermediates := x509.NewCertPool()
	for _, c := range parsed[1:] {
		intermediates.AddCert(c)
	}
	chains, err := parsed[0].Verify(x509.VerifyOptions{
		Roots:         v.roots,
		Intermediates: intermediates,
		CurrentTime:   v.now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUntrustedRoot, err)
	}
	if len(chains) != 1 {
		// Several valid chains means several roots claim this leaf. Choosing one
		// would be choosing which root to trust, which is not the application's
		// decision to make at runtime.
		return nil, fmt.Errorf("%w: %d valid chains to the pinned root, expected exactly 1",
			ErrUntrustedRoot, len(chains))
	}
	if err := v.shapeOK(chains[0]); err != nil {
		return nil, err
	}
	return chains[0][0], nil
}

// shapeOK asserts the direct-chain structural rules.
func (v *Verifier) shapeOK(chain []*x509.Certificate) error {
	if len(chain) > 2 {
		return fmt.Errorf("%w: chain is %d certificates deep; this mesh allows root and leaf only",
			ErrUntrustedRoot, len(chain))
	}
	leaf := chain[0]
	if leaf.NotAfter.Before(v.now()) {
		return fmt.Errorf("%w: peer certificate expired at %s", ErrUntrustedRoot,
			leaf.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// checkUsage enforces key usage and extended key usage on the leaf.
func (v *Verifier) checkUsage(leaf *x509.Certificate) error {
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("%w: leaf lacks the digitalSignature key usage", ErrIdentity)
	}
	// An unknown ExtKeyUsage list is a certificate from some other system; the
	// mesh always sets both usages explicitly.
	if len(leaf.ExtKeyUsage) == 0 {
		return fmt.Errorf("%w: leaf declares no extended key usage", ErrIdentity)
	}
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageAny {
			// "Any" is a wildcard and would make the check vacuous.
			return fmt.Errorf("%w: leaf declares ExtKeyUsageAny", ErrIdentity)
		}
	}
	if !hasExtKeyUsage(leaf, x509.ExtKeyUsageServerAuth) {
		return fmt.Errorf("%w: leaf is not valid for server authentication", ErrIdentity)
	}
	if !hasExtKeyUsage(leaf, x509.ExtKeyUsageClientAuth) {
		return fmt.Errorf("%w: leaf is not valid for client authentication", ErrIdentity)
	}
	return nil
}

func hasExtKeyUsage(cert *x509.Certificate, want x509.ExtKeyUsage) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == want {
			return true
		}
	}
	return false
}

// parseCertAnyEncoding accepts PEM or DER certificate bytes.
//
// Operators paste PEM out of a file; machines transmit DER. Accepting both at
// this one boundary means every caller does not have to re-implement the
// discrimination — and get it subtly wrong.
func parseCertAnyEncoding(b []byte) (*x509.Certificate, error) {
	if block, _ := pem.Decode(b); block != nil {
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("%w: PEM block type is %q, expected CERTIFICATE", ErrMalformed, block.Type)
		}
		b = block.Bytes
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, fmt.Errorf("%w: parse root certificate: %v", ErrMalformed, err)
	}
	return cert, nil
}

// TLSClientOptions configures a client-side TLS session.
type TLSClientOptions struct {
	// CertPEM and KeyPEM are this participant's own leaf. Required: the peer
	// requires a client certificate, so a client without one cannot connect.
	CertPEM []byte
	KeyPEM  []byte
	// Verifier authenticates the peer. Required.
	Verifier *Verifier
	// NextProtos is the ALPN list. Empty selects protocol defaults.
	NextProtos []string
}

// NewTLSClientConfig builds a client TLS configuration.
//
// InsecureSkipVerify is set deliberately, and the peer is verified by the
// callback instead: verification against the OPERATING SYSTEM store would
// either reject our self-signed mesh or, worse, accept a public CA's
// certificate for a JAWAKER endpoint. A nil Verifier is a hard error rather
// than a permissive default, because a TLS config that verifies nothing must
// not be constructible by omission.
func NewTLSClientConfig(opts TLSClientOptions) (*tls.Config, error) {
	if opts.Verifier == nil {
		return nil, errors.New("pki: a client TLS config requires a verifier")
	}
	cert, err := tls.X509KeyPair(opts.CertPEM, opts.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("pki: load client certificate: %w", err)
	}
	v := opts.Verifier
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		// System-store verification is deliberately replaced by the pinned-root
		// callback: the mesh is self-signed, so the OS store would reject it, and
		// a publicly trusted CA must never be able to authenticate a JAWAKER
		// peer. The callback below is therefore not optional, and a nil Verifier
		// is refused at construction.
		InsecureSkipVerify: true, //nolint:gosec // G402: replaced by VerifyPeerCertificate + VerifyConnection against a pinned internal root
		VerifyPeerCertificate: func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			_, err := v.Verify(rawCerts, chains)
			return err
		},
		// VerifyPeerCertificate is skipped on a resumed session; this is not.
		VerifyConnection: func(cs tls.ConnectionState) error {
			_, err := v.VerifyConnection(cs)
			return err
		},
		MinVersion:             tls.VersionTLS12,
		NextProtos:             opts.NextProtos,
		SessionTicketsDisabled: true,
	}, nil
}

// TLSServerOptions configures a server-side TLS session.
type TLSServerOptions struct {
	CertPEM  []byte
	KeyPEM   []byte
	Verifier *Verifier
	// NextProtos is the ALPN list.
	NextProtos []string
}

// NewTLSServerConfig builds a server TLS configuration that REQUIRES and
// verifies a client certificate.
//
// RequireAnyClientCert is used rather than the stronger-sounding
// RequireAndVerifyClientCert, and the reason is load-bearing: with
// VerifyClientCert-style auth Go verifies the client chain against ClientCAs
// BEFORE any callback runs, and ClientCAs is empty here because the trust anchor
// is a self-signed internal root that must never enter a system pool. The
// result would be every handshake rejected with "unknown authority" and our
// actual checks never reached.
//
// RequireAnyClientCert keeps the property that matters — an anonymous client is
// refused at the transport layer, so a handler can never forget to look — and
// moves chain validation into VerifyPeerCertificate, where the pinned root is
// genuinely consulted.
func NewTLSServerConfig(opts TLSServerOptions) (*tls.Config, error) {
	if opts.Verifier == nil {
		return nil, errors.New("pki: a server TLS config requires a verifier")
	}
	cert, err := tls.X509KeyPair(opts.CertPEM, opts.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("pki: load server certificate: %w", err)
	}
	v := opts.Verifier
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		// The callback checks the URI SAN, which a certificate pool cannot
		// express: a pool answers "who signed this", not "who is this".
		VerifyPeerCertificate: func(rawCerts [][]byte, chains [][]*x509.Certificate) error {
			_, err := v.Verify(rawCerts, chains)
			return err
		},
		// Called even on a resumed session, where VerifyPeerCertificate is not.
		VerifyConnection: func(cs tls.ConnectionState) error {
			_, err := v.VerifyConnection(cs)
			return err
		},
		MinVersion:             tls.VersionTLS12,
		NextProtos:             opts.NextProtos,
		SessionTicketsDisabled: true,
	}, nil
}
