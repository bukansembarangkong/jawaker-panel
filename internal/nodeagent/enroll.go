package nodeagent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
)

// Enrollment is the one exchange that happens WITHOUT mutual TLS, because the
// node has no certificate yet. It is therefore the only step in the design that
// cannot be protected by the mesh itself, and its trust properties are stated
// plainly rather than implied:
//
//   - The transport is TLS to the controller's public API. The node does not yet
//     trust the internal root, so it verifies the controller's serving certificate
//     the way any HTTPS client does.
//   - The token is single-use and short-lived, minted by an elevated, audited
//     operator action. It is a bearer credential, which is why its lifetime is
//     minutes and why losing it mid-enrollment costs a new token rather than a
//     standing risk.
//   - The node PINS the returned internal root by fingerprint. The fingerprint is
//     supplied out-of-band by the operator: it is shown in the UI when the token
//     is created and logged by the controller. Without that pin, whoever could
//     answer the enrollment request could hand the node its own root and become
//     its permanently trusted controller — the worst outcome of the one step that
//     cannot use mutual TLS. A mismatch is a hard failure and nothing is written.
//
// The node generates its own key pair and sends only the PUBLIC key. The private
// key never leaves this host, so a controller compromise can issue identities but
// can never authenticate as an already-enrolled node.

// EnrollmentRequest and EnrollmentResponse are the SHARED wire contract, defined
// in internal/nodewire and used by the controller too.
//
// They are aliased rather than redeclared: two struct definitions for one wire
// format is how the two ends stop agreeing, and this project has already paid
// that cost twice (the recovery-code canonical form, the enrollment-token
// digest). One definition, two importers.
type (
	EnrollmentRequest  = nodewire.EnrollmentRequest
	EnrollmentResponse = nodewire.EnrollmentResponse
)

// EnrollOptions configures an enrollment attempt.
type EnrollOptions struct {
	// ControllerURL is the base URL of the controller's public HTTPS API.
	ControllerURL string
	// Token is the one-time enrollment token.
	Token string
	// ExpectedControllerFingerprint, when set, must match the internal root the
	// controller returns. This is the out-of-band pinning anchor.
	ExpectedControllerFingerprint string
	// StateDir is where the resulting identity is written.
	StateDir string
	// AgentVersion identifies this build.
	AgentVersion string
	// OSFamily and OSVersion are the detected host facts.
	OSFamily  string
	OSVersion string
	// NodeAddress is where this agent listens for controller-initiated operations.
	NodeAddress string
	// HTTPClient overrides the transport. Nil uses a TLS client with a timeout.
	// Tests point it at an httptest server whose certificate they trust.
	HTTPClient *http.Client
	// Now supplies the clock. Nil means time.Now.
	Now func() time.Time
}

// ErrFingerprintMismatch means the controller presented a root other than the
// pinned one. Enrollment is refused and nothing is written: proceeding would
// permanently trust an unknown authority.
var ErrFingerprintMismatch = errors.New("nodeagent: controller root fingerprint does not match the pinned value")

// maxEnrollmentResponseBytes bounds the response. The payload is a certificate, a
// root, and a few short strings; a megabyte is generous and keeps a hostile
// endpoint from making the agent allocate without limit.
const maxEnrollmentResponseBytes = 1 << 20

// Enroll exchanges a one-time token for a long-lived node identity and writes it
// to the state directory. It returns the loaded state on success.
func Enroll(ctx context.Context, opts EnrollOptions) (*State, error) {
	if err := opts.validate(); err != nil {
		return nil, err
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}

	// The key pair is generated here; only the public half is ever transmitted.
	privatePEM, publicPEM, err := newECDSAKey()
	if err != nil {
		return nil, err
	}

	// Validate the outgoing request with the SHARED validator before sending it.
	// A misconfigured agent then fails locally with a message naming the field,
	// instead of receiving an opaque 400 from the controller.
	payload := EnrollmentRequest{
		Token:        opts.Token,
		PublicKeyPEM: publicPEM,
		AgentVersion: opts.AgentVersion,
		OSFamily:     opts.OSFamily,
		OSVersion:    opts.OSVersion,
		NodeAddress:  opts.NodeAddress,
	}
	if err = payload.Validate(); err != nil {
		return nil, fmt.Errorf("nodeagent: enrollment request is not valid: %w", err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("nodeagent: encode enrollment request: %w", err)
	}

	endpoint := strings.TrimSuffix(opts.ControllerURL, "/") + nodewire.EnrollmentPath
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("nodeagent: build enrollment request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("nodeagent: enrollment request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := readBounded(resp.Body, maxEnrollmentResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("nodeagent: read enrollment response: %w", err)
	}
	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("nodeagent: enrollment refused (HTTP %d): %s",
			resp.StatusCode, summarizeEnrollmentError(respBody))
	}

	var out EnrollmentResponse
	if err = decodeJSONStrict(respBody, &out); err != nil {
		return nil, fmt.Errorf("nodeagent: parse enrollment response: %w", err)
	}
	if err = out.Validate(); err != nil {
		return nil, err
	}

	// THE PINNING CHECK. Nothing is written until this passes. The pin is
	// guaranteed non-empty by validate(), so this runs on every enrollment.
	actual := fingerprintPEM(out.ControllerRootPEM)
	if !strings.EqualFold(actual, opts.ExpectedControllerFingerprint) {
		return nil, fmt.Errorf("%w: expected %s, controller presented %s",
			ErrFingerprintMismatch, opts.ExpectedControllerFingerprint, actual)
	}

	// Pair the issued certificate with the locally generated private key, and
	// verify the pairing and the identity BEFORE persisting anything. Writing
	// first and verifying later would leave a broken identity on disk that fails
	// at the next start with a less useful message.
	leaf, err := pki.DecodeLeaf(string(out.CertPEM) + string(privatePEM))
	if err != nil {
		return nil, fmt.Errorf("nodeagent: issued certificate does not match the generated key: %w", err)
	}
	if err = verifyIssuedIdentity(leaf, out); err != nil {
		return nil, err
	}

	if err = SaveIdentity(opts.StateDir, leaf, out.ControllerRootPEM); err != nil {
		return nil, err
	}
	controllerAddr, err := hostFromURL(opts.ControllerURL)
	if err != nil {
		return nil, err
	}
	cfg := Config{
		ServerID:              out.ServerID,
		ControllerAddress:     controllerAddr,
		ControllerID:          out.ControllerID,
		ControllerFingerprint: fingerprintPEM(out.ControllerRootPEM),
		EnrolledAt:            now().UTC(),
	}
	if err := SaveConfig(opts.StateDir, cfg); err != nil {
		return nil, err
	}
	return LoadState(opts.StateDir)
}

func (o EnrollOptions) validate() error {
	var errs []error
	if o.ControllerURL == "" {
		errs = append(errs, errors.New("controller URL is required"))
	} else {
		u, err := url.Parse(o.ControllerURL)
		if err != nil {
			errs = append(errs, fmt.Errorf("controller URL is not parseable: %w", err))
		} else if u.Scheme != "https" {
			// A bearer token must not travel in plaintext. This is a trust
			// boundary, so the requirement is enforced rather than warned about.
			errs = append(errs, fmt.Errorf(
				"controller URL %q must use https; enrollment carries a bearer token", o.ControllerURL))
		}
	}
	if o.Token == "" {
		errs = append(errs, errors.New("enrollment token is required"))
	}
	// THE PINNED FINGERPRINT IS REQUIRED, and it is required HERE rather than
	// only in the command. Enrollment is the one exchange that cannot use mutual
	// TLS, so without the pin whoever can answer the request becomes this node's
	// permanently trusted controller — the worst outcome of the whole design. A
	// CLI-level check would leave the library open to a future caller (a
	// provisioning script, a test) enrolling unpinned, which review would not
	// catch because nothing here would say it was wrong.
	if strings.TrimSpace(o.ExpectedControllerFingerprint) == "" {
		errs = append(errs, errors.New(
			"the expected controller fingerprint is required; without it the node would trust whoever answered the enrollment request"))
	}
	if o.StateDir == "" {
		errs = append(errs, errors.New("state directory is required"))
	}
	if o.NodeAddress == "" {
		errs = append(errs, errors.New("node address is required"))
	}
	return errors.Join(errs...)
}

// verifyIssuedIdentity confirms the certificate is usable as THIS node's
// identity: right kind, right server id, right serial.
func verifyIssuedIdentity(leaf *pki.Leaf, out EnrollmentResponse) error {
	id, err := leaf.Identity()
	if err != nil {
		return fmt.Errorf("nodeagent: issued certificate has no usable identity: %w", err)
	}
	if id.Kind != pki.KindNode {
		return fmt.Errorf("nodeagent: issued certificate is a %s identity, expected a node", id.Kind)
	}
	if id.ID != out.ServerID {
		return fmt.Errorf("nodeagent: issued certificate names %q but the response names server %q",
			id.ID, out.ServerID)
	}
	if leaf.SerialHex() != out.Serial {
		return fmt.Errorf("nodeagent: issued certificate serial %q does not match the response %q",
			leaf.SerialHex(), out.Serial)
	}
	// The supplied root must itself be usable to verify THIS controller, or the
	// node would start and then refuse every connection with no clear reason.
	if _, err := pki.NewVerifier(pki.VerifierOptions{
		RootPEM: out.ControllerRootPEM,
		Kind:    pki.KindController,
		ID:      out.ControllerID,
	}); err != nil {
		return fmt.Errorf("nodeagent: supplied controller root is not usable: %w", err)
	}
	return nil
}

// fingerprintPEM returns the SHA-256 of a PEM certificate's DER encoding, as
// lowercase hex. It is the value an operator compares against the controller's
// own reported fingerprint.
func fingerprintPEM(pemBytes []byte) string {
	cert, err := pki.DecodeCertPEM(string(pemBytes))
	if err != nil {
		// A fingerprint of unparseable material would be meaningless. Digesting
		// the raw bytes is still stable and comparable, and this branch should be
		// unreachable for a well-formed controller response.
		sum := sha256.Sum256(pemBytes)
		return hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// summarizeEnrollmentError extracts a safe, bounded message from an error body.
//
// It never echoes the whole body: an error response is attacker-influenced from
// the agent's point of view, and printing it unbounded into a systemd journal
// would let a malicious endpoint write arbitrary text into the operator's logs.
func summarizeEnrollmentError(body []byte) string {
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil || envelope.Error.Code == "" {
		return "the controller returned an error with no usable code"
	}
	const maxMessage = 200
	message := envelope.Error.Message
	if len(message) > maxMessage {
		message = message[:maxMessage]
	}
	return fmt.Sprintf("%s: %s", envelope.Error.Code, message)
}

// readBounded reads at most n bytes, refusing a larger body rather than
// allocating for it.
func readBounded(r io.Reader, n int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, n+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > n {
		return nil, fmt.Errorf("response body exceeds %d bytes", n)
	}
	return data, nil
}

// hostFromURL extracts host:port from an https URL for recording.
func hostFromURL(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("nodeagent: parse controller URL: %w", err)
	}
	if u.Host == "" {
		return "", errors.New("nodeagent: controller URL has no host")
	}
	return u.Host, nil
}
