package nodewire

import (
	"errors"
	"fmt"
	"time"
)

// The enrollment exchange, defined ONCE for both ends.
//
// This lives here rather than in internal/nodes and internal/nodeagent because
// the two ends must agree on the field names, the bounds and what counts as a
// usable response — and a duplicated struct definition is how they stop agreeing.
// This project has already paid that cost twice (recovery-code canonical form,
// enrollment-token digest), so the wire contract sits in the wire package.
//
// Enrollment is deliberately NOT an Operation in the registry: it happens before
// any node identity exists, so it cannot travel over the mutual-TLS channel that
// every registered operation uses. It is a plain HTTPS POST with a bearer token,
// and the bounds here exist because that endpoint is reachable by anything that
// can reach the controller.

// EnrollmentPath is the controller's enrollment endpoint. One constant so the
// agent cannot be pointed somewhere else by a stray edit.
const EnrollmentPath = "/api/v1/node/enroll"

// maxPublicKeyPEMBytes bounds the submitted public key. A P-256 PKIX key is
// ~120 DER bytes, ~200 in PEM. Ten kilobytes is far beyond any real key and far
// short of anything an attacker would want to make this parse.
const maxPublicKeyPEMBytes = 10 * 1024

// maxEnrollmentFieldBytes bounds the self-reported strings.
const maxEnrollmentFieldBytes = 512

// EnrollmentRequest is the POST body a node sends.
//
// It carries a PUBLIC KEY and no secret beyond the token. The private half of the
// pair never leaves the node, so a controller compromise cannot authenticate as
// an already-enrolled node.
type EnrollmentRequest struct {
	// Token is the one-time enrollment token. A bearer credential: single-use,
	// short-lived, minted by an elevated audited operator action.
	Token string `json:"token"`
	// PublicKeyPEM is the node's own public key, for the controller to sign.
	PublicKeyPEM []byte `json:"public_key_pem"`
	// AgentVersion, OSFamily and OSVersion are the facts the agent reports about
	// itself so the controller records what it enrolled without a second round
	// trip. They are descriptive, not identity-bearing, and are validated on the
	// controller before being stored.
	AgentVersion string `json:"agent_version"`
	OSFamily     string `json:"os_family"`
	OSVersion    string `json:"os_version"`
	// NodeAddress is where the controller will dial this agent afterwards.
	NodeAddress string `json:"node_address"`
}

// Validate checks a request before any expensive work.
//
// The controller validates again after decoding, at its own boundary — but the
// agent validates too, so a misconfigured agent fails locally with a message
// naming the field rather than receiving an opaque 400.
func (r EnrollmentRequest) Validate() error {
	var errs []error
	if r.Token == "" {
		errs = append(errs, errors.New("token is required"))
	}
	if len(r.PublicKeyPEM) == 0 {
		errs = append(errs, errors.New("public_key_pem is required"))
	}
	if len(r.PublicKeyPEM) > maxPublicKeyPEMBytes {
		errs = append(errs, fmt.Errorf("public_key_pem exceeds %d bytes", maxPublicKeyPEMBytes))
	}
	for name, v := range map[string]string{
		"agent_version": r.AgentVersion,
		"os_family":     r.OSFamily,
		"os_version":    r.OSVersion,
		"node_address":  r.NodeAddress,
	} {
		if len(v) > maxEnrollmentFieldBytes {
			errs = append(errs, fmt.Errorf("%s exceeds %d bytes", name, maxEnrollmentFieldBytes))
		}
	}
	if r.NodeAddress == "" {
		errs = append(errs, errors.New("node_address is required"))
	}
	return errors.Join(errs...)
}

// EnrollmentResponse is what the controller returns on success.
type EnrollmentResponse struct {
	ServerID  string    `json:"server_id"`
	NodeURI   string    `json:"node_uri"`
	CertPEM   []byte    `json:"cert_pem"`
	Serial    string    `json:"serial"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	// Controller identity, its internal root, and the root's fingerprint. The
	// root is what the node pins, and the fingerprint is what the operator
	// compares it against out-of-band.
	ControllerID          string `json:"controller_id"`
	ControllerRootPEM     []byte `json:"controller_root_pem"`
	ControllerFingerprint string `json:"controller_fingerprint"`
	// NodeListenerAddress echoes the address the controller recorded, so a node
	// that reported the wrong one can see it rather than wonder why nothing dials
	// it.
	NodeListenerAddress string `json:"node_listener_address"`
}

// Validate checks a response is structurally usable before the agent writes
// anything to disk.
//
// Writing first and checking later would leave a broken identity in the state
// directory that fails at the next start with a less useful message.
func (r EnrollmentResponse) Validate() error {
	var errs []error
	if r.ServerID == "" {
		errs = append(errs, errors.New("response has no server id"))
	}
	if r.ControllerID == "" {
		errs = append(errs, errors.New("response has no controller id"))
	}
	if len(r.CertPEM) == 0 {
		errs = append(errs, errors.New("response has no certificate"))
	}
	if len(r.ControllerRootPEM) == 0 {
		errs = append(errs, errors.New("response has no controller root"))
	}
	if r.Serial == "" {
		errs = append(errs, errors.New("response has no certificate serial"))
	}
	if !r.NotAfter.After(r.NotBefore) {
		errs = append(errs, errors.New("response certificate window is not a window"))
	}
	if r.ControllerFingerprint == "" {
		errs = append(errs, errors.New("response has no controller fingerprint"))
	}
	return errors.Join(errs...)
}
