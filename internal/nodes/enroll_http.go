package nodes

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
)

// The node-facing enrollment endpoint.
//
// This is the ONLY route on the controller that a node reaches without a client
// certificate, because at this moment the node has none. Everything about it is
// therefore written for that fact:
//
//   - it carries NO session and NO CSRF token. It is authenticated by the bearer
//     token alone, so it must not be wrapped in RequireAuth or RequirePermission:
//     a node is not a user and has no permissions;
//   - the permission check happens when the TOKEN is minted (server.enroll,
//     step-up), not here. That is the audited human decision; this endpoint only
//     exchanges the result;
//   - it is rate limited per client address, because it is the one unauthenticated
//     write on the controller and an unbounded token-guessing loop must cost
//     something;
//   - every refusal returns the SAME shape. Distinguishing "expired" from
//     "unknown" would tell a caller holding a guessed token that the guess was
//     structurally valid.

// DefaultEnrollRate bounds enrollment attempts per client address per minute.
//
// It is more generous than the login limiter on purpose: a fleet being installed
// is a burst of legitimate traffic from one NAT address, and a limiter that
// blocks the hundredth node of a rollout is a bug. It is still far below what
// guessing a token needs.
var DefaultEnrollRate = struct {
	Limit    int
	Interval time.Duration
}{Limit: 30, Interval: time.Minute}

// maxEnrollBytes bounds the request body. The payload is a token, a public key
// and a few short strings, so a small ceiling is correct and an attacker cannot
// make the controller allocate.
const maxEnrollBytes = 32 * 1024

// handleEnroll exchanges a one-time token for a node identity.
//
// Returns 201 with the issued certificate and the controller root; the plaintext
// token is NOT echoed anywhere in the response or the logs.
func (h *Handlers) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if !h.allowEnrollment(r) {
		retryAfter := DefaultEnrollRate.Interval
		secs := int(retryAfter.Seconds() + 0.999)
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		httpserver.WriteError(w, r, apierr.TooManyRequests(
			"Too many enrollment attempts. Try again shortly.", retryAfter))
		h.recordEnrollAudit(r, audit.ResultDenied, "", "rate limited")
		return
	}

	// Bound the body before reading it: r.Body is attacker-controlled and
	// unbounded, and this endpoint is reachable by anything that can reach the
	// controller.
	r.Body = http.MaxBytesReader(w, r.Body, maxEnrollBytes)
	var req nodewire.EnrollmentRequest
	if apiErr := decodeJSON(r, &req); apiErr != nil {
		httpserver.WriteError(w, r, apiErr)
		h.recordEnrollAudit(r, audit.ResultFailure, "", "malformed request")
		return
	}
	if err := req.Validate(); err != nil {
		httpserver.WriteError(w, r, apierr.InvalidRequest(
			"The enrollment request is not valid.",
			map[string]any{"detail": err.Error()}))
		h.recordEnrollAudit(r, audit.ResultFailure, "", "invalid request")
		return
	}

	// The public key is parsed at the trust boundary. DecodePublicKeyPEM refuses
	// a private key or a certificate in the stream rather than trimming it: a node
	// sending either has misunderstood the flow in a way worth surfacing.
	publicKey, err := pki.DecodePublicKeyPEM(string(req.PublicKeyPEM))
	if err != nil {
		httpserver.WriteError(w, r, apierr.InvalidRequest(
			"The public key is not a usable PEM-encoded public key.",
			map[string]any{"field": "public_key_pem"}))
		h.recordEnrollAudit(r, audit.ResultFailure, "", "invalid public key")
		return
	}

	result, err := h.store.Redeem(r.Context(), h.auth, RedeemRequest{
		Token:        req.Token,
		PublicKey:    publicKey,
		NodeAddress:  req.NodeAddress,
		AgentVersion: req.AgentVersion,
		OSFamily:     req.OSFamily,
		OSVersion:    req.OSVersion,
	})
	if err != nil {
		// ErrTokenInvalid, ErrNameTaken and ErrInvalid all collapse onto one
		// response for the caller, but the AUDIT records which it was: the
		// operator needs the distinction, the caller must not have it.
		httpserver.WriteError(w, r, errFor(err))
		h.recordEnrollAudit(r, audit.ResultFailure, "", refusalReason(err))
		return
	}

	// The controller's own root and fingerprint travel back so the node can pin
	// them. The node verifies the fingerprint against the value the operator
	// copied from the UI when the token was created, which is what closes the one
	// step that cannot use mutual TLS.
	writeJSON(w, http.StatusCreated, map[string]any{
		"server_id":              result.Server.ID,
		"node_uri":               result.NodeURI,
		"cert_pem":               result.CertPEM,
		"serial":                 result.Serial,
		"not_before":             result.NotBefore,
		"not_after":              result.NotAfter,
		"controller_id":          h.auth.ControllerID(),
		"controller_root_pem":    h.auth.ControllerCertPEM(),
		"controller_fingerprint": h.auth.ControllerFingerprint(),
		"node_listener_address":  result.Server.Address,
		"request_id":             httpserver.RequestIDFromRequest(r),
	})

	h.recordEnrollAudit(r, audit.ResultSuccess, result.Server.ID, "")
}

// allowEnrollment applies the per-address limiter.
//
// The key is the peer address, taken from RemoteAddr without consulting proxy
// headers: this controller does not trust X-Forwarded-For unless it is behind a
// proxy it was told about, and a spoofable rate-limit key is no limiter at all.
func (h *Handlers) allowEnrollment(r *http.Request) bool {
	if h.enrollLimiter == nil {
		return true
	}
	key := r.RemoteAddr
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		key = host
	}
	allowed, _ := h.enrollLimiter.Allow(key)
	return allowed
}

// refusalReason renders the internal reason for the audit trail.
//
// It never reaches the caller. The audit trail is where "was this an expired
// token or a guessed one?" is answerable, and it is not readable by whoever was
// probing.
func refusalReason(err error) string {
	switch {
	case errors.Is(err, ErrTokenInvalid):
		return "token refused"
	case errors.Is(err, ErrNameTaken):
		return "server name already in use"
	case errors.Is(err, ErrInvalid):
		return "invalid request"
	case errors.Is(err, ErrNoAuthority):
		return "no certificate authority configured"
	default:
		return "internal error"
	}
}

// recordEnrollAudit writes an enrollment event.
//
// Enrollment is a fleet-changing event that arrives with no user identity, so it
// is recorded as a SYSTEM actor with the request id and source address. The token
// itself is never recorded: an audit trail that stores the credential it audited
// is a credential leak with a timestamp.
func (h *Handlers) recordEnrollAudit(r *http.Request, result, serverID, reason string) {
	if h.audit == nil {
		return
	}
	e := audit.Event{
		ActorType:    audit.ActorSystem,
		Action:       "server.enroll.node",
		ResourceType: "server",
		ResourceID:   serverID,
		RequestID:    httpserver.RequestIDFromRequest(r),
		Result:       result,
		Reason:       reason,
		SourceIP:     r.RemoteAddr,
		UserAgent:    r.UserAgent(),
	}
	if err := audit.Record(r.Context(), h.audit, e); err != nil {
		// A failed audit write must not fail an enrollment that already
		// committed: the identity exists on the node. The fault is logged, which
		// is the honest report — telling the node "failed" would leave it holding
		// a certificate for a server the panel believes it refused.
		h.logger.ErrorContext(r.Context(), "audit write failed",
			"error", err, "action", e.Action, "request_id", e.RequestID)
	}
}
