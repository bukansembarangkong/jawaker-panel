package nodes

import (
	"crypto/x509"
	"encoding/json"
	"net/http"

	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
)

// The node-facing heartbeat endpoint, served on the controller's mTLS listener.
//
// Unlike enrollment, a heartbeat arrives over mutual TLS with a node certificate,
// so the peer is identified by WHAT IT PROVED rather than by what it claimed. That
// distinction is the whole design of this handler:
//
//   - the certificate's identity decides which server a beat belongs to. The
//     server_id in the body is compared against it and a mismatch is REFUSED,
//     because honoring the body would let any enrolled node report readings for
//     any other node — one node could mark a colleague offline, or feed it a load
//     figure that trips an alert nobody can explain;
//   - a revoked certificate is refused at the handshake by the listener's
//     verifier. This handler re-checks the serial anyway, so a revocation that
//     lands between the handshake and this call still takes effect rather than
//     waiting for the next connection;
//   - the readings are validated with the SHARED validator before storage, so an
//     impossible reading is refused rather than clamped.

// heartbeatBodyLimit bounds a heartbeat body. It is a handful of integers plus a
// timestamp, so a small ceiling is correct and keeps a hostile peer from making
// the controller allocate.
const heartbeatBodyLimit = 8 * 1024

// handleHeartbeat records one node heartbeat.
func (h *Handlers) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	identity, leaf, ok := verifiedNodePeer(r)
	if !ok {
		// No verified peer certificate. The listener requires one, so reaching
		// here means this handler was wired to a listener that does not, which is
		// a configuration fault. Refusing is the only safe answer: the
		// alternative is accepting anonymous heartbeats.
		h.logger.ErrorContext(r.Context(), "heartbeat reached without a verified node certificate")
		httpserver.WriteError(w, r, errFor(ErrInvalid))
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, heartbeatBodyLimit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	var payload nodewire.HeartbeatPayload
	if err := dec.Decode(&payload); err != nil {
		httpserver.WriteError(w, r, errFor(ErrInvalid))
		return
	}
	if err := payload.Validate(); err != nil {
		// An impossible reading is refused, not clamped: a clamped value in a
		// time series is a lie nobody can discover afterwards.
		h.logger.WarnContext(r.Context(), "refused an invalid heartbeat",
			"reason", err.Error(), "claimed_server_id", payload.ServerID)
		h.recordAudit(r, audit.Event{
			ActorType:    audit.ActorService,
			ActorID:      identity.ID,
			Action:       "node.heartbeat.invalid",
			ResourceType: "server",
			ResourceID:   identity.ID,
			Result:       audit.ResultDenied,
			Reason:       err.Error(),
		})
		httpserver.WriteError(w, r, errFor(ErrInvalid))
		return
	}

	// THE CHECK. The claimed server id must BE the certificate's identity.
	if payload.ServerID != identity.ID {
		h.recordAudit(r, audit.Event{
			ActorType:    audit.ActorService,
			ActorID:      identity.ID,
			Action:       "node.heartbeat.mismatch",
			ResourceType: "server",
			ResourceID:   payload.ServerID,
			Result:       audit.ResultDenied,
			Reason:       "the certificate identity does not match the reported server id",
			Context:      map[string]any{"certificate_identity": identity.ID},
		})
		httpserver.WriteError(w, r, errFor(ErrInvalid))
		return
	}

	// A revocation that landed after the handshake still takes effect here.
	if serial, err := pki.SerialHexOf(leaf); err == nil {
		revoked, err := h.store.IsRevoked(r.Context(), serial)
		if err != nil {
			httpserver.WriteError(w, r, errFor(err))
			return
		}
		if revoked {
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorService,
				ActorID:      identity.ID,
				Action:       "node.heartbeat.denied",
				ResourceType: "server",
				ResourceID:   identity.ID,
				Result:       audit.ResultDenied,
				Reason:       "the certificate is revoked",
			})
			httpserver.WriteError(w, r, errFor(ErrNotFound))
			return
		}
	}

	if err := h.store.RecordHeartbeat(r.Context(), identity.ID, payload.Reported); err != nil {
		httpserver.WriteError(w, r, errFor(err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"observed_at": payload.Reported.ObservedAt,
		"received_at": h.now().UTC(),
		"request_id":  httpserver.RequestIDFromRequest(r),
	})
}

// verifiedNodePeer extracts the identity and leaf certificate of a request's
// verified peer.
//
// It reads the certificate the LISTENER already verified rather than any header,
// and it re-checks the kind: a controller certificate must not be able to report
// as a node. The listener's verifier enforces that too, and the repetition is
// deliberate — this handler is reachable from any listener wired up later, and a
// missing check there would be invisible from here.
func verifiedNodePeer(r *http.Request) (pki.Identity, *x509.Certificate, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return pki.Identity{}, nil, false
	}
	leaf := r.TLS.PeerCertificates[0]
	identity, err := pki.IdentityOf(leaf)
	if err != nil || identity.Kind != pki.KindNode || identity.ID == "" {
		return pki.Identity{}, nil, false
	}
	return identity, leaf, true
}
