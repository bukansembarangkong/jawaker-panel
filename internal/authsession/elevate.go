package authsession

import (
	"errors"
	"net/http"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/identity"
)

// Step-up elevation (SECURITY.md §3, §4).
//
// The RBAC catalog marks high-risk permissions as requiring an elevation
// window; the evaluator refuses them when the session has none. This endpoint is
// how a window is obtained, and without it those permissions are not protected,
// they are unusable — a control that can never be satisfied locks the operator
// out of their own panel.
//
// Elevation is granted only in exchange for the SAME evidence login demands:
// the account password plus, when one is enrolled, a live second factor. Asking
// for less would make step-up a cheaper path into a privileged action than
// signing in, which inverts the point of having it. A recovery code is NOT
// accepted: it is the fallback for a lost device at LOGIN, and letting it stand
// in here would let one leaked code elevate any hijacked session for up to an
// hour per use.
//
// The elevation is a column on the session row, not a new cookie or a signed
// token. That is deliberate: revocation, expiry, and the device inventory all
// already act on that row, so an elevated session cannot outlive the controls
// that govern the session itself.

// maxElevationTTL bounds what a caller may ask for. An elevation lasting as long
// as the session would be a second session lifetime rather than a step-up, so
// the ceiling is enforced here rather than left to discipline.
const maxElevationTTL = time.Hour

// elevateRequest carries the re-authentication evidence.
type elevateRequest struct {
	// Password re-proves the caller is the person at the keyboard.
	Password string `json:"password"`
	// TOTPCode is required when the account has a confirmed enrollment.
	TOTPCode string `json:"totp_code"`
	// LifetimeSeconds optionally overrides DefaultElevationTTL. Bounded.
	LifetimeSeconds int `json:"lifetime_seconds,omitempty"`
}

// registerElevateRoutes mounts the step-up endpoint. CSRF and authentication are
// both required: this endpoint strengthens a session, so it must not be
// reachable by a cross-origin page holding a stolen cookie.
func (h *Handlers) registerElevateRoutes(mux *http.ServeMux) {
	mux.Handle("POST /api/v1/auth/elevate",
		RequireCSRF(h.csrf, RequireAuth(http.HandlerFunc(h.handleElevate))))
}

// handleElevate verifies the caller's credentials and opens an elevation window
// on the current session.
func (h *Handlers) handleElevate(w http.ResponseWriter, r *http.Request) {
	principal := auth.MustPrincipalFrom(r.Context())

	var req elevateRequest
	if apiErr := decodeJSON(r, &req); apiErr != nil {
		httpserver.WriteError(w, r, apiErr)
		return
	}

	if apiErr := h.reauthenticate(w, r, principal, req.Password, "auth.elevate"); apiErr != nil {
		httpserver.WriteError(w, r, apiErr)
		return
	}

	// The second factor, when one is enrolled. Loaded rather than trusted from
	// the session's grant set so a stale status cannot skip it.
	candidate, err := identity.GetLoginCandidate(r.Context(), h.opts.DB, principal.Email)
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			httpserver.WriteError(w, r, apierr.Unauthorized(""))
			return
		}
		httpserver.WriteError(w, r, apierr.DatabaseUnavailable())
		return
	}
	if candidate.ID != principal.UserID {
		// The account loaded from the session's email is not the session's
		// user. Fail closed: verifying one account and elevating another is
		// the worst possible outcome of this endpoint.
		h.auditElevateDenied(r, principal.UserID, "session identity mismatch")
		httpserver.WriteError(w, r, apierr.Unauthorized(""))
		return
	}
	if candidate.HasConfirmedTOTP {
		if apiErr := h.requireCurrentTOTP(r, principal, req.TOTPCode); apiErr != nil {
			httpserver.WriteError(w, r, apiErr)
			return
		}
	}

	now := h.opts.now()
	lifetime := identity.DefaultElevationTTL
	if req.LifetimeSeconds > 0 {
		lifetime = time.Duration(req.LifetimeSeconds) * time.Second
		if lifetime > maxElevationTTL {
			httpserver.WriteError(w, r, apierr.InvalidRequest(
				"Requested elevation lifetime is too long.",
				map[string]any{"field": "lifetime_seconds", "max_seconds": int(maxElevationTTL.Seconds())}))
			return
		}
	}
	// The window is written on the session row, so it can never outlive the
	// session: an expired or revoked session is refused at resolve time
	// before elevation is consulted. That is why this needs no separate cap.
	until := now.Add(lifetime)

	if err := identity.ElevateSession(r.Context(), h.opts.DB, principal.SessionID, until); err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			// Revoked between resolution and the write. The session is gone.
			httpserver.WriteError(w, r, apierr.Unauthorized(""))
			return
		}
		httpserver.WriteError(w, r, apierr.Internal(err))
		return
	}

	recordAudit(r.Context(), h.opts.Logger, h.opts.DB, httpserver.RequestIDFromRequest(r), audit.Event{
		ActorType:    audit.ActorUser,
		ActorID:      principal.UserID,
		Action:       "auth.elevate",
		ResourceType: "session",
		ResourceID:   principal.SessionID,
		Result:       audit.ResultSuccess,
		Reason:       "step-up reauthentication",
		SourceIP:     clientIP(r),
		UserAgent:    r.UserAgent(),
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"elevated":       true,
		"elevated_until": until.UTC(),
		"ttl_seconds":    int(lifetime.Seconds()),
	})
}

// auditElevateDenied records a refused step-up. A burst of these on one account
// is someone guessing at a privileged action, which is worth being able to see.
func (h *Handlers) auditElevateDenied(r *http.Request, userID, reason string) {
	recordAudit(r.Context(), h.opts.Logger, h.opts.DB, httpserver.RequestIDFromRequest(r), audit.Event{
		ActorType:    audit.ActorUser,
		ActorID:      userID,
		Action:       "auth.elevate",
		ResourceType: "user",
		ResourceID:   userID,
		Result:       audit.ResultDenied,
		Reason:       reason,
		SourceIP:     clientIP(r),
		UserAgent:    r.UserAgent(),
	})
}
