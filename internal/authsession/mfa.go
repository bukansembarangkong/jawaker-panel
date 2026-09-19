package authsession

import (
	"errors"
	"net/http"
	"strings"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/identity"
	"github.com/bukansembarangkong/jawaker-panel/internal/totp"
)

// Second-factor self-service (SECURITY.md §3, §4).
//
// Every endpoint here can WEAKEN an account's protection, so each mutation
// re-verifies the caller's password rather than trusting the session alone. A
// session cookie proves the caller once authenticated; it does not prove they
// are still the person at the keyboard, and a stolen cookie would otherwise be
// enough to disarm MFA or mint a fresh set of bypass codes.
//
// Re-entry is per request instead of a timed elevation window: the window would
// have to be long enough to be usable and short enough to be safe, and getting
// that judgement wrong is a vulnerability. A password prompt on a
// once-in-a-while settings screen costs the user nothing.

// issuerName is the label authenticator apps display for these entries.
const issuerName = "JAWAKER"

// registerMFARoutes mounts the second-factor endpoints. All are authenticated;
// mutations additionally require CSRF and a fresh password.
func (h *Handlers) registerMFARoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/auth/mfa",
		RequireAuth(http.HandlerFunc(h.handleMFAStatus)))
	mux.Handle("POST /api/v1/auth/mfa/totp/enroll",
		RequireCSRF(h.csrf, RequireAuth(http.HandlerFunc(h.handleTOTPEnroll))))
	mux.Handle("POST /api/v1/auth/mfa/totp/confirm",
		RequireCSRF(h.csrf, RequireAuth(http.HandlerFunc(h.handleTOTPConfirm))))
	mux.Handle("POST /api/v1/auth/mfa/totp/disable",
		RequireCSRF(h.csrf, RequireAuth(http.HandlerFunc(h.handleTOTPDisable))))
	mux.Handle("POST /api/v1/auth/mfa/recovery-codes",
		RequireCSRF(h.csrf, RequireAuth(http.HandlerFunc(h.handleRecoveryRegenerate))))
}

// mfaRequest carries the two credentials a mutating MFA endpoint may need.
//
// The password is a plain string field rather than a nested object so the
// request shape matches login: one familiar place for a credential, and no
// ambiguity about which field a client is expected to send.
type mfaRequest struct {
	// Password re-verifies the caller before a protection change.
	Password string `json:"password"`
	// Code is the current TOTP code, where the operation needs one.
	Code string `json:"code"`
	// Reason explains a disable, and is echoed into the audit trail.
	Reason string `json:"reason"`
}

// --- status --------------------------------------------------------------------

// handleMFAStatus reports the caller's second-factor state. It never returns
// secret material: only whether a factor is in force, whether an enrollment is
// awaiting confirmation, and how many recovery codes remain.
func (h *Handlers) handleMFAStatus(w http.ResponseWriter, r *http.Request) {
	principal := auth.MustPrincipalFrom(r.Context())

	status, err := identity.GetTOTPStatus(r.Context(), h.opts.DB, principal.UserID)
	if err != nil {
		httpserver.WriteError(w, r, apierr.DatabaseUnavailable())
		return
	}
	remaining, err := identity.CountUnusedRecoveryCodes(r.Context(), h.opts.DB, principal.UserID)
	if err != nil {
		httpserver.WriteError(w, r, apierr.DatabaseUnavailable())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"totp_enrolled":            status.Enrolled,
		"totp_enrollment_pending":  status.Pending,
		"recovery_codes_remaining": remaining,
	})
}

// --- enroll --------------------------------------------------------------------

// handleTOTPEnroll creates a pending enrollment and returns the provisioning
// URI once, so the user can scan it.
//
// The response is the only time the shared secret leaves the server in
// plaintext. It is not logged and not audited: the audit row records that an
// enrollment happened, never the secret.
//
// Enrolling does NOT disturb an already-confirmed factor. A user replacing a
// lost phone keeps working protection until the new one is confirmed, and a
// request that stops after this step cannot disarm the account.
func (h *Handlers) handleTOTPEnroll(w http.ResponseWriter, r *http.Request) {
	principal := auth.MustPrincipalFrom(r.Context())
	requestID := httpserver.RequestIDFromRequest(r)

	var req mfaRequest
	if apiErr := decodeJSON(r, &req); apiErr != nil {
		httpserver.WriteError(w, r, apiErr)
		return
	}
	if apiErr := h.reauthenticate(w, r, principal, req.Password, "mfa.totp.enroll"); apiErr != nil {
		httpserver.WriteError(w, r, apiErr)
		return
	}

	enrollmentID, secretRef, err := identity.CreateTOTPEnrollment(r.Context(), h.opts.DB, principal.UserID, requestID)
	if err != nil {
		h.opts.Logger.ErrorContext(r.Context(), "TOTP enrollment failed",
			"error", err, "user_id", principal.UserID, "request_id", requestID)
		httpserver.WriteError(w, r, apierr.DatabaseUnavailable())
		return
	}

	secret, err := totp.GenerateSecret()
	if err != nil {
		httpserver.WriteError(w, r, apierr.Internal(err))
		return
	}
	// Create seals and refuses to overwrite, so a collision with an existing
	// reference is reported rather than silently replacing another value.
	if createErr := h.opts.Secrets.Create(r.Context(), secretRef, secret, "TOTP shared secret"); createErr != nil {
		h.opts.Logger.ErrorContext(r.Context(), "TOTP secret store failed",
			"error", createErr, "user_id", principal.UserID,
			"secret_ref", secretRef, "request_id", requestID)
		httpserver.WriteError(w, r, apierr.Internal(createErr))
		return
	}

	uri, err := totp.ProvisioningURI(issuerName, principal.Email, secret, totp.DefaultConfig())
	if err != nil {
		httpserver.WriteError(w, r, apierr.Internal(err))
		return
	}

	cfg := totp.DefaultConfig()
	writeJSON(w, http.StatusOK, map[string]any{
		"enrollment_id":  enrollmentID,
		"otpauth_uri":    uri,
		"secret":         secret,
		"algorithm":      string(cfg.Algorithm),
		"digits":         cfg.Digits,
		"period_seconds": cfg.Period,
	})
}

// --- confirm -------------------------------------------------------------------

// handleTOTPConfirm proves possession of the pending secret and, on success,
// issues a fresh set of recovery codes.
//
// The candidate is located from the SESSION's user, never from a client-supplied
// id: an endpoint that confirmed whatever enrollment id it was handed would let
// any authenticated user confirm someone else's pending enrollment.
//
// Codes are issued here rather than at enroll time because they are a bypass for
// the factor, and handing them out before the factor exists would let a user
// save codes for an enrollment that never completed.
func (h *Handlers) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	principal := auth.MustPrincipalFrom(r.Context())
	requestID := httpserver.RequestIDFromRequest(r)

	var req mfaRequest
	if apiErr := decodeJSON(r, &req); apiErr != nil {
		httpserver.WriteError(w, r, apiErr)
		return
	}
	if strings.TrimSpace(req.Code) == "" {
		httpserver.WriteError(w, r, apierr.InvalidRequest("A two-factor code is required.", nil))
		return
	}

	pending, err := identity.GetPendingTOTP(r.Context(), h.opts.DB, principal.UserID)
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			httpserver.WriteError(w, r, apierr.NotFound("There is no enrollment waiting to be confirmed."))
			return
		}
		httpserver.WriteError(w, r, apierr.DatabaseUnavailable())
		return
	}

	secret, err := h.opts.Secrets.Open(r.Context(), pending.SecretRef)
	if err != nil {
		h.opts.Logger.ErrorContext(r.Context(), "pending TOTP secret unavailable",
			"error", err, "user_id", principal.UserID,
			"secret_ref", pending.SecretRef, "request_id", requestID)
		httpserver.WriteError(w, r, apierr.Internal(err))
		return
	}

	step, err := totp.Validate(secret, req.Code, h.opts.now())
	if err != nil {
		if errors.Is(err, totp.ErrCodeInvalid) {
			h.auditMFADenied(r, principal.UserID, "mfa.totp.confirm", "invalid confirmation code")
			httpserver.WriteError(w, r, totpCodeInvalid())
			return
		}
		httpserver.WriteError(w, r, apierr.Internal(err))
		return
	}

	// The step is recorded inside the same transaction that promotes the
	// enrollment, so the code that confirmed it cannot be replayed.
	if confirmErr := identity.ConfirmTOTPEnrollment(r.Context(), h.opts.DB, pending.ID, principal.UserID, step, requestID); confirmErr != nil {
		if errors.Is(confirmErr, identity.ErrNotFound) {
			// Lost a race with another confirmation, or the code was replayed.
			httpserver.WriteError(w, r, apierr.Conflict("This enrollment can no longer be confirmed.", nil))
			return
		}
		httpserver.WriteError(w, r, apierr.Internal(confirmErr))
		return
	}

	codes, err := identity.GenerateRecoveryCodes(r.Context(), h.opts.DB, principal.UserID, requestID)
	if err != nil {
		// The factor IS enabled; only the codes failed. Reporting that honestly
		// is better than failing the whole request and implying no change, which
		// would send the user back to a confirm step that now returns 404.
		h.opts.Logger.ErrorContext(r.Context(), "recovery code generation failed after confirmation",
			"error", err, "user_id", principal.UserID, "request_id", requestID)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":               "enabled",
			"recovery_codes":       nil,
			"recovery_codes_error": "Two-factor authentication is enabled, but recovery codes could not be generated. Generate them again from your security settings.",
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "enabled",
		"recovery_codes": codes,
	})
}

// --- disable -------------------------------------------------------------------

// handleTOTPDisable turns the second factor off, revokes the user's other
// sessions, and records the caller's reason.
//
// Requiring a reason is deliberate friction. Disabling MFA is the goal of most
// account-takeover playbooks, so the resulting audit entry should say why — and
// an attacker operating through a compromised session has to write that reason
// down while being logged.
func (h *Handlers) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	principal := auth.MustPrincipalFrom(r.Context())
	requestID := httpserver.RequestIDFromRequest(r)

	var req mfaRequest
	if apiErr := decodeJSON(r, &req); apiErr != nil {
		httpserver.WriteError(w, r, apiErr)
		return
	}
	if apiErr := h.reauthenticate(w, r, principal, req.Password, "mfa.totp.disable"); apiErr != nil {
		httpserver.WriteError(w, r, apiErr)
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		httpserver.WriteError(w, r, apierr.InvalidRequest("A reason is required to disable two-factor authentication.", nil))
		return
	}

	codesRevoked, err := identity.DisableTOTP(r.Context(), h.opts.DB, principal.UserID, principal.UserID, reason, requestID)
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			httpserver.WriteError(w, r, apierr.NotFound("Two-factor authentication is not enabled."))
			return
		}
		httpserver.WriteError(w, r, apierr.Internal(err))
		return
	}

	// EVERY session is revoked, including the caller's, and the cookie is
	// cleared. A session that was established while a second factor was
	// required was granted an assurance it no longer warrants, and there is no
	// way to tell which of the live sessions is the legitimate user's — the
	// caller's own session is exactly the one an attacker would be using.
	// Requiring a fresh login is the only answer that is the same for both.
	revoked, err := identity.RevokeAllUserSessions(r.Context(), h.opts.DB, principal.UserID, "second factor disabled")
	if err != nil {
		// Revocation is a compensating control, not the primary change. Log it
		// loudly and continue: reporting failure would suggest MFA is still on.
		h.opts.Logger.ErrorContext(r.Context(), "session revocation after MFA disable failed",
			"error", err, "user_id", principal.UserID, "request_id", requestID)
	}
	if clearErr := auth.ClearSessionCookie(w, h.opts.Cookies); clearErr != nil {
		h.opts.Logger.ErrorContext(r.Context(), "clearing session cookie after MFA disable failed",
			"error", clearErr, "user_id", principal.UserID, "request_id", requestID)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":                 "disabled",
		"recovery_codes_revoked": codesRevoked,
		"sessions_revoked":       revoked,
	})
}

// --- recovery codes ------------------------------------------------------------

// handleRecoveryRegenerate replaces the caller's recovery codes and returns the
// new set once.
//
// The caller's current second factor is required alongside the password when one
// is enrolled. Without it, a hijacked session plus a guessed password would mint
// a permanent bypass that survives the legitimate user changing that password.
func (h *Handlers) handleRecoveryRegenerate(w http.ResponseWriter, r *http.Request) {
	principal := auth.MustPrincipalFrom(r.Context())
	requestID := httpserver.RequestIDFromRequest(r)

	var req mfaRequest
	if apiErr := decodeJSON(r, &req); apiErr != nil {
		httpserver.WriteError(w, r, apiErr)
		return
	}
	if apiErr := h.reauthenticate(w, r, principal, req.Password, "mfa.recovery.generate"); apiErr != nil {
		httpserver.WriteError(w, r, apiErr)
		return
	}

	status, err := identity.GetTOTPStatus(r.Context(), h.opts.DB, principal.UserID)
	if err != nil {
		httpserver.WriteError(w, r, apierr.DatabaseUnavailable())
		return
	}
	if status.Enrolled {
		if apiErr := h.requireCurrentTOTP(r, principal, req.Code); apiErr != nil {
			httpserver.WriteError(w, r, apiErr)
			return
		}
	}

	codes, err := identity.GenerateRecoveryCodes(r.Context(), h.opts.DB, principal.UserID, requestID)
	if err != nil {
		httpserver.WriteError(w, r, apierr.Internal(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"recovery_codes": codes,
	})
}

// --- helpers -------------------------------------------------------------------

// reauthenticate verifies the caller's current password before a
// protection-weakening change, and audits a refusal.
//
// The account is loaded by the SESSION's email and then checked against the
// session's user id: if the two ever disagreed, the verification would be
// against the wrong account's credential, so that case fails closed.
func (h *Handlers) reauthenticate(w http.ResponseWriter, r *http.Request, principal auth.Principal, password, action string) *apierr.Error {
	if strings.TrimSpace(principal.UserID) == "" {
		return apierr.Forbidden("This operation requires a user session.")
	}
	if password == "" {
		return apierr.InvalidRequest("Your current password is required.", nil)
	}

	// The same limiter as login: the password being verified is the account
	// password, so guessing it here must be no cheaper than guessing it at the
	// login form.
	if allowed, retryAfter := h.loginLimiter.Allow(remoteKey(r)); !allowed {
		writeRetryAfter(w, retryAfter)
		return apierr.TooManyRequests("Too many attempts. Try again later.", retryAfter)
	}

	candidate, err := identity.GetLoginCandidate(r.Context(), h.opts.DB, principal.Email)
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			h.auditMFADenied(r, principal.UserID, action, "session user not found")
			return apierr.Unauthorized("")
		}
		return apierr.DatabaseUnavailable()
	}
	if candidate.ID != principal.UserID {
		h.auditMFADenied(r, principal.UserID, action, "session identity mismatch")
		return apierr.Unauthorized("")
	}

	ok, _, err := identity.VerifyPassword(candidate.PasswordHash, password, h.params)
	if err != nil {
		// An unusable stored hash is an operator fault, not a wrong password,
		// and must not be counted as a brute-force attempt.
		h.opts.Logger.ErrorContext(r.Context(), "stored credential is unusable",
			"error", err, "user_id", principal.UserID,
			"request_id", httpserver.RequestIDFromRequest(r))
		return apierr.Internal(err)
	}
	if !ok {
		h.auditMFADenied(r, principal.UserID, action, "current password incorrect")
		// 403 rather than 401: the caller IS authenticated; the extra proof
		// they supplied is what failed, and a 401 would tell the browser to
		// clear the session it legitimately holds.
		return &apierr.Error{
			Code:    apierr.CodeForbidden,
			Message: "The current password is incorrect.",
			Status:  http.StatusForbidden,
		}
	}
	return nil
}

// requireCurrentTOTP demands a valid code from the enrollment in force, for
// operations that must not be doable with a password alone.
func (h *Handlers) requireCurrentTOTP(r *http.Request, principal auth.Principal, code string) *apierr.Error {
	if strings.TrimSpace(code) == "" {
		return totpRequired()
	}
	enrollment, err := identity.GetActiveTOTP(r.Context(), h.opts.DB, principal.UserID)
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			// Status said a factor was enrolled but none is usable. Fail closed.
			return totpRequired()
		}
		return apierr.DatabaseUnavailable()
	}
	secret, err := h.opts.Secrets.Open(r.Context(), enrollment.SecretRef)
	if err != nil {
		h.opts.Logger.ErrorContext(r.Context(), "TOTP secret unavailable",
			"error", err, "user_id", principal.UserID,
			"secret_ref", enrollment.SecretRef,
			"request_id", httpserver.RequestIDFromRequest(r))
		return apierr.Internal(err)
	}
	step, err := totp.Validate(secret, code, h.opts.now())
	if err != nil {
		if errors.Is(err, totp.ErrCodeInvalid) {
			return totpCodeInvalid()
		}
		return apierr.Internal(err)
	}
	accepted, err := identity.ConsumeTOTPStep(r.Context(), h.opts.DB, enrollment.ID, step)
	if err != nil {
		return apierr.Internal(err)
	}
	if !accepted {
		return &apierr.Error{
			Code:    CodeTOTPInvalid,
			Message: "That two-factor code has already been used.",
			Status:  http.StatusUnauthorized,
		}
	}
	return nil
}

func totpCodeInvalid() *apierr.Error {
	return &apierr.Error{
		Code:    CodeTOTPInvalid,
		Message: "The two-factor code is incorrect.",
		Status:  http.StatusUnauthorized,
	}
}

// auditMFADenied records a refused protection change. Without this row, a burst
// of failed MFA-disarm attempts on one account looks like normal traffic, which
// is exactly what an attacker probing for a weak password wants.
func (h *Handlers) auditMFADenied(r *http.Request, userID, action, reason string) {
	recordAudit(r.Context(), h.opts.Logger, h.opts.DB, httpserver.RequestIDFromRequest(r), audit.Event{
		ActorType:    audit.ActorUser,
		ActorID:      userID,
		Action:       action,
		ResourceType: "user",
		ResourceID:   userID,
		Result:       audit.ResultDenied,
		ErrorCode:    apierr.CodeForbidden,
		Reason:       reason,
		SourceIP:     clientIP(r),
		UserAgent:    r.UserAgent(),
	})
}
