package authsession

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/identity"
	"github.com/bukansembarangkong/jawaker-panel/internal/password"
	"github.com/bukansembarangkong/jawaker-panel/internal/ratelimit"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/bukansembarangkong/jawaker-panel/internal/totp"
)

// Authentication outcome codes. These live here rather than in apierr because
// they describe authentication results, not generic HTTP semantics.
const (
	// CodeInvalidCredentials is returned for every failed credential check. It
	// deliberately does not distinguish unknown email from wrong password: a
	// distinguishable error turns the login endpoint into an account
	// enumerator.
	CodeInvalidCredentials = "invalid_credentials" //nolint:gosec // error code, not a credential
	// CodeBootstrapClosed is returned once the installation already has an
	// owner. Bootstrap is a one-time operation.
	CodeBootstrapClosed = "bootstrap_closed"
	// CodeAccountInactive is returned for a suspended or deleted account,
	// distinct from bad credentials because retrying cannot fix it.
	CodeAccountInactive = "account_inactive"
	// CodeTOTPRequired is returned when the password was correct but the second
	// factor is still needed. No session exists at that point.
	CodeTOTPRequired = "totp_required"
	// CodeTOTPInvalid is returned when a supplied second factor is wrong.
	CodeTOTPInvalid = "totp_invalid"
)

// LockoutPolicy configures brute-force behavior (SECURITY.md §3).
type LockoutPolicy struct {
	// Threshold is the number of consecutive failures that arms a lockout.
	Threshold int
	// Duration is how long the lockout lasts.
	Duration time.Duration
}

// DefaultLockoutPolicy is deliberately modest: it must stop online guessing
// without letting an attacker lock a real user out of their own panel for long
// by deliberately failing a few attempts.
func DefaultLockoutPolicy() LockoutPolicy {
	return LockoutPolicy{Threshold: 5, Duration: 15 * time.Minute}
}

func (p LockoutPolicy) validate() error {
	if p.Threshold <= 0 {
		return errors.New("authsession: lockout threshold must be positive")
	}
	if p.Duration <= 0 {
		return errors.New("authsession: lockout duration must be positive")
	}
	return nil
}

// Handlers holds the authentication endpoints.
type Handlers struct {
	opts    Options
	csrf    *auth.CSRF
	lockout LockoutPolicy
	params  password.Params
	// loginLimiter bounds attempts per client address, independently of the
	// per-account lockout. Both are needed: the account counter stops guessing
	// one account, the address limiter blunts spraying across many accounts.
	loginLimiter *ratelimit.Limiter
	// bootstrapLimiter bounds bootstrap attempts, which are unauthenticated by
	// definition.
	bootstrapLimiter *ratelimit.Limiter
}

// HandlerOptions configures Handlers.
type HandlerOptions struct {
	Options
	CSRF         *auth.CSRF
	Lockout      LockoutPolicy
	PasswordHash password.Params
	// LoginRate bounds login attempts per client address.
	LoginRate ratelimit.Options
	// BootstrapRate bounds bootstrap attempts per client address.
	BootstrapRate ratelimit.Options
}

// NewHandlers builds the authentication handlers. Every input is validated here
// so a misconfiguration fails at startup rather than on the first login.
func NewHandlers(opts HandlerOptions) (*Handlers, error) {
	if err := opts.validateHandlers(); err != nil {
		return nil, err
	}
	if opts.CSRF == nil {
		return nil, errors.New("authsession: CSRF helper is required")
	}
	if err := opts.Lockout.validate(); err != nil {
		return nil, err
	}
	if err := opts.PasswordHash.Validate(); err != nil {
		return nil, fmt.Errorf("authsession: password parameters: %w", err)
	}

	loginLimiter, err := ratelimit.New(opts.LoginRate)
	if err != nil {
		return nil, fmt.Errorf("authsession: login rate: %w", err)
	}
	bootstrapLimiter, err := ratelimit.New(opts.BootstrapRate)
	if err != nil {
		return nil, fmt.Errorf("authsession: bootstrap rate: %w", err)
	}

	return &Handlers{
		opts:             opts.Options,
		csrf:             opts.CSRF,
		lockout:          opts.Lockout,
		params:           opts.PasswordHash,
		loginLimiter:     loginLimiter,
		bootstrapLimiter: bootstrapLimiter,
	}, nil
}

// Routes registers the authentication endpoints on mux.
//
// The caller applies Middleware ONCE around the whole mux (so every route gets
// a resolved principal when a session cookie is present); this method only
// declares each route's OWN protection requirements: which need CSRF and which
// need an authenticated session. Nothing is protected merely by order.
func (h *Handlers) Routes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/auth/csrf", http.HandlerFunc(h.handleCSRF))
	mux.Handle("GET /api/v1/auth/bootstrap", http.HandlerFunc(h.handleBootstrapStatus))
	mux.Handle("POST /api/v1/auth/bootstrap",
		RequireCSRF(h.csrf, http.HandlerFunc(h.handleBootstrap)))
	mux.Handle("POST /api/v1/auth/login",
		RequireCSRF(h.csrf, http.HandlerFunc(h.handleLogin)))
	mux.Handle("POST /api/v1/auth/logout",
		RequireCSRF(h.csrf, RequireAuth(http.HandlerFunc(h.handleLogout))))
	mux.Handle("GET /api/v1/auth/session",
		RequireAuth(http.HandlerFunc(h.handleSession)))
}

// --- CSRF priming ---------------------------------------------------------------

// handleCSRF issues the double-submit token. The front end calls it before its
// first state-changing request. Unauthenticated by design: a pre-login form
// needs a token too.
func (h *Handlers) handleCSRF(w http.ResponseWriter, r *http.Request) {
	token, err := h.csrf.EnsureToken(w, r)
	if err != nil {
		httpserver.WriteError(w, r, apierr.Internal(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"csrf_token": token})
}

// --- bootstrap -------------------------------------------------------------------

type bootstrapRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
}

// handleBootstrapStatus reports whether the installation still needs an owner.
// Unauthenticated: the login page must know whether to show the setup form, and
// the answer reveals nothing an attacker could not learn by attempting a
// bootstrap.
func (h *Handlers) handleBootstrapStatus(w http.ResponseWriter, r *http.Request) {
	exists, err := identity.HasAnyUser(r.Context(), h.opts.DB)
	if err != nil {
		httpserver.WriteError(w, r, apierr.DatabaseUnavailable())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"requires_bootstrap": !exists})
}

// handleBootstrap creates the single platform owner.
func (h *Handlers) handleBootstrap(w http.ResponseWriter, r *http.Request) {
	requestID := httpserver.RequestIDFromRequest(r)

	// Unauthenticated endpoint: limit by address before doing any work.
	if allowed, retryAfter := h.bootstrapLimiter.Allow(remoteKey(r)); !allowed {
		writeRetryAfter(w, retryAfter)
		httpserver.WriteError(w, r, apierr.TooManyRequests("Too many attempts. Try again later.", retryAfter))
		return
	}

	var req bootstrapRequest
	if apiErr := decodeJSON(r, &req); apiErr != nil {
		httpserver.WriteError(w, r, apiErr)
		return
	}

	email := identity.NormalizeEmail(req.Email)
	if err := ValidateEmail(email); err != nil {
		httpserver.WriteError(w, r, apierr.InvalidRequest(err.Error(), map[string]any{"field": "email"}))
		return
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		httpserver.WriteError(w, r, apierr.InvalidRequest("A display name is required.", map[string]any{"field": "display_name"}))
		return
	}
	if err := ValidatePassword(req.Password); err != nil {
		httpserver.WriteError(w, r, apierr.InvalidRequest(err.Error(), map[string]any{"field": "password"}))
		return
	}

	// Pre-check so the common "already installed" case is a clean 409 instead
	// of a constraint error. The database still decides: the partial unique
	// index rejects a race between two concurrent bootstraps.
	exists, err := identity.HasAnyUser(r.Context(), h.opts.DB)
	if err != nil {
		httpserver.WriteError(w, r, apierr.DatabaseUnavailable())
		return
	}
	if exists {
		httpserver.WriteError(w, r, bootstrapClosed())
		return
	}

	userID, err := identity.Bootstrap(r.Context(), h.opts.DB, identity.BootstrapParams{
		Email:       email,
		DisplayName: displayName,
		Password:    req.Password,
		RequestID:   requestID,
	}, h.params)
	if err != nil {
		if errors.Is(err, identity.ErrAlreadyExists) {
			httpserver.WriteError(w, r, bootstrapClosed())
			return
		}
		h.opts.Logger.ErrorContext(r.Context(), "bootstrap failed",
			"error", err, "request_id", requestID)
		httpserver.WriteError(w, r, apierr.Internal(err))
		return
	}

	h.opts.Logger.InfoContext(r.Context(), "platform owner bootstrapped",
		"user_id", userID, "request_id", requestID)
	// Bootstrap does NOT create a session. The operator logs in normally, so
	// there is exactly one way to obtain a session.
	writeJSON(w, http.StatusCreated, map[string]any{"user_id": userID})
}

// --- login -----------------------------------------------------------------------

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	// TOTPCode carries the second factor when the account has one enrolled.
	TOTPCode string `json:"totp_code"`
}

// handleLogin authenticates a browser and issues a session cookie.
func (h *Handlers) handleLogin(w http.ResponseWriter, r *http.Request) {
	requestID := httpserver.RequestIDFromRequest(r)
	clientKey := remoteKey(r)

	if allowed, retryAfter := h.loginLimiter.Allow(clientKey); !allowed {
		writeRetryAfter(w, retryAfter)
		httpserver.WriteError(w, r, apierr.TooManyRequests("Too many login attempts. Try again later.", retryAfter))
		return
	}

	var req loginRequest
	if apiErr := decodeJSON(r, &req); apiErr != nil {
		httpserver.WriteError(w, r, apiErr)
		return
	}
	email := identity.NormalizeEmail(req.Email)
	if email == "" || req.Password == "" {
		// Still audited: a malformed attempt is part of the brute-force picture.
		h.auditLoginFailure(r, "", email, "missing credentials")
		httpserver.WriteError(w, r, invalidCredentials())
		return
	}

	now := h.opts.now()
	candidate, err := identity.GetLoginCandidate(r.Context(), h.opts.DB, email)
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			// Unknown account. The response is IDENTICAL to a wrong password so
			// the endpoint cannot be used to enumerate accounts.
			h.auditLoginFailure(r, "", email, "unknown account")
			httpserver.WriteError(w, r, invalidCredentials())
			return
		}
		httpserver.WriteError(w, r, apierr.DatabaseUnavailable())
		return
	}

	// Lockout is checked BEFORE verifying the password: otherwise a locked
	// account would still be an oracle for whether a password is correct.
	if candidate.Locked(now) {
		retryAfter := candidate.LockedUntil.Sub(now)
		h.auditAuthEvent(r, candidate.User, audit.ResultDenied, "account locked", "")
		httpserver.WriteError(w, r, apierr.AccountLocked(retryAfter))
		return
	}

	ok, needsRehash, err := identity.VerifyPassword(candidate.PasswordHash, req.Password, h.params)
	if err != nil {
		// The stored hash is unusable: an operator-visible fault, not a bad
		// password. It is NOT counted as a brute-force failure.
		h.opts.Logger.ErrorContext(r.Context(), "stored credential is unusable",
			"error", err, "user_id", candidate.ID, "request_id", requestID)
		httpserver.WriteError(w, r, apierr.Internal(err))
		return
	}
	if !ok {
		h.recordFailedLogin(r, candidate, email)
		httpserver.WriteError(w, r, invalidCredentials())
		return
	}

	if !candidate.Active() {
		h.auditAuthEvent(r, candidate.User, audit.ResultDenied, "account is not active", "")
		httpserver.WriteError(w, r, &apierr.Error{
			Code:    CodeAccountInactive,
			Message: "This account is not active.",
			Status:  http.StatusForbidden,
		})
		return
	}

	// Second factor. No session is created until BOTH factors pass, so a correct
	// password alone never yields a usable session.
	if candidate.HasConfirmedTOTP {
		if apiErr := h.verifySecondFactor(r, candidate, req.TOTPCode, now); apiErr != nil {
			h.recordFailedLogin(r, candidate, email)
			httpserver.WriteError(w, r, apiErr)
			return
		}
	}

	if successErr := identity.RecordLoginSuccess(r.Context(), h.opts.DB, candidate.ID); successErr != nil {
		h.opts.Logger.ErrorContext(r.Context(), "record login success failed",
			"error", successErr, "user_id", candidate.ID, "request_id", requestID)
		httpserver.WriteError(w, r, apierr.Internal(successErr))
		return
	}
	// Successful login clears this address's limiter, so a user who mistyped a
	// few times is not penalized afterwards.
	h.loginLimiter.Reset(clientKey)

	// Opportunistic rehash: the stored parameters are outdated and this is the
	// one moment the plaintext is available.
	if needsRehash {
		if rehashErr := identity.RotatePassword(r.Context(), h.opts.DB, candidate.ID, req.Password, h.params); rehashErr != nil {
			// The login already succeeded; failing it over a rehash would be
			// worse than keeping an outdated-but-valid hash one more cycle.
			h.opts.Logger.WarnContext(r.Context(), "transparent rehash failed",
				"error", rehashErr, "user_id", candidate.ID)
		}
	}

	session, err := identity.CreateSession(r.Context(), h.opts.DB, candidate.ID,
		sessionMetadata(r), h.opts.Policy, now)
	if err != nil {
		httpserver.WriteError(w, r, apierr.Internal(err))
		return
	}
	if cookieErr := auth.SetSessionCookie(w, h.opts.Cookies, session.Token); cookieErr != nil {
		httpserver.WriteError(w, r, apierr.Internal(cookieErr))
		return
	}
	// Rotate the CSRF token on authentication, so a token obtained before login
	// cannot be reused after it.
	csrfToken, err := h.csrf.RotateToken(w)
	if err != nil {
		httpserver.WriteError(w, r, apierr.Internal(err))
		return
	}

	h.auditAuthEvent(r, candidate.User, audit.ResultSuccess, "password and second factor verified", session.ID)
	writeJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":           candidate.ID,
			"email":        candidate.Email,
			"display_name": candidate.DisplayName,
			"account_type": candidate.AccountType,
			"is_owner":     candidate.IsOwner,
		},
		"session_id": session.ID,
		"csrf_token": csrfToken,
	})
}

// verifySecondFactor validates the TOTP code against the user's confirmed
// enrollment.
//
// A missing code is reported as "second factor required" rather than as invalid
// credentials, so the UI can prompt for it: the password has already been proven
// correct, and withholding that fact gains an attacker nothing because they
// supplied it.
func (h *Handlers) verifySecondFactor(r *http.Request, candidate identity.LoginCandidate, code string, now time.Time) *apierr.Error {
	if strings.TrimSpace(code) == "" {
		return totpRequired()
	}

	enrollment, err := identity.GetActiveTOTP(r.Context(), h.opts.DB, candidate.ID)
	if err != nil {
		if errors.Is(err, identity.ErrNotFound) {
			// The candidate said a factor was enrolled but no usable enrollment
			// exists. Fail closed rather than letting a stale flag bypass the
			// second factor.
			return totpRequired()
		}
		return apierr.Internal(err)
	}

	secret, err := h.opts.Secrets.Open(r.Context(), enrollment.SecretRef)
	if err != nil {
		h.opts.Logger.ErrorContext(r.Context(), "TOTP secret unavailable",
			"error", err, "user_id", candidate.ID,
			"secret_ref", enrollment.SecretRef,
			"request_id", httpserver.RequestIDFromRequest(r))
		return apierr.Internal(err)
	}

	step, err := totp.Validate(secret, code, now)
	if err != nil {
		if errors.Is(err, totp.ErrCodeInvalid) {
			return &apierr.Error{
				Code:    CodeTOTPInvalid,
				Message: "The two-factor code is incorrect.",
				Status:  http.StatusUnauthorized,
			}
		}
		return apierr.Internal(err)
	}

	// Anti-replay: a code is accepted at most once. Without this, an attacker
	// who observes a code (shoulder-surf, log, proxy) can reuse it inside the
	// same 30-second window even after the legitimate user consumed it.
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

func totpRequired() *apierr.Error {
	return &apierr.Error{
		Code:    CodeTOTPRequired,
		Message: "A two-factor code is required.",
		Status:  http.StatusUnauthorized,
	}
}

// recordFailedLogin increments the brute-force counter and audits the failure.
func (h *Handlers) recordFailedLogin(r *http.Request, candidate identity.LoginCandidate, email string) {
	lockedUntil, err := identity.RecordLoginFailure(r.Context(), h.opts.DB, candidate.ID,
		h.lockout.Threshold, h.lockout.Duration, h.opts.now())
	if err != nil {
		// The credential check already failed; a counter fault must not change
		// the response, or the response would leak storage health.
		h.opts.Logger.ErrorContext(r.Context(), "record login failure failed",
			"error", err, "user_id", candidate.ID)
	}
	if lockedUntil != nil {
		h.opts.Logger.WarnContext(r.Context(), "account locked after repeated failures",
			"user_id", candidate.ID,
			"locked_until", lockedUntil.UTC(),
			"request_id", httpserver.RequestIDFromRequest(r))
	}
	h.auditLoginFailure(r, candidate.ID, email, "invalid credentials")
}

// --- logout ----------------------------------------------------------------------

// handleLogout revokes the current session. The cookie is cleared even if the
// store write fails, so the browser cannot keep presenting a token the user
// asked to discard.
func (h *Handlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	principal := auth.MustPrincipalFrom(r.Context())
	requestID := httpserver.RequestIDFromRequest(r)

	err := identity.RevokeSession(r.Context(), h.opts.DB, principal.SessionID, "user logout")
	if err != nil && !errors.Is(err, identity.ErrNotFound) {
		h.opts.Logger.ErrorContext(r.Context(), "session revoke failed on logout",
			"error", err, "session_id", principal.SessionID, "request_id", requestID)
	}
	if clearErr := auth.ClearSessionCookie(w, h.opts.Cookies); clearErr != nil {
		httpserver.WriteError(w, r, apierr.Internal(clearErr))
		return
	}

	recordAudit(r.Context(), h.opts.Logger, h.opts.DB, requestID, audit.Event{
		ActorType:    audit.ActorUser,
		ActorID:      principal.UserID,
		Action:       "session.logout",
		ResourceType: "session",
		ResourceID:   principal.SessionID,
		Result:       audit.ResultSuccess,
		SourceIP:     clientIP(r),
		UserAgent:    r.UserAgent(),
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// --- session introspection ---------------------------------------------------------

// handleSession returns the caller's own identity, effective permissions, and
// elevation state.
//
// Effective permissions come from the SAME evaluator the API uses, so the UI's
// view of what is allowed cannot drift from what the server enforces. The UI is
// still not the authority: hiding a control is cosmetic and every endpoint
// re-checks.
func (h *Handlers) handleSession(w http.ResponseWriter, r *http.Request) {
	principal := auth.MustPrincipalFrom(r.Context())
	now := h.opts.now()

	globalPerms := rbac.EffectivePermissions(principal.Principal, rbac.GlobalScope(), now)
	var scopedPerms []string
	scopeKind, scopeID := r.URL.Query().Get("scope_type"), r.URL.Query().Get("scope_id")
	if scope, ok := toRBACScope(scopeKind, scopeID); ok {
		scopedPerms = rbac.EffectivePermissions(principal.Principal, scope, now)
	}
	if globalPerms == nil {
		globalPerms = []string{}
	}
	if scopedPerms == nil {
		scopedPerms = []string{}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":           principal.UserID,
			"email":        principal.Email,
			"display_name": principal.DisplayName,
			"is_owner":     principal.IsOwner,
		},
		"session_id": principal.SessionID,
		"elevated":   principal.ElevatedUntil != nil && principal.ElevatedUntil.After(now),
		"permissions": map[string]any{
			"global": globalPerms,
			"scoped": scopedPerms,
		},
	})
}

// --- helpers ------------------------------------------------------------------------

func invalidCredentials() *apierr.Error {
	return &apierr.Error{
		Code:    CodeInvalidCredentials,
		Message: "The email address or password is incorrect.",
		Status:  http.StatusUnauthorized,
	}
}

func bootstrapClosed() *apierr.Error {
	return &apierr.Error{
		Code:    CodeBootstrapClosed,
		Message: "This installation already has an owner; bootstrap is no longer available.",
		Status:  http.StatusConflict,
	}
}

// auditLoginFailure records a failed authentication attempt. A reason is always
// supplied because an unexplained denial cannot be investigated later.
func (h *Handlers) auditLoginFailure(r *http.Request, userID, email, reason string) {
	actorType := audit.ActorUser
	if userID == "" {
		// No resolved actor. Recorded as a system-observed event so the trail
		// never claims a user acted when none was identified.
		actorType = audit.ActorSystem
	}
	recordAudit(r.Context(), h.opts.Logger, h.opts.DB, httpserver.RequestIDFromRequest(r), audit.Event{
		ActorType:    actorType,
		ActorID:      userID,
		Action:       "auth.login",
		ResourceType: "user",
		ResourceID:   userID,
		Result:       audit.ResultFailure,
		ErrorCode:    CodeInvalidCredentials,
		Reason:       reason,
		Context:      map[string]any{"email": email},
		SourceIP:     clientIP(r),
		UserAgent:    r.UserAgent(),
	})
}

// auditAuthEvent records an authentication outcome for an IDENTIFIED account.
func (h *Handlers) auditAuthEvent(r *http.Request, user identity.User, result, reason, sessionID string) {
	e := audit.Event{
		ActorType:    audit.ActorUser,
		ActorID:      user.ID,
		Action:       "auth.login",
		ResourceType: "user",
		ResourceID:   user.ID,
		Result:       result,
		Reason:       reason,
		SourceIP:     clientIP(r),
		UserAgent:    r.UserAgent(),
	}
	if sessionID != "" {
		e.Context = map[string]any{"session_id": sessionID}
	}
	recordAudit(r.Context(), h.opts.Logger, h.opts.DB, httpserver.RequestIDFromRequest(r), e)
}

// decodeJSON reads a bounded JSON body and maps a decode failure onto the
// canonical error envelope.
func decodeJSON(r *http.Request, dst any) *apierr.Error {
	dec := json.NewDecoder(r.Body)
	// Reject unknown fields so a typo in a request field is reported instead of
	// silently ignored — a silently ignored field looks like the server accepted
	// a setting it never applied.
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return apierr.PayloadTooLarge("")
		}
		return apierr.InvalidRequest("The request body is not valid JSON.", nil)
	}
	// Reject trailing content: two concatenated JSON objects usually mean a bug
	// or an attempt to smuggle a second payload past validation.
	if dec.More() {
		return apierr.InvalidRequest("The request body contains trailing content.", nil)
	}
	return nil
}

func sessionMetadata(r *http.Request) identity.SessionMetadata {
	return identity.SessionMetadata{
		UserAgent: truncate(r.UserAgent(), maxUserAgentLen),
		ClientIP:  rbac.ParseAddr(r.RemoteAddr),
	}
}

// maxUserAgentLen bounds the client-supplied user agent before it is persisted.
const maxUserAgentLen = 512

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// remoteKey derives the rate-limit key from the SOCKET address only. Forwarded
// headers are not trusted until a trusted-proxy policy exists (SECURITY.md §10);
// trusting them here would let an attacker bypass the limiter by inventing a new
// address per request.
func remoteKey(r *http.Request) string {
	if addr := rbac.ParseAddr(r.RemoteAddr); addr.IsValid() {
		return addr.String()
	}
	return "unknown"
}

func clientIP(r *http.Request) string {
	if addr := rbac.ParseAddr(r.RemoteAddr); addr.IsValid() {
		return addr.String()
	}
	return ""
}

// writeRetryAfter sets the standard header so any client, including a plain
// HTTP one, can back off without parsing the JSON body.
func writeRetryAfter(w http.ResponseWriter, d time.Duration) {
	secs := int(d.Seconds() + 0.999)
	if secs < 1 {
		secs = 1
	}
	w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
}

// ValidateEmail performs bounded syntactic validation only. Deliverability is
// not verified: an address that cannot receive mail is the operator's problem to
// notice, and a strict grammar rejects legitimate addresses.
func ValidateEmail(email string) error {
	if email == "" {
		return errors.New("an email address is required")
	}
	if len(email) > 254 {
		return errors.New("the email address is too long")
	}
	at := strings.LastIndex(email, "@")
	if at <= 0 || at == len(email)-1 {
		return errors.New("the email address is not valid")
	}
	if strings.ContainsAny(email, " \t\r\n") {
		return errors.New("the email address is not valid")
	}
	// A dot-free domain and a literal IP are both technically addressable, but
	// the panel is not an SMTP implementation: require a dot in the domain so an
	// obvious typo is caught at creation time.
	if !strings.Contains(email[at+1:], ".") {
		return errors.New("the email address is not valid")
	}
	return nil
}

// Password policy. MinimumPasswordLength follows NIST guidance: length is the
// dominant factor, and composition rules push users toward predictable
// substitutions. MaxPasswordLength bounds work, because argon2id hashes the
// whole input and an unbounded password is an unbounded CPU commitment per
// login attempt.
const (
	MinimumPasswordLength = 12
	MaxPasswordLength     = 1024
)

// ValidatePassword enforces the password policy.
func ValidatePassword(pw string) error {
	if len(pw) < MinimumPasswordLength {
		return fmt.Errorf("the password must be at least %d characters", MinimumPasswordLength)
	}
	if len(pw) > MaxPasswordLength {
		return fmt.Errorf("the password must be at most %d characters", MaxPasswordLength)
	}
	return nil
}

// writeJSON is the local response writer, kept private so httpserver remains the
// single public response surface.
func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		// Only reachable for unsupported types — a programming error.
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
