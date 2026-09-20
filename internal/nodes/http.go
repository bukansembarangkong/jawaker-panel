package nodes

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
)

// The HTTP surface for node management (API.md §3). Every route declares its own
// permission and scope here, in one place, so "which routes are protected and
// how" is answerable by reading this file rather than by auditing handlers.
//
//	GET    /api/v1/servers                       server.read    GLOBAL
//	GET    /api/v1/servers/{id}                  server.read    SERVER(id)
//	DELETE /api/v1/servers/{id}                  server.delete  SERVER(id), step-up
//	GET    /api/v1/servers/enrollment-tokens     server.enroll  GLOBAL
//	POST   /api/v1/servers/enrollment-tokens     server.enroll  GLOBAL, step-up
//	DELETE /api/v1/servers/enrollment-tokens/{id} server.enroll GLOBAL, step-up
//
// The fleet LIST is global because it spans servers: a per-server grant cannot
// describe "some subset of the fleet" under this model, and pretending otherwise
// would mean fetching rows the caller may not read and hiding them afterwards.
// Detail is server-scoped, so a binding scoped to one server reads exactly that
// one and nothing else.
//
// Token endpoints use `server.enroll`, which the RBAC catalog already marks as
// requiring step-up. Minting a credential that adds a machine to the fleet is
// exactly the kind of action that should cost a re-authentication.

// maxListLimit bounds a page. Exceeding it is a caller error rather than a silent
// clamp: a client asking for 10000 rows must be told no, not handed a short page
// it will mistake for a complete one.
const maxListLimit = 200

// HandlerOptions configures the node HTTP surface.
type HandlerOptions struct {
	// Store is the inventory and enrollment store. Required.
	Store *Store
	// Authority supplies the controller identity and mints node certificates.
	// Required: without it no token can be bound to a controller.
	Authority *Authority
	// Audit receives authorization and mutation events. Nil disables the trail,
	// which is only acceptable in tests.
	Audit audit.Execer
	// Logger receives audit-write faults, which must not fail the request that
	// already succeeded. Required.
	Logger *slog.Logger
	// Now supplies the clock for permission evaluation and token state. Nil
	// means time.Now.
	Now func() time.Time
}

// Handlers holds the node HTTP surface.
type Handlers struct {
	store  *Store
	auth   *Authority
	audit  audit.Execer
	logger *slog.Logger
	now    func() time.Time
}

// NewHandlers builds the node handlers.
func NewHandlers(opts HandlerOptions) (*Handlers, error) {
	if opts.Store == nil {
		return nil, errors.New("nodes: store is required")
	}
	if opts.Authority == nil {
		return nil, errors.New("nodes: authority is required")
	}
	if opts.Logger == nil {
		return nil, errors.New("nodes: logger is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Handlers{store: opts.Store, auth: opts.Authority, audit: opts.Audit, logger: opts.Logger, now: now}, nil
}

// Routes registers the node routes.
//
// Go's ServeMux prefers the more specific pattern, so the static
// "/servers/enrollment-tokens" never resolves as "/servers/{id}".
//
// The per-server routes are wrapped in an inner RequirePermission whose scope
// comes from the path. That is why they are not wrapped here: the scope is not a
// constant of the route, it is a fact about the request.
func (h *Handlers) Routes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/servers",
		authsession.RequirePermission(h.now, "server.read", rbac.GlobalScope(), false,
			http.HandlerFunc(h.handleListServers)))
	mux.Handle("GET /api/v1/servers/enrollment-tokens",
		authsession.RequirePermission(h.now, "server.enroll", rbac.GlobalScope(), false,
			http.HandlerFunc(h.handleListTokens)))
	mux.Handle("POST /api/v1/servers/enrollment-tokens",
		authsession.RequirePermission(h.now, "server.enroll", rbac.GlobalScope(), true,
			http.HandlerFunc(h.handleCreateToken)))
	mux.Handle("DELETE /api/v1/servers/enrollment-tokens/{id}",
		authsession.RequirePermission(h.now, "server.enroll", rbac.GlobalScope(), true,
			http.HandlerFunc(h.handleRevokeToken)))
	mux.Handle("GET /api/v1/servers/{id}",
		http.HandlerFunc(h.handleGetServer))
	mux.Handle("DELETE /api/v1/servers/{id}",
		http.HandlerFunc(h.handleDeleteServer))
}

// --- server inventory ---------------------------------------------------------

func (h *Handlers) handleListServers(w http.ResponseWriter, r *http.Request) {
	limit, offset, apiErr := pagination(r)
	if apiErr != nil {
		httpserver.WriteError(w, r, apiErr)
		return
	}
	servers, total, err := h.store.ListServers(r.Context(), limit, offset, r.URL.Query().Get("status"))
	if err != nil {
		httpserver.WriteError(w, r, errFor(err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"servers":    serverResponses(servers),
		"total":      total,
		"limit":      limit,
		"offset":     offset,
		"has_more":   offset+len(servers) < total,
		"request_id": httpserver.RequestIDFromRequest(r),
	})
}

func (h *Handlers) handleGetServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.read", rbac.ServerScope(id), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			server, err := h.store.GetServer(r.Context(), id)
			if err != nil {
				httpserver.WriteError(w, r, errFor(err))
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"server":     serverResponse(server),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *Handlers) handleDeleteServer(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.delete", rbac.ServerScope(id), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.deleteServerAuthorized(w, r, id)
		})).ServeHTTP(w, r)
}

// deleteServerAuthorized tombstones a server and revokes its certificate.
//
// Both happen together, and the revocation goes FIRST, because a tombstoned
// server whose certificate still authenticates is a node that can reconnect and
// be trusted while the panel says it is gone. Doing the revoke first means a
// revocation failure aborts the request and leaves the server present, which is
// the safe direction: a server that is still listed is visible, whereas a
// server that is gone but still trusted is not.
func (h *Handlers) deleteServerAuthorized(w http.ResponseWriter, r *http.Request, id string) {
	server, err := h.store.GetServer(r.Context(), id)
	if err != nil {
		httpserver.WriteError(w, r, errFor(err))
		return
	}

	var revokedSerial string
	serial, _, _, certErr := h.store.ActiveCertificate(r.Context(), id)
	switch {
	case certErr == nil:
		if revokeErr := h.store.RevokeCertificate(r.Context(), id, serial,
			"server removed from the fleet"); revokeErr != nil {
			httpserver.WriteError(w, r, errFor(revokeErr))
			return
		}
		revokedSerial = serial
	case errors.Is(certErr, ErrNotFound):
		// A server that never completed enrollment has no certificate to revoke.
		// That is a legitimate state, not a failure.
	default:
		httpserver.WriteError(w, r, errFor(certErr))
		return
	}

	if err := h.store.SetStatus(r.Context(), id, "deleted"); err != nil {
		httpserver.WriteError(w, r, errFor(err))
		return
	}

	h.recordAudit(r, audit.Event{
		ActorType:    audit.ActorUser,
		ActorID:      actorID(r),
		Action:       "server.delete",
		ResourceType: "server",
		ResourceID:   id,
		Result:       audit.ResultSuccess,
		Context:      map[string]any{"name": server.Name, "revoked_serial": revokedSerial},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "deleted",
		"server_id":  id,
		"request_id": httpserver.RequestIDFromRequest(r),
	})
}

// --- enrollment tokens --------------------------------------------------------

type createTokenRequest struct {
	NodeName string `json:"node_name"`
	// LifetimeSeconds optionally overrides the default. Bounded server-side.
	LifetimeSeconds int `json:"lifetime_seconds,omitempty"`
}

// handleCreateToken mints a one-time enrollment token.
//
// The plaintext appears in THIS RESPONSE ONLY. It is never stored, never
// retrievable, and the list endpoint cannot reveal it — so a client that loses it
// mints another, which is the right cost for a credential of this kind.
func (h *Handlers) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req createTokenRequest
	if apiErr := decodeJSON(r, &req); apiErr != nil {
		httpserver.WriteError(w, r, apiErr)
		return
	}
	name := strings.TrimSpace(req.NodeName)
	if !ValidServerName(name) {
		httpserver.WriteError(w, r, apierr.InvalidRequest(
			"A server name is required: letters, digits, dash, dot, and underscore, up to 100 characters.",
			map[string]any{"field": "node_name"}))
		return
	}
	params := CreateTokenParams{NodeName: name, CreatedBy: actorID(r)}
	if req.LifetimeSeconds > 0 {
		params.Lifetime = time.Duration(req.LifetimeSeconds) * time.Second
	}

	token, plaintext, err := h.store.CreateToken(r.Context(), h.auth.ControllerID(), params)
	if err != nil {
		httpserver.WriteError(w, r, errFor(err))
		return
	}

	h.recordAudit(r, audit.Event{
		ActorType:    audit.ActorUser,
		ActorID:      actorID(r),
		Action:       "server.enrollment_token.create",
		ResourceType: "enrollment_token",
		ResourceID:   token.ID,
		Result:       audit.ResultSuccess,
		Context:      map[string]any{"node_name": token.NodeName, "expires_at": token.ExpiresAt},
	})

	// The controller fingerprint travels with the token so an install command has
	// everything it needs and the node pins a root the operator can compare
	// against the controller's own reported fingerprint.
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":                  plaintext,
		"id":                     token.ID,
		"node_name":              token.NodeName,
		"expires_at":             token.ExpiresAt,
		"controller_fingerprint": h.auth.ControllerFingerprint(),
		"notice":                 "This token is shown once and cannot be retrieved again.",
		"request_id":             httpserver.RequestIDFromRequest(r),
	})
}

func (h *Handlers) handleListTokens(w http.ResponseWriter, r *http.Request) {
	limit, _, apiErr := pagination(r)
	if apiErr != nil {
		httpserver.WriteError(w, r, apiErr)
		return
	}
	tokens, err := h.store.ListTokens(r.Context(), limit)
	if err != nil {
		httpserver.WriteError(w, r, errFor(err))
		return
	}
	now := h.now()
	out := make([]map[string]any, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, map[string]any{
			"id":         t.ID,
			"node_name":  t.NodeName,
			"expires_at": t.ExpiresAt,
			"created_at": t.CreatedAt,
			"used_at":    t.UsedAt,
			"revoked_at": t.RevokedAt,
			"state":      tokenState(t, now),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tokens":     out,
		"request_id": httpserver.RequestIDFromRequest(r),
	})
}

func (h *Handlers) handleRevokeToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := h.store.RevokeToken(r.Context(), id, actorID(r)); err != nil {
		httpserver.WriteError(w, r, errFor(err))
		return
	}
	h.recordAudit(r, audit.Event{
		ActorType:    audit.ActorUser,
		ActorID:      actorID(r),
		Action:       "server.enrollment_token.revoke",
		ResourceType: "enrollment_token",
		ResourceID:   id,
		Result:       audit.ResultSuccess,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "revoked",
		"request_id": httpserver.RequestIDFromRequest(r),
	})
}

// --- helpers ------------------------------------------------------------------

// serverResponse is the API representation of a server. It is spelled out rather
// than serialized from the domain struct so that adding a field to the domain
// type cannot leak into the API silently.
func serverResponse(s Server) map[string]any {
	out := map[string]any{
		"id":            s.ID,
		"name":          s.Name,
		"description":   s.Description,
		"address":       s.Address,
		"status":        s.Status,
		"cert_status":   s.CertStatus,
		"os_family":     s.OSFamily,
		"os_version":    s.OSVersion,
		"agent_version": s.AgentVersion,
		"created_at":    s.CreatedAt,
	}
	if s.LastSeenAt != nil {
		out["last_seen_at"] = s.LastSeenAt
	}
	if s.EnrolledAt != nil {
		out["enrolled_at"] = s.EnrolledAt
	}
	return out
}

func serverResponses(servers []Server) []map[string]any {
	out := make([]map[string]any, 0, len(servers))
	for _, s := range servers {
		out = append(out, serverResponse(s))
	}
	return out
}

// tokenState renders a token's lifecycle for a list view. It is derived rather
// than stored because "expired" is a function of the current time, and a stored
// value would say "live" long after the token stopped being usable.
func tokenState(t EnrollmentToken, now time.Time) string {
	switch {
	case t.RevokedAt != nil:
		return "revoked"
	case t.UsedAt != nil:
		return "used"
	case !t.ExpiresAt.After(now):
		return "expired"
	default:
		return "live"
	}
}

// pagination parses and bounds the page parameters.
func pagination(r *http.Request) (limit, offset int, apiErr *apierr.Error) {
	limit = 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return 0, 0, apierr.InvalidRequest("limit must be a positive integer.",
				map[string]any{"field": "limit"})
		}
		if n > maxListLimit {
			return 0, 0, apierr.InvalidRequest("limit is too large.",
				map[string]any{"field": "limit", "max": maxListLimit})
		}
		limit = n
	}
	if raw := r.URL.Query().Get("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return 0, 0, apierr.InvalidRequest("offset must be a non-negative integer.",
				map[string]any{"field": "offset"})
		}
		offset = n
	}
	return limit, offset, nil
}

// errFor maps a store error onto the API error envelope.
//
// The mapping lives in one place so a new error cannot become a 500 by default:
// an unmapped error is an internal fault by definition, and anything a caller can
// act on has to be mapped explicitly here.
func errFor(err error) *apierr.Error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNotFound):
		return apierr.NotFound("The requested resource does not exist.")
	case errors.Is(err, ErrNameTaken):
		return apierr.Conflict("A server with that name already exists.",
			map[string]any{"field": "node_name"})
	case errors.Is(err, ErrTokenInvalid):
		return apierr.InvalidRequest("The enrollment token is not valid.", nil)
	case errors.Is(err, ErrInvalid), errors.Is(err, ErrStatus):
		return apierr.InvalidRequest("The request is not valid for the resource's current state.", nil)
	case errors.Is(err, ErrNoAuthority):
		return apierr.ServiceUnavailable("This installation has no certificate authority configured.")
	default:
		return apierr.Internal(err)
	}
}

// actorID returns the authenticated principal's user id, or empty when the
// request carried no principal. An empty value becomes SQL NULL in the store, so
// an unattributed event is visibly unattributed rather than pointing at a zero
// UUID.
func actorID(r *http.Request) string {
	if principal, ok := auth.PrincipalFrom(r.Context()); ok {
		return principal.UserID
	}
	return ""
}

// recordAudit writes an audit event without failing the request on a write fault.
//
// It is used for events describing something that ALREADY succeeded, where there
// is no surrounding transaction to abort. Telling the client the operation failed
// because the trail could not be written would be a lie about the mutation's
// effect; the fault is logged instead.
func (h *Handlers) recordAudit(r *http.Request, e audit.Event) {
	if h.audit == nil {
		return
	}
	e.RequestID = httpserver.RequestIDFromRequest(r)
	e.SourceIP = r.RemoteAddr
	e.UserAgent = r.UserAgent()
	if err := audit.Record(r.Context(), h.audit, e); err != nil {
		h.logger.ErrorContext(r.Context(), "audit write failed",
			"error", err, "action", e.Action, "request_id", e.RequestID)
	}
}

// decodeJSON reads a bounded JSON body into dst, refusing unknown fields and
// trailing values.
func decodeJSON(r *http.Request, dst any) *apierr.Error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return apierr.InvalidRequest("The request body is not valid JSON.",
			map[string]any{"error": err.Error()})
	}
	// A trailing value would otherwise be ignored, letting a request carry
	// something the server never inspects.
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return apierr.InvalidRequest("The request body contains more than one JSON value.", nil)
	}
	return nil
}

// writeJSON writes a JSON response with the canonical content type.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
