// Package controller: API tokens management endpoints per PRD §26.2.
package controller

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/apitoken"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/jackc/pgx/v5/pgxpool"
)

type APITokenHandlerOptions struct {
	Tokens *apitoken.Store
	Pool   *pgxpool.Pool
	Logger *slog.Logger
	Audit  audit.Execer
	Now    func() time.Time
}

type APITokenHandlers struct {
	tokens *apitoken.Store
	pool   *pgxpool.Pool
	logger *slog.Logger
	audit  audit.Execer
	now    func() time.Time
}

func NewAPITokenHandlers(opts APITokenHandlerOptions) (*APITokenHandlers, error) {
	if opts.Tokens == nil {
		return nil, errors.New("controller: tokens store is required")
	}
	if opts.Pool == nil {
		return nil, errors.New("controller: pool is required")
	}
	if opts.Logger == nil {
		return nil, errors.New("controller: logger is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &APITokenHandlers{
		tokens: opts.Tokens,
		pool:   opts.Pool,
		logger: opts.Logger,
		audit:  opts.Audit,
		now:    now,
	}, nil
}

func (h *APITokenHandlers) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/tokens", h.handleList)
	mux.HandleFunc("POST /api/v1/tokens", h.handleCreate)
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", h.handleRevoke)
}

func (h *APITokenHandlers) handleList(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFrom(r.Context())
	if !ok {
		httpserver.WriteError(w, r, apierr.Unauthorized(""))
		return
	}

	tokens, err := h.tokens.ListByUser(r.Context(), principal.UserID)
	if err != nil {
		httpserver.WriteError(w, r, apierr.Internal(err))
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]any{
		"tokens":     tokens,
		"request_id": httpserver.RequestIDFromRequest(r),
	})
}

type createTokenRequest struct {
	Name         string     `json:"name"`
	Kind         string     `json:"kind"`
	Scopes       []string   `json:"scopes"`
	AllowedCIDRs []string   `json:"allowed_cidrs"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

func (h *APITokenHandlers) handleCreate(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFrom(r.Context())
	if !ok {
		httpserver.WriteError(w, r, apierr.Unauthorized(""))
		return
	}

	var req createTokenRequest
	if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
		httpserver.WriteError(w, r, apiErr)
		return
	}

	if req.Name == "" {
		httpserver.WriteError(w, r, apierr.InvalidRequest("token name is required", nil))
		return
	}
	if req.Kind == "" {
		req.Kind = "personal"
	}
	if req.Kind != "personal" && req.Kind != "service" {
		httpserver.WriteError(w, r, apierr.InvalidRequest("kind must be personal or service", nil))
		return
	}

	created, err := h.tokens.Create(r.Context(), principal.UserID, req.Name, req.Kind, req.Scopes, req.AllowedCIDRs, req.ExpiresAt)
	if err != nil {
		httpserver.WriteError(w, r, apierr.Internal(err))
		return
	}

	h.recordAudit(r, audit.Event{
		ActorType:    audit.ActorUser,
		ActorID:      principal.UserID,
		Action:       "token.create",
		ResourceType: "api_token",
		ResourceID:   created.ID,
		Result:       audit.ResultSuccess,
		Context: map[string]any{
			"name": created.Name,
			"kind": created.Kind,
		},
	})

	writeJSONResponse(w, http.StatusCreated, map[string]any{
		"token":      created,
		"request_id": httpserver.RequestIDFromRequest(r),
	})
}

func (h *APITokenHandlers) handleRevoke(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFrom(r.Context())
	if !ok {
		httpserver.WriteError(w, r, apierr.Unauthorized(""))
		return
	}

	id := r.PathValue("id")
	if err := h.tokens.Revoke(r.Context(), principal.UserID, id); err != nil {
		if errors.Is(err, apitoken.ErrNotFound) {
			httpserver.WriteError(w, r, apierr.NotFound("Token not found or already revoked"))
			return
		}
		httpserver.WriteError(w, r, apierr.Internal(err))
		return
	}

	h.recordAudit(r, audit.Event{
		ActorType:    audit.ActorUser,
		ActorID:      principal.UserID,
		Action:       "token.revoke",
		ResourceType: "api_token",
		ResourceID:   id,
		Result:       audit.ResultSuccess,
	})

	writeJSONResponse(w, http.StatusOK, map[string]any{
		"revoked":    true,
		"request_id": httpserver.RequestIDFromRequest(r),
	})
}

func (h *APITokenHandlers) recordAudit(r *http.Request, event audit.Event) {
	if h.audit == nil {
		return
	}
	event.RequestID = httpserver.RequestIDFromRequest(r)
	event.SourceIP = r.RemoteAddr
	event.UserAgent = r.UserAgent()
	_ = audit.Record(r.Context(), h.audit, event)
}
