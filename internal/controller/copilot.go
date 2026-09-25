package controller

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/copilot"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CopilotHandlerOptions configures the AI copilot HTTP surface.
type CopilotHandlerOptions struct {
	Copilot *copilot.Store
	Pool    *pgxpool.Pool
	Logger  *slog.Logger
	Audit   audit.Execer
	Now     func() time.Time
}

// CopilotHandlers holds the AI copilot HTTP handlers.
type CopilotHandlers struct {
	store       *copilot.Store
	pool        *pgxpool.Pool
	logger      *slog.Logger
	auditExecer audit.Execer
	now         func() time.Time
}

// NewCopilotHandlers builds the copilot handlers.
func NewCopilotHandlers(opts CopilotHandlerOptions) (*CopilotHandlers, error) {
	if opts.Copilot == nil {
		return nil, errors.New("controller: copilot store is required")
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
	return &CopilotHandlers{
		store:       opts.Copilot,
		pool:        opts.Pool,
		logger:      opts.Logger,
		auditExecer: opts.Audit,
		now:         now,
	}, nil
}

// Routes registers copilot endpoints on the mux.
//
// Permissions:
//   - copilot.read   — list sessions, plans, tool-call audit
//   - copilot.run    — create sessions, invoke tools
//   - copilot.review — approve/reject plans
func (h *CopilotHandlers) Routes(mux *http.ServeMux) {
	// Sessions
	mux.HandleFunc("GET /api/v1/projects/{project_id}/copilot/sessions", h.handleListSessions)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/copilot/sessions", h.handleCreateSession)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/copilot/sessions/{id}", h.handleGetSession)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/copilot/sessions/{id}/close", h.handleCloseSession)

	// Tool invocation (all calls audited; allowlist enforced)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/copilot/sessions/{id}/tool", h.handleInvokeTool)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/copilot/sessions/{id}/audit", h.handleListToolCalls)

	// Plans
	mux.HandleFunc("GET /api/v1/projects/{project_id}/copilot/plans", h.handleListPlans)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/copilot/plans/{id}", h.handleGetPlan)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/copilot/plans/{id}/submit", h.handleSubmitPlan)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/copilot/plans/{id}/cancel", h.handleCancelPlan)

	// Approvals
	mux.HandleFunc("GET /api/v1/projects/{project_id}/copilot/plans/{plan_id}/approvals", h.handleListApprovals)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/copilot/plans/{plan_id}/approvals/{id}/review", h.handleReviewApproval)

	// LLM Provider Configuration (PRD §28: endpoint, apiKey, model settings)
	mux.HandleFunc("GET /api/v1/copilot/provider", h.handleGetProvider)
	mux.HandleFunc("PUT /api/v1/copilot/provider", h.handleSetProvider)
}

// ── Audit helper ─────────────────────────────────────────────────────────────

func (h *CopilotHandlers) recordAudit(r *http.Request, ev audit.Event) {
	if h.auditExecer == nil {
		return
	}
	ev.RequestID = httpserver.RequestIDFromRequest(r)
	ev.SourceIP = r.RemoteAddr
	ev.UserAgent = r.UserAgent()
	if ev.ActorType == "" {
		ev.ActorType = audit.ActorUser
	}
	if err := audit.Record(r.Context(), h.auditExecer, ev); err != nil {
		h.logger.ErrorContext(r.Context(), "audit write failed",
			"error", err, "action", ev.Action)
	}
}

// ── Sessions ──────────────────────────────────────────────────────────────────

// GET /api/v1/projects/{project_id}/copilot/sessions
func (h *CopilotHandlers) handleListSessions(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "copilot.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessions, err := h.store.ListSessions(r.Context(), projectID)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"sessions":   sessions,
				"total":      len(sessions),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST /api/v1/projects/{project_id}/copilot/sessions
func (h *CopilotHandlers) handleCreateSession(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "copilot.run", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Intent string `json:"intent"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			sess, err := h.store.CreateSession(r.Context(), projectID, p.UserID, req.Intent)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "copilot.session.create",
				ResourceType: "copilot_session", ResourceID: sess.ID, Result: "ok",
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"session":    sess,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// GET /api/v1/projects/{project_id}/copilot/sessions/{id}
func (h *CopilotHandlers) handleGetSession(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "copilot.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sess, err := h.store.GetSession(r.Context(), r.PathValue("id"))
			if errors.Is(err, copilot.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("session not found"))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"session":    sess,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST .../sessions/{id}/close
func (h *CopilotHandlers) handleCloseSession(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "copilot.run", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			var req struct {
				State string `json:"state"` // completed | cancelled
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.State == "" {
				req.State = "completed"
			}
			if err := h.store.CloseSession(r.Context(), id, req.State); errors.Is(err, copilot.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("session not found"))
				return
			} else if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{"state": req.State, "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}

// ── Tool invocation ───────────────────────────────────────────────────────────

// POST .../sessions/{id}/tool
// AI cannot bypass RBAC — all tools checked against allowlist and audited.
func (h *CopilotHandlers) handleInvokeTool(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "copilot.run", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sessionID := r.PathValue("id")
			var req struct {
				ToolName string         `json:"tool_name"`
				Input    map[string]any `json:"input"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.ToolName == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("tool_name is required", nil))
				return
			}

			// Enforce allowlist — no unrestricted shell.
			if !copilot.IsAllowedTool(req.ToolName) {
				// Audit the denial.
				_, _ = h.store.RecordToolCall(r.Context(), sessionID, req.ToolName,
					req.Input, nil, "denied", "tool not in allowlist")
				httpserver.WriteError(w, r, apierr.InvalidRequest("tool not permitted: "+req.ToolName, nil))
				return
			}

			// Execute through LLM provider when configured, otherwise rule-based advisor (PRD §28).
			toolResult, execErr := copilot.ExecuteTool(req.ToolName, req.Input)
			outcome := "ok"
			errMsg := ""

			// Attempt LLM completion — augments/replaces rule-based result.
			if llmCfg, cfgErr := h.store.GetProviderConfig(r.Context()); cfgErr == nil && llmCfg.Endpoint != "" {
				llm := copilot.NewLLMClient(llmCfg)
				system := "You are JAWAKER infrastructure copilot. Respond in structured JSON analysis format."
				user, _ := json.Marshal(map[string]any{"tool": req.ToolName, "input": req.Input})
				if llmText, llmErr := llm.Complete(r.Context(), system, string(user)); llmErr == nil {
					toolResult.Details = llmText
					toolResult.Source = "llm"
				}
			}

			if execErr != nil {
				outcome = "error"
				errMsg = execErr.Error()
			}

			output := map[string]any{
				"tool":    req.ToolName,
				"result":  toolResult,
				"outcome": outcome,
				"error":   errMsg,
			}

			tc, err := h.store.RecordToolCall(r.Context(), sessionID, req.ToolName,
				req.Input, output, "ok", "")
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "copilot.tool.invoke",
				ResourceType: "copilot_tool_call", ResourceID: tc.ID, Result: "ok",
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"tool_call":  tc,
				"output":     output,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// GET .../sessions/{id}/audit
func (h *CopilotHandlers) handleListToolCalls(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "copilot.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls, err := h.store.ListToolCalls(r.Context(), r.PathValue("id"))
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"tool_calls": calls,
				"total":      len(calls),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Plans ─────────────────────────────────────────────────────────────────────

// GET .../plans
func (h *CopilotHandlers) handleListPlans(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "copilot.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			plans, err := h.store.ListPlans(r.Context(), projectID)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"plans":      plans,
				"total":      len(plans),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// GET .../plans/{id}
func (h *CopilotHandlers) handleGetPlan(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "copilot.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			plan, err := h.store.GetPlan(r.Context(), r.PathValue("id"))
			if errors.Is(err, copilot.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("plan not found"))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"plan":       plan,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST .../plans/{id}/submit — submit for approval (required if risk >= high)
func (h *CopilotHandlers) handleSubmitPlan(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "copilot.run", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			plan, err := h.store.GetPlan(r.Context(), id)
			if errors.Is(err, copilot.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("plan not found"))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			// High/critical risk: require explicit approval.
			if plan.RiskLevel == "high" || plan.RiskLevel == "critical" {
				approval, aErr := h.store.RequestApproval(r.Context(), id, p.UserID)
				if aErr != nil {
					writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(aErr))
					return
				}
				h.recordAudit(r, audit.Event{
					ActorID: p.UserID, Action: "copilot.plan.submit",
					ResourceType: "copilot_plan", ResourceID: id, Result: "pending_approval",
				})
				writeJSONResponse(w, http.StatusAccepted, map[string]any{
					"plan_id":    id,
					"approval":   approval,
					"message":    "Plan requires approval due to risk level: " + plan.RiskLevel,
					"request_id": httpserver.RequestIDFromRequest(r),
				})
				return
			}
			// Low/medium: auto-approve.
			if err := h.store.UpdatePlanState(r.Context(), id, "approved", p.UserID); err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "copilot.plan.submit",
				ResourceType: "copilot_plan", ResourceID: id, Result: "approved",
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"plan_id":    id,
				"state":      "approved",
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST .../plans/{id}/cancel
func (h *CopilotHandlers) handleCancelPlan(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "copilot.run", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			if err := h.store.UpdatePlanState(r.Context(), id, "cancelled", ""); errors.Is(err, copilot.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("plan not found"))
				return
			} else if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{"cancelled": true, "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}

// ── Approvals ─────────────────────────────────────────────────────────────────

// GET .../plans/{plan_id}/approvals
func (h *CopilotHandlers) handleListApprovals(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "copilot.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			approvals, err := h.store.ListApprovals(r.Context(), r.PathValue("plan_id"))
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"approvals":  approvals,
				"total":      len(approvals),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST .../plans/{plan_id}/approvals/{id}/review
func (h *CopilotHandlers) handleReviewApproval(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "copilot.review", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			var req struct {
				State   string `json:"state"` // approved | rejected
				Comment string `json:"comment"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.State != "approved" && req.State != "rejected" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("state must be 'approved' or 'rejected'", nil))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			approval, err := h.store.ReviewApproval(r.Context(), id, req.State, p.UserID, req.Comment)
			if errors.Is(err, copilot.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("approval not found"))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "copilot.approval." + req.State,
				ResourceType: "copilot_approval", ResourceID: id, Result: req.State,
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"approval":   approval,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── LLM Provider ──────────────────────────────────────────────────────────────

// handleGetProvider returns the current LLM provider config (API key redacted).
func (h *CopilotHandlers) handleGetProvider(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "copilot.run", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cfg, err := h.store.GetProviderConfig(r.Context())
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"provider":   cfg.RedactedCopy(),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// handleSetProvider updates the LLM provider configuration.
func (h *CopilotHandlers) handleSetProvider(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "copilot.run", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				ProviderType string `json:"type"`
				Endpoint     string `json:"endpoint"`
				APIKey       string `json:"api_key"`
				Model        string `json:"model"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, apierr.InvalidRequest(err.Error(), nil))
				return
			}
			if req.Endpoint == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("endpoint is required", nil))
				return
			}
			if req.Model == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("model is required", nil))
				return
			}
			ptype := copilot.ProviderType(req.ProviderType)
			if ptype == "" {
				ptype = copilot.ProviderOpenAICompat
			}
			cfg := copilot.ProviderConfig{
				Type:     ptype,
				Endpoint: req.Endpoint,
				APIKey:   req.APIKey,
				Model:    req.Model,
			}
			if err := h.store.SetProviderConfig(r.Context(), cfg); err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "copilot.provider.update",
				ResourceType: "copilot_provider", ResourceID: "default",
				Result:  audit.ResultSuccess,
				Context: map[string]any{"type": req.ProviderType, "model": req.Model},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"provider":   cfg.RedactedCopy(),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}
