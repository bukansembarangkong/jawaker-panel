package controller

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/ha"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HAHandlerOptions configures the HA HTTP surface.
type HAHandlerOptions struct {
	HA     *ha.Store
	Pool   *pgxpool.Pool
	Logger *slog.Logger
	Audit  audit.Execer
	Now    func() time.Time
}

// HAHandlers holds the HA HTTP handlers.
type HAHandlers struct {
	store       *ha.Store
	pool        *pgxpool.Pool
	logger      *slog.Logger
	auditExecer audit.Execer
	now         func() time.Time
}

// NewHAHandlers builds the HA handlers.
func NewHAHandlers(opts HAHandlerOptions) (*HAHandlers, error) {
	if opts.HA == nil {
		return nil, errors.New("controller: ha store is required")
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
	return &HAHandlers{
		store:       opts.HA,
		pool:        opts.Pool,
		logger:      opts.Logger,
		auditExecer: opts.Audit,
		now:         now,
	}, nil
}

// Routes registers HA endpoints on the mux.
//
// Permissions:
//   - ha.read   — list pools, members, events, drills
//   - ha.manage — create/update/delete (step-up required)
func (h *HAHandlers) Routes(mux *http.ServeMux) {
	// Server pools (project-scoped)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/ha/pools", h.handleListPools)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/ha/pools", h.handleCreatePool)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/ha/pools/{id}", h.handleGetPool)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/ha/pools/{id}", h.handleDeletePool)

	// Pool members
	mux.HandleFunc("GET /api/v1/projects/{project_id}/ha/pools/{pool_id}/members", h.handleListMembers)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/ha/pools/{pool_id}/members", h.handleAddMember)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/ha/pools/{pool_id}/members/{id}", h.handleRemoveMember)

	// Drain
	mux.HandleFunc("GET /api/v1/projects/{project_id}/ha/pools/{pool_id}/drain", h.handleListDrain)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/ha/pools/{pool_id}/drain", h.handleStartDrain)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/ha/pools/{pool_id}/drain/{id}/cancel", h.handleCancelDrain)

	// Quorum config
	mux.HandleFunc("GET /api/v1/projects/{project_id}/ha/pools/{pool_id}/quorum", h.handleGetQuorum)
	mux.HandleFunc("PUT /api/v1/projects/{project_id}/ha/pools/{pool_id}/quorum", h.handleSetQuorum)

	// Failover events
	mux.HandleFunc("GET /api/v1/projects/{project_id}/ha/pools/{pool_id}/events", h.handleListEvents)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/ha/pools/{pool_id}/events/{id}/resolve", h.handleResolveEvent)

	// Failover drills
	mux.HandleFunc("GET /api/v1/projects/{project_id}/ha/pools/{pool_id}/drills", h.handleListDrills)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/ha/pools/{pool_id}/drills", h.handleCreateDrill)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/ha/pools/{pool_id}/drills/{id}/complete", h.handleCompleteDrill)
}

// ── Audit helper ────────────────────────────────────────────────────────────────

func (h *HAHandlers) recordAudit(r *http.Request, ev audit.Event) {
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

// ── Server Pools ────────────────────────────────────────────────────────────────

// GET /api/v1/projects/{project_id}/ha/pools
func (h *HAHandlers) handleListPools(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ha.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pools, err := h.store.ListPools(r.Context(), projectID)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"pools":      pools,
				"total":      len(pools),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST /api/v1/projects/{project_id}/ha/pools
func (h *HAHandlers) handleCreatePool(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ha.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Name        string `json:"name"`
				Description string `json:"description"`
				Mode        string `json:"mode"`
				MinHealthy  int    `json:"min_healthy"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.Name == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("name is required", nil))
				return
			}
			if req.Mode == "" {
				req.Mode = "active-passive"
			}
			if req.MinHealthy <= 0 {
				req.MinHealthy = 1
			}
			pool, err := h.store.CreatePool(r.Context(), projectID, req.Name, req.Description, req.Mode, req.MinHealthy)
			if errors.Is(err, ha.ErrConflict) {
				httpserver.WriteError(w, r, apierr.Conflict("pool name already exists", nil))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "ha.pool.create",
				ResourceType: "server_pool", ResourceID: pool.ID, Result: "ok",
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"pool":       pool,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// GET /api/v1/projects/{project_id}/ha/pools/{id}
func (h *HAHandlers) handleGetPool(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ha.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			pool, err := h.store.GetPool(r.Context(), r.PathValue("id"))
			if errors.Is(err, ha.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("pool not found"))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"pool":       pool,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// DELETE /api/v1/projects/{project_id}/ha/pools/{id}
func (h *HAHandlers) handleDeletePool(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ha.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			if err := h.store.DeletePool(r.Context(), id); errors.Is(err, ha.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("pool not found"))
				return
			} else if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "ha.pool.delete",
				ResourceType: "server_pool", ResourceID: id, Result: "ok",
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{"deleted": true, "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}

// ── Pool Members ────────────────────────────────────────────────────────────────

// GET .../pools/{pool_id}/members
func (h *HAHandlers) handleListMembers(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ha.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			members, err := h.store.ListMembers(r.Context(), r.PathValue("pool_id"))
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"members":    members,
				"total":      len(members),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST .../pools/{pool_id}/members
func (h *HAHandlers) handleAddMember(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ha.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			poolID := r.PathValue("pool_id")
			var req struct {
				ServerID string `json:"server_id"`
				Role     string `json:"role"`
				Weight   int    `json:"weight"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.ServerID == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("server_id is required", nil))
				return
			}
			if req.Role == "" {
				req.Role = "member"
			}
			if req.Weight <= 0 {
				req.Weight = 100
			}
			member, err := h.store.AddMember(r.Context(), poolID, req.ServerID, req.Role, req.Weight)
			if errors.Is(err, ha.ErrConflict) {
				httpserver.WriteError(w, r, apierr.Conflict("server already in pool", nil))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "ha.pool.member.add",
				ResourceType: "pool_member", ResourceID: member.ID, Result: "ok",
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"member":     member,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// DELETE .../pools/{pool_id}/members/{id}
func (h *HAHandlers) handleRemoveMember(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ha.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			if err := h.store.RemoveMember(r.Context(), id); errors.Is(err, ha.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("member not found"))
				return
			} else if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{"deleted": true, "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}

// ── Drain ────────────────────────────────────────────────────────────────────────

// GET .../drain
func (h *HAHandlers) handleListDrain(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ha.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqs, err := h.store.ListDrainRequests(r.Context(), r.PathValue("pool_id"))
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"drain_requests": reqs,
				"total":          len(reqs),
				"request_id":     httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST .../drain
func (h *HAHandlers) handleStartDrain(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ha.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			poolID := r.PathValue("pool_id")
			var req struct {
				ServerID string `json:"server_id"`
				Reason   string `json:"reason"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.ServerID == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("server_id is required", nil))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			dr, err := h.store.CreateDrainRequest(r.Context(), poolID, req.ServerID, p.UserID, req.Reason)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			// Mark the pool member as draining.
			_ = h.store.UpdateMemberState(r.Context(), req.ServerID, "draining")
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "ha.drain.start",
				ResourceType: "drain_request", ResourceID: dr.ID, Result: "ok",
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"drain_request": dr,
				"request_id":    httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST .../drain/{id}/cancel
func (h *HAHandlers) handleCancelDrain(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ha.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			if err := h.store.UpdateDrainState(r.Context(), id, "cancelled"); errors.Is(err, ha.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("drain request not found"))
				return
			} else if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{"cancelled": true, "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}

// ── Quorum ────────────────────────────────────────────────────────────────────────

// GET .../quorum
func (h *HAHandlers) handleGetQuorum(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ha.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q, err := h.store.GetQuorumConfig(r.Context(), r.PathValue("pool_id"))
			if errors.Is(err, ha.ErrNotFound) {
				// Return defaults — no quorum configured yet.
				writeJSONResponse(w, http.StatusOK, map[string]any{
					"pool_id":            r.PathValue("pool_id"),
					"min_votes":          2,
					"fencing_enabled":    false,
					"fencing_method":     "none",
					"split_brain_policy": "pause",
					"request_id":         httpserver.RequestIDFromRequest(r),
				})
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"pool_id":            q.PoolID,
				"min_votes":          q.MinVotes,
				"fencing_enabled":    q.FencingEnabled,
				"fencing_method":     q.FencingMethod,
				"split_brain_policy": q.SplitBrainPolicy,
				"request_id":         httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// PUT .../quorum
func (h *HAHandlers) handleSetQuorum(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ha.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			poolID := r.PathValue("pool_id")
			var req struct {
				MinVotes         int    `json:"min_votes"`
				FencingEnabled   bool   `json:"fencing_enabled"`
				FencingMethod    string `json:"fencing_method"`
				SplitBrainPolicy string `json:"split_brain_policy"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.MinVotes < 1 {
				req.MinVotes = 2
			}
			if req.FencingMethod == "" {
				req.FencingMethod = "none"
			}
			if req.SplitBrainPolicy == "" {
				req.SplitBrainPolicy = "pause"
			}
			q, err := h.store.UpsertQuorumConfig(r.Context(), poolID, req.MinVotes, req.FencingEnabled, req.FencingMethod, req.SplitBrainPolicy)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"pool_id":            q.PoolID,
				"min_votes":          q.MinVotes,
				"fencing_enabled":    q.FencingEnabled,
				"fencing_method":     q.FencingMethod,
				"split_brain_policy": q.SplitBrainPolicy,
				"request_id":         httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Failover Events ────────────────────────────────────────────────────────────

// GET .../events
func (h *HAHandlers) handleListEvents(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ha.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			poolID := r.PathValue("pool_id")
			limit := 50
			if s := r.URL.Query().Get("limit"); s != "" {
				if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 200 {
					limit = n
				}
			}
			events, err := h.store.ListFailoverEvents(r.Context(), poolID, limit)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"events":     events,
				"total":      len(events),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST .../events/{id}/resolve
func (h *HAHandlers) handleResolveEvent(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ha.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			if err := h.store.ResolveFailoverEvent(r.Context(), id); errors.Is(err, ha.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("event not found"))
				return
			} else if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{"resolved": true, "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}

// ── Failover Drills ────────────────────────────────────────────────────────────

// GET .../drills
func (h *HAHandlers) handleListDrills(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ha.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			drills, err := h.store.ListDrills(r.Context(), r.PathValue("pool_id"))
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"drills":     drills,
				"total":      len(drills),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST .../drills
func (h *HAHandlers) handleCreateDrill(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ha.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			poolID := r.PathValue("pool_id")
			var req struct {
				DrillType string `json:"drill_type"`
				Notes     string `json:"notes"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.DrillType == "" {
				req.DrillType = "manual"
			}
			p, _ := auth.PrincipalFrom(r.Context())
			drill, err := h.store.CreateDrill(r.Context(), poolID, req.DrillType, p.UserID, req.Notes)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "ha.drill.create",
				ResourceType: "failover_drill", ResourceID: drill.ID, Result: "ok",
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"drill":      drill,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST .../drills/{id}/complete
func (h *HAHandlers) handleCompleteDrill(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ha.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			var req struct {
				State     string `json:"state"` // passed | failed | cancelled
				ResultLog string `json:"result_log"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.State == "" {
				req.State = "passed"
			}
			if err := h.store.UpdateDrillState(r.Context(), id, req.State, req.ResultLog); errors.Is(err, ha.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("drill not found"))
				return
			} else if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "ha.drill.complete",
				ResourceType: "failover_drill", ResourceID: id, Result: req.State,
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{"state": req.State, "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}
