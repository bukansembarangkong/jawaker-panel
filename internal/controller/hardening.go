package controller

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/health"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/jackc/pgx/v5/pgxpool"
)

// HardeningHandlerOptions configures the production hardening HTTP surface.
type HardeningHandlerOptions struct {
	Health *health.Store
	Pool   *pgxpool.Pool
	Logger *slog.Logger
	Audit  audit.Execer
	Now    func() time.Time
}

// HardeningHandlers holds the production hardening HTTP handlers.
type HardeningHandlers struct {
	store       *health.Store
	pool        *pgxpool.Pool
	logger      *slog.Logger
	auditExecer audit.Execer
	now         func() time.Time
}

// NewHardeningHandlers builds the hardening handlers.
func NewHardeningHandlers(opts HardeningHandlerOptions) (*HardeningHandlers, error) {
	if opts.Health == nil {
		return nil, errors.New("controller: health store is required")
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
	return &HardeningHandlers{
		store:       opts.Health,
		pool:        opts.Pool,
		logger:      opts.Logger,
		auditExecer: opts.Audit,
		now:         now,
	}, nil
}

// Routes registers hardening endpoints.
//
// Permissions:
//   - GET /api/v1/health/checks   — ops.read
//   - POST /api/v1/health/checks  — ops.read (run on-demand check)
//   - GET /api/v1/health/upgrades — ops.read
//   - GET /api/v1/health/runbooks — ops.read
//   - POST /api/v1/health/runbooks — ops.manage (record runbook event)
func (h *HardeningHandlers) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/health/checks", h.handleListChecks)
	mux.HandleFunc("POST /api/v1/health/checks", h.handleRunCheck)
	mux.HandleFunc("GET /api/v1/health/upgrades", h.handleListUpgrades)
	mux.HandleFunc("GET /api/v1/health/runbooks", h.handleListRunbooks)
	mux.HandleFunc("POST /api/v1/health/runbooks", h.handleRecordRunbook)
}

// ── Audit helper ─────────────────────────────────────────────────────────────

func (h *HardeningHandlers) recordAudit(r *http.Request, ev audit.Event) {
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

// ── Health checks ─────────────────────────────────────────────────────────────

// GET /api/v1/health/checks
func (h *HardeningHandlers) handleListChecks(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "ops.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logs, err := h.store.LatestByCheck(r.Context())
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			// Compute overall status.
			overall := health.StatusOK
			for _, l := range logs {
				if l.Status == health.StatusFailed {
					overall = health.StatusFailed
					break
				}
				if l.Status == health.StatusDegraded {
					overall = health.StatusDegraded
				}
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"overall":    overall,
				"checks":     logs,
				"total":      len(logs),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST /api/v1/health/checks — run on-demand checks
func (h *HardeningHandlers) handleRunCheck(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "ops.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			dbLog, _ := h.store.CheckDatabase(ctx)
			selfLog, _ := h.store.CheckSelf(ctx)
			chainLog, _ := h.store.CheckMigrationChain(ctx, 1, 0) // any positive count is ok

			overall := health.StatusOK
			for _, l := range []health.HealthLog{dbLog, selfLog, chainLog} {
				if l.Status == health.StatusFailed {
					overall = health.StatusFailed
					break
				}
				if l.Status == health.StatusDegraded {
					overall = health.StatusDegraded
				}
			}
			p, _ := auth.PrincipalFrom(r.Context())
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "health.check.run",
				ResourceType: "health_check", ResourceID: "", Result: overall,
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"overall":    overall,
				"results":    []health.HealthLog{dbLog, selfLog, chainLog},
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Upgrade history ───────────────────────────────────────────────────────────

// GET /api/v1/health/upgrades
func (h *HardeningHandlers) handleListUpgrades(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "ops.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			upgrades, err := h.store.ListUpgrades(r.Context(), 50)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"upgrades":   upgrades,
				"total":      len(upgrades),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Runbook events ────────────────────────────────────────────────────────────

// GET /api/v1/health/runbooks
func (h *HardeningHandlers) handleListRunbooks(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "ops.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			events, err := h.store.ListRunbookEvents(r.Context(), 50)
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

// POST /api/v1/health/runbooks — record a runbook drill/incident outcome
func (h *HardeningHandlers) handleRecordRunbook(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "ops.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				RunbookName string `json:"runbook_name"`
				EventType   string `json:"event_type"`
				Outcome     string `json:"outcome"`
				Notes       string `json:"notes"`
				DurationMin int    `json:"duration_min"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.RunbookName == "" || req.EventType == "" || req.Outcome == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("runbook_name, event_type, outcome are required", nil))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			ev, err := h.store.RecordRunbookEvent(r.Context(), req.RunbookName, req.EventType, req.Outcome, p.UserID, req.Notes, req.DurationMin)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "runbook.event.record",
				ResourceType: "runbook_event", ResourceID: ev.ID, Result: req.Outcome,
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"event":      ev,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}
