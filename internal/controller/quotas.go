// Package controller: project resource quota endpoints (PRD §5.5).
//
// Endpoints:
//
//	GET    /api/v1/projects/{id}/quotas     — list quotas for project
//	PUT    /api/v1/projects/{id}/quotas/{resource} — set quota limit
package controller

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/jackc/pgx/v5/pgxpool"
)

type QuotaHandlerOptions struct {
	Pool   *pgxpool.Pool
	Logger *slog.Logger
	Audit  audit.Execer
	Now    func() time.Time
}

type QuotaHandlers struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
	audit  audit.Execer
	now    func() time.Time
}

func NewQuotaHandlers(opts QuotaHandlerOptions) (*QuotaHandlers, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &QuotaHandlers{
		pool:   opts.Pool,
		logger: opts.Logger,
		audit:  opts.Audit,
		now:    now,
	}, nil
}

func (h *QuotaHandlers) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/projects/{id}/quotas", h.handleListQuotas)
	mux.HandleFunc("PUT /api/v1/projects/{id}/quotas/{resource}", h.handleSetQuota)
}

type quotaRow struct {
	ID           string    `json:"id"`
	ProjectID    string    `json:"project_id"`
	Resource     string    `json:"resource"`
	LimitValue   int64     `json:"limit_value"`
	CurrentValue int64     `json:"current_value"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

func (h *QuotaHandlers) handleListQuotas(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rows, err := h.pool.Query(r.Context(), `
				SELECT id, project_id, resource, limit_value, current_value, created_at, updated_at
				FROM project_quotas
				WHERE project_id = $1
				ORDER BY resource
			`, projectID)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			defer rows.Close()
			var quotas []quotaRow
			for rows.Next() {
				var q quotaRow
				if err := rows.Scan(&q.ID, &q.ProjectID, &q.Resource, &q.LimitValue, &q.CurrentValue, &q.CreatedAt, &q.UpdatedAt); err != nil {
					httpserver.WriteError(w, r, apierr.Internal(err))
					return
				}
				quotas = append(quotas, q)
			}
			if rows.Err() != nil {
				httpserver.WriteError(w, r, apierr.Internal(rows.Err()))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"quotas":     quotas,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type setQuotaRequest struct {
	LimitValue int64 `json:"limit_value"` // -1 = unlimited
}

func (h *QuotaHandlers) handleSetQuota(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("id")
	resource := r.PathValue("resource")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req setQuotaRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			var id string
			err := h.pool.QueryRow(r.Context(), `
				INSERT INTO project_quotas (project_id, resource, limit_value)
				VALUES ($1, $2, $3)
				ON CONFLICT (project_id, resource)
				DO UPDATE SET limit_value = EXCLUDED.limit_value, updated_at = now()
				RETURNING id
			`, projectID, resource, req.LimitValue).Scan(&id)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordAuditQ(r, audit.Event{
				ActorType: audit.ActorUser, ActorID: principalUserID(r),
				Action: "quota.set", ResourceType: "project_quota", ResourceID: id,
				Result:  audit.ResultSuccess,
				Context: map[string]any{"project_id": projectID, "resource": resource, "limit_value": req.LimitValue},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"quota_id":   id,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *QuotaHandlers) recordAuditQ(r *http.Request, event audit.Event) {
	if h.audit == nil {
		return
	}
	event.RequestID = httpserver.RequestIDFromRequest(r)
	event.SourceIP = r.RemoteAddr
	event.UserAgent = r.UserAgent()
	_ = audit.Record(r.Context(), h.audit, event)
}
