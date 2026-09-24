// Package controller: jobs HTTP handlers.
//
// Mounts job status queries under /api/v1/jobs.
//
// Security invariants enforced here:
//   - GET /api/v1/jobs/{id} requires jobs.read (GLOBAL scope, 0007_rbac_seed.sql L88).
//   - Nonexistent job returns 404.
package controller

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/jobs"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/jackc/pgx/v5/pgxpool"
)

// JobHandlerOptions configures the jobs HTTP surface.
type JobHandlerOptions struct {
	Pool   *pgxpool.Pool
	Logger *slog.Logger
	Now    func() time.Time
}

// JobHandlers holds the jobs HTTP surface.
type JobHandlers struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
	now    func() time.Time
}

// NewJobHandlers builds the job handlers.
func NewJobHandlers(opts JobHandlerOptions) (*JobHandlers, error) {
	if opts.Pool == nil {
		return nil, errors.New("controller: database pool is required for job handlers")
	}
	if opts.Logger == nil {
		return nil, errors.New("controller: logger is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &JobHandlers{
		pool:   opts.Pool,
		logger: opts.Logger,
		now:    now,
	}, nil
}

// Routes registers the job endpoints on the mux.
func (h *JobHandlers) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/jobs", h.handleListJobs)
	mux.HandleFunc("GET /api/v1/jobs/{id}", h.handleGetJob)
	mux.HandleFunc("POST /api/v1/jobs/{id}/cancel", h.handleCancelJob)
}

func (h *JobHandlers) handleGetJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "jobs.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			job, err := jobs.GetByID(r.Context(), h.pool, id)
			if err != nil {
				if errors.Is(err, jobs.ErrNotFound) {
					httpserver.WriteError(w, r, apierr.NotFound("The requested job does not exist."))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}

			stepList, err := jobs.ListSteps(r.Context(), h.pool, id)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}

			steps := make([]map[string]any, 0, len(stepList))
			for _, s := range stepList {
				stepMap := map[string]any{
					"index":         s.Index,
					"name":          s.Name,
					"state":         s.State,
					"output":        s.Output,
					"error_code":    s.ErrorCode,
					"error_summary": s.ErrorSummary,
					"attempt":       s.Attempt,
				}
				if s.StartedAt != nil {
					stepMap["started_at"] = *s.StartedAt
				}
				if s.FinishedAt != nil {
					stepMap["finished_at"] = *s.FinishedAt
				}
				steps = append(steps, stepMap)
			}

			jobMap := map[string]any{
				"id":            job.ID,
				"type":          job.Type,
				"server_id":     job.ServerID,
				"project_id":    job.ProjectID,
				"state":         job.State,
				"priority":      job.Priority,
				"attempt_count": job.AttemptCount,
				"max_attempts":  job.MaxAttempts,
				"error_code":    job.ErrorCode,
				"error_summary": job.ErrorSummary,
				"created_at":    job.CreatedAt,
			}
			if job.StartedAt != nil {
				jobMap["started_at"] = *job.StartedAt
			}
			if job.FinishedAt != nil {
				jobMap["finished_at"] = *job.FinishedAt
			}

			writeJSONResponse(w, http.StatusOK, map[string]any{
				"job":        jobMap,
				"steps":      steps,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *JobHandlers) handleListJobs(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "jobs.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rows, err := h.pool.Query(r.Context(), `
				SELECT id, type, server_id, project_id, state, priority,
				       progress_current, progress_total, current_step,
				       attempt_count, max_attempts, error_code, error_summary,
				       created_at, lease_expires_at
				FROM jobs
				ORDER BY created_at DESC
				LIMIT 50
			`)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			defer rows.Close()

			type jobSummary struct {
				ID              string     `json:"id"`
				Type            string     `json:"type"`
				ServerID        *string    `json:"server_id,omitempty"`
				ProjectID       *string    `json:"project_id,omitempty"`
				State           string     `json:"state"`
				Priority        int        `json:"priority"`
				ProgressCurrent int        `json:"progress_current"`
				ProgressTotal   *int       `json:"progress_total,omitempty"`
				CurrentStep     *string    `json:"current_step,omitempty"`
				AttemptCount    int        `json:"attempt_count"`
				MaxAttempts     int        `json:"max_attempts"`
				ErrorCode       *string    `json:"error_code,omitempty"`
				ErrorSummary    *string    `json:"error_summary,omitempty"`
				CreatedAt       time.Time  `json:"created_at"`
				LeaseExpiresAt  *time.Time `json:"lease_expires_at,omitempty"`
			}

			var list []jobSummary
			for rows.Next() {
				var j jobSummary
				if err := rows.Scan(&j.ID, &j.Type, &j.ServerID, &j.ProjectID, &j.State, &j.Priority,
					&j.ProgressCurrent, &j.ProgressTotal, &j.CurrentStep,
					&j.AttemptCount, &j.MaxAttempts, &j.ErrorCode, &j.ErrorSummary,
					&j.CreatedAt, &j.LeaseExpiresAt); err != nil {
					httpserver.WriteError(w, r, apierr.Internal(err))
					return
				}
				list = append(list, j)
			}
			if rows.Err() != nil {
				httpserver.WriteError(w, r, apierr.Internal(rows.Err()))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"jobs":       list,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *JobHandlers) handleCancelJob(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principalUserID := principalUserID(r)
			res, err := h.pool.Exec(r.Context(), `
				UPDATE jobs
				SET cancel_requested_at = now(),
				    cancel_requested_by = $1,
				    state = CASE WHEN state IN ('queued') THEN 'canceled' ELSE state END
				WHERE id = $2 AND state NOT IN ('succeeded', 'failed', 'canceled', 'dead_letter')
			`, principalUserID, id)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			if res.RowsAffected() == 0 {
				httpserver.WriteError(w, r, apierr.NotFound("Job not found or already terminal"))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"canceled":   true,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}
