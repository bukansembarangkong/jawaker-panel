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
	mux.HandleFunc("GET /api/v1/jobs/{id}", h.handleGetJob)
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
