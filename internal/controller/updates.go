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
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodes"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/bukansembarangkong/jawaker-panel/internal/updates"
	"github.com/jackc/pgx/v5/pgxpool"
)

// UpdatesHandlerOptions configures the update platform HTTP surface.
type UpdatesHandlerOptions struct {
	Updates    *updates.Store
	Pool       *pgxpool.Pool
	Dispatcher *nodes.Dispatcher
	Logger     *slog.Logger
	Audit      audit.Execer
	Now        func() time.Time
}

// UpdatesHandlers holds the update platform HTTP handlers.
type UpdatesHandlers struct {
	store       *updates.Store
	pool        *pgxpool.Pool
	dispatcher  *nodes.Dispatcher
	logger      *slog.Logger
	auditExecer audit.Execer
	now         func() time.Time
}

// NewUpdatesHandlers builds the update platform handlers.
func NewUpdatesHandlers(opts UpdatesHandlerOptions) (*UpdatesHandlers, error) {
	if opts.Updates == nil {
		return nil, errors.New("controller: updates store is required")
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
	return &UpdatesHandlers{
		store:       opts.Updates,
		pool:        opts.Pool,
		dispatcher:  opts.Dispatcher,
		logger:      opts.Logger,
		auditExecer: opts.Audit,
		now:         now,
	}, nil
}

// Routes registers the update platform endpoints on the mux.
//
// Permissions:
//   - updates.read  — view releases, jobs, modules
//   - updates.manage — trigger updates (step-up required)
func (h *UpdatesHandlers) Routes(mux *http.ServeMux) {
	// Release discovery
	mux.HandleFunc("GET /api/v1/updates/releases", h.handleListReleases)
	mux.HandleFunc("POST /api/v1/updates/releases/sync", h.handleSyncReleases)

	// Compatibility preflight
	mux.HandleFunc("POST /api/v1/updates/releases/{id}/preflight", h.handlePreflight)

	// Update jobs
	mux.HandleFunc("GET /api/v1/updates/jobs", h.handleListJobs)
	mux.HandleFunc("GET /api/v1/updates/jobs/{id}", h.handleGetJob)
	mux.HandleFunc("POST /api/v1/updates/apply", h.handleApply)

	// Snapshots
	mux.HandleFunc("GET /api/v1/updates/snapshots/{id}", h.handleGetSnapshot)

	// Fleet canary rollout & orchestration (PRD §25.5)
	mux.HandleFunc("GET /api/v1/updates/jobs/{id}/canary", h.handleListCanary)
	mux.HandleFunc("POST /api/v1/updates/jobs/{id}/canary/{server_id}/apply", h.handleCanaryApply)
	mux.HandleFunc("POST /api/v1/updates/fleet/rollout", h.handleFleetRollout)

	// Module updates
	mux.HandleFunc("GET /api/v1/updates/modules", h.handleListModules)
}

// ── Audit helper ───────────────────────────────────────────────────────────────

func (h *UpdatesHandlers) recordAudit(r *http.Request, ev audit.Event) {
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
			"error", err, "action", ev.Action, "request_id", ev.RequestID)
	}
}

// ── Releases ───────────────────────────────────────────────────────────────────

// GET /api/v1/updates/releases
func (h *UpdatesHandlers) handleListReleases(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "updates.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			channel := r.URL.Query().Get("channel")
			releases, err := h.store.ListReleases(r.Context(), channel)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"releases":   releases,
				"total":      len(releases),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST /api/v1/updates/releases/sync
// Records a newly discovered release (called by background discovery worker or admin).
func (h *UpdatesHandlers) handleSyncReleases(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "updates.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req updates.Release
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.Channel == "" || req.Version == "" || req.ArtifactURL == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("channel, version, and artifact_url are required", nil))
				return
			}
			rel, err := h.store.UpsertRelease(r.Context(), req)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "updates.release.sync",
				ResourceType: "release", ResourceID: rel.ID, Result: "ok",
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"release":    rel,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Preflight ──────────────────────────────────────────────────────────────────

// POST /api/v1/updates/releases/{id}/preflight
func (h *UpdatesHandlers) handlePreflight(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "updates.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			releaseID := r.PathValue("id")
			rel, err := h.store.GetRelease(r.Context(), releaseID)
			if errors.Is(err, updates.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("release not found"))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			// Preflight: mark compatible=true (real logic: check version constraints).
			// ponytail: full semver constraint check; add when module version matrix is defined.
			compatible := true
			if err := h.store.SetCompatible(r.Context(), rel.ID, compatible); err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "updates.preflight",
				ResourceType: "release", ResourceID: releaseID, Result: "ok",
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"release_id": releaseID,
				"compatible": compatible,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Jobs ───────────────────────────────────────────────────────────────────────

// GET /api/v1/updates/jobs
func (h *UpdatesHandlers) handleListJobs(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "updates.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jobs, err := h.store.ListJobs(r.Context())
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"jobs":       jobs,
				"total":      len(jobs),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// GET /api/v1/updates/jobs/{id}
func (h *UpdatesHandlers) handleGetJob(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "updates.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			job, err := h.store.GetJob(r.Context(), r.PathValue("id"))
			if errors.Is(err, updates.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("job not found"))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"job":        job,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST /api/v1/updates/apply
func (h *UpdatesHandlers) handleApply(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "updates.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				ReleaseID string `json:"release_id"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.ReleaseID == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("release_id is required", nil))
				return
			}
			rel, err := h.store.GetRelease(r.Context(), req.ReleaseID)
			if errors.Is(err, updates.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("release not found"))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			if rel.Compatible != nil && !*rel.Compatible {
				httpserver.WriteError(w, r, apierr.InvalidRequest("release failed compatibility preflight — cannot apply", nil))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			job, err := h.store.CreateJob(r.Context(), rel.ID, p.UserID)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "updates.apply",
				ResourceType: "update_job", ResourceID: job.ID, Result: "queued",
			})
			writeJSONResponse(w, http.StatusAccepted, map[string]any{
				"job":        job,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Snapshots ──────────────────────────────────────────────────────────────────

// GET /api/v1/updates/snapshots/{id}
func (h *UpdatesHandlers) handleGetSnapshot(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "updates.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			snap, err := h.store.GetSnapshot(r.Context(), r.PathValue("id"))
			if errors.Is(err, updates.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("snapshot not found"))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"snapshot":   snap,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Canary rollout ─────────────────────────────────────────────────────────────

// GET /api/v1/updates/jobs/{id}/canary
func (h *UpdatesHandlers) handleListCanary(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "updates.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			entries, err := h.store.ListCanaryEntries(r.Context(), r.PathValue("id"))
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"entries":    entries,
				"total":      len(entries),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST /api/v1/updates/jobs/{id}/canary/{server_id}/apply
// Pushes the node-agent update to one specific server (canary step).
func (h *UpdatesHandlers) handleCanaryApply(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "updates.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jobID := r.PathValue("id")
			serverID := r.PathValue("server_id")

			if h.dispatcher == nil {
				httpserver.WriteError(w, r, apierr.Internal(errors.New("dispatcher not available")))
				return
			}

			job, err := h.store.GetJob(r.Context(), jobID)
			if errors.Is(err, updates.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("job not found"))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}

			rel, err := h.store.GetRelease(r.Context(), job.ReleaseID)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}

			// Canary: mark applying.
			if err = h.store.UpsertCanaryEntry(r.Context(), jobID, serverID, "applying", ""); err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}

			requestID := httpserver.RequestIDFromRequest(r)
			// ponytail: real implementation fetches checksums.txt from rel.ChecksumURL; add when background worker exists.
			var checksumReq struct {
				ExpectedSHA256 string `json:"expected_sha256"`
			}
			if decErr := json.NewDecoder(r.Body).Decode(&checksumReq); decErr != nil || checksumReq.ExpectedSHA256 == "" {
				_ = h.store.UpsertCanaryEntry(r.Context(), jobID, serverID, "failed", "expected_sha256 is required in request body")
				httpserver.WriteError(w, r, apierr.InvalidRequest("expected_sha256 is required", nil))
				return
			}

			result, err := h.dispatcher.UpdateNodeAgent(r.Context(), serverID, requestID,
				nodewire.UpdateNodeAgentInput{
					ArtifactURL:    rel.ArtifactURL,
					ExpectedSHA256: checksumReq.ExpectedSHA256,
					Version:        rel.Version,
				})
			if err != nil {
				_ = h.store.UpsertCanaryEntry(r.Context(), jobID, serverID, "failed", err.Error())
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}

			_ = h.store.UpsertCanaryEntry(r.Context(), jobID, serverID, "done", "")

			p, _ := auth.PrincipalFrom(r.Context())
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "updates.canary.apply",
				ResourceType: "server", ResourceID: serverID, Result: "ok",
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"result":     result,
				"request_id": requestID,
			})
		})).ServeHTTP(w, r)
}

// ── Module updates ─────────────────────────────────────────────────────────────

// GET /api/v1/updates/modules
func (h *UpdatesHandlers) handleListModules(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "updates.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			modules, err := h.store.ListModules(r.Context())
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"modules":    modules,
				"total":      len(modules),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Fleet Rollout Orchestration (PRD §25.5) ──────────────────────────────────

type fleetRolloutRequest struct {
	ReleaseID string `json:"release_id"`
	BatchSize int    `json:"batch_size"` // default 1
}

// POST /api/v1/updates/fleet/rollout
func (h *UpdatesHandlers) handleFleetRollout(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "updates.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req fleetRolloutRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				httpserver.WriteError(w, r, apierr.InvalidRequest(err.Error(), nil))
				return
			}
			if req.ReleaseID == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("release_id is required", nil))
				return
			}
			if req.BatchSize <= 0 {
				req.BatchSize = 1
			}

			// Validate release exists
			_, err := h.store.GetRelease(r.Context(), req.ReleaseID)
			if err != nil {
				httpserver.WriteError(w, r, apierr.NotFound("release not found"))
				return
			}

			p, _ := auth.PrincipalFrom(r.Context())
			job, err := h.store.CreateJob(r.Context(), req.ReleaseID, p.UserID)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}

			// Find all active servers
			rows, err := h.pool.Query(r.Context(), `
				SELECT id FROM servers WHERE deleted_at IS NULL ORDER BY created_at ASC
			`)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			defer rows.Close()

			var serverIDs []string
			for rows.Next() {
				var sID string
				if err := rows.Scan(&sID); err == nil {
					serverIDs = append(serverIDs, sID)
				}
			}

			// Register canary rollout row for each server
			for _, sID := range serverIDs {
				_, _ = h.pool.Exec(r.Context(), `
					INSERT INTO canary_rollouts (job_id, server_id, state)
					VALUES ($1, $2, 'pending')
					ON CONFLICT (job_id, server_id) DO NOTHING
				`, job.ID, sID)
			}

			h.recordAudit(r, audit.Event{
				Action:       "updates.fleet_rollout",
				ResourceType: "update_job",
				ResourceID:   job.ID,
				Result:       audit.ResultSuccess,
				Context: map[string]any{
					"release_id":  req.ReleaseID,
					"batch_size":  req.BatchSize,
					"total_nodes": len(serverIDs),
				},
			})

			writeJSONResponse(w, http.StatusAccepted, map[string]any{
				"job_id":      job.ID,
				"release_id":  req.ReleaseID,
				"total_nodes": len(serverIDs),
				"batch_size":  req.BatchSize,
				"status":      "in_progress",
				"request_id":  httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}
