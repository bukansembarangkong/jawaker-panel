package controller

// backups.go — Phase 6 backup plan HTTP surface.
//
// Routes:
//   GET    /api/v1/projects/{project_id}/backup-plans
//   POST   /api/v1/projects/{project_id}/backup-plans
//   GET    /api/v1/projects/{project_id}/backup-plans/{id}
//   PATCH  /api/v1/projects/{project_id}/backup-plans/{id}
//   DELETE /api/v1/projects/{project_id}/backup-plans/{id}
//   POST   /api/v1/projects/{project_id}/backup-plans/{id}/run
//   GET    /api/v1/projects/{project_id}/backup-runs
//   GET    /api/v1/projects/{project_id}/backup-runs/{run_id}
//   POST   /api/v1/projects/{project_id}/backup-runs/{run_id}/verify
//   POST   /api/v1/projects/{project_id}/backup-runs/{run_id}/restore
//   DELETE /api/v1/projects/{project_id}/backup-runs/{run_id}
//   POST   /api/v1/projects/{project_id}/backup-runs/{run_id}/links
//   GET    /api/v1/backup-links/{token}   (public, no session)

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/backups"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/jobs"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Job types for backup async operations (PR-E will implement the workers).
const (
	JobTypeBackupRun     = "backup.run"
	JobTypeBackupVerify  = "backup.verify"
	JobTypeBackupRestore = "backup.restore"
	JobTypeBackupDelete  = "backup.delete"
)

// DefaultLinkTTL is the default time-to-live for expiring download links.
const DefaultLinkTTL = 4 * time.Hour

// BackupHandlerOptions configures the backup HTTP surface.
type BackupHandlerOptions struct {
	Backups *backups.Store
	Pool    *pgxpool.Pool
	Logger  *slog.Logger
	Audit   audit.Execer
	Now     func() time.Time
}

// BackupHandlers holds the backup HTTP handlers.
type BackupHandlers struct {
	store  *backups.Store
	pool   *pgxpool.Pool
	logger *slog.Logger
	audit  audit.Execer
	now    func() time.Time
}

// NewBackupHandlers builds the backup handlers.
func NewBackupHandlers(opts BackupHandlerOptions) (*BackupHandlers, error) {
	if opts.Backups == nil {
		return nil, errors.New("controller: backups store is required")
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
	return &BackupHandlers{
		store:  opts.Backups,
		pool:   opts.Pool,
		logger: opts.Logger,
		audit:  opts.Audit,
		now:    now,
	}, nil
}

// Routes registers the backup endpoints on the mux.
func (h *BackupHandlers) Routes(mux *http.ServeMux) {
	// Plan CRUD.
	mux.HandleFunc("GET /api/v1/projects/{project_id}/backup-plans", h.handleListPlans)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/backup-plans", h.handleCreatePlan)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/backup-plans/{id}", h.handleGetPlan)
	mux.HandleFunc("PATCH /api/v1/projects/{project_id}/backup-plans/{id}", h.handleUpdatePlan)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/backup-plans/{id}", h.handleDeletePlan)
	// Trigger a manual run.
	mux.HandleFunc("POST /api/v1/projects/{project_id}/backup-plans/{id}/run", h.handleTriggerRun)
	// Run collection + detail.
	mux.HandleFunc("GET /api/v1/projects/{project_id}/backup-runs", h.handleListRuns)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/backup-runs/{run_id}", h.handleGetRun)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/backup-runs/{run_id}/verify", h.handleVerifyRun)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/backup-runs/{run_id}/restore", h.handleRestoreRun)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/backup-runs/{run_id}", h.handleDeleteRun)
	// Expiring download links (authenticated creation, public redemption).
	mux.HandleFunc("POST /api/v1/projects/{project_id}/backup-runs/{run_id}/links", h.handleCreateLink)
	// Public download link — session-free; token is the credential.
	mux.HandleFunc("GET /api/v1/backup-links/{token}", h.handleRedeemLink)
}

// --- Plan CRUD ---------------------------------------------------------------

func (h *BackupHandlers) handleListPlans(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "backup.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limit := parseIntQuery(r, "limit", 50)
			offset := parseIntQuery(r, "offset", 0)
			list, err := h.store.ListPlans(r.Context(), projectID, limit, offset)
			if err != nil {
				httpserver.WriteError(w, r, backupErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"plans":      planResponses(list),
				"total":      len(list),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createPlanRequest struct {
	ServerID           string         `json:"server_id"`
	Name               string         `json:"name"`
	Slug               string         `json:"slug"`
	ScopeType          string         `json:"scope_type"`
	ScopeID            string         `json:"scope_id,omitempty"`
	DestinationType    string         `json:"destination_type"`
	DestinationConfig  map[string]any `json:"destination_config,omitempty"`
	DestinationConfRef string         `json:"destination_config_ref,omitempty"`
	EncryptionKeyRef   string         `json:"encryption_key_ref,omitempty"`
	ScheduleCron       string         `json:"schedule_cron,omitempty"`
	RetentionCount     int            `json:"retention_count,omitempty"`
	RetentionDays      int            `json:"retention_days,omitempty"`
}

func (h *BackupHandlers) handleCreatePlan(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "backup.create", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createPlanRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			plan, err := h.store.CreatePlan(r.Context(), backups.CreatePlanParams{
				ProjectID:          projectID,
				ServerID:           req.ServerID,
				Name:               req.Name,
				Slug:               req.Slug,
				ScopeType:          req.ScopeType,
				ScopeID:            req.ScopeID,
				DestinationType:    req.DestinationType,
				DestinationConfig:  req.DestinationConfig,
				DestinationConfRef: req.DestinationConfRef,
				EncryptionKeyRef:   req.EncryptionKeyRef,
				ScheduleCron:       req.ScheduleCron,
				RetentionCount:     req.RetentionCount,
				RetentionDays:      req.RetentionDays,
				CreatedBy:          principalUserID(r),
			})
			if err != nil {
				httpserver.WriteError(w, r, backupErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "backup.plan.create",
				ResourceType: "backup_plan",
				ResourceID:   plan.ID,
				Result:       audit.ResultSuccess,
				Context:      map[string]any{"project_id": projectID, "slug": plan.Slug},
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"plan":       planResponse(plan),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *BackupHandlers) handleGetPlan(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "backup.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			plan, err := h.store.GetPlanInProject(r.Context(), projectID, id)
			if err != nil {
				httpserver.WriteError(w, r, backupErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"plan":       planResponse(plan),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type updatePlanRequest struct {
	Name           *string `json:"name,omitempty"`
	ScheduleCron   *string `json:"schedule_cron,omitempty"`
	Enabled        *bool   `json:"enabled,omitempty"`
	RetentionCount *int    `json:"retention_count,omitempty"`
	RetentionDays  *int    `json:"retention_days,omitempty"`
	State          *string `json:"state,omitempty"`
}

func (h *BackupHandlers) handleUpdatePlan(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "backup.create", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req updatePlanRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			plan, err := h.store.UpdatePlan(r.Context(), projectID, id, backups.UpdatePlanParams{
				Name:           req.Name,
				ScheduleCron:   req.ScheduleCron,
				Enabled:        req.Enabled,
				RetentionCount: req.RetentionCount,
				RetentionDays:  req.RetentionDays,
				State:          req.State,
			})
			if err != nil {
				httpserver.WriteError(w, r, backupErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "backup.plan.update",
				ResourceType: "backup_plan",
				ResourceID:   id,
				Result:       audit.ResultSuccess,
				Context:      map[string]any{"project_id": projectID},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"plan":       planResponse(plan),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *BackupHandlers) handleDeletePlan(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	// Step-up: backup.delete is a destructive operation per RBAC seed.
	authsession.RequirePermission(h.now, "backup.delete", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			plan, err := h.store.MarkPendingDelete(r.Context(), projectID, id, backups.DefaultDeleteGrace)
			if err != nil {
				httpserver.WriteError(w, r, backupErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "backup.plan.delete",
				ResourceType: "backup_plan",
				ResourceID:   id,
				Result:       audit.ResultSuccess,
				Context:      map[string]any{"project_id": projectID, "delete_after": plan.DeleteAfter},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"status":       "pending_delete",
				"plan_id":      id,
				"delete_after": plan.DeleteAfter,
				"request_id":   httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// --- Manual run trigger ------------------------------------------------------

func (h *BackupHandlers) handleTriggerRun(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "backup.create", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			plan, err := h.store.GetPlanInProject(r.Context(), projectID, id)
			if err != nil {
				httpserver.WriteError(w, r, backupErr(err))
				return
			}
			if !plan.Live() || plan.State == backups.StatePendingDelete {
				httpserver.WriteError(w, r, apierr.Conflict("Backup plan is not active.", map[string]any{"state": plan.State}))
				return
			}
			userID := principalUserID(r)
			run, rErr := h.store.CreateRun(r.Context(), backups.CreateRunParams{
				PlanID:          plan.ID,
				ProjectID:       projectID,
				ServerID:        plan.ServerID,
				Trigger:         backups.TriggerManual,
				RequestedByType: "user",
				RequestedByID:   userID,
			})
			if rErr != nil {
				httpserver.WriteError(w, r, backupErr(rErr))
				return
			}

			reqID := httpserver.RequestIDFromRequest(r)
			job, jErr := jobs.Enqueue(r.Context(), h.pool, jobs.Requested{
				Type:             JobTypeBackupRun,
				ServerID:         plan.ServerID,
				ProjectID:        projectID,
				IdempotencyKey:   run.ID,
				IdempotencyScope: "backup.run:" + plan.ID,
				RequestedByType:  "user",
				RequestedByID:    userID,
				RequestID:        reqID,
				Payload: map[string]any{
					"plan_id": plan.ID,
					"run_id":  run.ID,
				},
				Steps:    []jobs.StepPlan{{Name: "archive"}, {Name: "upload"}, {Name: "checksum"}, {Name: "notify"}},
				LockKeys: []string{"backup_plan:" + plan.ID},
			})
			if jErr != nil {
				_ = h.store.MarkRunFailed(r.Context(), run.ID, "failed to enqueue backup job: "+jErr.Error())
				httpserver.WriteError(w, r, apierr.Internal(jErr))
				return
			}
			_ = h.store.SetRunJob(r.Context(), run.ID, job.ID)

			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      userID,
				Action:       "backup.run.trigger",
				ResourceType: "backup_run",
				ResourceID:   run.ID,
				Result:       audit.ResultSuccess,
				Context:      map[string]any{"project_id": projectID, "plan_id": plan.ID, "trigger": "manual"},
			})
			writeJSONResponse(w, http.StatusAccepted, map[string]any{
				"run_id":     run.ID,
				"job_id":     job.ID,
				"status":     "queued",
				"request_id": reqID,
			})
		})).ServeHTTP(w, r)
}

// --- Run collection + detail -------------------------------------------------

func (h *BackupHandlers) handleListRuns(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "backup.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			planID := r.URL.Query().Get("plan_id")
			limit := parseIntQuery(r, "limit", 50)
			offset := parseIntQuery(r, "offset", 0)
			list, err := h.store.ListRuns(r.Context(), projectID, planID, limit, offset)
			if err != nil {
				httpserver.WriteError(w, r, backupErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"runs":       runResponses(list),
				"total":      len(list),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *BackupHandlers) handleGetRun(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	runID := r.PathValue("run_id")
	authsession.RequirePermission(h.now, "backup.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			run, err := h.store.GetRun(r.Context(), projectID, runID)
			if err != nil {
				httpserver.WriteError(w, r, backupErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"run":        runResponse(run),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *BackupHandlers) handleVerifyRun(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	runID := r.PathValue("run_id")
	authsession.RequirePermission(h.now, "backup.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			run, err := h.store.GetRun(r.Context(), projectID, runID)
			if err != nil {
				httpserver.WriteError(w, r, backupErr(err))
				return
			}
			if run.State != backups.RunCompleted {
				httpserver.WriteError(w, r, apierr.Conflict("Only a completed run can be verified.", map[string]any{"state": run.State}))
				return
			}
			reqID := httpserver.RequestIDFromRequest(r)
			job, jErr := jobs.Enqueue(r.Context(), h.pool, jobs.Requested{
				Type:             JobTypeBackupVerify,
				ServerID:         run.ServerID,
				ProjectID:        projectID,
				IdempotencyKey:   "verify:" + run.ID,
				IdempotencyScope: "backup.verify:" + run.ID,
				RequestedByType:  "user",
				RequestedByID:    principalUserID(r),
				RequestID:        reqID,
				Payload:          map[string]any{"run_id": run.ID},
				Steps:            []jobs.StepPlan{{Name: "checksum"}},
				LockKeys:         []string{"backup_run:" + run.ID},
			})
			if jErr != nil {
				httpserver.WriteError(w, r, apierr.Internal(jErr))
				return
			}
			writeJSONResponse(w, http.StatusAccepted, map[string]any{
				"run_id":     run.ID,
				"job_id":     job.ID,
				"status":     "queued",
				"request_id": reqID,
			})
		})).ServeHTTP(w, r)
}

func (h *BackupHandlers) handleRestoreRun(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	runID := r.PathValue("run_id")
	// Step-up: backup.restore is a destructive operation per RBAC seed.
	authsession.RequirePermission(h.now, "backup.restore", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			run, err := h.store.GetRun(r.Context(), projectID, runID)
			if err != nil {
				httpserver.WriteError(w, r, backupErr(err))
				return
			}
			if run.State != backups.RunCompleted {
				httpserver.WriteError(w, r, apierr.Conflict("Only a completed run can be restored.", map[string]any{"state": run.State}))
				return
			}
			userID := principalUserID(r)
			reqID := httpserver.RequestIDFromRequest(r)
			sum := sha256.Sum256([]byte(run.ID))
			job, jErr := jobs.Enqueue(r.Context(), h.pool, jobs.Requested{
				Type:             JobTypeBackupRestore,
				ServerID:         run.ServerID,
				ProjectID:        projectID,
				IdempotencyKey:   "restore:" + hex.EncodeToString(sum[:8]),
				IdempotencyScope: "backup.restore:" + run.ID,
				RequestedByType:  "user",
				RequestedByID:    userID,
				RequestID:        reqID,
				Payload:          map[string]any{"run_id": run.ID},
				Steps:            []jobs.StepPlan{{Name: "restore"}, {Name: "verify"}},
				LockKeys:         []string{"backup_run:" + run.ID},
			})
			if jErr != nil {
				httpserver.WriteError(w, r, apierr.Internal(jErr))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      userID,
				Action:       "backup.run.restore",
				ResourceType: "backup_run",
				ResourceID:   runID,
				Result:       audit.ResultSuccess,
				Context:      map[string]any{"project_id": projectID},
			})
			writeJSONResponse(w, http.StatusAccepted, map[string]any{
				"run_id":     runID,
				"job_id":     job.ID,
				"status":     "queued",
				"request_id": reqID,
			})
		})).ServeHTTP(w, r)
}

func (h *BackupHandlers) handleDeleteRun(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	runID := r.PathValue("run_id")
	authsession.RequirePermission(h.now, "backup.delete", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			run, err := h.store.GetRun(r.Context(), projectID, runID)
			if err != nil {
				httpserver.WriteError(w, r, backupErr(err))
				return
			}
			reqID := httpserver.RequestIDFromRequest(r)
			job, jErr := jobs.Enqueue(r.Context(), h.pool, jobs.Requested{
				Type:             JobTypeBackupDelete,
				ServerID:         run.ServerID,
				ProjectID:        projectID,
				IdempotencyKey:   "delete-run:" + run.ID,
				IdempotencyScope: "backup.delete:" + run.ID,
				RequestedByType:  "user",
				RequestedByID:    principalUserID(r),
				RequestID:        reqID,
				Payload:          map[string]any{"run_id": run.ID},
				Steps:            []jobs.StepPlan{{Name: "delete_artifact"}},
				LockKeys:         []string{"backup_run:" + run.ID},
			})
			if jErr != nil {
				httpserver.WriteError(w, r, apierr.Internal(jErr))
				return
			}
			writeJSONResponse(w, http.StatusAccepted, map[string]any{
				"run_id":     runID,
				"job_id":     job.ID,
				"status":     "queued",
				"request_id": reqID,
			})
		})).ServeHTTP(w, r)
}

// --- Expiring download links -------------------------------------------------

type createLinkRequest struct {
	TTLSeconds int  `json:"ttl_seconds,omitempty"`
	SingleUse  bool `json:"single_use,omitempty"`
}

func (h *BackupHandlers) handleCreateLink(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	runID := r.PathValue("run_id")
	authsession.RequirePermission(h.now, "backup.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			run, err := h.store.GetRun(r.Context(), projectID, runID)
			if err != nil {
				httpserver.WriteError(w, r, backupErr(err))
				return
			}
			if run.State != backups.RunCompleted {
				httpserver.WriteError(w, r, apierr.Conflict("Only a completed run can have a download link.", map[string]any{"state": run.State}))
				return
			}

			var req createLinkRequest
			if r.ContentLength > 0 {
				if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
					httpserver.WriteError(w, r, apiErr)
					return
				}
			}
			ttl := time.Duration(req.TTLSeconds) * time.Second
			if ttl <= 0 || ttl > 24*time.Hour {
				ttl = DefaultLinkTTL
			}

			// Generate a 32-byte random token; the plaintext is returned ONCE,
			// and only the SHA-256 hash is stored.
			raw := make([]byte, 32)
			if _, rErr := rand.Read(raw); rErr != nil {
				httpserver.WriteError(w, r, apierr.Internal(rErr))
				return
			}
			plainToken := base64.RawURLEncoding.EncodeToString(raw)
			sum := sha256.Sum256([]byte(plainToken))
			tokenHash := hex.EncodeToString(sum[:])

			link, lErr := h.store.CreateExpiringLink(r.Context(), backups.CreateExpiringLinkParams{
				RunID:     runID,
				ProjectID: projectID,
				TokenHash: tokenHash,
				TTL:       ttl,
				SingleUse: req.SingleUse,
				CreatedBy: principalUserID(r),
			})
			if lErr != nil {
				httpserver.WriteError(w, r, backupErr(lErr))
				return
			}
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				// Plaintext token returned once; the hash is what's stored.
				"token":      plainToken,
				"link_id":    link.ID,
				"expires_at": link.ExpiresAt,
				"single_use": link.SingleUse,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *BackupHandlers) handleRedeemLink(w http.ResponseWriter, r *http.Request) {
	// Public route: the token IS the credential. No session check.
	rawToken := r.PathValue("token")
	if rawToken == "" {
		httpserver.WriteError(w, r, apierr.NotFound("The requested backup link does not exist or has expired."))
		return
	}
	sum := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(sum[:])

	runID, err := h.store.RedeemExpiringLink(r.Context(), tokenHash)
	if err != nil {
		// ErrLinkExpired and ErrNotFound both return 404 — no oracle.
		httpserver.WriteError(w, r, apierr.NotFound("The requested backup link does not exist or has expired."))
		return
	}
	// The run archive_path is the location of the artifact on the node's disk.
	// In a real implementation the handler would stream the file from the target
	// storage adapter; for the baseline (Phase 6) we return the run metadata so
	// the caller knows which archive to fetch.
	// ponytail: streaming download from target, add when BackupTarget.Get() is wired.
	writeJSONResponse(w, http.StatusOK, map[string]any{
		"run_id":  runID,
		"message": "link redeemed; fetch archive via node target",
	})
}

// --- helpers -----------------------------------------------------------------

func backupErr(err error) *apierr.Error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, backups.ErrNotFound):
		return apierr.NotFound("The requested backup resource does not exist.")
	case errors.Is(err, backups.ErrSlugTaken):
		return apierr.Conflict("A backup plan with that slug already exists in this project.", map[string]any{"field": "slug"})
	case errors.Is(err, backups.ErrConflictActive):
		return apierr.Conflict("A backup run is already queued or running for this plan.", nil)
	case errors.Is(err, backups.ErrLinkExpired):
		return apierr.NotFound("The requested backup link does not exist or has expired.")
	case errors.Is(err, backups.ErrInvalid):
		return apierr.InvalidRequest(err.Error(), nil)
	case errors.Is(err, backups.ErrState):
		return apierr.InvalidRequest("The request is not valid for the current lifecycle state.", nil)
	default:
		return apierr.Internal(err)
	}
}

func (h *BackupHandlers) recordAudit(r *http.Request, ev audit.Event) {
	if h.audit == nil {
		return
	}
	_ = audit.Record(r.Context(), h.audit, ev)
}

func parseIntQuery(r *http.Request, key string, def int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return def
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return def
	}
	return v
}

// --- response shapes ---------------------------------------------------------

func planResponse(p backups.Plan) map[string]any {
	out := map[string]any{
		"id":               p.ID,
		"project_id":       p.ProjectID,
		"server_id":        p.ServerID,
		"name":             p.Name,
		"slug":             p.Slug,
		"scope_type":       p.ScopeType,
		"destination_type": p.DestinationType,
		"schedule_cron":    p.ScheduleCron,
		"enabled":          p.Enabled,
		"retention_count":  p.RetentionCount,
		"retention_days":   p.RetentionDays,
		"state":            p.State,
		"created_at":       p.CreatedAt,
		"updated_at":       p.UpdatedAt,
	}
	if p.ScopeID != nil {
		out["scope_id"] = *p.ScopeID
	}
	if p.NextRunAt != nil {
		out["next_run_at"] = *p.NextRunAt
	}
	if p.DeleteAfter != nil {
		out["delete_after"] = *p.DeleteAfter
	}
	return out
}

func planResponses(list []backups.Plan) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, p := range list {
		out = append(out, planResponse(p))
	}
	return out
}

func runResponse(run backups.Run) map[string]any {
	out := map[string]any{
		"id":           run.ID,
		"project_id":   run.ProjectID,
		"server_id":    run.ServerID,
		"trigger":      run.Trigger,
		"state":        run.State,
		"archive_path": run.ArchivePath,
		"archive_size": run.ArchiveSize,
		"sha256":       run.SHA256,
		"verification": run.Verification,
		"created_at":   run.CreatedAt,
	}
	if run.PlanID != nil {
		out["plan_id"] = *run.PlanID
	}
	if run.JobID != nil {
		out["job_id"] = *run.JobID
	}
	if run.StartedAt != nil {
		out["started_at"] = *run.StartedAt
	}
	if run.CompletedAt != nil {
		out["completed_at"] = *run.CompletedAt
	}
	if run.FailedReason != "" {
		out["failed_reason"] = run.FailedReason
	}
	return out
}

func runResponses(list []backups.Run) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, r := range list {
		out = append(out, runResponse(r))
	}
	return out
}
