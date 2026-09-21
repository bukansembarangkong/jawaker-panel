// Package controller: apps HTTP handlers.
//
// Mounts application management under /api/v1/projects/{project_id}/apps.
// All deployment.* permissions have scope_kind = 'project' (0007_rbac_seed.sql L50-54),
// so every route wraps with rbac.ProjectScope(projectID).
//
// Security invariants enforced here:
//   - Cross-project access returns 404, not 403: GetAppInProject filters by project_id
//     in the WHERE clause, so an id belonging to another project returns ErrNotFound
//     and answers 404 without disclosing whether the id exists elsewhere.
//   - List endpoints filter by project_id server-side in the query (API.md §5).
//   - deployment.create, deployment.rollback, and app deletion require step-up.
//   - Deploy is ASYNCHRONOUS: it creates a deployment in queued state, enqueues
//     an app.deploy job, and returns HTTP 202 with {deployment_id, job: {id, state}}
//     (PRD.md §38.1).
//   - Secret refs: plaintext values are never accepted into or returned from the
//     app_env_vars table.
package controller

import (
	"errors"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/apps"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/jobs"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodes"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AppHandlerOptions configures the apps HTTP surface.
type AppHandlerOptions struct {
	Apps       *apps.Store
	Pool       *pgxpool.Pool
	Secrets    *secret.Store
	Dispatcher *nodes.Dispatcher
	Logger     *slog.Logger
	Audit      audit.Execer
	Now        func() time.Time
}

// AppHandlers holds the application HTTP surface.
type AppHandlers struct {
	apps       *apps.Store
	pool       *pgxpool.Pool
	secrets    *secret.Store
	dispatcher *nodes.Dispatcher
	logger     *slog.Logger
	audit      audit.Execer
	now        func() time.Time
}

// NewAppHandlers builds the application handlers.
func NewAppHandlers(opts AppHandlerOptions) (*AppHandlers, error) {
	if opts.Apps == nil {
		return nil, errors.New("controller: apps store is required")
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
	return &AppHandlers{
		apps:       opts.Apps,
		pool:       opts.Pool,
		secrets:    opts.Secrets,
		dispatcher: opts.Dispatcher,
		logger:     opts.Logger,
		audit:      opts.Audit,
		now:        now,
	}, nil
}

// Routes registers the application endpoints on the mux.
func (h *AppHandlers) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/projects/{project_id}/apps", h.handleListApps)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/apps", h.handleCreateApp)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/apps/{id}", h.handleGetApp)
	mux.HandleFunc("PATCH /api/v1/projects/{project_id}/apps/{id}", h.handleUpdateApp)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/apps/{id}", h.handleDeleteApp)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/apps/{id}/env", h.handleListEnvVars)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/apps/{id}/env", h.handleSetEnvVar)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/apps/{id}/env/{name}", h.handleDeleteEnvVar)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/apps/{id}/deploy", h.handleDeployApp)
}

// --- CRUD -------------------------------------------------------------------

func (h *AppHandlers) handleListApps(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "deployment.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limit, offset, apiErr := parsePagination(r)
			if apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			appList, total, err := h.apps.ListApps(r.Context(), projectID, limit, offset)
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"apps":       appResponses(appList),
				"total":      total,
				"limit":      limit,
				"offset":     offset,
				"has_more":   offset+len(appList) < total,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createAppRequest struct {
	ServerID      string   `json:"server_id"`
	Slug          string   `json:"slug"`
	Name          string   `json:"name"`
	RuntimeType   string   `json:"runtime_type"`
	GitRepoURL    string   `json:"git_repo_url"`
	GitRefDefault string   `json:"git_ref_default,omitempty"`
	BuildProgram  string   `json:"build_program,omitempty"`
	BuildArgs     []string `json:"build_args,omitempty"`
	StartProgram  string   `json:"start_program,omitempty"`
	StartArgs     []string `json:"start_args,omitempty"`
	WorkingDir    string   `json:"working_dir,omitempty"`
	Port          *int     `json:"port,omitempty"`
	HealthPath    *string  `json:"health_path,omitempty"`
	EnvName       string   `json:"env_name,omitempty"`
}

func (h *AppHandlers) handleCreateApp(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "deployment.create", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createAppRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			app, err := h.apps.CreateApp(r.Context(), apps.CreateAppParams{
				ProjectID:     projectID,
				ServerID:      req.ServerID,
				Slug:          req.Slug,
				Name:          req.Name,
				RuntimeType:   req.RuntimeType,
				GitRepoURL:    req.GitRepoURL,
				GitRefDefault: req.GitRefDefault,
				BuildProgram:  req.BuildProgram,
				BuildArgs:     req.BuildArgs,
				StartProgram:  req.StartProgram,
				StartArgs:     req.StartArgs,
				WorkingDir:    req.WorkingDir,
				Port:          req.Port,
				HealthPath:    req.HealthPath,
				EnvName:       req.EnvName,
				CreatedBy:     principalUserID(r),
			})
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "app.create",
				ResourceType: "app",
				ResourceID:   app.ID,
				Result:       audit.ResultSuccess,
				Context: map[string]any{
					"project_id":   app.ProjectID,
					"server_id":    app.ServerID,
					"slug":         app.Slug,
					"runtime_type": app.RuntimeType,
				},
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"app":        appResponse(app),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *AppHandlers) handleGetApp(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "deployment.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			app, err := h.apps.GetAppInProject(r.Context(), projectID, id)
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"app":        appResponse(app),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type updateAppRequest struct {
	Name          *string   `json:"name,omitempty"`
	GitRepoURL    *string   `json:"git_repo_url,omitempty"`
	GitRefDefault *string   `json:"git_ref_default,omitempty"`
	BuildProgram  *string   `json:"build_program,omitempty"`
	BuildArgs     *[]string `json:"build_args,omitempty"`
	StartProgram  *string   `json:"start_program,omitempty"`
	StartArgs     *[]string `json:"start_args,omitempty"`
	WorkingDir    *string   `json:"working_dir,omitempty"`
	Port          *int      `json:"port,omitempty"`
	HealthPath    *string   `json:"health_path,omitempty"`
}

func (h *AppHandlers) handleUpdateApp(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "deployment.create", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := h.apps.GetAppInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			var req updateAppRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			app, err := h.apps.UpdateApp(r.Context(), id, apps.UpdateAppParams{
				Name:          req.Name,
				GitRepoURL:    req.GitRepoURL,
				GitRefDefault: req.GitRefDefault,
				BuildProgram:  req.BuildProgram,
				BuildArgs:     req.BuildArgs,
				StartProgram:  req.StartProgram,
				StartArgs:     req.StartArgs,
				WorkingDir:    req.WorkingDir,
				Port:          req.Port,
				HealthPath:    req.HealthPath,
			})
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "app.update",
				ResourceType: "app",
				ResourceID:   app.ID,
				Result:       audit.ResultSuccess,
				Context:      map[string]any{"project_id": projectID},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"app":        appResponse(app),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *AppHandlers) handleDeleteApp(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "deployment.create", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := h.apps.GetAppInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			app, err := h.apps.RequestDelete(r.Context(), id, apps.DefaultDeleteGrace)
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "app.delete",
				ResourceType: "app",
				ResourceID:   id,
				Result:       audit.ResultSuccess,
				Context: map[string]any{
					"project_id":   projectID,
					"delete_after": app.DeleteAfter,
				},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"status":       "pending_delete",
				"app_id":       id,
				"delete_after": app.DeleteAfter,
				"request_id":   httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// --- Environment Variables ---------------------------------------------------

func (h *AppHandlers) handleListEnvVars(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "deployment.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := h.apps.GetAppInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			envList, err := h.apps.ListEnvVars(r.Context(), id)
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			out := make([]map[string]any, 0, len(envList))
			for _, ev := range envList {
				entry := map[string]any{
					"id":           ev.ID,
					"name":         ev.Name,
					"value_source": ev.ValueSource,
					"created_at":   ev.CreatedAt,
					"updated_at":   ev.UpdatedAt,
				}
				if ev.ValueSource == apps.ValueLiteral && ev.LiteralValue != nil {
					entry["value"] = *ev.LiteralValue
				} else {
					// Never return secret values or refs verbatim to clients (Gate 3).
					entry["secret_ref"] = ev.SecretRef
				}
				out = append(out, entry)
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"env_vars":   out,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type setEnvVarRequest struct {
	Name        string `json:"name"`
	ValueSource string `json:"value_source"` // "literal" or "secret_ref"
	Value       string `json:"value"`
}

func (h *AppHandlers) handleSetEnvVar(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "deployment.create", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := h.apps.GetAppInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			var req setEnvVarRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			ev, err := h.apps.SetEnvVar(r.Context(), id, req.Name, req.ValueSource, req.Value)
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "app.env.set",
				ResourceType: "app",
				ResourceID:   id,
				Result:       audit.ResultSuccess,
				Context: map[string]any{
					"name":         ev.Name,
					"value_source": ev.ValueSource,
				},
			})
			resp := map[string]any{
				"id":           ev.ID,
				"name":         ev.Name,
				"value_source": ev.ValueSource,
				"updated_at":   ev.UpdatedAt,
			}
			if ev.ValueSource == apps.ValueLiteral && ev.LiteralValue != nil {
				resp["value"] = *ev.LiteralValue
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"env_var":    resp,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *AppHandlers) handleDeleteEnvVar(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	name := r.PathValue("name")
	authsession.RequirePermission(h.now, "deployment.create", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := h.apps.GetAppInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			if err := h.apps.DeleteEnvVar(r.Context(), id, name); err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "app.env.delete",
				ResourceType: "app",
				ResourceID:   id,
				Result:       audit.ResultSuccess,
				Context:      map[string]any{"name": name},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"deleted":    true,
				"name":       name,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// --- Deployment Trigger ------------------------------------------------------

type deployAppRequest struct {
	GitRef         string  `json:"git_ref,omitempty"`
	CommitSHA      *string `json:"commit_sha,omitempty"`
	IdempotencyKey *string `json:"idempotency_key,omitempty"`
}

// handleDeployApp triggers a manual deployment for an application.
//
// Asynchronous pipeline: creates a deployment record in 'queued' state, enqueues
// an app.deploy job, and returns 202 Accepted with {deployment_id, job: {id, state}}.
// Gate 4: concurrent active deploys for the same app return 409 Conflict.
func (h *AppHandlers) handleDeployApp(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "deployment.create", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			app, err := h.apps.GetAppInProject(r.Context(), projectID, id)
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			if !app.Usable() {
				httpserver.WriteError(w, r, apierr.Conflict("Application is not active and cannot accept deployments.", map[string]any{
					"app_id": app.ID,
					"state":  app.State,
				}))
				return
			}

			var req deployAppRequest
			if r.ContentLength > 0 {
				if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
					httpserver.WriteError(w, r, apiErr)
					return
				}
			}

			gitRef := req.GitRef
			if strings.TrimSpace(gitRef) == "" {
				gitRef = app.GitRefDefault
			}
			if strings.TrimSpace(gitRef) == "" {
				gitRef = "main"
			}

			// commit_sha is REQUIRED: the node executor fetches the exact
			// commit (git fetch origin <sha>), and the spec requires
			// exact-commit redeploy. A ref-only deploy would need a
			// resolution step that does not exist yet — refuse honestly
			// rather than send a placeholder SHA that cannot fetch.
			commitSHA := ""
			if req.CommitSHA != nil {
				commitSHA = strings.TrimSpace(*req.CommitSHA)
			}
			if !commitSHAPattern.MatchString(commitSHA) {
				httpserver.WriteError(w, r, apierr.InvalidRequest(
					"commit_sha is required and must be 7..40 lowercase hex characters.",
					map[string]any{"field": "commit_sha"}))
				return
			}

			reqID := httpserver.RequestIDFromRequest(r)

			// Step 1: Create deployment record in queued state.
			// Fails with ErrConflictActive if another deploy is already active.
			dep, depErr := h.apps.CreateDeployment(r.Context(), apps.CreateDeploymentParams{
				AppID:          app.ID,
				ProjectID:      app.ProjectID,
				ServerID:       app.ServerID,
				Trigger:        apps.TriggerManual,
				CommitSHA:      &commitSHA,
				GitRef:         gitRef,
				RequestedBy:    principalUserID(r),
				IdempotencyKey: req.IdempotencyKey,
			})
			if depErr != nil {
				httpserver.WriteError(w, r, appErr(depErr))
				return
			}

			// Step 2: Enqueue the app.deploy job.
			job, jobErr := jobs.Enqueue(r.Context(), h.pool, jobs.Requested{
				Type:             JobTypeAppDeploy,
				ServerID:         app.ServerID,
				ProjectID:        app.ProjectID,
				IdempotencyKey:   dep.ID,
				IdempotencyScope: "app.deploy:" + app.ID,
				RequestedByType:  "user",
				RequestedByID:    principalUserID(r),
				RequestID:        reqID,
				Payload: map[string]any{
					"app_id":        app.ID,
					"deployment_id": dep.ID,
					"git_ref":       gitRef,
					"commit_sha":    commitSHA,
				},
				Steps: []jobs.StepPlan{
					{Name: "fetch"},
					{Name: "build"},
					{Name: "activate"},
					{Name: "health"},
				},
				LockKeys: []string{"app:" + app.ID},
			})
			if jobErr != nil {
				// Job enqueue failed: mark deployment failed so it does not block future deploys.
				_, _ = h.apps.UpdateDeploymentState(r.Context(), dep.ID, apps.UpdateDeploymentStateParams{
					State:        apps.DeployFailed,
					ErrorCode:    "job_enqueue_failed",
					ErrorSummary: jobErr.Error(),
				})
				httpserver.WriteError(w, r, apierr.Internal(jobErr))
				return
			}

			// Attach job_id to the deployment record.
			_, _ = h.apps.UpdateDeploymentState(r.Context(), dep.ID, apps.UpdateDeploymentStateParams{
				State: apps.DeployQueued,
				JobID: &job.ID,
			})

			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "deployment.create",
				ResourceType: "app",
				ResourceID:   app.ID,
				Result:       audit.ResultSuccess,
				Context: map[string]any{
					"deployment_id": dep.ID,
					"job_id":        job.ID,
					"git_ref":       gitRef,
				},
			})

			writeJSONResponse(w, http.StatusAccepted, map[string]any{
				"deployment_id": dep.ID,
				"job": map[string]any{
					"id":    job.ID,
					"state": job.State,
				},
				"request_id": reqID,
			})
		})).ServeHTTP(w, r)
}

// JobTypeAppDeploy is the job type enqueued when an application is deployed.
const JobTypeAppDeploy = "app.deploy"

// commitSHAPattern mirrors nodewire's commitSHARegex: 7..40 lowercase hex. It
// is spelled here rather than exported from nodewire because the controller
// validates at its own boundary before enqueueing, and the node re-validates on
// receipt. A ref (e.g. "main") is NOT accepted: the node fetches by exact SHA.
var commitSHAPattern = regexp.MustCompile(`^[0-9a-f]{7,40}$`)

// --- Helpers ----------------------------------------------------------------

func (h *AppHandlers) recordAudit(r *http.Request, event audit.Event) {
	if h.audit == nil {
		return
	}
	event.RequestID = httpserver.RequestIDFromRequest(r)
	event.SourceIP = r.RemoteAddr
	event.UserAgent = r.UserAgent()
	if err := audit.Record(r.Context(), h.audit, event); err != nil {
		h.logger.ErrorContext(r.Context(), "audit write failed",
			"error", err, "action", event.Action, "request_id", event.RequestID)
	}
}

func appErr(err error) *apierr.Error {
	switch {
	case errors.Is(err, apps.ErrNotFound):
		return apierr.NotFound("Application not found.")
	case errors.Is(err, apps.ErrSlugTaken):
		return apierr.Conflict("An application with this slug already exists in this project.", nil)
	case errors.Is(err, apps.ErrConflictActive):
		return apierr.Conflict("A deployment is already queued or running for this application.", nil)
	case errors.Is(err, apps.ErrInvalid):
		return apierr.InvalidRequest(err.Error(), nil)
	case errors.Is(err, apps.ErrState):
		return apierr.Conflict(err.Error(), nil)
	default:
		return apierr.Internal(err)
	}
}

func appResponse(a apps.App) map[string]any {
	return map[string]any{
		"id":              a.ID,
		"project_id":      a.ProjectID,
		"server_id":       a.ServerID,
		"slug":            a.Slug,
		"name":            a.Name,
		"runtime_type":    a.RuntimeType,
		"state":           a.State,
		"git_repo_url":    a.GitRepoURL,
		"git_ref_default": a.GitRefDefault,
		"build_program":   a.BuildProgram,
		"build_args":      a.BuildArgs,
		"start_program":   a.StartProgram,
		"start_args":      a.StartArgs,
		"working_dir":     a.WorkingDir,
		"port":            a.Port,
		"health_path":     a.HealthPath,
		"env_name":        a.EnvName,
		"created_at":      a.CreatedAt,
		"updated_at":      a.UpdatedAt,
		"delete_after":    a.DeleteAfter,
	}
}

func appResponses(list []apps.App) []map[string]any {
	out := make([]map[string]any, len(list))
	for i, a := range list {
		out[i] = appResponse(a)
	}
	return out
}
