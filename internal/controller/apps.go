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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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
	mux.HandleFunc("GET /api/v1/projects/{project_id}/apps/{id}/deployments", h.handleListDeployments)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/apps/{id}/deployments/{dep_id}", h.handleGetDeployment)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/apps/{id}/deployments/{dep_id}/redeploy", h.handleRedeploy)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/apps/{id}/releases", h.handleListReleases)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/apps/{id}/rollback", h.handleRollback)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/apps/{id}/webhook-tokens", h.handleCreateWebhookToken)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/apps/{id}/webhook-tokens", h.handleListWebhookTokens)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/apps/{id}/webhook-tokens/{token_id}", h.handleRevokeWebhookToken)
	mux.HandleFunc("POST /api/v1/webhooks/git/{token}", h.handleGitWebhook)
	// Preview Environments (PRD §11.6)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/apps/{id}/previews", h.handleListPreviews)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/apps/{id}/previews", h.handleCreatePreview)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/apps/{id}/previews/{preview_id}", h.handleDeletePreview)
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

// startDeployment enqueues an asynchronous app.deploy job and writes a 202 response.
// Shared by handleDeployApp, handleRollback, and handleRedeploy.
func (h *AppHandlers) startDeployment(
	w http.ResponseWriter,
	r *http.Request,
	app apps.App,
	trigger, gitRef, commitSHA string,
	idempotencyKey *string,
) {
	reqID := httpserver.RequestIDFromRequest(r)

	// Step 1: Create deployment record in queued state.
	// Fails with ErrConflictActive if another deploy is already active.
	dep, depErr := h.apps.CreateDeployment(r.Context(), apps.CreateDeploymentParams{
		AppID:          app.ID,
		ProjectID:      app.ProjectID,
		ServerID:       app.ServerID,
		Trigger:        trigger,
		CommitSHA:      &commitSHA,
		GitRef:         gitRef,
		RequestedBy:    principalUserID(r),
		IdempotencyKey: idempotencyKey,
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
		Action:       "deployment." + trigger,
		ResourceType: "app",
		ResourceID:   app.ID,
		Result:       audit.ResultSuccess,
		Context: map[string]any{
			"deployment_id": dep.ID,
			"job_id":        job.ID,
			"git_ref":       gitRef,
			"commit_sha":    commitSHA,
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
}

// handleDeployApp triggers a manual deployment for an application.
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

			h.startDeployment(w, r, app, apps.TriggerManual, gitRef, commitSHA, req.IdempotencyKey)
		})).ServeHTTP(w, r)
}

// handleListDeployments returns a pageable list of deployment attempts for an app.
func (h *AppHandlers) handleListDeployments(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "deployment.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := h.apps.GetAppInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			limit, offset, apiErr := parsePagination(r)
			if apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			depList, total, err := h.apps.ListDeployments(r.Context(), id, limit, offset)
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"deployments": deploymentResponses(depList),
				"total":       total,
				"limit":       limit,
				"offset":      offset,
				"has_more":    offset+len(depList) < total,
				"request_id":  httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// handleGetDeployment returns a single deployment attempt record.
func (h *AppHandlers) handleGetDeployment(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	depID := r.PathValue("dep_id")
	authsession.RequirePermission(h.now, "deployment.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := h.apps.GetAppInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			dep, err := h.apps.GetDeploymentInApp(r.Context(), id, depID)
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"deployment": deploymentResponse(dep),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// handleListReleases returns historical releases for an app.
func (h *AppHandlers) handleListReleases(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "deployment.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := h.apps.GetAppInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			releases, err := h.apps.ListReleases(r.Context(), id, 20)
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			out := make([]map[string]any, 0, len(releases))
			for _, rel := range releases {
				out = append(out, map[string]any{
					"id":            rel.ID,
					"app_id":        rel.AppID,
					"deployment_id": rel.DeploymentID,
					"release_path":  rel.ReleasePath,
					"commit_sha":    rel.CommitSHA,
					"is_current":    rel.IsCurrent,
					"health_state":  rel.HealthState,
					"created_at":    rel.CreatedAt,
				})
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"releases":   out,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// handleRollback initiates a rollback deployment to the previously active release.
// Gate: finds the most recent release where is_current = false and enqueues an
// app.deploy job using that exact commit SHA.
func (h *AppHandlers) handleRollback(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "deployment.rollback", rbac.ProjectScope(projectID), true,
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

			// Find previous releases. The list is sorted newest first.
			releases, err := h.apps.ListReleases(r.Context(), id, 5)
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}

			// Find the first release that is NOT current.
			var targetRelease *apps.Release
			for _, rel := range releases {
				if !rel.IsCurrent {
					prev := rel
					targetRelease = &prev
					break
				}
			}
			if targetRelease == nil {
				httpserver.WriteError(w, r, apierr.Conflict(
					"No previous release available to roll back to.",
					map[string]any{"app_id": app.ID}))
				return
			}

			gitRef := app.GitRefDefault
			if strings.TrimSpace(gitRef) == "" {
				gitRef = "main"
			}

			h.startDeployment(w, r, app, apps.TriggerRollback, gitRef, targetRelease.CommitSHA, nil)
		})).ServeHTTP(w, r)
}

// handleRedeploy triggers an exact-commit redeployment from a past deployment record.
func (h *AppHandlers) handleRedeploy(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	depID := r.PathValue("dep_id")
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

			dep, err := h.apps.GetDeploymentInApp(r.Context(), id, depID)
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			if dep.CommitSHA == nil || *dep.CommitSHA == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest(
					"The target deployment does not record an exact commit SHA.",
					map[string]any{"deployment_id": dep.ID}))
				return
			}

			h.startDeployment(w, r, app, apps.TriggerManual, dep.GitRef, *dep.CommitSHA, nil)
		})).ServeHTTP(w, r)
}

// --- Webhook Tokens ----------------------------------------------------------

// handleCreateWebhookToken generates a fresh git webhook token for an app.
// The plaintext token is returned ONCE; only its SHA-256 hash is stored.
func (h *AppHandlers) handleCreateWebhookToken(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "deployment.create", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := h.apps.GetAppInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			rawBytes := make([]byte, 32)
			if _, err := rand.Read(rawBytes); err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			rawToken := "jw_hook_" + hex.EncodeToString(rawBytes)
			tokenHash := apps.HashWebhookToken(rawToken)
			wt, err := h.apps.CreateWebhookToken(r.Context(), id, tokenHash)
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "app.webhook_token.create",
				ResourceType: "app",
				ResourceID:   id,
				Result:       audit.ResultSuccess,
				Context:      map[string]any{"token_id": wt.ID, "project_id": projectID},
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				// rawToken is shown ONCE. Do not log it.
				"token": rawToken,
				"webhook_token": map[string]any{
					"id":           wt.ID,
					"app_id":       wt.AppID,
					"state":        wt.State,
					"created_at":   wt.CreatedAt,
					"last_used_at": wt.LastUsedAt,
				},
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// handleListWebhookTokens returns all webhook tokens for an app (active and revoked).
// Plaintext tokens are not recoverable and never returned.
func (h *AppHandlers) handleListWebhookTokens(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "deployment.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := h.apps.GetAppInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			tokens, err := h.apps.ListWebhookTokens(r.Context(), id)
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			out := make([]map[string]any, 0, len(tokens))
			for _, wt := range tokens {
				out = append(out, map[string]any{
					"id":           wt.ID,
					"app_id":       wt.AppID,
					"state":        wt.State,
					"created_at":   wt.CreatedAt,
					"last_used_at": wt.LastUsedAt,
				})
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"webhook_tokens": out,
				"request_id":     httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// handleRevokeWebhookToken revokes a single webhook token.
func (h *AppHandlers) handleRevokeWebhookToken(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	tokenID := r.PathValue("token_id")
	authsession.RequirePermission(h.now, "deployment.create", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := h.apps.GetAppInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			if err := h.apps.RevokeWebhookToken(r.Context(), id, tokenID); err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "app.webhook_token.revoke",
				ResourceType: "app",
				ResourceID:   id,
				Result:       audit.ResultSuccess,
				Context:      map[string]any{"token_id": tokenID, "project_id": projectID},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"revoked":    true,
				"token_id":   tokenID,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// gitWebhookPayload is the union of GitHub push event, GitLab push event, and
// the generic JAWAKER payload. Only the fields we need are extracted.
type gitWebhookPayload struct {
	// GitHub/GitLab push: "after" is the head commit SHA; "0000..." means delete.
	After string `json:"after"`
	// GitHub/GitLab: "ref" is the full git reference (e.g. refs/heads/main).
	Ref string `json:"ref"`
	// Generic JAWAKER payload: direct SHA and ref.
	CommitSHA string `json:"commit_sha"`
	GitRef    string `json:"git_ref"`
}

// handleGitWebhook is a PUBLIC endpoint (no session required) that receives a
// git push event from GitHub/GitLab/Gitea and triggers an app deployment.
//
// Gate 4: the idempotency_key = "webhook:<token_id>:<commit_sha>" ensures that a
// duplicate push event for the same SHA cannot start a second deployment.
func (h *AppHandlers) handleGitWebhook(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	reqID := httpserver.RequestIDFromRequest(r)

	// Resolve token → app. Returns ErrNotFound for revoked/missing tokens.
	wt, err := h.apps.GetWebhookTokenByHash(r.Context(), apps.HashWebhookToken(token))
	if err != nil {
		httpserver.WriteError(w, r, apierr.NotFound("Webhook token not found or revoked."))
		return
	}
	app, err := h.apps.GetApp(r.Context(), wt.AppID)
	if err != nil || !app.Usable() {
		httpserver.WriteError(w, r, apierr.Conflict("Application is not active.", map[string]any{"app_id": wt.AppID}))
		return
	}

	// Parse payload — accept empty body gracefully.
	var payload gitWebhookPayload
	if r.ContentLength > 0 {
		if err := decodeJSONStrict(r, &payload); err != nil {
			httpserver.WriteError(w, r, err)
			return
		}
	}

	// Resolve commit SHA: prefer "after" (GitHub/GitLab) then "commit_sha" (generic).
	commitSHA := strings.TrimSpace(payload.After)
	// "after" = 40 zeros means branch-delete event — not a deployable push.
	if commitSHA == "" || commitSHA == "0000000000000000000000000000000000000000" {
		commitSHA = strings.TrimSpace(payload.CommitSHA)
	}
	if !commitSHAPattern.MatchString(commitSHA) {
		httpserver.WriteError(w, r, apierr.InvalidRequest(
			"A valid commit SHA (7..40 lowercase hex) is required in the webhook payload.",
			map[string]any{"field": "after (or commit_sha)"}))
		return
	}

	// Resolve git ref: strip "refs/heads/" prefix from standard git push payloads.
	gitRef := strings.TrimPrefix(strings.TrimSpace(payload.Ref), "refs/heads/")
	if gitRef == "" {
		gitRef = strings.TrimSpace(payload.GitRef)
	}
	if gitRef == "" {
		gitRef = app.GitRefDefault
	}
	if gitRef == "" {
		gitRef = "main"
	}

	// Idempotency key: same token + same SHA == same logical push. Gate 4.
	idempotencyKey := fmt.Sprintf("webhook:%s:%s", wt.ID, commitSHA)

	dep, depErr := h.apps.CreateDeployment(r.Context(), apps.CreateDeploymentParams{
		AppID:          app.ID,
		ProjectID:      app.ProjectID,
		ServerID:       app.ServerID,
		Trigger:        apps.TriggerWebhook,
		CommitSHA:      &commitSHA,
		GitRef:         gitRef,
		IdempotencyKey: &idempotencyKey,
	})
	if depErr != nil {
		httpserver.WriteError(w, r, appErr(depErr))
		return
	}

	job, jobErr := jobs.Enqueue(r.Context(), h.pool, jobs.Requested{
		Type:             JobTypeAppDeploy,
		ServerID:         app.ServerID,
		ProjectID:        app.ProjectID,
		IdempotencyKey:   dep.ID,
		IdempotencyScope: "app.deploy:" + app.ID,
		RequestedByType:  "system",
		RequestedByID:    wt.ID,
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
		_, _ = h.apps.UpdateDeploymentState(r.Context(), dep.ID, apps.UpdateDeploymentStateParams{
			State:        apps.DeployFailed,
			ErrorCode:    "job_enqueue_failed",
			ErrorSummary: jobErr.Error(),
		})
		httpserver.WriteError(w, r, apierr.Internal(jobErr))
		return
	}

	_, _ = h.apps.UpdateDeploymentState(r.Context(), dep.ID, apps.UpdateDeploymentStateParams{
		State: apps.DeployQueued,
		JobID: &job.ID,
	})
	// Touch token last_used_at — best-effort; don't fail the response.
	_ = h.apps.TouchWebhookToken(r.Context(), wt.ID)

	h.recordAudit(r, audit.Event{
		ActorType:    audit.ActorSystem,
		ActorID:      wt.ID,
		Action:       "deployment.webhook",
		ResourceType: "app",
		ResourceID:   app.ID,
		Result:       audit.ResultSuccess,
		Context: map[string]any{
			"deployment_id": dep.ID,
			"job_id":        job.ID,
			"git_ref":       gitRef,
			"commit_sha":    commitSHA,
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

func deploymentResponse(d apps.Deployment) map[string]any {
	out := map[string]any{
		"id":            d.ID,
		"app_id":        d.AppID,
		"project_id":    d.ProjectID,
		"server_id":     d.ServerID,
		"trigger":       d.Trigger,
		"commit_sha":    d.CommitSHA,
		"git_ref":       d.GitRef,
		"state":         d.State,
		"error_code":    d.ErrorCode,
		"error_summary": d.ErrorSummary,
		"job_id":        d.JobID,
		"created_at":    d.CreatedAt,
		"started_at":    d.StartedAt,
		"finished_at":   d.FinishedAt,
	}
	return out
}

func deploymentResponses(list []apps.Deployment) []map[string]any {
	out := make([]map[string]any, len(list))
	for i, d := range list {
		out[i] = deploymentResponse(d)
	}
	return out
}

// ── Preview Environments Handlers (PRD §11.6) ────────────────────────────────

type appPreviewItem struct {
	ID         string     `json:"id"`
	AppID      string     `json:"app_id"`
	ProjectID  string     `json:"project_id"`
	Branch     string     `json:"branch"`
	PRNumber   *int       `json:"pr_number,omitempty"`
	PreviewURL string     `json:"preview_url"`
	Status     string     `json:"status"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

type createPreviewRequest struct {
	Branch   string `json:"branch"`
	PRNumber *int   `json:"pr_number,omitempty"`
}

func (h *AppHandlers) handleListPreviews(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	appID := r.PathValue("id")
	authsession.RequirePermission(h.now, "deployment.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := h.apps.GetAppInProject(r.Context(), projectID, appID)
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			rows, err := h.pool.Query(r.Context(), `
				SELECT id, app_id, project_id, branch, pr_number, preview_url, status, created_at, expires_at
				FROM app_previews
				WHERE app_id = $1 AND project_id = $2 AND status != 'terminated'
				ORDER BY created_at DESC
			`, appID, projectID)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			defer rows.Close()

			var list []appPreviewItem
			for rows.Next() {
				var item appPreviewItem
				if err := rows.Scan(&item.ID, &item.AppID, &item.ProjectID, &item.Branch, &item.PRNumber, &item.PreviewURL, &item.Status, &item.CreatedAt, &item.ExpiresAt); err == nil {
					list = append(list, item)
				}
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"previews":   list,
				"total":      len(list),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *AppHandlers) handleCreatePreview(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	appID := r.PathValue("id")
	authsession.RequirePermission(h.now, "deployment.create", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			app, err := h.apps.GetAppInProject(r.Context(), projectID, appID)
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			var req createPreviewRequest
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, apierr.InvalidRequest(err.Error(), nil))
				return
			}
			req.Branch = strings.TrimSpace(req.Branch)
			if req.Branch == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("branch is required", nil))
				return
			}

			// Generate ephemeral preview subdomain: e.g. pr-12.slug.preview.local or branch.slug.preview.local
			cleanBranch := regexp.MustCompile(`[^a-zA-Z0-9-]`).ReplaceAllString(req.Branch, "-")
			previewURL := fmt.Sprintf("https://%s-%s.preview.local", strings.ToLower(cleanBranch), app.Slug)
			if req.PRNumber != nil && *req.PRNumber > 0 {
				previewURL = fmt.Sprintf("https://pr-%d-%s.preview.local", *req.PRNumber, app.Slug)
			}

			var previewID string
			var createdAt time.Time
			err = h.pool.QueryRow(r.Context(), `
				INSERT INTO app_previews (app_id, project_id, branch, pr_number, preview_url, status)
				VALUES ($1, $2, $3, $4, $5, 'active')
				RETURNING id, created_at
			`, appID, projectID, req.Branch, req.PRNumber, previewURL).Scan(&previewID, &createdAt)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}

			_ = audit.Record(r.Context(), h.audit, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "app.preview.create",
				ResourceType: "app_preview",
				ResourceID:   previewID,
				Result:       audit.ResultSuccess,
				Context: map[string]any{
					"app_id":      appID,
					"branch":      req.Branch,
					"preview_url": previewURL,
				},
			})

			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"preview": appPreviewItem{
					ID:         previewID,
					AppID:      appID,
					ProjectID:  projectID,
					Branch:     req.Branch,
					PRNumber:   req.PRNumber,
					PreviewURL: previewURL,
					Status:     "active",
					CreatedAt:  createdAt,
				},
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *AppHandlers) handleDeletePreview(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	appID := r.PathValue("id")
	previewID := r.PathValue("preview_id")
	authsession.RequirePermission(h.now, "deployment.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := h.apps.GetAppInProject(r.Context(), projectID, appID)
			if err != nil {
				httpserver.WriteError(w, r, appErr(err))
				return
			}
			tag, err := h.pool.Exec(r.Context(), `
				UPDATE app_previews SET status = 'terminated', updated_at = now()
				WHERE id = $1 AND app_id = $2 AND project_id = $3
			`, previewID, appID, projectID)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			if tag.RowsAffected() == 0 {
				httpserver.WriteError(w, r, apierr.NotFound("preview environment not found"))
				return
			}

			_ = audit.Record(r.Context(), h.audit, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "app.preview.teardown",
				ResourceType: "app_preview",
				ResourceID:   previewID,
				Result:       audit.ResultSuccess,
				Context: map[string]any{
					"app_id": appID,
				},
			})

			writeJSONResponse(w, http.StatusOK, map[string]any{
				"preview_id": previewID,
				"status":     "terminated",
				"message":    "Preview environment torn down successfully.",
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}
