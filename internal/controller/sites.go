// Package controller: sites HTTP handlers.
//
// Mounts site management under /api/v1/projects/{project_id}/sites. All site.*
// permissions have scope_kind = 'project' (0007_rbac_seed.sql L42-45), so every
// route wraps with rbac.ProjectScope(projectID).
//
// Security invariants enforced here:
//   - Cross-project access returns 404, not 403: GetInProject filters by project_id
//     in the WHERE clause, so an id belonging to another project returns ErrNotFound
//     and answers 404. It never discloses whether the id exists elsewhere.
//   - List endpoints filter by project_id server-side in the query (API.md §5).
//   - site.delete requires step-up (0007_rbac_seed.sql L45).
//   - Apply is ASYNCHRONOUS (ARCHITECTURE.md §15): it creates a revision,
//     enqueues a job, and returns {job_id, status} (PRD.md §38.1).
package controller

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/jobs"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodes"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/bukansembarangkong/jawaker-panel/internal/revisions"
	"github.com/bukansembarangkong/jawaker-panel/internal/sites"
	"github.com/jackc/pgx/v5/pgxpool"
)

// JobTypeSiteApply is the job type enqueued when a configuration candidate is
// applied to a site.
const JobTypeSiteApply = "site.apply"

// SiteHandlerOptions configures the sites HTTP surface.
type SiteHandlerOptions struct {
	Sites      *sites.Store
	Pool       *pgxpool.Pool
	Dispatcher *nodes.Dispatcher
	Logger     *slog.Logger
	Audit      audit.Execer
	Now        func() time.Time
}

// SiteHandlers holds the site HTTP surface.
type SiteHandlers struct {
	sites      *sites.Store
	pool       *pgxpool.Pool
	dispatcher *nodes.Dispatcher
	logger     *slog.Logger
	audit      audit.Execer
	now        func() time.Time
}

// NewSiteHandlers builds the site handlers.
func NewSiteHandlers(opts SiteHandlerOptions) (*SiteHandlers, error) {
	if opts.Sites == nil {
		return nil, errors.New("controller: sites store is required")
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
	return &SiteHandlers{
		sites:      opts.Sites,
		pool:       opts.Pool,
		dispatcher: opts.Dispatcher,
		logger:     opts.Logger,
		audit:      opts.Audit,
		now:        now,
	}, nil
}

// Routes registers the site endpoints on the mux.
//
// All routes live under /api/v1/projects/{project_id}/sites.
func (h *SiteHandlers) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/projects/{project_id}/sites", h.handleListSites)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/sites", h.handleCreateSite)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/sites/{id}", h.handleGetSite)
	mux.HandleFunc("PATCH /api/v1/projects/{project_id}/sites/{id}", h.handleUpdateSite)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/sites/{id}", h.handleDeleteSite)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/sites/{id}/validate", h.handleValidateConfig)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/sites/{id}/apply", h.handleApplyConfig)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/sites/{id}/logs", h.handleReadLogs)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/sites/{id}/nodejs", h.handleGetNodeJSConfig)
	mux.HandleFunc("PUT /api/v1/projects/{project_id}/sites/{id}/nodejs", h.handleUpsertNodeJSConfig)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/sites/{id}/nodejs/action", h.handleNodeJSAction)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/sites/{id}/nodejs/status", h.handleNodeJSStatus)
}

// --- CRUD -------------------------------------------------------------------

func (h *SiteHandlers) handleListSites(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "site.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limit, offset, apiErr := parsePagination(r)
			if apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			siteList, total, err := h.sites.List(r.Context(), projectID, limit, offset, r.URL.Query().Get("state"))
			if err != nil {
				httpserver.WriteError(w, r, siteErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"sites":      siteResponses(siteList),
				"total":      total,
				"limit":      limit,
				"offset":     offset,
				"has_more":   offset+len(siteList) < total,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createSiteRequest struct {
	ServerID string `json:"server_id"`
	Slug     string `json:"slug"`
	Name     string `json:"name"`
	Mode     string `json:"mode"`
	DocRoot  string `json:"doc_root,omitempty"`
	Upstream string `json:"upstream,omitempty"`
	PHPUnit  string `json:"php_unit,omitempty"`
}

func (h *SiteHandlers) handleCreateSite(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "site.create", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createSiteRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			site, err := h.sites.Create(r.Context(), sites.CreateParams{
				ProjectID: projectID,
				ServerID:  req.ServerID,
				Slug:      req.Slug,
				Name:      req.Name,
				Mode:      req.Mode,
				DocRoot:   req.DocRoot,
				Upstream:  req.Upstream,
				PHPUnit:   req.PHPUnit,
				CreatedBy: principalUserID(r),
			})
			if err != nil {
				httpserver.WriteError(w, r, siteErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "site.create",
				ResourceType: "site",
				ResourceID:   site.ID,
				Result:       audit.ResultSuccess,
				Context: map[string]any{
					"project_id": site.ProjectID,
					"server_id":  site.ServerID,
					"slug":       site.Slug,
					"mode":       site.Mode,
				},
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"site":       siteResponse(site),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *SiteHandlers) handleGetSite(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "site.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			site, err := h.sites.GetInProject(r.Context(), projectID, id)
			if err != nil {
				httpserver.WriteError(w, r, siteErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"site":       siteResponse(site),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type updateSiteRequest struct {
	Name     *string `json:"name,omitempty"`
	DocRoot  *string `json:"doc_root,omitempty"`
	Upstream *string `json:"upstream,omitempty"`
	PHPUnit  *string `json:"php_unit,omitempty"`
}

func (h *SiteHandlers) handleUpdateSite(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "site.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Cross-project guard: ensure the site belongs to this project first.
			if _, err := h.sites.GetInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, siteErr(err))
				return
			}
			var req updateSiteRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			site, err := h.sites.Update(r.Context(), id, sites.UpdateParams{
				Name:     req.Name,
				DocRoot:  req.DocRoot,
				Upstream: req.Upstream,
				PHPUnit:  req.PHPUnit,
			})
			if err != nil {
				httpserver.WriteError(w, r, siteErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "site.update",
				ResourceType: "site",
				ResourceID:   site.ID,
				Result:       audit.ResultSuccess,
				Context:      map[string]any{"project_id": projectID},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"site":       siteResponse(site),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *SiteHandlers) handleDeleteSite(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	// site.delete is step-up in catalog (0007 L45) and rbac auto-flags any .delete.
	authsession.RequirePermission(h.now, "site.delete", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := h.sites.GetInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, siteErr(err))
				return
			}
			site, err := h.sites.ImmediateDelete(r.Context(), id)
			if err != nil {
				httpserver.WriteError(w, r, siteErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "site.delete",
				ResourceType: "site",
				ResourceID:   id,
				Result:       audit.ResultSuccess,
				Context: map[string]any{
					"project_id": projectID,
					"site_slug":  site.Slug,
				},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"status":     "deleted",
				"site_id":    id,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// --- Configuration Candidate & Validation -----------------------------------

type validateConfigRequest struct {
	Config   string `json:"config"`
	Filename string `json:"filename"`
}

// handleValidateConfig validates a candidate configuration against the node
// hosting this site, using Dispatcher.ValidateWebConfig (PR-B).
//
// The candidate is NOT applied and NOT stored: this is the read-only check an
// operator runs before asking the system to apply.
func (h *SiteHandlers) handleValidateConfig(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "site.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			site, err := h.sites.GetInProject(r.Context(), projectID, id)
			if err != nil {
				httpserver.WriteError(w, r, siteErr(err))
				return
			}
			var req validateConfigRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			if h.dispatcher == nil {
				httpserver.WriteError(w, r, apierr.ServiceUnavailable("Node dispatcher is not available on this controller."))
				return
			}

			reqID := httpserver.RequestIDFromRequest(r)
			result, valErr := h.dispatcher.ValidateWebConfig(r.Context(), site.ServerID, reqID, site.ID, nodewire.WebConfigValidateInput{
				Config:   req.Config,
				Filename: req.Filename,
			})
			if valErr != nil {
				var opErr *nodes.NodeOperationError
				if errors.As(valErr, &opErr) && opErr.Unsupported() {
					httpserver.WriteError(w, r, apierr.ServiceUnavailable("The host web server is not available or does not support validation."))
					return
				}
				h.logger.Error("validate web config failed", "site_id", site.ID, "server_id", site.ServerID, "error", valErr)
				httpserver.WriteError(w, r, apierr.Internal(valErr))
				return
			}

			if !result.Valid {
				// 422 with the web server's own error output (API.md §8, D-009).
				httpserver.WriteError(w, r, apierr.ConfigValidationFailed(
					"The candidate configuration did not pass validation.",
					map[string]any{
						"site_id":   site.ID,
						"tool":      result.Tool,
						"output":    result.Output,
						"truncated": result.Truncated,
					}))
				return
			}

			writeJSONResponse(w, http.StatusOK, map[string]any{
				"valid":        true,
				"tool":         result.Tool,
				"tool_version": result.ToolVersion,
				"output":       result.Output,
				"request_id":   reqID,
			})
		})).ServeHTTP(w, r)
}

type applyConfigRequest struct {
	Config         string `json:"config"`
	Filename       string `json:"filename"`
	BaseRevisionID string `json:"base_revision_id,omitempty"`
}

// handleApplyConfig validates the candidate, records it as a revision, and
// enqueues a background job to apply it to the host node.
//
// This is the core Phase 3 pipeline: revisions -> jobs -> Dispatcher.
// ARCHITECTURE.md §15 forbids synchronous deploy inside an API handler, so this
// returns {request_id, job: {id, state}} immediately (API.md §7, PRD.md §38.1).
func (h *SiteHandlers) handleApplyConfig(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "site.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			site, err := h.sites.GetInProject(r.Context(), projectID, id)
			if err != nil {
				httpserver.WriteError(w, r, siteErr(err))
				return
			}
			var req applyConfigRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			reqID := httpserver.RequestIDFromRequest(r)

			// Step 1: Pre-flight validate candidate on node if dispatcher available.
			if h.dispatcher != nil {
				valResult, valErr := h.dispatcher.ValidateWebConfig(r.Context(), site.ServerID, reqID, site.ID, nodewire.WebConfigValidateInput{
					Config:   req.Config,
					Filename: req.Filename,
				})
				if valErr == nil && !valResult.Valid {
					// Hard refusal: an invalid config is never applied (Phase 3 gate).
					httpserver.WriteError(w, r, apierr.ConfigValidationFailed(
						"The candidate configuration did not pass validation.",
						map[string]any{
							"site_id": site.ID,
							"tool":    valResult.Tool,
							"output":  valResult.Output,
						}))
					return
				}
			}

			// Step 2: Create proposed revision.
			proposed := revisions.Proposed{
				ResourceType:   "site",
				ResourceID:     site.ID,
				ActorType:      audit.ActorUser,
				ActorID:        principalUserID(r),
				BaseRevisionID: req.BaseRevisionID,
				Candidate: revisions.Candidate{
					"config":   req.Config,
					"filename": req.Filename,
				},
				RequestID: reqID,
			}
			rev, revErr := revisions.Create(r.Context(), h.pool, proposed)
			if revErr != nil {
				if errors.Is(revErr, revisions.ErrStaleBase) {
					httpserver.WriteError(w, r, apierr.Conflict(
						"The base revision is stale. Another configuration was applied since this candidate was prepared.",
						map[string]any{"resource_id": site.ID}))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(revErr))
				return
			}

			// Step 3: Enqueue the apply job.
			job, jobErr := jobs.Enqueue(r.Context(), h.pool, jobs.Requested{
				Type:             JobTypeSiteApply,
				ServerID:         site.ServerID,
				ProjectID:        site.ProjectID,
				IdempotencyKey:   rev.CandidateHash,
				IdempotencyScope: "site.apply:" + site.ID,
				RequestedByType:  "user",
				RequestedByID:    principalUserID(r),
				RequestID:        reqID,
				Payload: map[string]any{
					"site_id":     site.ID,
					"revision_id": rev.ID,
					"config":      req.Config,
					"filename":    req.Filename,
				},
				Steps: []jobs.StepPlan{
					{Name: "validate"},
					{Name: "apply"},
				},
			})
			if jobErr != nil {
				httpserver.WriteError(w, r, apierr.Internal(jobErr))
				return
			}

			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "site.config.apply",
				ResourceType: "site",
				ResourceID:   site.ID,
				Result:       audit.ResultSuccess,
				Context: map[string]any{
					"revision_id": rev.ID,
					"job_id":      job.ID,
				},
			})

			// Mutation response pattern (API.md §7, PRD.md §38.1).
			writeJSONResponse(w, http.StatusAccepted, map[string]any{
				"revision_id": rev.ID,
				"job": map[string]any{
					"id":    job.ID,
					"state": job.State,
				},
				"request_id": reqID,
			})
		})).ServeHTTP(w, r)
}

// handleReadLogs serves GET /api/v1/projects/{project_id}/sites/{id}/logs.
//
// Per D-005: log content is read from the node on demand and never stored in
// PostgreSQL. Per D-006: this route uses the project-scoped site.logs.read
// permission rather than the server-scoped logs.read.
func (h *SiteHandlers) handleReadLogs(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "site.logs.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Cross-project 404 guard runs FIRST: GetInProject returns ErrNotFound
			// for a site in a different project.
			site, err := h.sites.GetInProject(r.Context(), projectID, id)
			if err != nil {
				httpserver.WriteError(w, r, siteErr(err))
				return
			}

			// Validate query parameters before checking the dispatcher, so a
			// client error returns 400 Bad Request rather than masking it
			// behind a 503 Service Unavailable.
			logType := r.URL.Query().Get("type")
			if logType == "" {
				logType = nodewire.LogTypeAccess
			}
			if logType != nodewire.LogTypeAccess && logType != nodewire.LogTypeError {
				httpserver.WriteError(w, r, apierr.InvalidRequest(
					"type must be \"access\" or \"error\".",
					map[string]any{"field": "type"}))
				return
			}

			lines := nodewire.DefaultSiteLogsTailLines
			if raw := r.URL.Query().Get("lines"); raw != "" {
				n, parseErr := strconv.Atoi(raw)
				if parseErr != nil || n < 1 {
					httpserver.WriteError(w, r, apierr.InvalidRequest("lines must be a positive integer.", map[string]any{"field": "lines"}))
					return
				}
				if n > nodewire.MaxSiteLogsTailLines {
					httpserver.WriteError(w, r, apierr.InvalidRequest("lines exceeds the maximum.", map[string]any{
						"field": "lines",
						"max":   nodewire.MaxSiteLogsTailLines,
					}))
					return
				}
				lines = n
			}

			if h.dispatcher == nil {
				httpserver.WriteError(w, r, apierr.ServiceUnavailable("Node dispatcher is not available on this controller."))
				return
			}

			// Obtain the project slug to construct the node path. We read it
			// from the pool rather than caching it in SiteHandlers to keep the
			// struct dependency-free.
			var projectSlug string
			if scanErr := h.pool.QueryRow(r.Context(),
				`SELECT slug FROM projects WHERE id = $1 AND deleted_at IS NULL`,
				projectID).Scan(&projectSlug); scanErr != nil {
				httpserver.WriteError(w, r, apierr.Internal(scanErr))
				return
			}

			reqID := httpserver.RequestIDFromRequest(r)
			result, readErr := h.dispatcher.ReadSiteLogs(r.Context(), site.ServerID, reqID, nodewire.SiteLogsTailInput{
				ProjectSlug: projectSlug,
				SiteSlug:    site.Slug,
				LogType:     logType,
				Lines:       lines,
			})
			if readErr != nil {
				var opErr *nodes.NodeOperationError
				if errors.As(readErr, &opErr) && opErr.Unsupported() {
					httpserver.WriteError(w, r, apierr.ServiceUnavailable("Log reading is not supported on this host."))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(readErr))
				return
			}

			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "site.logs.read",
				ResourceType: "site",
				ResourceID:   site.ID,
				Result:       audit.ResultSuccess,
				Context: map[string]any{
					"log_type": logType,
					"lines":    lines,
				},
			})

			writeJSONResponse(w, http.StatusOK, map[string]any{
				"site_id":    site.ID,
				"log_type":   result.LogType,
				"lines":      result.Lines,
				"truncated":  result.Truncated,
				"request_id": reqID,
			})
		})).ServeHTTP(w, r)
}


// --- Node.js runtime --------------------------------------------------------

// handleGetNodeJSConfig returns the Node.js runtime config for a site.
func (h *SiteHandlers) handleGetNodeJSConfig(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "site.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Cross-project 404 guard: GetInProject filters by project_id.
			if _, err := h.sites.GetInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, siteErr(err))
				return
			}
			cfg, err := h.sites.GetNodeJSConfig(r.Context(), id)
			if err != nil {
				if errors.Is(err, sites.ErrNotFound) {
					// Config not yet saved: return sensible defaults rather than 404
					writeJSONResponse(w, http.StatusOK, map[string]any{
						"nodejs_config": map[string]any{
							"site_id":      id,
							"node_version": "22",
							"app_root":     "",
							"startup_file": "server.js",
							"start_args":   []string{},
							"env_vars":     map[string]string{},
							"port":         3000,
						},
						"request_id": httpserver.RequestIDFromRequest(r),
					})
					return
				}
				httpserver.WriteError(w, r, siteErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"nodejs_config": nodejsConfigResponse(cfg),
				"request_id":   httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type upsertNodeJSConfigRequest struct {
	NodeVersion string            `json:"node_version,omitempty"`
	AppRoot     string            `json:"app_root,omitempty"`
	StartupFile string            `json:"startup_file"`
	StartArgs   []string          `json:"start_args,omitempty"`
	EnvVars     map[string]string `json:"env_vars,omitempty"`
	Port        int               `json:"port,omitempty"`
}

// handleUpsertNodeJSConfig creates or replaces the Node.js config for a site.
func (h *SiteHandlers) handleUpsertNodeJSConfig(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "site.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := h.sites.GetInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, siteErr(err))
				return
			}
			var req upsertNodeJSConfigRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			if req.StartupFile == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("startup_file is required.", map[string]any{"field": "startup_file"}))
				return
			}
			if req.Port != 0 && (req.Port < 1024 || req.Port > 65535) {
				httpserver.WriteError(w, r, apierr.InvalidRequest("port must be between 1024 and 65535.", map[string]any{"field": "port"}))
				return
			}
			cfg, err := h.sites.UpsertNodeJSConfig(r.Context(), id, sites.UpsertNodeJSConfigParams{
				NodeVersion: req.NodeVersion,
				AppRoot:     req.AppRoot,
				StartupFile: req.StartupFile,
				StartArgs:   req.StartArgs,
				EnvVars:     req.EnvVars,
				Port:        req.Port,
			})
			if err != nil {
				httpserver.WriteError(w, r, siteErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "site.nodejs.config.updated",
				ResourceType: "site",
				ResourceID:   id,
				Result:       audit.ResultSuccess,
				Context:      map[string]any{"project_id": projectID},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"nodejs_config": nodejsConfigResponse(cfg),
				"request_id":   httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type nodejsActionRequest struct {
	Action string `json:"action"` // start | stop | restart | npm_install
}

// handleNodeJSAction performs a lifecycle action on the site's Node.js service.
func (h *SiteHandlers) handleNodeJSAction(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	// step-up=true: mutates a running process.
	authsession.RequirePermission(h.now, "site.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			site, err := h.sites.GetInProject(r.Context(), projectID, id)
			if err != nil {
				httpserver.WriteError(w, r, siteErr(err))
				return
			}
			var req nodejsActionRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			validActions := map[string]bool{"start": true, "stop": true, "restart": true, "npm_install": true}
			if !validActions[req.Action] {
				httpserver.WriteError(w, r, apierr.InvalidRequest(`action must be "start", "stop", "restart", or "npm_install".`, map[string]any{"field": "action"}))
				return
			}
			if h.dispatcher == nil {
				httpserver.WriteError(w, r, apierr.ServiceUnavailable("Node dispatcher is not available on this controller."))
				return
			}
			// Fetch nodejs config for service parameters.
			nodeCfg, err := h.sites.GetNodeJSConfig(r.Context(), id)
			if err != nil {
				httpserver.WriteError(w, r, siteErr(err))
				return
			}
			// Fetch project slug.
			var projectSlug string
			if scanErr := h.pool.QueryRow(r.Context(),
				`SELECT slug FROM projects WHERE id = $1 AND deleted_at IS NULL`,
				projectID).Scan(&projectSlug); scanErr != nil {
				httpserver.WriteError(w, r, apierr.Internal(scanErr))
				return
			}
			reqID := httpserver.RequestIDFromRequest(r)
			result, actErr := h.dispatcher.ManageSiteNodeJS(r.Context(), site.ServerID, reqID, nodewire.SiteNodeJSManageInput{
				ProjectSlug: projectSlug,
				SiteSlug:    site.Slug,
				Action:      req.Action,
				NodeVersion: nodeCfg.NodeVersion,
				AppRoot:     nodeCfg.AppRoot,
				StartupFile: nodeCfg.StartupFile,
				StartArgs:   nodeCfg.StartArgs,
				EnvVars:     nodeCfg.EnvVars,
				Port:        nodeCfg.Port,
			})
			if actErr != nil {
				if errors.Is(actErr, nodes.ErrNodeUnreachable) {
					httpserver.WriteError(w, r, apierr.ServiceUnavailable("The node hosting this site is not reachable."))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(actErr))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "site.nodejs." + req.Action,
				ResourceType: "site",
				ResourceID:   id,
				Result:       audit.ResultSuccess,
				Context:      map[string]any{"project_id": projectID, "action": req.Action},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"result":     result,
				"request_id": reqID,
			})
		})).ServeHTTP(w, r)
}

// handleNodeJSStatus returns the current systemd state of the site's Node.js service.
// Node unreachable is not an error; it returns {"active": false, "state": "unknown"}.
func (h *SiteHandlers) handleNodeJSStatus(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "site.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			site, err := h.sites.GetInProject(r.Context(), projectID, id)
			if err != nil {
				httpserver.WriteError(w, r, siteErr(err))
				return
			}
			if h.dispatcher == nil {
				httpserver.WriteError(w, r, apierr.ServiceUnavailable("Node dispatcher is not available on this controller."))
				return
			}
			// Fetch project slug.
			var projectSlug string
			if scanErr := h.pool.QueryRow(r.Context(),
				`SELECT slug FROM projects WHERE id = $1 AND deleted_at IS NULL`,
				projectID).Scan(&projectSlug); scanErr != nil {
				httpserver.WriteError(w, r, apierr.Internal(scanErr))
				return
			}
			reqID := httpserver.RequestIDFromRequest(r)
			status, statErr := h.dispatcher.GetSiteNodeJSStatus(r.Context(), site.ServerID, reqID, nodewire.SiteNodeJSStatusInput{
				ProjectSlug: projectSlug,
				SiteSlug:    site.Slug,
			})
			if statErr != nil {
					// Any error (unreachable, no node, internal) → degraded status, not 500.
					writeJSONResponse(w, http.StatusOK, map[string]any{
						"status":     map[string]any{"active": false, "state": "unknown", "unit_name": ""},
						"request_id": reqID,
					})
					return
				}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"status":     status,
				"request_id": reqID,
			})
		})).ServeHTTP(w, r)
}

func nodejsConfigResponse(c sites.NodeJSConfig) map[string]any {
	return map[string]any{
		"id":           c.ID,
		"site_id":      c.SiteID,
		"node_version": c.NodeVersion,
		"app_root":     c.AppRoot,
		"startup_file": c.StartupFile,
		"start_args":   c.StartArgs,
		"env_vars":     c.EnvVars,
		"port":         c.Port,
		"created_at":   c.CreatedAt,
		"updated_at":   c.UpdatedAt,
	}
}

// --- helpers ----------------------------------------------------------------

func siteResponse(s sites.Site) map[string]any {
	out := map[string]any{
		"id":         s.ID,
		"project_id": s.ProjectID,
		"server_id":  s.ServerID,
		"slug":       s.Slug,
		"name":       s.Name,
		"mode":       s.Mode,
		"state":      s.State,
		"doc_root":   s.DocRoot,
		"upstream":   s.Upstream,
		"php_unit":   s.PHPUnit,
		"created_at": s.CreatedAt,
		"updated_at": s.UpdatedAt,
	}
	if s.AppliedRevisionID != nil {
		out["applied_revision_id"] = *s.AppliedRevisionID
	}
	if s.DeleteAfter != nil {
		out["delete_after"] = *s.DeleteAfter
	}
	if s.DeletedAt != nil {
		out["deleted_at"] = *s.DeletedAt
	}
	return out
}

func siteResponses(s []sites.Site) []map[string]any {
	out := make([]map[string]any, 0, len(s))
	for _, site := range s {
		out = append(out, siteResponse(site))
	}
	return out
}

func siteErr(err error) *apierr.Error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, sites.ErrNotFound):
		return apierr.NotFound("The requested site does not exist.")
	case errors.Is(err, sites.ErrSlugTaken):
		return apierr.Conflict("A site with that slug already exists in this project.",
			map[string]any{"field": "slug"})
	case errors.Is(err, sites.ErrInvalid):
		return apierr.InvalidRequest(err.Error(), nil)
	case errors.Is(err, sites.ErrState):
		return apierr.InvalidRequest("The request is not valid for the site's or project's current state.", nil)
	default:
		return apierr.Internal(err)
	}
}

func (h *SiteHandlers) recordAudit(r *http.Request, e audit.Event) {
	if h.audit == nil {
		return
	}
	e.RequestID = httpserver.RequestIDFromRequest(r)
	e.SourceIP = r.RemoteAddr
	e.UserAgent = r.UserAgent()
	if err := audit.Record(r.Context(), h.audit, e); err != nil {
		h.logger.ErrorContext(r.Context(), "audit write failed",
			"error", err, "action", e.Action, "request_id", e.RequestID)
	}
}

func principalUserID(r *http.Request) string {
	if principal, ok := auth.PrincipalFrom(r.Context()); ok {
		return principal.UserID
	}
	return ""
}

func parsePagination(r *http.Request) (limit, offset int, apiErr *apierr.Error) {
	limit = 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return 0, 0, apierr.InvalidRequest("limit must be a positive integer.", map[string]any{"field": "limit"})
		}
		if n > 200 {
			return 0, 0, apierr.InvalidRequest("limit is too large.", map[string]any{"field": "limit", "max": 200})
		}
		limit = n
	}
	if raw := r.URL.Query().Get("offset"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			return 0, 0, apierr.InvalidRequest("offset must be a non-negative integer.", map[string]any{"field": "offset"})
		}
		offset = n
	}
	return limit, offset, nil
}

func decodeJSONStrict(r *http.Request, dst any) *apierr.Error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return apierr.InvalidRequest("The request body is not valid JSON.", map[string]any{"error": err.Error()})
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return apierr.InvalidRequest("The request body contains more than one JSON value.", nil)
	}
	return nil
}

func writeJSONResponse(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
