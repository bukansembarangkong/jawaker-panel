package controller

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/containers"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodes"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ContainerHandlerOptions configures the container HTTP surface.
type ContainerHandlerOptions struct {
	Containers *containers.Store
	Pool       *pgxpool.Pool
	Secrets    *secret.Store
	Dispatcher *nodes.Dispatcher
	Logger     *slog.Logger
	Audit      audit.Execer
	Now        func() time.Time
}

// ContainerHandlers holds the container HTTP handlers.
type ContainerHandlers struct {
	containers *containers.Store
	pool       *pgxpool.Pool
	secrets    *secret.Store
	dispatcher *nodes.Dispatcher
	logger     *slog.Logger
	audit      audit.Execer
	now        func() time.Time
}

// NewContainerHandlers builds the container handlers.
func NewContainerHandlers(opts ContainerHandlerOptions) (*ContainerHandlers, error) {
	if opts.Containers == nil {
		return nil, errors.New("controller: containers store is required")
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
	return &ContainerHandlers{
		containers: opts.Containers,
		pool:       opts.Pool,
		secrets:    opts.Secrets,
		dispatcher: opts.Dispatcher,
		logger:     opts.Logger,
		audit:      opts.Audit,
		now:        now,
	}, nil
}

// Routes registers the container endpoints on the mux.
func (h *ContainerHandlers) Routes(mux *http.ServeMux) {
	// Registries — sealed credential store per project
	mux.HandleFunc("GET /api/v1/projects/{project_id}/container-registries", h.handleListRegistries)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/container-registries", h.handleCreateRegistry)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/container-registries/{id}", h.handleGetRegistry)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/container-registries/{id}", h.handleDeleteRegistry)

	// Compose stacks
	mux.HandleFunc("GET /api/v1/projects/{project_id}/container-stacks", h.handleListStacks)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/container-stacks", h.handleCreateStack)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/container-stacks/{id}", h.handleGetStack)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/container-stacks/{id}", h.handleDeleteStack)

	// Containers inventory
	// NOTE: /privileged must be registered BEFORE /{id} so the literal path wins.
	mux.HandleFunc("GET /api/v1/projects/{project_id}/containers/privileged", h.handleListPrivilegedContainers)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/containers", h.handleListContainers)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/containers/{id}", h.handleGetContainer)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/containers/{id}/logs", h.handleContainerLogs)

	// Volumes (read-only inventory)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/container-volumes", h.handleListVolumes)
}

// --- Registries ---------------------------------------------------------------

func (h *ContainerHandlers) handleListRegistries(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "container.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			list, err := h.containers.ListRegistries(r.Context(), projectID)
			if err != nil {
				httpserver.WriteError(w, r, containerErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"registries": registryResponses(list),
				"total":      len(list),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createRegistryRequest struct {
	Name     string `json:"name"`
	Host     string `json:"host"`
	Password string `json:"password"`
}

func (h *ContainerHandlers) handleCreateRegistry(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "container.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createRegistryRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			if req.Name == "" || req.Host == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("name and host are required", nil))
				return
			}
			reg, err := h.containers.CreateRegistry(r.Context(), containers.CreateRegistryParams{
				ProjectID: projectID,
				Name:      req.Name,
				Host:      req.Host,
				Password:  req.Password,
			})
			if err != nil {
				httpserver.WriteError(w, r, containerErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				Action:       "container_registry.created",
				ResourceType: "container_registry",
				ResourceID:   reg.ID,
				Result:       audit.ResultSuccess,
				Context:      map[string]any{"project_id": projectID, "host": reg.Host},
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"registry":   registryResponse(reg),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *ContainerHandlers) handleGetRegistry(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "container.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reg, err := h.containers.GetRegistry(r.Context(), id)
			if err != nil {
				httpserver.WriteError(w, r, containerErr(err))
				return
			}
			if reg.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("The requested registry does not exist."))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"registry":   registryResponse(reg),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *ContainerHandlers) handleDeleteRegistry(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "container.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reg, err := h.containers.GetRegistry(r.Context(), id)
			if err != nil {
				httpserver.WriteError(w, r, containerErr(err))
				return
			}
			if reg.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("The requested registry does not exist."))
				return
			}
			if err := h.containers.DeleteRegistry(r.Context(), id); err != nil {
				httpserver.WriteError(w, r, containerErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				Action:       "container_registry.deleted",
				ResourceType: "container_registry",
				ResourceID:   id,
				Result:       audit.ResultSuccess,
				Context:      map[string]any{"project_id": projectID},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"deleted":    true,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// --- Stacks -------------------------------------------------------------------

func (h *ContainerHandlers) handleListStacks(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "container.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			list, err := h.containers.ListStacks(r.Context(), projectID)
			if err != nil {
				httpserver.WriteError(w, r, containerErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"stacks":     stackResponses(list),
				"total":      len(list),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createStackRequest struct {
	ServerID    string `json:"server_id"`
	Name        string `json:"name"`
	ComposeYAML string `json:"compose_yaml"`
}

func (h *ContainerHandlers) handleCreateStack(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "container.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createStackRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			if req.ServerID == "" || req.Name == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("server_id and name are required", nil))
				return
			}
			stack, err := h.containers.CreateStack(r.Context(), containers.CreateStackParams{
				ProjectID:   projectID,
				ServerID:    req.ServerID,
				Name:        req.Name,
				ComposeYAML: req.ComposeYAML,
			})
			if err != nil {
				httpserver.WriteError(w, r, containerErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				Action:       "container_stack.created",
				ResourceType: "container_stack",
				ResourceID:   stack.ID,
				Result:       audit.ResultSuccess,
				Context:      map[string]any{"project_id": projectID, "server_id": stack.ServerID, "name": stack.Name},
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"stack":      stackResponse(stack),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *ContainerHandlers) handleGetStack(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "container.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			stack, err := h.containers.GetStack(r.Context(), id)
			if err != nil {
				httpserver.WriteError(w, r, containerErr(err))
				return
			}
			if stack.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("The requested stack does not exist."))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"stack":      stackResponse(stack),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *ContainerHandlers) handleDeleteStack(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "container.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			stack, err := h.containers.GetStack(r.Context(), id)
			if err != nil {
				httpserver.WriteError(w, r, containerErr(err))
				return
			}
			if stack.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("The requested stack does not exist."))
				return
			}
			if err := h.containers.DeleteStack(r.Context(), id); err != nil {
				httpserver.WriteError(w, r, containerErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				Action:       "container_stack.deleted",
				ResourceType: "container_stack",
				ResourceID:   id,
				Result:       audit.ResultSuccess,
				Context:      map[string]any{"project_id": projectID},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"deleted":    true,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// --- Containers ---------------------------------------------------------------

func (h *ContainerHandlers) handleListContainers(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "container.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Optional server_id filter via query param.
			serverID := r.URL.Query().Get("server_id")
			list, err := h.containers.ListContainers(r.Context(), projectID, serverID)
			if err != nil {
				httpserver.WriteError(w, r, containerErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"containers": containerResponses(list),
				"total":      len(list),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *ContainerHandlers) handleGetContainer(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "container.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := h.containers.GetContainer(r.Context(), id)
			if err != nil {
				httpserver.WriteError(w, r, containerErr(err))
				return
			}
			if c.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("The requested container does not exist."))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"container":  containerResponse(c),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// handleContainerLogs proxies a live log tail from the node via OpContainerLogs.
func (h *ContainerHandlers) handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "container.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.dispatcher == nil {
				httpserver.WriteError(w, r, apierr.ServiceUnavailable("Node dispatcher is not available on this controller."))
				return
			}
			c, err := h.containers.GetContainer(r.Context(), id)
			if err != nil {
				httpserver.WriteError(w, r, containerErr(err))
				return
			}
			if c.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("The requested container does not exist."))
				return
			}
			if !nodewire.ValidContainerName(c.Name) {
				httpserver.WriteError(w, r, apierr.InvalidRequest(
					"Container name is not safe to pass to the docker CLI.", nil))
				return
			}

			in := nodewire.ContainerLogsInput{
				Name:  c.Name,
				Lines: 200,
			}
			reqID := httpserver.RequestIDFromRequest(r)
			result, logsErr := h.dispatcher.ContainerLogs(r.Context(), c.ServerID, reqID, in)
			if logsErr != nil {
				httpserver.WriteError(w, r, apierr.Internal(logsErr))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"container_id": id,
				"name":         c.Name,
				"lines":        result.Lines,
				"truncated":    result.Truncated,
				"observed_at":  result.ObservedAt,
				"request_id":   reqID,
			})
		})).ServeHTTP(w, r)
}

// handleListPrivilegedContainers lists containers with privileged=true.
func (h *ContainerHandlers) handleListPrivilegedContainers(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "container.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			list, err := h.containers.ListPrivileged(r.Context(), projectID)
			if err != nil {
				httpserver.WriteError(w, r, containerErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"containers": containerResponses(list),
				"total":      len(list),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// --- Volumes ------------------------------------------------------------------

func (h *ContainerHandlers) handleListVolumes(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "container.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			list, err := h.containers.ListVolumes(r.Context(), projectID)
			if err != nil {
				httpserver.WriteError(w, r, containerErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"volumes":    volumeResponses(list),
				"total":      len(list),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// --- Error mapping ------------------------------------------------------------

func containerErr(err error) *apierr.Error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, containers.ErrNotFound):
		return apierr.NotFound("The requested container resource does not exist.")
	case errors.Is(err, containers.ErrConflict):
		return apierr.Conflict("A container resource with that name already exists.", nil)
	case errors.Is(err, containers.ErrInvalid):
		return apierr.InvalidRequest(err.Error(), nil)
	case errors.Is(err, containers.ErrState):
		return apierr.InvalidRequest("The request is not valid for the current lifecycle state.", nil)
	default:
		return apierr.Internal(err)
	}
}

// --- Audit helper -------------------------------------------------------------

func (h *ContainerHandlers) recordAudit(r *http.Request, e audit.Event) {
	if h.audit == nil {
		return
	}
	e.RequestID = httpserver.RequestIDFromRequest(r)
	e.SourceIP = r.RemoteAddr
	e.UserAgent = r.UserAgent()
	if e.ActorType == "" {
		e.ActorType = audit.ActorUser
	}
	if err := audit.Record(r.Context(), h.audit, e); err != nil {
		h.logger.ErrorContext(r.Context(), "audit write failed",
			"error", err, "action", e.Action, "request_id", e.RequestID)
	}
}

// --- Response helpers ---------------------------------------------------------

func registryResponse(r containers.Registry) map[string]any {
	// secret_ref is intentionally not returned; only has_credential is reported.
	out := map[string]any{
		"id":             r.ID,
		"project_id":     r.ProjectID,
		"name":           r.Name,
		"host":           r.Host,
		"has_credential": r.SecretRef != nil,
		"created_at":     r.CreatedAt,
	}
	if r.DeletedAt != nil {
		out["deleted_at"] = *r.DeletedAt
	}
	return out
}

func registryResponses(list []containers.Registry) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, r := range list {
		out = append(out, registryResponse(r))
	}
	return out
}

func stackResponse(s containers.Stack) map[string]any {
	out := map[string]any{
		"id":         s.ID,
		"project_id": s.ProjectID,
		"server_id":  s.ServerID,
		"name":       s.Name,
		"state":      s.State,
		"created_at": s.CreatedAt,
	}
	if s.DeletedAt != nil {
		out["deleted_at"] = *s.DeletedAt
	}
	return out
}

func stackResponses(list []containers.Stack) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, s := range list {
		out = append(out, stackResponse(s))
	}
	return out
}

func containerResponse(c containers.Container) map[string]any {
	out := map[string]any{
		"id":           c.ID,
		"project_id":   c.ProjectID,
		"server_id":    c.ServerID,
		"name":         c.Name,
		"container_id": c.ContainerID,
		"image_ref":    c.ImageRef,
		"state":        c.State,
		"cpu_limit":    c.CPULimit,
		"mem_limit_mb": c.MemLimitMB,
		"privileged":   c.Privileged,
		"health":       c.Health,
		"created_at":   c.CreatedAt,
	}
	if c.StackID != nil {
		out["stack_id"] = *c.StackID
	}
	if c.StartedAt != nil {
		out["started_at"] = *c.StartedAt
	}
	if c.DeletedAt != nil {
		out["deleted_at"] = *c.DeletedAt
	}
	return out
}

func containerResponses(list []containers.Container) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, c := range list {
		out = append(out, containerResponse(c))
	}
	return out
}

func volumeResponse(v containers.Volume) map[string]any {
	out := map[string]any{
		"id":          v.ID,
		"project_id":  v.ProjectID,
		"server_id":   v.ServerID,
		"name":        v.Name,
		"driver":      v.Driver,
		"mount_point": v.MountPoint,
		"created_at":  v.CreatedAt,
	}
	if v.ContainerID != nil {
		out["container_id"] = *v.ContainerID
	}
	if v.SizeBytes != nil {
		out["size_bytes"] = *v.SizeBytes
	}
	if v.DeletedAt != nil {
		out["deleted_at"] = *v.DeletedAt
	}
	return out
}

func volumeResponses(list []containers.Volume) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, v := range list {
		out = append(out, volumeResponse(v))
	}
	return out
}
