// Package controller: projects HTTP handlers.
//
// Mounts tenant project endpoints under /api/v1/projects.
//
// Security invariants enforced here:
//   - GET /api/v1/projects requires project.read (GLOBAL scope) or ownership.
//   - POST /api/v1/projects requires project.create (GLOBAL scope).
package controller

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/projects"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ProjectHandlerOptions configures the projects HTTP surface.
type ProjectHandlerOptions struct {
	Projects *projects.Store
	Pool     *pgxpool.Pool
	Logger   *slog.Logger
	Audit    audit.Execer
	Now      func() time.Time
}

// ProjectHandlers holds the projects HTTP surface.
type ProjectHandlers struct {
	projects *projects.Store
	pool     *pgxpool.Pool
	logger   *slog.Logger
	audit    audit.Execer
	now      func() time.Time
}

// NewProjectHandlers builds the project handlers.
func NewProjectHandlers(opts ProjectHandlerOptions) (*ProjectHandlers, error) {
	if opts.Projects == nil {
		return nil, errors.New("controller: projects store is required")
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
	return &ProjectHandlers{
		projects: opts.Projects,
		pool:     opts.Pool,
		logger:   opts.Logger,
		audit:    opts.Audit,
		now:      now,
	}, nil
}

// Routes registers the project endpoints on the mux.
func (h *ProjectHandlers) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/projects", h.handleListProjects)
	mux.HandleFunc("POST /api/v1/projects", h.handleCreateProject)
	mux.HandleFunc("GET /api/v1/projects/{id}", h.handleGetProject)
}

func (h *ProjectHandlers) handleListProjects(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "project.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			limit, offset, apiErr := parsePagination(r)
			if apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			stateFilter := r.URL.Query().Get("state")
			list, total, err := h.projects.List(r.Context(), limit, offset, stateFilter)
			if err != nil {
				httpserver.WriteError(w, r, projectErr(err))
				return
			}
			out := make([]map[string]any, 0, len(list))
			for _, p := range list {
				out = append(out, projectResponse(p))
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"projects":   out,
				"total":      total,
				"limit":      limit,
				"offset":     offset,
				"has_more":   offset+len(list) < total,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createProjectRequest struct {
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
}

func (h *ProjectHandlers) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "project.create", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createProjectRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			p, err := h.projects.Create(r.Context(), projects.CreateParams{
				Slug:        req.Slug,
				Name:        req.Name,
				Description: req.Description,
				CreatedBy:   principalUserID(r),
			})
			if err != nil {
				httpserver.WriteError(w, r, projectErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "project.create",
				ResourceType: "project",
				ResourceID:   p.ID,
				Result:       audit.ResultSuccess,
				Context: map[string]any{
					"slug": p.Slug,
					"name": p.Name,
				},
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"project":    projectResponse(p),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *ProjectHandlers) handleGetProject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "project.read", rbac.ProjectScope(id), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p, err := h.projects.Get(r.Context(), id)
			if err != nil {
				httpserver.WriteError(w, r, projectErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"project":    projectResponse(p),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *ProjectHandlers) recordAudit(r *http.Request, event audit.Event) {
	if h.audit == nil {
		return
	}
	event.RequestID = httpserver.RequestIDFromRequest(r)
	event.SourceIP = r.RemoteAddr
	event.UserAgent = r.UserAgent()
	if err := audit.Record(r.Context(), h.audit, event); err != nil {
		h.logger.ErrorContext(r.Context(), "audit record failed",
			"action", event.Action, "error", err, "request_id", event.RequestID)
	}
}

func projectResponse(p projects.Project) map[string]any {
	out := map[string]any{
		"id":          p.ID,
		"slug":        p.Slug,
		"name":        p.Name,
		"description": p.Description,
		"state":       p.State,
		"created_at":  p.CreatedAt,
		"updated_at":  p.UpdatedAt,
	}
	if p.CreatedBy != nil {
		out["created_by"] = *p.CreatedBy
	}
	if p.DeleteAfter != nil {
		out["delete_after"] = *p.DeleteAfter
	}
	if p.DeletedAt != nil {
		out["deleted_at"] = *p.DeletedAt
	}
	return out
}

func projectErr(err error) *apierr.Error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, projects.ErrNotFound):
		return apierr.NotFound("The requested project does not exist.")
	case errors.Is(err, projects.ErrSlugTaken):
		return apierr.Conflict("A project with that slug already exists.",
			map[string]any{"field": "slug"})
	case errors.Is(err, projects.ErrInvalid):
		return apierr.InvalidRequest(err.Error(), nil)
	case errors.Is(err, projects.ErrState):
		return apierr.InvalidRequest("The requested transition is not valid for the project's current state.", nil)
	default:
		return apierr.Internal(err)
	}
}
