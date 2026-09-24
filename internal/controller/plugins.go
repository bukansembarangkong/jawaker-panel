package controller

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/plugins"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PluginHandlerOptions configures the plugin SDK HTTP surface.
type PluginHandlerOptions struct {
	Plugins *plugins.Store
	Pool    *pgxpool.Pool
	Logger  *slog.Logger
	Audit   audit.Execer
	Now     func() time.Time
}

// PluginHandlers holds the plugin SDK HTTP handlers.
type PluginHandlers struct {
	store       *plugins.Store
	pool        *pgxpool.Pool
	logger      *slog.Logger
	auditExecer audit.Execer
	now         func() time.Time
}

// NewPluginHandlers builds the plugin handlers.
func NewPluginHandlers(opts PluginHandlerOptions) (*PluginHandlers, error) {
	if opts.Plugins == nil {
		return nil, errors.New("controller: plugins store is required")
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
	return &PluginHandlers{
		store:       opts.Plugins,
		pool:        opts.Pool,
		logger:      opts.Logger,
		auditExecer: opts.Audit,
		now:         now,
	}, nil
}

// Routes registers plugin SDK endpoints on the mux.
//
// Permissions:
//   - plugins.read   — list/get plugins and their permissions
//   - plugins.manage — install/enable/disable/uninstall (step-up required)
//   - plugins.review — grant permissions, quarantine/restore, set trust level
func (h *PluginHandlers) Routes(mux *http.ServeMux) {
	// Registry
	mux.HandleFunc("GET /api/v1/plugins", h.handleListPlugins)
	mux.HandleFunc("POST /api/v1/plugins", h.handleRegisterPlugin)
	mux.HandleFunc("GET /api/v1/plugins/{id}", h.handleGetPlugin)
	mux.HandleFunc("POST /api/v1/plugins/{id}/enable", h.handleEnablePlugin)
	mux.HandleFunc("POST /api/v1/plugins/{id}/disable", h.handleDisablePlugin)
	mux.HandleFunc("DELETE /api/v1/plugins/{id}", h.handleUninstallPlugin)

	// Trust level (requires review)
	mux.HandleFunc("POST /api/v1/plugins/{id}/trust", h.handleSetTrust)

	// Permissions
	mux.HandleFunc("GET /api/v1/plugins/{id}/permissions", h.handleListPermissions)
	mux.HandleFunc("POST /api/v1/plugins/{id}/permissions/{perm_id}/grant", h.handleGrantPermission)

	// Install history
	mux.HandleFunc("GET /api/v1/plugins/{id}/history", h.handleListHistory)

	// Quarantine
	mux.HandleFunc("POST /api/v1/plugins/{id}/quarantine", h.handleQuarantine)
	mux.HandleFunc("GET /api/v1/plugins/{id}/quarantine", h.handleListQuarantines)
	mux.HandleFunc("POST /api/v1/plugins/{id}/quarantine/{q_id}/resolve", h.handleResolveQuarantine)
}

// ── Audit helper ─────────────────────────────────────────────────────────────

func (h *PluginHandlers) recordAudit(r *http.Request, ev audit.Event) {
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
			"error", err, "action", ev.Action)
	}
}

// ── Registry ─────────────────────────────────────────────────────────────────

// GET /api/v1/plugins
func (h *PluginHandlers) handleListPlugins(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "plugins.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			stateFilter := r.URL.Query().Get("state")
			ps, err := h.store.ListPlugins(r.Context(), stateFilter)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"plugins":    ps,
				"total":      len(ps),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST /api/v1/plugins
func (h *PluginHandlers) handleRegisterPlugin(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "plugins.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Name        string         `json:"name"`
				DisplayName string         `json:"display_name"`
				Description string         `json:"description"`
				Version     string         `json:"version"`
				Author      string         `json:"author"`
				HomepageURL string         `json:"homepage_url"`
				Signature   string         `json:"signature"`
				Checksum    string         `json:"checksum"`
				Manifest    map[string]any `json:"manifest"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.Name == "" || req.Version == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("name and version are required", nil))
				return
			}
			plugin, err := h.store.RegisterPlugin(r.Context(), req.Name, req.DisplayName, req.Description,
				req.Version, req.Author, req.HomepageURL, req.Signature, req.Checksum, req.Manifest)
			if errors.Is(err, plugins.ErrConflict) {
				httpserver.WriteError(w, r, apierr.Conflict("plugin already registered", nil))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			_, _ = h.store.RecordInstallEvent(r.Context(), plugin.ID, "install", "", req.Version, p.UserID, "")
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "plugin.register",
				ResourceType: "plugin", ResourceID: plugin.ID, Result: "ok",
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"plugin":     plugin,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// GET /api/v1/plugins/{id}
func (h *PluginHandlers) handleGetPlugin(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "plugins.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			plugin, err := h.store.GetPlugin(r.Context(), r.PathValue("id"))
			if errors.Is(err, plugins.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("plugin not found"))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"plugin":     plugin,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST /api/v1/plugins/{id}/enable
func (h *PluginHandlers) handleEnablePlugin(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "plugins.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			// Verify not quarantined.
			plugin, err := h.store.GetPlugin(r.Context(), id)
			if errors.Is(err, plugins.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("plugin not found"))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			if plugin.State == "quarantined" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("plugin is quarantined; resolve quarantine first", nil))
				return
			}
			if err := h.store.UpdatePluginState(r.Context(), id, "enabled"); err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			_, _ = h.store.RecordInstallEvent(r.Context(), id, "enable", "", "", p.UserID, "")
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "plugin.enable",
				ResourceType: "plugin", ResourceID: id, Result: "ok",
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{"state": "enabled", "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}

// POST /api/v1/plugins/{id}/disable
func (h *PluginHandlers) handleDisablePlugin(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "plugins.manage", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			if err := h.store.UpdatePluginState(r.Context(), id, "disabled"); errors.Is(err, plugins.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("plugin not found"))
				return
			} else if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			_, _ = h.store.RecordInstallEvent(r.Context(), id, "disable", "", "", p.UserID, "")
			writeJSONResponse(w, http.StatusOK, map[string]any{"state": "disabled", "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}

// DELETE /api/v1/plugins/{id}
func (h *PluginHandlers) handleUninstallPlugin(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "plugins.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			if err := h.store.UpdatePluginState(r.Context(), id, "removed"); errors.Is(err, plugins.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("plugin not found"))
				return
			} else if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			_, _ = h.store.RecordInstallEvent(r.Context(), id, "uninstall", "", "", p.UserID, "")
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "plugin.uninstall",
				ResourceType: "plugin", ResourceID: id, Result: "ok",
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{"removed": true, "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}

// POST /api/v1/plugins/{id}/trust
func (h *PluginHandlers) handleSetTrust(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "plugins.review", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			var req struct {
				TrustLevel string `json:"trust_level"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.TrustLevel == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("trust_level is required", nil))
				return
			}
			if err := h.store.SetTrustLevel(r.Context(), id, req.TrustLevel); errors.Is(err, plugins.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("plugin not found"))
				return
			} else if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "plugin.trust.set",
				ResourceType: "plugin", ResourceID: id, Result: req.TrustLevel,
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{"trust_level": req.TrustLevel, "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}

// ── Permissions ───────────────────────────────────────────────────────────────

// GET /api/v1/plugins/{id}/permissions
func (h *PluginHandlers) handleListPermissions(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "plugins.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			perms, err := h.store.ListPermissions(r.Context(), r.PathValue("id"))
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"permissions": perms,
				"total":       len(perms),
				"request_id":  httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST /api/v1/plugins/{id}/permissions/{perm_id}/grant
func (h *PluginHandlers) handleGrantPermission(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "plugins.review", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			permID := r.PathValue("perm_id")
			p, _ := auth.PrincipalFrom(r.Context())
			if err := h.store.GrantPermission(r.Context(), permID, p.UserID); errors.Is(err, plugins.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("permission not found"))
				return
			} else if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "plugin.permission.grant",
				ResourceType: "plugin_permission", ResourceID: permID, Result: "ok",
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{"granted": true, "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}

// ── History ───────────────────────────────────────────────────────────────────

// GET /api/v1/plugins/{id}/history
func (h *PluginHandlers) handleListHistory(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "plugins.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			events, err := h.store.ListInstallEvents(r.Context(), r.PathValue("id"))
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"events":     events,
				"total":      len(events),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Quarantine ────────────────────────────────────────────────────────────────

// POST /api/v1/plugins/{id}/quarantine
func (h *PluginHandlers) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "plugins.review", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			var req struct {
				Reason string `json:"reason"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.Reason == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("reason is required", nil))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			q, err := h.store.QuarantinePlugin(r.Context(), id, req.Reason, p.UserID)
			if errors.Is(err, plugins.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("plugin not found"))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			_, _ = h.store.RecordInstallEvent(r.Context(), id, "quarantine", "", "", p.UserID, req.Reason)
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "plugin.quarantine",
				ResourceType: "plugin", ResourceID: id, Result: "quarantined",
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"quarantine": q,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// GET /api/v1/plugins/{id}/quarantine
func (h *PluginHandlers) handleListQuarantines(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "plugins.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			qs, err := h.store.ListQuarantines(r.Context(), r.PathValue("id"))
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"quarantines": qs,
				"total":       len(qs),
				"request_id":  httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST /api/v1/plugins/{id}/quarantine/{q_id}/resolve
func (h *PluginHandlers) handleResolveQuarantine(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "plugins.review", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			qID := r.PathValue("q_id")
			pluginID := r.PathValue("id")
			p, _ := auth.PrincipalFrom(r.Context())
			q, err := h.store.ResolveQuarantine(r.Context(), qID, p.UserID)
			if errors.Is(err, plugins.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("quarantine not found"))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			_, _ = h.store.RecordInstallEvent(r.Context(), pluginID, "restore", "", "", p.UserID, "quarantine resolved")
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "plugin.quarantine.resolve",
				ResourceType: "plugin_quarantine", ResourceID: qID, Result: "resolved",
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"quarantine": q,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}
