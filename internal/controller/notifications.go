// Package controller: notification channel + route management endpoints (PRD §26.4 / §27).
//
// Endpoints:
//
//	GET    /api/v1/notifications/channels          — list channels
//	POST   /api/v1/notifications/channels          — create channel
//	GET    /api/v1/notifications/channels/{id}     — get channel
//	PATCH  /api/v1/notifications/channels/{id}     — update channel
//	DELETE /api/v1/notifications/channels/{id}     — delete channel
//	POST   /api/v1/notifications/channels/{id}/test — test channel
//
//	GET    /api/v1/notifications/inbox             — user's inbox (delivered)
//	POST   /api/v1/notifications/inbox/{id}/read   — mark read
//	GET    /api/v1/notifications/inbox/unread      — unread count
//
//	GET    /api/v1/notifications/routes            — user's routes
//	POST   /api/v1/notifications/routes            — add route
//	DELETE /api/v1/notifications/routes/{id}       — remove route
package controller

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/notify"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/jackc/pgx/v5/pgxpool"
)

type NotifyHandlerOptions struct {
	Pool   *pgxpool.Pool
	Logger *slog.Logger
	Audit  audit.Execer
	Now    func() time.Time
}

type NotifyHandlers struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
	audit  audit.Execer
	now    func() time.Time
}

func NewNotifyHandlers(opts NotifyHandlerOptions) (*NotifyHandlers, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &NotifyHandlers{
		pool:   opts.Pool,
		logger: opts.Logger,
		audit:  opts.Audit,
		now:    now,
	}, nil
}

func (h *NotifyHandlers) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/notifications/channels", h.handleListChannels)
	mux.HandleFunc("POST /api/v1/notifications/channels", h.handleCreateChannel)
	mux.HandleFunc("GET /api/v1/notifications/channels/{id}", h.handleGetChannel)
	mux.HandleFunc("PATCH /api/v1/notifications/channels/{id}", h.handleUpdateChannel)
	mux.HandleFunc("DELETE /api/v1/notifications/channels/{id}", h.handleDeleteChannel)
	mux.HandleFunc("POST /api/v1/notifications/channels/{id}/test", h.handleTestChannel)
	mux.HandleFunc("GET /api/v1/notifications/inbox", h.handleInbox)
	mux.HandleFunc("POST /api/v1/notifications/inbox/{id}/read", h.handleMarkRead)
	mux.HandleFunc("GET /api/v1/notifications/inbox/unread", h.handleUnreadCount)
	mux.HandleFunc("GET /api/v1/notifications/routes", h.handleListRoutes)
	mux.HandleFunc("POST /api/v1/notifications/routes", h.handleCreateRoute)
	mux.HandleFunc("DELETE /api/v1/notifications/routes/{id}", h.handleDeleteRoute)
}

// ── Channels ──────────────────────────────────────────────────────────────────

type channelRow struct {
	ID        string         `json:"id"`
	Type      string         `json:"type"`
	Name      string         `json:"name"`
	Config    map[string]any `json:"config"`
	Enabled   bool           `json:"enabled"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
}

func (h *NotifyHandlers) handleListChannels(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rows, err := h.pool.Query(r.Context(), `
				SELECT id, type, name, config, enabled, created_at, updated_at
				FROM notification_channels
				ORDER BY created_at DESC
			`)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			defer rows.Close()
			var channels []channelRow
			for rows.Next() {
				var c channelRow
				if err := rows.Scan(&c.ID, &c.Type, &c.Name, &c.Config, &c.Enabled, &c.CreatedAt, &c.UpdatedAt); err != nil {
					httpserver.WriteError(w, r, apierr.Internal(err))
					return
				}
				channels = append(channels, c)
			}
			if rows.Err() != nil {
				httpserver.WriteError(w, r, apierr.Internal(rows.Err()))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"channels":   channels,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createChannelRequest struct {
	Type    string         `json:"type"`
	Name    string         `json:"name"`
	Config  map[string]any `json:"config"`
	Enabled *bool          `json:"enabled"`
}

func (h *NotifyHandlers) handleCreateChannel(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createChannelRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			if req.Type == "" || req.Name == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("type and name are required", nil))
				return
			}
			validTypes := map[string]bool{
				"in_panel": true, "email": true, "telegram": true,
				"webhook": true, "discord": true, "slack": true,
			}
			if !validTypes[req.Type] {
				httpserver.WriteError(w, r, apierr.InvalidRequest("invalid channel type", nil))
				return
			}
			enabled := true
			if req.Enabled != nil {
				enabled = *req.Enabled
			}
			if req.Config == nil {
				req.Config = map[string]any{}
			}
			var id string
			err := h.pool.QueryRow(r.Context(), `
				INSERT INTO notification_channels (type, name, config, enabled)
				VALUES ($1, $2, $3, $4)
				RETURNING id
			`, req.Type, req.Name, req.Config, enabled).Scan(&id)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordAuditN(r, audit.Event{
				ActorType: audit.ActorUser, ActorID: principalUserID(r),
				Action: "notification_channel.create", ResourceType: "notification_channel", ResourceID: id,
				Result:  audit.ResultSuccess,
				Context: map[string]any{"type": req.Type, "name": req.Name},
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"channel_id": id,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *NotifyHandlers) handleGetChannel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var c channelRow
			err := h.pool.QueryRow(r.Context(), `
				SELECT id, type, name, config, enabled, created_at, updated_at
				FROM notification_channels WHERE id = $1
			`, id).Scan(&c.ID, &c.Type, &c.Name, &c.Config, &c.Enabled, &c.CreatedAt, &c.UpdatedAt)
			if err != nil {
				httpserver.WriteError(w, r, apierr.NotFound("Channel not found"))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"channel":    c,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type updateChannelRequest struct {
	Name    *string        `json:"name"`
	Config  map[string]any `json:"config"`
	Enabled *bool          `json:"enabled"`
}

func (h *NotifyHandlers) handleUpdateChannel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req updateChannelRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			_, err := h.pool.Exec(r.Context(), `
				UPDATE notification_channels
				SET
					name       = COALESCE($1, name),
					config     = CASE WHEN $2::jsonb IS NOT NULL THEN $2::jsonb ELSE config END,
					enabled    = COALESCE($3, enabled),
					updated_at = now()
				WHERE id = $4
			`, req.Name, req.Config, req.Enabled, id)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordAuditN(r, audit.Event{
				ActorType: audit.ActorUser, ActorID: principalUserID(r),
				Action: "notification_channel.update", ResourceType: "notification_channel", ResourceID: id,
				Result: audit.ResultSuccess,
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"updated":    true,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *NotifyHandlers) handleDeleteChannel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := h.pool.Exec(r.Context(), `DELETE FROM notification_channels WHERE id = $1`, id)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordAuditN(r, audit.Event{
				ActorType: audit.ActorUser, ActorID: principalUserID(r),
				Action: "notification_channel.delete", ResourceType: "notification_channel", ResourceID: id,
				Result: audit.ResultSuccess,
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"deleted":    true,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// handleTestChannel sends a test notification through the specified channel.
func (h *NotifyHandlers) handleTestChannel(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, _ := auth.PrincipalFrom(r.Context())
			result, err := notify.Publish(r.Context(), h.pool, notify.Event{
				Event:    "notification.test",
				Severity: "info",
				Title:    "Test notification",
				Body:     "This is a test from the JAWAKER notification system.",
				Payload:  map[string]any{"channel_id": id, "actor_id": principal.UserID},
			}, notify.PublishOptions{})
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"enqueued":   result.Enqueued,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Inbox ─────────────────────────────────────────────────────────────────────

func (h *NotifyHandlers) handleInbox(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, _ := auth.PrincipalFrom(r.Context())
			deliveries, err := notify.Inbox(r.Context(), h.pool, principal.UserID, 50)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"deliveries": deliveries,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *NotifyHandlers) handleMarkRead(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := notify.MarkRead(r.Context(), h.pool, id); err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"read":       true,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *NotifyHandlers) handleUnreadCount(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, _ := auth.PrincipalFrom(r.Context())
			count, err := notify.UnreadCount(r.Context(), h.pool, principal.UserID)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"unread_count": count,
				"request_id":   httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Routes ────────────────────────────────────────────────────────────────────

type notifyRouteRow struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	ChannelID   string    `json:"channel_id"`
	ChannelName string    `json:"channel_name"`
	ChannelType string    `json:"channel_type"`
	MinSeverity string    `json:"min_severity"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

func (h *NotifyHandlers) handleListRoutes(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, _ := auth.PrincipalFrom(r.Context())
			rows, err := h.pool.Query(r.Context(), `
				SELECT nr.id, nr.user_id, nr.channel_id, nc.name, nc.type,
				       nr.min_severity, nr.enabled, nr.created_at
				FROM notification_routes nr
				JOIN notification_channels nc ON nc.id = nr.channel_id
				WHERE nr.user_id = $1
				ORDER BY nr.created_at DESC
			`, principal.UserID)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			defer rows.Close()
			var routes []notifyRouteRow
			for rows.Next() {
				var rt notifyRouteRow
				if err := rows.Scan(&rt.ID, &rt.UserID, &rt.ChannelID, &rt.ChannelName, &rt.ChannelType, &rt.MinSeverity, &rt.Enabled, &rt.CreatedAt); err != nil {
					httpserver.WriteError(w, r, apierr.Internal(err))
					return
				}
				routes = append(routes, rt)
			}
			if rows.Err() != nil {
				httpserver.WriteError(w, r, apierr.Internal(rows.Err()))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"routes":     routes,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createRouteRequest struct {
	ChannelID   string `json:"channel_id"`
	MinSeverity string `json:"min_severity"`
}

func (h *NotifyHandlers) handleCreateRoute(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createRouteRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			if req.ChannelID == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("channel_id is required", nil))
				return
			}
			if req.MinSeverity == "" {
				req.MinSeverity = "info"
			}
			principal, _ := auth.PrincipalFrom(r.Context())
			var id string
			err := h.pool.QueryRow(r.Context(), `
				INSERT INTO notification_routes (user_id, channel_id, min_severity)
				VALUES ($1, $2, $3)
				ON CONFLICT (user_id, channel_id) DO UPDATE SET min_severity = EXCLUDED.min_severity
				RETURNING id
			`, principal.UserID, req.ChannelID, req.MinSeverity).Scan(&id)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"route_id":   id,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *NotifyHandlers) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, _ := auth.PrincipalFrom(r.Context())
			_, err := h.pool.Exec(r.Context(), `
				DELETE FROM notification_routes WHERE id = $1 AND user_id = $2
			`, id, principal.UserID)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"deleted":    true,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *NotifyHandlers) recordAuditN(r *http.Request, event audit.Event) {
	if h.audit == nil {
		return
	}
	event.RequestID = httpserver.RequestIDFromRequest(r)
	event.SourceIP = r.RemoteAddr
	event.UserAgent = r.UserAgent()
	_ = audit.Record(r.Context(), h.audit, event)
}
