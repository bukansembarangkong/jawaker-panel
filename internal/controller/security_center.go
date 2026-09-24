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
	"github.com/bukansembarangkong/jawaker-panel/internal/nodes"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/bukansembarangkong/jawaker-panel/internal/security"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SecurityCenterHandlerOptions configures the security-center HTTP surface.
type SecurityCenterHandlerOptions struct {
	Security   *security.Store
	Pool       *pgxpool.Pool
	Dispatcher *nodes.Dispatcher
	Logger     *slog.Logger
	Audit      audit.Execer
	Now        func() time.Time
}

// SecurityCenterHandlers holds the security-center HTTP handlers.
type SecurityCenterHandlers struct {
	store       *security.Store
	pool        *pgxpool.Pool
	dispatcher  *nodes.Dispatcher
	logger      *slog.Logger
	auditExecer audit.Execer
	now         func() time.Time
}

// NewSecurityCenterHandlers builds the security-center handlers.
func NewSecurityCenterHandlers(opts SecurityCenterHandlerOptions) (*SecurityCenterHandlers, error) {
	if opts.Security == nil {
		return nil, errors.New("controller: security store is required")
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
	return &SecurityCenterHandlers{
		store:       opts.Security,
		pool:        opts.Pool,
		dispatcher:  opts.Dispatcher,
		logger:      opts.Logger,
		auditExecer: opts.Audit,
		now:         now,
	}, nil
}

// Routes registers the security-center endpoints on the mux.
//
// All routes are server-scoped. Permissions:
//   - security.read  — read findings, posture, events, bans, WAF rules
//   - security.manage — manage bans and WAF rules (step-up required)
func (h *SecurityCenterHandlers) Routes(mux *http.ServeMux) {
	// Hardening
	mux.HandleFunc("GET /api/v1/servers/{server_id}/security/hardening", h.handleListChecks)
	mux.HandleFunc("POST /api/v1/servers/{server_id}/security/hardening/scan", h.handleTriggerScan)

	// SSH posture
	mux.HandleFunc("GET /api/v1/servers/{server_id}/security/ssh-posture", h.handleSSHPosture)

	// Security events
	mux.HandleFunc("GET /api/v1/servers/{server_id}/security/events", h.handleListEvents)

	// Bans
	mux.HandleFunc("GET /api/v1/servers/{server_id}/security/bans", h.handleListBans)
	mux.HandleFunc("POST /api/v1/servers/{server_id}/security/bans", h.handleCreateBan)
	mux.HandleFunc("DELETE /api/v1/servers/{server_id}/security/bans/{id}", h.handleRemoveBan)
	mux.HandleFunc("GET /api/v1/servers/{server_id}/security/bans/live", h.handleLiveBanList)

	// WAF rules
	mux.HandleFunc("GET /api/v1/servers/{server_id}/security/waf-rules", h.handleListWAFRules)
	mux.HandleFunc("POST /api/v1/servers/{server_id}/security/waf-rules", h.handleCreateWAFRule)
	mux.HandleFunc("DELETE /api/v1/servers/{server_id}/security/waf-rules/{id}", h.handleDeleteWAFRule)

	// Under Attack Mode (PRD §21.4)
	mux.HandleFunc("GET /api/v1/servers/{server_id}/security/attack-mode", h.handleGetAttackMode)
	mux.HandleFunc("POST /api/v1/servers/{server_id}/security/attack-mode", h.handleEnableAttackMode)
	mux.HandleFunc("DELETE /api/v1/servers/{server_id}/security/attack-mode", h.handleDisableAttackMode)
}

// ── Audit helpers ──────────────────────────────────────────────────────────────

func (h *SecurityCenterHandlers) recordSecAudit(r *http.Request, ev audit.Event) {
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

// ── Hardening ──────────────────────────────────────────────────────────────────

// GET /api/v1/servers/{server_id}/security/hardening
func (h *SecurityCenterHandlers) handleListChecks(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	stepUp := false
	authsession.RequirePermission(h.now, "security.read", rbac.ServerScope(serverID), stepUp,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			checks, err := h.store.ListChecks(r.Context(), serverID)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"checks":     checks,
				"total":      len(checks),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST /api/v1/servers/{server_id}/security/hardening/scan
func (h *SecurityCenterHandlers) handleTriggerScan(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	stepUp := false
	authsession.RequirePermission(h.now, "security.read", rbac.ServerScope(serverID), stepUp,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.dispatcher == nil {
				httpserver.WriteError(w, r, apierr.Internal(errors.New("dispatcher not available")))
				return
			}
			var req struct {
				Categories []string `json:"categories"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			requestID := httpserver.RequestIDFromRequest(r)
			result, err := h.dispatcher.SecHardeningScan(r.Context(), serverID, requestID,
				nodewire.SecHardeningScanInput{Categories: req.Categories})
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			// Persist findings.
			for _, f := range result.Findings {
				_, _ = h.store.UpsertCheck(r.Context(), security.UpsertCheckParams{
					ServerID:    serverID,
					CheckName:   f.CheckName,
					Category:    f.Category,
					Severity:    f.Severity,
					Status:      f.Status,
					Title:       f.Title,
					Description: f.Description,
					Remediation: f.Remediation,
				})
			}
			h.recordSecAudit(r, audit.Event{Action: "security.hardening.scan", ResourceID: serverID})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"findings":   result.Findings,
				"total":      result.Total,
				"request_id": requestID,
			})
		})).ServeHTTP(w, r)
}

// ── SSH posture ────────────────────────────────────────────────────────────────

// GET /api/v1/servers/{server_id}/security/ssh-posture
func (h *SecurityCenterHandlers) handleSSHPosture(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	stepUp := false
	authsession.RequirePermission(h.now, "security.read", rbac.ServerScope(serverID), stepUp,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.dispatcher == nil {
				httpserver.WriteError(w, r, apierr.Internal(errors.New("dispatcher not available")))
				return
			}
			requestID := httpserver.RequestIDFromRequest(r)
			result, err := h.dispatcher.SecSSHPosture(r.Context(), serverID, requestID)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			// Persist posture snapshot.
			_, _ = h.store.RecordSSHPosture(r.Context(), security.RecordSSHPostureParams{
				ServerID:         serverID,
				PermitRootLogin:  result.PermitRootLogin,
				PasswordAuth:     result.PasswordAuth,
				PubkeyAuth:       result.PubkeyAuth,
				Port:             result.Port,
				ProtocolVersions: result.ProtocolVersions,
				ActiveSessions:   result.ActiveSessions,
				AuthFailures1h:   result.AuthFailures1h,
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"posture":    result,
				"request_id": requestID,
			})
		})).ServeHTTP(w, r)
}

// ── Security events ────────────────────────────────────────────────────────────

// GET /api/v1/servers/{server_id}/security/events
func (h *SecurityCenterHandlers) handleListEvents(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	stepUp := false
	authsession.RequirePermission(h.now, "security.read", rbac.ServerScope(serverID), stepUp,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			events, err := h.store.ListEvents(r.Context(), serverID)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"events":     events,
				"total":      len(events),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Bans ───────────────────────────────────────────────────────────────────────

// GET /api/v1/servers/{server_id}/security/bans
func (h *SecurityCenterHandlers) handleListBans(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	stepUp := false
	authsession.RequirePermission(h.now, "security.read", rbac.ServerScope(serverID), stepUp,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bans, err := h.store.ListBans(r.Context(), serverID)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"bans":       bans,
				"total":      len(bans),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST /api/v1/servers/{server_id}/security/bans
func (h *SecurityCenterHandlers) handleCreateBan(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	stepUp := true
	authsession.RequirePermission(h.now, "security.manage", rbac.ServerScope(serverID), stepUp,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				IP     string `json:"ip"`
				Reason string `json:"reason"`
				Source string `json:"source"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.IP == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("ip is required", nil))
				return
			}
			ban, err := h.store.CreateBan(r.Context(), security.CreateBanParams{
				ServerID: serverID,
				IP:       req.IP,
				Source:   req.Source,
				Reason:   req.Reason,
			})
			if err != nil {
				if errors.Is(err, security.ErrConflict) {
					httpserver.WriteError(w, r, apierr.Conflict("active ban already exists for this IP", nil))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			// Push ban to node agent (fail2ban/crowdsec/iptables) — best-effort,
			// DB record is the source of truth even if push fails.
			if h.dispatcher != nil {
				requestID := httpserver.RequestIDFromRequest(r)
				src := req.Source
				if src == "" {
					src = "iptables"
				}
				_, _ = h.dispatcher.SecBanAdd(r.Context(), serverID, requestID, nodewire.SecBanAddInput{
					IP:     req.IP,
					Source: src,
					Reason: req.Reason,
				})
			}
			h.recordSecAudit(r, audit.Event{Action: "security.ban.create", ResourceID: ban.ID})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"ban":        ban,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// DELETE /api/v1/servers/{server_id}/security/bans/{id}
func (h *SecurityCenterHandlers) handleRemoveBan(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	id := r.PathValue("id")
	stepUp := true
	authsession.RequirePermission(h.now, "security.manage", rbac.ServerScope(serverID), stepUp,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Fetch IP+source before removing so we can push to node agent.
			var ip, source string
			_ = h.pool.QueryRow(r.Context(), `
				SELECT ip, source FROM bans WHERE id = $1 AND server_id = $2
			`, id, serverID).Scan(&ip, &source)

			if err := h.store.RemoveBan(r.Context(), id); err != nil {
				if errors.Is(err, security.ErrNotFound) {
					httpserver.WriteError(w, r, apierr.NotFound("ban not found"))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			// Push unban to node agent — best-effort.
			if h.dispatcher != nil && ip != "" {
				requestID := httpserver.RequestIDFromRequest(r)
				_, _ = h.dispatcher.SecBanRemove(r.Context(), serverID, requestID, nodewire.SecBanRemoveInput{
					IP:     ip,
					Source: source,
				})
			}
			h.recordSecAudit(r, audit.Event{Action: "security.ban.remove", ResourceID: id})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"deleted":    true,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// GET /api/v1/servers/{server_id}/security/bans/live
func (h *SecurityCenterHandlers) handleLiveBanList(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	stepUp := false
	authsession.RequirePermission(h.now, "security.read", rbac.ServerScope(serverID), stepUp,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.dispatcher == nil {
				httpserver.WriteError(w, r, apierr.Internal(errors.New("dispatcher not available")))
				return
			}
			source := r.URL.Query().Get("source")
			requestID := httpserver.RequestIDFromRequest(r)
			result, err := h.dispatcher.SecBanList(r.Context(), serverID, requestID,
				nodewire.SecBanListInput{Source: source})
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"bans":        result.Bans,
				"total":       result.Total,
				"observed_at": result.ObservedAt,
				"request_id":  requestID,
			})
		})).ServeHTTP(w, r)
}

// ── WAF rules ──────────────────────────────────────────────────────────────────

// GET /api/v1/servers/{server_id}/security/waf-rules
func (h *SecurityCenterHandlers) handleListWAFRules(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	stepUp := false
	authsession.RequirePermission(h.now, "security.read", rbac.ServerScope(serverID), stepUp,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rules, err := h.store.ListWAFRules(r.Context(), serverID)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"rules":      rules,
				"total":      len(rules),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST /api/v1/servers/{server_id}/security/waf-rules
func (h *SecurityCenterHandlers) handleCreateWAFRule(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	stepUp := true
	authsession.RequirePermission(h.now, "security.manage", rbac.ServerScope(serverID), stepUp,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				Kind        string `json:"kind"`
				Pattern     string `json:"pattern"`
				Action      string `json:"action"`
				Enabled     bool   `json:"enabled"`
				Priority    int    `json:"priority"`
				Description string `json:"description"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.Pattern == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("pattern is required", nil))
				return
			}
			rule, err := h.store.CreateWAFRule(r.Context(), security.CreateWAFRuleParams{
				ServerID:    serverID,
				Kind:        req.Kind,
				Pattern:     req.Pattern,
				Action:      req.Action,
				Enabled:     req.Enabled,
				Priority:    req.Priority,
				Description: req.Description,
			})
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordSecAudit(r, audit.Event{Action: "security.waf_rule.create", ResourceID: rule.ID})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"rule":       rule,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// DELETE /api/v1/servers/{server_id}/security/waf-rules/{id}
func (h *SecurityCenterHandlers) handleDeleteWAFRule(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	id := r.PathValue("id")
	stepUp := true
	authsession.RequirePermission(h.now, "security.manage", rbac.ServerScope(serverID), stepUp,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := h.store.DeleteWAFRule(r.Context(), id); err != nil {
				if errors.Is(err, security.ErrNotFound) {
					httpserver.WriteError(w, r, apierr.NotFound("WAF rule not found"))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordSecAudit(r, audit.Event{Action: "security.waf_rule.delete", ResourceID: id})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"deleted":    true,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Under Attack Mode Handlers (PRD §21.4) ───────────────────────────────────

type attackModeStatus struct {
	ServerID            string     `json:"server_id"`
	Enabled             bool       `json:"enabled"`
	RateLimitMultiplier float64    `json:"rate_limit_multiplier"`
	ChallengeSuspicious bool       `json:"challenge_suspicious"`
	RestrictExpensive   bool       `json:"restrict_expensive"`
	ActivatedBy         *string    `json:"activated_by,omitempty"`
	ActivatedAt         *time.Time `json:"activated_at,omitempty"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

func (h *SecurityCenterHandlers) handleGetAttackMode(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	authsession.RequirePermission(h.now, "server.manage", rbac.ServerScope(serverID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var st attackModeStatus
			err := h.pool.QueryRow(r.Context(), `
				SELECT server_id, enabled, rate_limit_multiplier, challenge_suspicious,
				       restrict_expensive, activated_by, activated_at, updated_at
				FROM server_attack_mode WHERE server_id = $1
			`, serverID).Scan(&st.ServerID, &st.Enabled, &st.RateLimitMultiplier,
				&st.ChallengeSuspicious, &st.RestrictExpensive, &st.ActivatedBy,
				&st.ActivatedAt, &st.UpdatedAt)
			if err != nil {
				// Default not active if no row exists yet
				st = attackModeStatus{
					ServerID:            serverID,
					Enabled:             false,
					RateLimitMultiplier: 5.0,
					ChallengeSuspicious: true,
					RestrictExpensive:   true,
					UpdatedAt:           h.now(),
				}
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"attack_mode": st,
				"request_id":  httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *SecurityCenterHandlers) handleEnableAttackMode(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	authsession.RequirePermission(h.now, "server.manage", rbac.ServerScope(serverID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := principalUserID(r)
			_, err := h.pool.Exec(r.Context(), `
				INSERT INTO server_attack_mode (server_id, enabled, activated_by, activated_at, updated_at)
				VALUES ($1, true, $2, now(), now())
				ON CONFLICT (server_id) DO UPDATE SET
					enabled = true,
					activated_by = EXCLUDED.activated_by,
					activated_at = now(),
					updated_at = now()
			`, serverID, userID)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordSecAudit(r, audit.Event{
				Action:     "security.attack_mode.enable",
				ResourceID: serverID,
				Context:    map[string]any{"server_id": serverID},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"enabled":    true,
				"server_id":  serverID,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *SecurityCenterHandlers) handleDisableAttackMode(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	authsession.RequirePermission(h.now, "server.manage", rbac.ServerScope(serverID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := h.pool.Exec(r.Context(), `
				UPDATE server_attack_mode
				SET enabled = false, updated_at = now()
				WHERE server_id = $1
			`, serverID)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordSecAudit(r, audit.Event{
				Action:     "security.attack_mode.disable",
				ResourceID: serverID,
				Context:    map[string]any{"server_id": serverID},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"enabled":    false,
				"server_id":  serverID,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}
