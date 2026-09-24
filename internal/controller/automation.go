// Package controller: automation rules and outbound webhooks (PRD §26.4, §26.5).
//
// Endpoints:
//
//	GET    /api/v1/automation/rules         — list rules
//	POST   /api/v1/automation/rules         — create rule
//	PATCH  /api/v1/automation/rules/{id}    — update rule (toggle/edit)
//	DELETE /api/v1/automation/rules/{id}    — delete rule
//	POST   /api/v1/automation/rules/{id}/test — simulate trigger
//
//	GET    /api/v1/webhooks/outbound                    — list outbound webhooks
//	POST   /api/v1/webhooks/outbound                    — create
//	PATCH  /api/v1/webhooks/outbound/{id}               — update
//	DELETE /api/v1/webhooks/outbound/{id}               — delete
//	GET    /api/v1/webhooks/outbound/{id}/deliveries    — delivery history
//	POST   /api/v1/webhooks/outbound/{id}/test          — send test ping
package controller

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AutomationHandlerOptions struct {
	Pool   *pgxpool.Pool
	Logger *slog.Logger
	Audit  audit.Execer
	Now    func() time.Time
}

type AutomationHandlers struct {
	pool   *pgxpool.Pool
	logger *slog.Logger
	audit  audit.Execer
	now    func() time.Time
}

func NewAutomationHandlers(opts AutomationHandlerOptions) (*AutomationHandlers, error) {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &AutomationHandlers{
		pool:   opts.Pool,
		logger: opts.Logger,
		audit:  opts.Audit,
		now:    now,
	}, nil
}

func (h *AutomationHandlers) Routes(mux *http.ServeMux) {
	// Automation Rules
	mux.HandleFunc("GET /api/v1/automation/rules", h.handleListRules)
	mux.HandleFunc("POST /api/v1/automation/rules", h.handleCreateRule)
	mux.HandleFunc("PATCH /api/v1/automation/rules/{id}", h.handleUpdateRule)
	mux.HandleFunc("DELETE /api/v1/automation/rules/{id}", h.handleDeleteRule)
	mux.HandleFunc("POST /api/v1/automation/rules/{id}/test", h.handleTestRule)
	// Outbound Webhooks
	mux.HandleFunc("GET /api/v1/webhooks/outbound", h.handleListWebhooks)
	mux.HandleFunc("POST /api/v1/webhooks/outbound", h.handleCreateWebhook)
	mux.HandleFunc("PATCH /api/v1/webhooks/outbound/{id}", h.handleUpdateWebhook)
	mux.HandleFunc("DELETE /api/v1/webhooks/outbound/{id}", h.handleDeleteWebhook)
	mux.HandleFunc("GET /api/v1/webhooks/outbound/{id}/deliveries", h.handleWebhookDeliveries)
	mux.HandleFunc("POST /api/v1/webhooks/outbound/{id}/test", h.handleTestWebhook)
}

// ── Automation Rules ──────────────────────────────────────────────────────────

type automationRuleRow struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	TriggerEvent    string         `json:"trigger_event"`
	Condition       map[string]any `json:"condition"`
	ActionType      string         `json:"action_type"`
	ActionTarget    map[string]any `json:"action_target"`
	Enabled         bool           `json:"enabled"`
	LastTriggeredAt *time.Time     `json:"last_triggered_at,omitempty"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}

func (h *AutomationHandlers) handleListRules(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rows, err := h.pool.Query(r.Context(), `
				SELECT id, name, trigger_event, condition, action_type, action_target,
				       enabled, last_triggered_at, created_at, updated_at
				FROM automation_rules
				ORDER BY created_at DESC
			`)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			defer rows.Close()
			var rules []automationRuleRow
			for rows.Next() {
				var rule automationRuleRow
				if err := rows.Scan(
					&rule.ID, &rule.Name, &rule.TriggerEvent, &rule.Condition,
					&rule.ActionType, &rule.ActionTarget, &rule.Enabled,
					&rule.LastTriggeredAt, &rule.CreatedAt, &rule.UpdatedAt,
				); err != nil {
					httpserver.WriteError(w, r, apierr.Internal(err))
					return
				}
				rules = append(rules, rule)
			}
			if rows.Err() != nil {
				httpserver.WriteError(w, r, apierr.Internal(rows.Err()))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"rules":      rules,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createAutomationRuleRequest struct {
	Name         string         `json:"name"`
	TriggerEvent string         `json:"trigger_event"`
	Condition    map[string]any `json:"condition"`
	ActionType   string         `json:"action_type"`
	ActionTarget map[string]any `json:"action_target"`
	Enabled      *bool          `json:"enabled"`
}

var validActionTypes = map[string]bool{
	"notify": true, "incident_open": true,
	"job_postpone": true, "service_restart": true,
}

func (h *AutomationHandlers) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createAutomationRuleRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			if req.Name == "" || req.TriggerEvent == "" || req.ActionType == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("name, trigger_event, and action_type are required", nil))
				return
			}
			if !validActionTypes[req.ActionType] {
				httpserver.WriteError(w, r, apierr.InvalidRequest("invalid action_type", nil))
				return
			}
			enabled := true
			if req.Enabled != nil {
				enabled = *req.Enabled
			}
			if req.Condition == nil {
				req.Condition = map[string]any{}
			}
			if req.ActionTarget == nil {
				req.ActionTarget = map[string]any{}
			}
			var id string
			err := h.pool.QueryRow(r.Context(), `
				INSERT INTO automation_rules (name, trigger_event, condition, action_type, action_target, enabled)
				VALUES ($1, $2, $3, $4, $5, $6)
				RETURNING id
			`, req.Name, req.TriggerEvent, req.Condition, req.ActionType, req.ActionTarget, enabled).Scan(&id)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordAuditA(r, audit.Event{
				ActorType: audit.ActorUser, ActorID: principalUserID(r),
				Action: "automation_rule.create", ResourceType: "automation_rule", ResourceID: id,
				Result:  audit.ResultSuccess,
				Context: map[string]any{"trigger_event": req.TriggerEvent, "action_type": req.ActionType},
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"rule_id":    id,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type updateAutomationRuleRequest struct {
	Name         *string        `json:"name"`
	TriggerEvent *string        `json:"trigger_event"`
	Condition    map[string]any `json:"condition"`
	ActionType   *string        `json:"action_type"`
	ActionTarget map[string]any `json:"action_target"`
	Enabled      *bool          `json:"enabled"`
}

func (h *AutomationHandlers) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req updateAutomationRuleRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			_, err := h.pool.Exec(r.Context(), `
				UPDATE automation_rules
				SET
					name          = COALESCE($1, name),
					trigger_event = COALESCE($2, trigger_event),
					condition     = CASE WHEN $3::jsonb IS NOT NULL THEN $3::jsonb ELSE condition END,
					action_type   = COALESCE($4, action_type),
					action_target = CASE WHEN $5::jsonb IS NOT NULL THEN $5::jsonb ELSE action_target END,
					enabled       = COALESCE($6, enabled),
					updated_at    = now()
				WHERE id = $7
			`, req.Name, req.TriggerEvent, req.Condition, req.ActionType, req.ActionTarget, req.Enabled, id)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordAuditA(r, audit.Event{
				ActorType: audit.ActorUser, ActorID: principalUserID(r),
				Action: "automation_rule.update", ResourceType: "automation_rule", ResourceID: id,
				Result: audit.ResultSuccess,
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{"updated": true, "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}

func (h *AutomationHandlers) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := h.pool.Exec(r.Context(), `DELETE FROM automation_rules WHERE id = $1`, id)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordAuditA(r, audit.Event{
				ActorType: audit.ActorUser, ActorID: principalUserID(r),
				Action: "automation_rule.delete", ResourceType: "automation_rule", ResourceID: id,
				Result: audit.ResultSuccess,
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{"deleted": true, "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}

// handleTestRule simulates the trigger without taking destructive action.
func (h *AutomationHandlers) handleTestRule(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var rule automationRuleRow
			err := h.pool.QueryRow(r.Context(), `
				SELECT id, name, trigger_event, condition, action_type, action_target,
				       enabled, last_triggered_at, created_at, updated_at
				FROM automation_rules WHERE id = $1
			`, id).Scan(&rule.ID, &rule.Name, &rule.TriggerEvent, &rule.Condition,
				&rule.ActionType, &rule.ActionTarget, &rule.Enabled,
				&rule.LastTriggeredAt, &rule.CreatedAt, &rule.UpdatedAt)
			if err != nil {
				httpserver.WriteError(w, r, apierr.NotFound("Rule not found"))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"simulated":    true,
				"rule":         rule,
				"would_action": rule.ActionType,
				"request_id":   httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Outbound Webhooks ─────────────────────────────────────────────────────────

type webhookRow struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	TargetURL   string    `json:"target_url"`
	EventFilter []string  `json:"event_filter"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	// secret_token is never returned in list/get responses — security invariant
}

func (h *AutomationHandlers) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rows, err := h.pool.Query(r.Context(), `
				SELECT id, name, target_url, event_filter, enabled, created_at, updated_at
				FROM outbound_webhooks ORDER BY created_at DESC
			`)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			defer rows.Close()
			var webhooks []webhookRow
			for rows.Next() {
				var wh webhookRow
				if err := rows.Scan(&wh.ID, &wh.Name, &wh.TargetURL, &wh.EventFilter, &wh.Enabled, &wh.CreatedAt, &wh.UpdatedAt); err != nil {
					httpserver.WriteError(w, r, apierr.Internal(err))
					return
				}
				webhooks = append(webhooks, wh)
			}
			if rows.Err() != nil {
				httpserver.WriteError(w, r, apierr.Internal(rows.Err()))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"webhooks":   webhooks,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createWebhookRequest struct {
	Name        string   `json:"name"`
	TargetURL   string   `json:"target_url"`
	EventFilter []string `json:"event_filter"`
	Enabled     *bool    `json:"enabled"`
}

func generateWebhookSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (h *AutomationHandlers) handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createWebhookRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			if req.Name == "" || req.TargetURL == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("name and target_url are required", nil))
				return
			}
			secret, err := generateWebhookSecret()
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			enabled := true
			if req.Enabled != nil {
				enabled = *req.Enabled
			}
			if req.EventFilter == nil {
				req.EventFilter = []string{}
			}
			var id string
			err = h.pool.QueryRow(r.Context(), `
				INSERT INTO outbound_webhooks (name, target_url, secret_token, event_filter, enabled)
				VALUES ($1, $2, $3, $4, $5)
				RETURNING id
			`, req.Name, req.TargetURL, secret, req.EventFilter, enabled).Scan(&id)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordAuditA(r, audit.Event{
				ActorType: audit.ActorUser, ActorID: principalUserID(r),
				Action: "outbound_webhook.create", ResourceType: "outbound_webhook", ResourceID: id,
				Result: audit.ResultSuccess,
			})
			// Return secret ONCE at creation — cannot be retrieved again
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"webhook_id":     id,
				"signing_secret": secret,
				"request_id":     httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type updateWebhookRequest struct {
	Name        *string  `json:"name"`
	TargetURL   *string  `json:"target_url"`
	EventFilter []string `json:"event_filter"`
	Enabled     *bool    `json:"enabled"`
}

func (h *AutomationHandlers) handleUpdateWebhook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req updateWebhookRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			_, err := h.pool.Exec(r.Context(), `
				UPDATE outbound_webhooks
				SET
					name         = COALESCE($1, name),
					target_url   = COALESCE($2, target_url),
					enabled      = COALESCE($3, enabled),
					updated_at   = now()
				WHERE id = $4
			`, req.Name, req.TargetURL, req.Enabled, id)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{"updated": true, "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}

func (h *AutomationHandlers) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := h.pool.Exec(r.Context(), `DELETE FROM outbound_webhooks WHERE id = $1`, id)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordAuditA(r, audit.Event{
				ActorType: audit.ActorUser, ActorID: principalUserID(r),
				Action: "outbound_webhook.delete", ResourceType: "outbound_webhook", ResourceID: id,
				Result: audit.ResultSuccess,
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{"deleted": true, "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}

func (h *AutomationHandlers) handleWebhookDeliveries(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rows, err := h.pool.Query(r.Context(), `
				SELECT id, webhook_id, event, payload, status, status_code,
				       error_message, attempt_count, max_attempts, delivered_at, created_at
				FROM outbound_webhook_deliveries
				WHERE webhook_id = $1
				ORDER BY created_at DESC
				LIMIT 50
			`, id)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			defer rows.Close()

			type deliveryRow struct {
				ID           string         `json:"id"`
				WebhookID    string         `json:"webhook_id"`
				Event        string         `json:"event"`
				Payload      map[string]any `json:"payload"`
				Status       string         `json:"status"`
				StatusCode   *int           `json:"status_code,omitempty"`
				ErrorMessage *string        `json:"error_message,omitempty"`
				AttemptCount int            `json:"attempt_count"`
				MaxAttempts  int            `json:"max_attempts"`
				DeliveredAt  *time.Time     `json:"delivered_at,omitempty"`
				CreatedAt    time.Time      `json:"created_at"`
			}

			var deliveries []deliveryRow
			for rows.Next() {
				var d deliveryRow
				if err := rows.Scan(&d.ID, &d.WebhookID, &d.Event, &d.Payload, &d.Status,
					&d.StatusCode, &d.ErrorMessage, &d.AttemptCount, &d.MaxAttempts,
					&d.DeliveredAt, &d.CreatedAt); err != nil {
					httpserver.WriteError(w, r, apierr.Internal(err))
					return
				}
				deliveries = append(deliveries, d)
			}
			if rows.Err() != nil {
				httpserver.WriteError(w, r, apierr.Internal(rows.Err()))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"deliveries": deliveries,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// handleTestWebhook sends a test ping with correct HMAC signature to verify the endpoint.
func (h *AutomationHandlers) handleTestWebhook(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var targetURL, secret string
			err := h.pool.QueryRow(r.Context(), `
				SELECT target_url, secret_token FROM outbound_webhooks WHERE id = $1
			`, id).Scan(&targetURL, &secret)
			if err != nil {
				httpserver.WriteError(w, r, apierr.NotFound("Webhook not found"))
				return
			}
			payload := []byte(`{"event":"webhook.test","source":"jawaker"}`)
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(payload)
			sig := hex.EncodeToString(mac.Sum(nil))
			// Enqueue delivery row for test; actual dispatch done by webhook worker
			var deliveryID string
			_ = h.pool.QueryRow(r.Context(), `
				INSERT INTO outbound_webhook_deliveries (webhook_id, event, payload)
				VALUES ($1, 'webhook.test', '{"event":"webhook.test"}'::jsonb)
				RETURNING id
			`, id).Scan(&deliveryID)
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"enqueued":          true,
				"target_url":        targetURL,
				"signature_preview": "sha256=" + sig[:8] + "…",
				"delivery_id":       deliveryID,
				"request_id":        httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *AutomationHandlers) recordAuditA(r *http.Request, event audit.Event) {
	if h.audit == nil {
		return
	}
	event.RequestID = httpserver.RequestIDFromRequest(r)
	event.SourceIP = r.RemoteAddr
	event.UserAgent = r.UserAgent()
	_ = audit.Record(r.Context(), h.audit, event)
}
