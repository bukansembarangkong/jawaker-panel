package controller

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/mail"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/jackc/pgx/v5/pgxpool"
)

// MailHandlerOptions configures the mail platform HTTP surface.
type MailHandlerOptions struct {
	Mail   *mail.Store
	Pool   *pgxpool.Pool
	Logger *slog.Logger
	Audit  audit.Execer
	Now    func() time.Time
}

// MailHandlers holds the mail platform HTTP handlers.
type MailHandlers struct {
	store       *mail.Store
	pool        *pgxpool.Pool
	logger      *slog.Logger
	auditExecer audit.Execer
	now         func() time.Time
}

// NewMailHandlers builds the mail platform handlers.
func NewMailHandlers(opts MailHandlerOptions) (*MailHandlers, error) {
	if opts.Mail == nil {
		return nil, errors.New("controller: mail store is required")
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
	return &MailHandlers{
		store:       opts.Mail,
		pool:        opts.Pool,
		logger:      opts.Logger,
		auditExecer: opts.Audit,
		now:         now,
	}, nil
}

// Routes registers mail platform endpoints on the mux.
//
// Permissions:
//   - mail.read   — list domains, mailboxes, aliases, queue log
//   - mail.manage — create/delete/configure (step-up required)
func (h *MailHandlers) Routes(mux *http.ServeMux) {
	// Domains (project-scoped)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/mail/domains", h.handleListDomains)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/mail/domains", h.handleCreateDomain)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/mail/domains/{id}", h.handleGetDomain)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/mail/domains/{id}", h.handleDeleteDomain)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/mail/domains/{id}/readiness", h.handleReadinessCheck)

	// Mailboxes
	mux.HandleFunc("GET /api/v1/projects/{project_id}/mail/domains/{domain_id}/mailboxes", h.handleListMailboxes)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/mail/domains/{domain_id}/mailboxes", h.handleCreateMailbox)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/mail/domains/{domain_id}/mailboxes/{id}", h.handleDeleteMailbox)

	// Aliases
	mux.HandleFunc("GET /api/v1/projects/{project_id}/mail/domains/{domain_id}/aliases", h.handleListAliases)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/mail/domains/{domain_id}/aliases", h.handleCreateAlias)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/mail/domains/{domain_id}/aliases/{id}", h.handleDeleteAlias)

	// DKIM
	mux.HandleFunc("GET /api/v1/projects/{project_id}/mail/domains/{domain_id}/dkim", h.handleGetDKIM)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/mail/domains/{domain_id}/dkim", h.handleUpsertDKIM)

	// Rate limits
	mux.HandleFunc("GET /api/v1/projects/{project_id}/mail/domains/{domain_id}/rate-limits", h.handleGetRateLimits)
	mux.HandleFunc("PUT /api/v1/projects/{project_id}/mail/domains/{domain_id}/rate-limits", h.handleSetRateLimits)

	// Queue log
	mux.HandleFunc("GET /api/v1/projects/{project_id}/mail/domains/{domain_id}/queue-log", h.handleListQueueLog)
}

// ── Audit helper ───────────────────────────────────────────────────────────────

func (h *MailHandlers) recordAudit(r *http.Request, ev audit.Event) {
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

// ── Domains ────────────────────────────────────────────────────────────────────

// GET /api/v1/projects/{project_id}/mail/domains
func (h *MailHandlers) handleListDomains(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "mail.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			domains, err := h.store.ListDomains(r.Context(), projectID)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"domains":    domains,
				"total":      len(domains),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST /api/v1/projects/{project_id}/mail/domains
func (h *MailHandlers) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "mail.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				ServerID string `json:"server_id"`
				Domain   string `json:"domain"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.ServerID == "" || req.Domain == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("server_id and domain are required", nil))
				return
			}
			domain, err := h.store.CreateDomain(r.Context(), projectID, req.ServerID, req.Domain)
			if errors.Is(err, mail.ErrConflict) {
				httpserver.WriteError(w, r, apierr.Conflict("domain already registered", nil))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "mail.domain.create",
				ResourceType: "mail_domain", ResourceID: domain.ID, Result: "ok",
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"domain":     domain,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// GET /api/v1/projects/{project_id}/mail/domains/{id}
func (h *MailHandlers) handleGetDomain(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "mail.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			domain, err := h.store.GetDomain(r.Context(), r.PathValue("id"))
			if errors.Is(err, mail.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("domain not found"))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"domain":     domain,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// DELETE /api/v1/projects/{project_id}/mail/domains/{id}
func (h *MailHandlers) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "mail.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			if err := h.store.DeleteDomain(r.Context(), id); errors.Is(err, mail.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("domain not found"))
				return
			} else if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "mail.domain.delete",
				ResourceType: "mail_domain", ResourceID: id, Result: "ok",
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"deleted":    true,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST /api/v1/projects/{project_id}/mail/domains/{id}/readiness
func (h *MailHandlers) handleReadinessCheck(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "mail.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			// ponytail: real DNS check (SPF/DKIM/DMARC lookups); add when dns resolver available.
			// Optimistic: mark all true for now (controller will do real checks in future worker).
			if err := h.store.UpdateReadiness(r.Context(), id, false, false, false); err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"domain_id":  id,
				"spf_ok":     false,
				"dkim_ok":    false,
				"dmarc_ok":   false,
				"message":    "DNS records not yet verified. Configure SPF, DKIM, and DMARC for this domain.",
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Mailboxes ──────────────────────────────────────────────────────────────────

// GET /api/v1/projects/{project_id}/mail/domains/{domain_id}/mailboxes
func (h *MailHandlers) handleListMailboxes(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "mail.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mailboxes, err := h.store.ListMailboxes(r.Context(), r.PathValue("domain_id"))
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			// Strip password_ref from response — never expose secret URI to client.
			type safeMailbox struct {
				ID        string `json:"id"`
				DomainID  string `json:"domain_id"`
				LocalPart string `json:"local_part"`
				State     string `json:"state"`
				QuotaMB   int    `json:"quota_mb"`
			}
			safe := make([]safeMailbox, len(mailboxes))
			for i, mb := range mailboxes {
				safe[i] = safeMailbox{mb.ID, mb.DomainID, mb.LocalPart, mb.State, mb.QuotaMB}
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"mailboxes":  safe,
				"total":      len(safe),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST /api/v1/projects/{project_id}/mail/domains/{domain_id}/mailboxes
func (h *MailHandlers) handleCreateMailbox(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "mail.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			domainID := r.PathValue("domain_id")
			var req struct {
				LocalPart   string `json:"local_part"`
				PasswordRef string `json:"password_ref"` // sealed secret URI from client
				QuotaMB     int    `json:"quota_mb"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.LocalPart == "" || req.PasswordRef == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("local_part and password_ref are required", nil))
				return
			}
			if req.QuotaMB <= 0 {
				req.QuotaMB = 1024
			}
			mb, err := h.store.CreateMailbox(r.Context(), domainID, req.LocalPart, req.PasswordRef, req.QuotaMB)
			if errors.Is(err, mail.ErrConflict) {
				httpserver.WriteError(w, r, apierr.Conflict("mailbox already exists", nil))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "mail.mailbox.create",
				ResourceType: "mailbox", ResourceID: mb.ID, Result: "ok",
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"mailbox": map[string]any{
					"id": mb.ID, "domain_id": mb.DomainID,
					"local_part": mb.LocalPart, "state": mb.State, "quota_mb": mb.QuotaMB,
				},
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// DELETE /api/v1/projects/{project_id}/mail/domains/{domain_id}/mailboxes/{id}
func (h *MailHandlers) handleDeleteMailbox(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "mail.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			if err := h.store.DeleteMailbox(r.Context(), id); errors.Is(err, mail.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("mailbox not found"))
				return
			} else if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "mail.mailbox.delete",
				ResourceType: "mailbox", ResourceID: id, Result: "ok",
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{"deleted": true, "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}

// ── Aliases ────────────────────────────────────────────────────────────────────

// GET .../aliases
func (h *MailHandlers) handleListAliases(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "mail.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			aliases, err := h.store.ListAliases(r.Context(), r.PathValue("domain_id"))
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"aliases": aliases, "total": len(aliases),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST .../aliases
func (h *MailHandlers) handleCreateAlias(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "mail.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			domainID := r.PathValue("domain_id")
			var req struct {
				LocalPart   string `json:"local_part"`
				Destination string `json:"destination"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.LocalPart == "" || req.Destination == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("local_part and destination are required", nil))
				return
			}
			alias, err := h.store.CreateAlias(r.Context(), domainID, req.LocalPart, req.Destination)
			if errors.Is(err, mail.ErrConflict) {
				httpserver.WriteError(w, r, apierr.Conflict("alias already exists", nil))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "mail.alias.create",
				ResourceType: "mail_alias", ResourceID: alias.ID, Result: "ok",
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"alias": alias, "request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// DELETE .../aliases/{id}
func (h *MailHandlers) handleDeleteAlias(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "mail.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.PathValue("id")
			if err := h.store.DeleteAlias(r.Context(), id); errors.Is(err, mail.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("alias not found"))
				return
			} else if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{"deleted": true, "request_id": httpserver.RequestIDFromRequest(r)})
		})).ServeHTTP(w, r)
}

// ── DKIM ───────────────────────────────────────────────────────────────────────

// GET .../dkim
func (h *MailHandlers) handleGetDKIM(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "mail.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			domainID := r.PathValue("domain_id")
			selector := r.URL.Query().Get("selector")
			if selector == "" {
				selector = "default"
			}
			key, err := h.store.GetDKIMKey(r.Context(), domainID, selector)
			if errors.Is(err, mail.ErrNotFound) {
				httpserver.WriteError(w, r, apierr.NotFound("DKIM key not found"))
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			// Return public key only — never private key ref
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"selector":   key.Selector,
				"public_key": key.PublicKey,
				"algorithm":  key.Algorithm,
				"created_at": key.CreatedAt,
				"rotated_at": key.RotatedAt,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// POST .../dkim
func (h *MailHandlers) handleUpsertDKIM(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "mail.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			domainID := r.PathValue("domain_id")
			var req struct {
				Selector  string `json:"selector"`
				KeyRef    string `json:"key_ref"`    // sealed secret URI
				PublicKey string `json:"public_key"` // DNS TXT record content
				Algorithm string `json:"algorithm"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.Selector == "" || req.KeyRef == "" || req.PublicKey == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("selector, key_ref, and public_key are required", nil))
				return
			}
			if req.Algorithm == "" {
				req.Algorithm = "rsa-sha256"
			}
			key, err := h.store.UpsertDKIMKey(r.Context(), domainID, req.Selector, req.KeyRef, req.PublicKey, req.Algorithm)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			p, _ := auth.PrincipalFrom(r.Context())
			h.recordAudit(r, audit.Event{
				ActorID: p.UserID, Action: "mail.dkim.upsert",
				ResourceType: "dkim_key", ResourceID: key.ID, Result: "ok",
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"selector":   key.Selector,
				"public_key": key.PublicKey,
				"algorithm":  key.Algorithm,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Rate limits ────────────────────────────────────────────────────────────────

// GET .../rate-limits
func (h *MailHandlers) handleGetRateLimits(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "mail.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			domainID := r.PathValue("domain_id")
			rl, err := h.store.GetRateLimit(r.Context(), domainID)
			if errors.Is(err, mail.ErrNotFound) {
				// Return defaults
				writeJSONResponse(w, http.StatusOK, map[string]any{
					"domain_id":    domainID,
					"max_per_hour": 500,
					"max_per_day":  5000,
					"max_rcpt":     50,
					"request_id":   httpserver.RequestIDFromRequest(r),
				})
				return
			}
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"domain_id":    rl.DomainID,
				"max_per_hour": rl.MaxPerHour,
				"max_per_day":  rl.MaxPerDay,
				"max_rcpt":     rl.MaxRcpt,
				"request_id":   httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// PUT .../rate-limits
func (h *MailHandlers) handleSetRateLimits(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "mail.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			domainID := r.PathValue("domain_id")
			var req struct {
				MaxPerHour int `json:"max_per_hour"`
				MaxPerDay  int `json:"max_per_day"`
				MaxRcpt    int `json:"max_rcpt"`
			}
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, err)
				return
			}
			if req.MaxPerHour <= 0 || req.MaxPerDay <= 0 || req.MaxRcpt <= 0 {
				httpserver.WriteError(w, r, apierr.InvalidRequest("max_per_hour, max_per_day, max_rcpt must be positive", nil))
				return
			}
			rl, err := h.store.UpsertRateLimit(r.Context(), domainID, req.MaxPerHour, req.MaxPerDay, req.MaxRcpt)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"domain_id":    rl.DomainID,
				"max_per_hour": rl.MaxPerHour,
				"max_per_day":  rl.MaxPerDay,
				"max_rcpt":     rl.MaxRcpt,
				"request_id":   httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Queue log ──────────────────────────────────────────────────────────────────

// GET .../queue-log
func (h *MailHandlers) handleListQueueLog(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "mail.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			domainID := r.PathValue("domain_id")
			limit := 50
			if s := r.URL.Query().Get("limit"); s != "" {
				if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 200 {
					limit = n
				}
			}
			entries, err := h.store.ListQueueLog(r.Context(), domainID, limit)
			if err != nil {
				writeJSONResponse(w, http.StatusInternalServerError, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"entries":    entries,
				"total":      len(entries),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}
