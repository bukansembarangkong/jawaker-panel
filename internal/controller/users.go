// Package controller: user management endpoints per PRD §5.
//
// Endpoints:
//
//	GET    /api/v1/users             — list users (requires server.manage or owner)
//	POST   /api/v1/users             — invite/create user (owner only)
//	GET    /api/v1/users/{id}        — get user
//	POST   /api/v1/users/{id}/state  — activate or suspend user
//	POST   /api/v1/users/{id}/roles  — bind a role to user
//	DELETE /api/v1/users/{id}/roles/{binding_id} — unbind role
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
	"github.com/bukansembarangkong/jawaker-panel/internal/identity"
	"github.com/bukansembarangkong/jawaker-panel/internal/password"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserHandlerOptions struct {
	Pool           *pgxpool.Pool
	Logger         *slog.Logger
	Audit          audit.Execer
	PasswordParams password.Params
	Now            func() time.Time
}

type UserHandlers struct {
	pool           *pgxpool.Pool
	logger         *slog.Logger
	audit          audit.Execer
	passwordParams password.Params
	now            func() time.Time
}

func NewUserHandlers(opts UserHandlerOptions) (*UserHandlers, error) {
	if opts.Pool == nil {
		return nil, errors.New("controller: user handler pool is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &UserHandlers{
		pool:           opts.Pool,
		logger:         opts.Logger,
		audit:          opts.Audit,
		passwordParams: opts.PasswordParams,
		now:            now,
	}, nil
}

func (h *UserHandlers) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/users", h.handleList)
	mux.HandleFunc("POST /api/v1/users", h.handleCreate)
	mux.HandleFunc("GET /api/v1/users/{id}", h.handleGet)
	mux.HandleFunc("POST /api/v1/users/{id}/state", h.handleSetState)
	mux.HandleFunc("POST /api/v1/users/{id}/roles", h.handleBindRole)
	mux.HandleFunc("DELETE /api/v1/users/{id}/roles/{binding_id}", h.handleUnbindRole)
}

// handleList lists platform users. Requires owner or server.manage.
func (h *UserHandlers) handleList(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rows, err := h.pool.Query(r.Context(), `
				SELECT id, email, display_name, state, account_type, is_owner, last_login_at, created_at
				FROM users
				WHERE deleted_at IS NULL
				ORDER BY created_at DESC
				LIMIT 200
			`)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			defer rows.Close()

			type userRow struct {
				ID          string     `json:"id"`
				Email       string     `json:"email"`
				DisplayName string     `json:"display_name"`
				State       string     `json:"state"`
				AccountType string     `json:"account_type"`
				IsOwner     bool       `json:"is_owner"`
				LastLoginAt *time.Time `json:"last_login_at,omitempty"`
				CreatedAt   time.Time  `json:"created_at"`
			}

			var users []userRow
			for rows.Next() {
				var u userRow
				if err := rows.Scan(&u.ID, &u.Email, &u.DisplayName, &u.State, &u.AccountType, &u.IsOwner, &u.LastLoginAt, &u.CreatedAt); err != nil {
					httpserver.WriteError(w, r, apierr.Internal(err))
					return
				}
				users = append(users, u)
			}
			if rows.Err() != nil {
				httpserver.WriteError(w, r, apierr.Internal(rows.Err()))
				return
			}

			writeJSONResponse(w, http.StatusOK, map[string]any{
				"users":      users,
				"total":      len(users),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type inviteUserRequest struct {
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	Password    string `json:"password"`
	AccountType string `json:"account_type"`
}

// handleCreate creates a new user. Owner only.
func (h *UserHandlers) handleCreate(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req inviteUserRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			if req.Email == "" || req.DisplayName == "" || req.Password == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("email, display_name, and password are required", nil))
				return
			}
			if req.AccountType == "" {
				req.AccountType = "customer"
			}

			params := h.passwordParams
			userID, err := identity.CreateUser(r.Context(), h.pool, identity.CreateUserParams{
				Email:       identity.NormalizeEmail(req.Email),
				DisplayName: req.DisplayName,
				Password:    req.Password,
				AccountType: req.AccountType,
			}, params)
			if err != nil {
				if errors.Is(err, identity.ErrAlreadyExists) {
					httpserver.WriteError(w, r, apierr.Conflict("A user with that email already exists.", nil))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}

			h.recordAudit(r, audit.Event{
				ActorType: audit.ActorUser, ActorID: principalUserID(r),
				Action: "user.create", ResourceType: "user", ResourceID: userID,
				Result:  audit.ResultSuccess,
				Context: map[string]any{"email": req.Email, "account_type": req.AccountType},
			})

			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"user_id":    userID,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// handleGet retrieves a single user by ID.
func (h *UserHandlers) handleGet(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, err := identity.GetUserByID(r.Context(), h.pool, id)
			if err != nil {
				if errors.Is(err, identity.ErrNotFound) {
					httpserver.WriteError(w, r, apierr.NotFound("User not found"))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"user":       u,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type setUserStateRequest struct {
	State string `json:"state"` // "active" or "suspended"
}

// handleSetState activates or suspends a user. Owner only.
func (h *UserHandlers) handleSetState(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req setUserStateRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			if req.State != "active" && req.State != "suspended" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("state must be active or suspended", nil))
				return
			}

			// Prevent owner from being suspended
			target, err := identity.GetUserByID(r.Context(), h.pool, id)
			if err != nil {
				if errors.Is(err, identity.ErrNotFound) {
					httpserver.WriteError(w, r, apierr.NotFound("User not found"))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			if target.IsOwner && req.State == "suspended" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("Platform owner cannot be suspended", nil))
				return
			}

			principal, _ := auth.PrincipalFrom(r.Context())
			if principal.UserID == id && req.State == "suspended" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("You cannot suspend your own account", nil))
				return
			}

			_, err = h.pool.Exec(r.Context(), `UPDATE users SET state = $1 WHERE id = $2`, req.State, id)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}

			h.recordAudit(r, audit.Event{
				ActorType: audit.ActorUser, ActorID: principalUserID(r),
				Action: "user.state_change", ResourceType: "user", ResourceID: id,
				Result:  audit.ResultSuccess,
				Context: map[string]any{"new_state": req.State},
			})

			writeJSONResponse(w, http.StatusOK, map[string]any{
				"user_id":    id,
				"state":      req.State,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type bindRoleRequest struct {
	RoleKey   string `json:"role_key"`
	ScopeType string `json:"scope_type"` // global, server, project
	ScopeID   string `json:"scope_id,omitempty"`
}

// handleBindRole assigns a role to a user.
func (h *UserHandlers) handleBindRole(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req bindRoleRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			if req.RoleKey == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("role_key is required", nil))
				return
			}
			grantedBy := principalUserID(r)
			if err := identity.BindRole(r.Context(), h.pool, id, req.RoleKey, req.ScopeType, req.ScopeID, grantedBy, nil); err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}

			h.recordAudit(r, audit.Event{
				ActorType: audit.ActorUser, ActorID: grantedBy,
				Action: "user.role_bind", ResourceType: "user", ResourceID: id,
				Result:  audit.ResultSuccess,
				Context: map[string]any{"role_key": req.RoleKey, "scope_type": req.ScopeType},
			})

			writeJSONResponse(w, http.StatusOK, map[string]any{
				"bound":      true,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// handleUnbindRole removes a role binding from a user.
func (h *UserHandlers) handleUnbindRole(w http.ResponseWriter, r *http.Request) {
	bindingID := r.PathValue("binding_id")
	authsession.RequirePermission(h.now, "server.manage", rbac.GlobalScope(), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := identity.UnbindRole(r.Context(), h.pool, bindingID); err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}

			h.recordAudit(r, audit.Event{
				ActorType: audit.ActorUser, ActorID: principalUserID(r),
				Action: "user.role_unbind", ResourceType: "user_role_binding", ResourceID: bindingID,
				Result: audit.ResultSuccess,
			})

			writeJSONResponse(w, http.StatusOK, map[string]any{
				"unbound":    true,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *UserHandlers) recordAudit(r *http.Request, event audit.Event) {
	if h.audit == nil {
		return
	}
	event.RequestID = httpserver.RequestIDFromRequest(r)
	event.SourceIP = r.RemoteAddr
	event.UserAgent = r.UserAgent()
	_ = audit.Record(r.Context(), h.audit, event)
}
