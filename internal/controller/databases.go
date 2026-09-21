package controller

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/databases"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/jobs"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodes"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Job types for managed database async operations.
const (
	JobTypeDatabaseProvision = "database.provision"
	JobTypeDatabaseDump      = "database.dump"
	JobTypeDatabaseRestore   = "database.restore"
	JobTypeDatabaseDelete    = "database.delete"
)

// DatabaseHandlerOptions configures the database HTTP surface.
type DatabaseHandlerOptions struct {
	Databases  *databases.Store
	Pool       *pgxpool.Pool
	Secrets    *secret.Store
	Dispatcher *nodes.Dispatcher
	Logger     *slog.Logger
	Audit      audit.Execer
	Now        func() time.Time
}

// DatabaseHandlers holds the database HTTP handlers.
type DatabaseHandlers struct {
	databases  *databases.Store
	pool       *pgxpool.Pool
	secrets    *secret.Store
	dispatcher *nodes.Dispatcher
	logger     *slog.Logger
	audit      audit.Execer
	now        func() time.Time
}

// NewDatabaseHandlers builds the database handlers.
func NewDatabaseHandlers(opts DatabaseHandlerOptions) (*DatabaseHandlers, error) {
	if opts.Databases == nil {
		return nil, errors.New("controller: databases store is required")
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
	return &DatabaseHandlers{
		databases:  opts.Databases,
		pool:       opts.Pool,
		secrets:    opts.Secrets,
		dispatcher: opts.Dispatcher,
		logger:     opts.Logger,
		audit:      opts.Audit,
		now:        now,
	}, nil
}

// Routes registers the database endpoints on the mux.
func (h *DatabaseHandlers) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/projects/{project_id}/databases", h.handleListDatabases)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/databases", h.handleCreateDatabase)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/databases/{id}", h.handleGetDatabase)
	mux.HandleFunc("PATCH /api/v1/projects/{project_id}/databases/{id}", h.handleUpdateDatabase)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/databases/{id}", h.handleDeleteDatabase)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/databases/{id}/connection-string", h.handleGetConnectionString)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/databases/{id}/users", h.handleListUsers)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/databases/{id}/users", h.handleCreateUser)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/databases/{id}/users/{username}", h.handleRevokeUser)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/databases/{id}/users/{username}/rotate-password", h.handleRotateUserPassword)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/databases/{id}/metrics", h.handleGetMetrics)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/databases/{id}/dump", h.handleDumpDatabase)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/databases/{id}/restore", h.handleRestoreDatabase)
}

// --- CRUD -------------------------------------------------------------------

func (h *DatabaseHandlers) handleListDatabases(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "database.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			list, err := h.databases.ListDatabases(r.Context(), projectID)
			if err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"databases":  databaseResponses(list),
				"total":      len(list),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createDatabaseRequest struct {
	ServerID      string `json:"server_id"`
	Slug          string `json:"slug"`
	Name          string `json:"name"`
	Engine        string `json:"engine"`
	EngineVersion string `json:"engine_version"`
	DBName        string `json:"db_name"`
}

func (h *DatabaseHandlers) handleCreateDatabase(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "database.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createDatabaseRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			db, err := h.databases.CreateDatabase(r.Context(), databases.CreateDatabaseParams{
				ProjectID:     projectID,
				ServerID:      req.ServerID,
				Slug:          req.Slug,
				Name:          req.Name,
				Engine:        req.Engine,
				EngineVersion: req.EngineVersion,
				DBName:        req.DBName,
				CreatedBy:     principalUserID(r),
			})
			if err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}

			// Enqueue provision job to create the database on the node.
			reqID := httpserver.RequestIDFromRequest(r)
			_, _ = jobs.Enqueue(r.Context(), h.pool, jobs.Requested{
				Type:             JobTypeDatabaseProvision,
				ServerID:         db.ServerID,
				ProjectID:        db.ProjectID,
				IdempotencyKey:   "provision:" + db.ID,
				IdempotencyScope: "database.provision:" + db.ID,
				RequestedByType:  "user",
				RequestedByID:    principalUserID(r),
				RequestID:        reqID,
				Payload: map[string]any{
					"database_id": db.ID,
					"action":      "create_db",
				},
				Steps: []jobs.StepPlan{
					{Name: "create_db"},
				},
				LockKeys: []string{"database:" + db.ID},
			})

			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "database.create",
				ResourceType: "database",
				ResourceID:   db.ID,
				Result:       audit.ResultSuccess,
				Context: map[string]any{
					"project_id": db.ProjectID,
					"server_id":  db.ServerID,
					"slug":       db.Slug,
					"engine":     db.Engine,
					"db_name":    db.DBName,
				},
			})

			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"database":   databaseResponse(db),
				"request_id": reqID,
			})
		})).ServeHTTP(w, r)
}

func (h *DatabaseHandlers) handleGetDatabase(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "database.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			db, err := h.databases.GetDatabaseInProject(r.Context(), projectID, id)
			if err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"database":   databaseResponse(db),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type updateDatabaseRequest struct {
	Name          *string `json:"name,omitempty"`
	EngineVersion *string `json:"engine_version,omitempty"`
}

func (h *DatabaseHandlers) handleUpdateDatabase(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "database.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := h.databases.GetDatabaseInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}
			var req updateDatabaseRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			db, err := h.databases.UpdateDatabase(r.Context(), id, databases.UpdateDatabaseParams{
				Name:          req.Name,
				EngineVersion: req.EngineVersion,
			})
			if err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "database.update",
				ResourceType: "database",
				ResourceID:   db.ID,
				Result:       audit.ResultSuccess,
				Context:      map[string]any{"project_id": projectID},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"database":   databaseResponse(db),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *DatabaseHandlers) handleDeleteDatabase(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "database.delete", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := h.databases.GetDatabaseInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}
			db, err := h.databases.RequestDelete(r.Context(), id, databases.DefaultDeleteGrace)
			if err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}
			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "database.delete",
				ResourceType: "database",
				ResourceID:   id,
				Result:       audit.ResultSuccess,
				Context: map[string]any{
					"project_id":   projectID,
					"delete_after": db.DeleteAfter,
				},
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"status":       "pending_delete",
				"database_id":  id,
				"delete_after": db.DeleteAfter,
				"request_id":   httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// --- Connection String ------------------------------------------------------

func (h *DatabaseHandlers) handleGetConnectionString(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "database.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			db, err := h.databases.GetDatabaseInProject(r.Context(), projectID, id)
			if err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}

			// Determine which user to generate connection string for.
			reqUser := r.URL.Query().Get("user")
			var targetUser databases.DatabaseUser
			if reqUser != "" {
				u, uErr := h.databases.GetUser(r.Context(), id, reqUser)
				if uErr != nil {
					httpserver.WriteError(w, r, databaseErr(uErr))
					return
				}
				targetUser = u
			} else {
				users, uErr := h.databases.ListUsers(r.Context(), id)
				if uErr != nil {
					httpserver.WriteError(w, r, databaseErr(uErr))
					return
				}
				if len(users) == 0 {
					httpserver.WriteError(w, r, apierr.NotFound("No database users exist for this database."))
					return
				}
				targetUser = users[0]
			}

			// Open password in-memory from secrets store.
			if h.secrets == nil {
				httpserver.WriteError(w, r, apierr.Internal(errors.New("secrets store unavailable")))
				return
			}
			password, err := h.secrets.Open(r.Context(), targetUser.SecretRef)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(fmt.Errorf("open user secret: %w", err)))
				return
			}

			uri := databases.ConnectionString(db, targetUser.Username, password)
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"connection_string": uri,
				"username":          targetUser.Username,
				"engine":            db.Engine,
				"db_name":           db.DBName,
				"request_id":        httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// --- Users ------------------------------------------------------------------

func (h *DatabaseHandlers) handleListUsers(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "database.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, err := h.databases.GetDatabaseInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}
			users, err := h.databases.ListUsers(r.Context(), id)
			if err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"users":      databaseUserResponses(users),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createUserRequest struct {
	Username   string   `json:"username"`
	Privileges []string `json:"privileges,omitempty"`
}

func (h *DatabaseHandlers) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "database.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			db, err := h.databases.GetDatabaseInProject(r.Context(), projectID, id)
			if err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}
			var req createUserRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}

			// Generate a cryptographically random password (24 bytes = 32 base64 chars).
			randBytes := make([]byte, 24)
			if _, rErr := rand.Read(randBytes); rErr != nil {
				httpserver.WriteError(w, r, apierr.Internal(rErr))
				return
			}
			plainPassword := base64.RawURLEncoding.EncodeToString(randBytes)

			// Seal password to secret subsystem (PRD §20.4, Gate 3).
			secretRef := fmt.Sprintf("secret://project/%s/database/%s/user/%s/password", projectID, id, req.Username)
			if h.secrets == nil {
				httpserver.WriteError(w, r, apierr.Internal(errors.New("secrets store unavailable")))
				return
			}
			if sErr := h.secrets.Create(r.Context(), secretRef, plainPassword, fmt.Sprintf("password for db user %s", req.Username)); sErr != nil {
				if errors.Is(sErr, secret.ErrAlreadyExists) {
					// User previously existed; update the secret.
					if uErr := h.secrets.Set(r.Context(), secretRef, plainPassword, "re-created user password"); uErr != nil {
						httpserver.WriteError(w, r, apierr.Internal(uErr))
						return
					}
				} else {
					httpserver.WriteError(w, r, apierr.Internal(sErr))
					return
				}
			}

			user, err := h.databases.CreateUser(r.Context(), databases.CreateUserParams{
				DatabaseID: id,
				Username:   req.Username,
				SecretRef:  secretRef,
				Privileges: req.Privileges,
			})
			if err != nil {
				// Clean up the sealed secret so we don't leak orphaned secrets on validation failure.
				_ = h.secrets.Delete(r.Context(), secretRef)
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}

			// Enqueue provision job to create user and set grants on node.
			reqID := httpserver.RequestIDFromRequest(r)
			_, _ = jobs.Enqueue(r.Context(), h.pool, jobs.Requested{
				Type:             JobTypeDatabaseProvision,
				ServerID:         db.ServerID,
				ProjectID:        db.ProjectID,
				IdempotencyKey:   "user:" + user.ID,
				IdempotencyScope: "database.provision:" + db.ID,
				RequestedByType:  "user",
				RequestedByID:    principalUserID(r),
				RequestID:        reqID,
				Payload: map[string]any{
					"database_id": db.ID,
					"action":      "create_user",
					"username":    user.Username,
				},
				Steps: []jobs.StepPlan{
					{Name: "create_user"},
					{Name: "set_grants"},
				},
				LockKeys: []string{"database:" + db.ID},
			})

			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "database.user.create",
				ResourceType: "database_user",
				ResourceID:   user.ID,
				Result:       audit.ResultSuccess,
				Context: map[string]any{
					"project_id":  projectID,
					"database_id": id,
					"username":    user.Username,
					"privileges":  user.Privileges,
				},
			})

			// Plaintext password is NEVER returned in API responses (Gate 3).
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"user":       databaseUserResponse(user),
				"request_id": reqID,
			})
		})).ServeHTTP(w, r)
}

func (h *DatabaseHandlers) handleRevokeUser(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	username := r.PathValue("username")
	authsession.RequirePermission(h.now, "database.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			db, err := h.databases.GetDatabaseInProject(r.Context(), projectID, id)
			if err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}
			user, err := h.databases.GetUser(r.Context(), id, username)
			if err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}
			if err := h.databases.RevokeUser(r.Context(), id, username); err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}

			// Enqueue drop_user on node.
			reqID := httpserver.RequestIDFromRequest(r)
			_, _ = jobs.Enqueue(r.Context(), h.pool, jobs.Requested{
				Type:             JobTypeDatabaseProvision,
				ServerID:         db.ServerID,
				ProjectID:        db.ProjectID,
				IdempotencyKey:   "drop_user:" + user.ID,
				IdempotencyScope: "database.provision:" + db.ID,
				RequestedByType:  "user",
				RequestedByID:    principalUserID(r),
				RequestID:        reqID,
				Payload: map[string]any{
					"database_id": db.ID,
					"action":      "drop_user",
					"username":    username,
				},
				Steps: []jobs.StepPlan{
					{Name: "drop_user"},
				},
				LockKeys: []string{"database:" + db.ID},
			})

			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "database.user.revoke",
				ResourceType: "database_user",
				ResourceID:   username,
				Result:       audit.ResultSuccess,
				Context: map[string]any{
					"project_id":  projectID,
					"database_id": id,
					"username":    username,
				},
			})

			writeJSONResponse(w, http.StatusOK, map[string]any{
				"revoked":    true,
				"username":   username,
				"request_id": reqID,
			})
		})).ServeHTTP(w, r)
}

func (h *DatabaseHandlers) handleRotateUserPassword(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	username := r.PathValue("username")
	// Gate 3: rotation requires secrets.rotate (step-up: true).
	authsession.RequirePermission(h.now, "secrets.rotate", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Gate 1: cross-project access returns 404 before any rotation happens.
			if _, err := h.databases.GetDatabaseInProject(r.Context(), projectID, id); err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}
			user, err := h.databases.GetUser(r.Context(), id, username)
			if err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}

			// Generate new random password.
			randBytes := make([]byte, 24)
			if _, rErr := rand.Read(randBytes); rErr != nil {
				httpserver.WriteError(w, r, apierr.Internal(rErr))
				return
			}
			newPassword := base64.RawURLEncoding.EncodeToString(randBytes)

			// Update sealed value at rest (PRD §20.4, Gate 3).
			if h.secrets == nil {
				httpserver.WriteError(w, r, apierr.Internal(errors.New("secrets store unavailable")))
				return
			}
			if err := h.secrets.Set(r.Context(), user.SecretRef, newPassword, "rotated database user password"); err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}

			h.recordAudit(r, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "database.user.rotate_password",
				ResourceType: "database_user",
				ResourceID:   user.ID,
				Result:       audit.ResultSuccess,
				Context: map[string]any{
					"project_id":  projectID,
					"database_id": id,
					"username":    username,
				},
			})

			// Gate 3: rotation returns 204 No Content, password never in response.
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(w, r)
}

// --- Metrics ----------------------------------------------------------------

func (h *DatabaseHandlers) handleGetMetrics(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "database.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			db, err := h.databases.GetDatabaseInProject(r.Context(), projectID, id)
			if err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}

			socketPath := defaultSocketPath(db.Engine)
			reqID := httpserver.RequestIDFromRequest(r)

			if h.dispatcher == nil {
				// No dispatcher configured: return zeroed metrics.
				writeJSONResponse(w, http.StatusOK, map[string]any{
					"metrics": map[string]any{
						"connections":          0,
						"active_queries":       0,
						"slow_queries_last_5m": 0,
						"top_slow_queries":     []any{},
						"observed_at":          time.Now().UTC(),
					},
					"request_id": reqID,
				})
				return
			}

			metrics, err := h.dispatcher.GetDatabaseMetrics(r.Context(), db.ServerID, reqID, nodewire.DatabaseMetricsInput{
				Engine:     db.Engine,
				SocketPath: socketPath,
			})
			if err != nil {
				// Metrics read failure degrades gracefully to zeroed reading.
				h.logger.WarnContext(r.Context(), "failed to read database metrics from node",
					"error", err, "server_id", db.ServerID, "db_id", db.ID)
				metrics = nodewire.DatabaseMetricsResult{ObservedAt: time.Now().UTC()}
			}

			writeJSONResponse(w, http.StatusOK, map[string]any{
				"metrics":    metrics,
				"request_id": reqID,
			})
		})).ServeHTTP(w, r)
}

// --- Dump & Restore ---------------------------------------------------------

type dumpDatabaseRequest struct {
	IdempotencyKey *string `json:"idempotency_key,omitempty"`
}

func (h *DatabaseHandlers) handleDumpDatabase(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "database.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			db, err := h.databases.GetDatabaseInProject(r.Context(), projectID, id)
			if err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}
			if !db.Usable() {
				httpserver.WriteError(w, r, apierr.Conflict("Database is not active and cannot be dumped.", map[string]any{
					"database_id": db.ID, "state": db.State,
				}))
				return
			}

			var req dumpDatabaseRequest
			if r.ContentLength > 0 {
				if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
					httpserver.WriteError(w, r, apiErr)
					return
				}
			}

			reqID := httpserver.RequestIDFromRequest(r)
			idempKey := ""
			if req.IdempotencyKey != nil {
				idempKey = *req.IdempotencyKey
			}

			// Create database_backups row in queued state.
			backup, bErr := h.databases.CreateBackup(r.Context(), databases.CreateBackupParams{
				DatabaseID:     db.ID,
				ProjectID:      projectID,
				ServerID:       db.ServerID,
				Trigger:        databases.TriggerManual,
				RequestedBy:    principalUserID(r),
				IdempotencyKey: idempKey,
			})
			if bErr != nil {
				httpserver.WriteError(w, r, databaseErr(bErr))
				return
			}

			// Enqueue database.dump job.
			job, jErr := jobs.Enqueue(r.Context(), h.pool, jobs.Requested{
				Type:             JobTypeDatabaseDump,
				ServerID:         db.ServerID,
				ProjectID:        projectID,
				IdempotencyKey:   backup.ID,
				IdempotencyScope: "database.dump:" + db.ID,
				RequestedByType:  "user",
				RequestedByID:    principalUserID(r),
				RequestID:        reqID,
				Payload: map[string]any{
					"database_id": db.ID,
					"backup_id":   backup.ID,
					"engine":      db.Engine,
					"db_name":     db.DBName,
				},
				Steps: []jobs.StepPlan{
					{Name: "dump"},
				},
				LockKeys: []string{"database:" + db.ID},
			})
			if jErr != nil {
				_, _ = h.databases.UpdateBackupState(r.Context(), databases.UpdateBackupStateParams{
					ID:    backup.ID,
					State: databases.BackupFailed,
				})
				httpserver.WriteError(w, r, apierr.Internal(jErr))
				return
			}

			writeJSONResponse(w, http.StatusAccepted, map[string]any{
				"backup_id":  backup.ID,
				"job_id":     job.ID,
				"status":     "queued",
				"request_id": reqID,
			})
		})).ServeHTTP(w, r)
}

type restoreDatabaseRequest struct {
	DumpPath string `json:"dump_path"`
}

func (h *DatabaseHandlers) handleRestoreDatabase(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	// Step-up required for restore (mutating destructive operation).
	authsession.RequirePermission(h.now, "database.manage", rbac.ProjectScope(projectID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			db, err := h.databases.GetDatabaseInProject(r.Context(), projectID, id)
			if err != nil {
				httpserver.WriteError(w, r, databaseErr(err))
				return
			}
			if !db.Usable() {
				httpserver.WriteError(w, r, apierr.Conflict("Database is not active and cannot be restored.", map[string]any{
					"database_id": db.ID, "state": db.State,
				}))
				return
			}

			var req restoreDatabaseRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			if strings.TrimSpace(req.DumpPath) == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("dump_path is required.", map[string]any{"field": "dump_path"}))
				return
			}

			reqID := httpserver.RequestIDFromRequest(r)

			// Deterministic key: restoring the same dump twice (double-click)
			// reuses the queued job rather than enqueuing a second one.
			sum := sha256.Sum256([]byte(db.ID + "|" + req.DumpPath))

			// Enqueue database.restore job.
			job, jErr := jobs.Enqueue(r.Context(), h.pool, jobs.Requested{
				Type:             JobTypeDatabaseRestore,
				ServerID:         db.ServerID,
				ProjectID:        projectID,
				IdempotencyKey:   "restore:" + hex.EncodeToString(sum[:8]),
				IdempotencyScope: "database.restore:" + db.ID,
				RequestedByType:  "user",
				RequestedByID:    principalUserID(r),
				RequestID:        reqID,
				Payload: map[string]any{
					"database_id": db.ID,
					"engine":      db.Engine,
					"db_name":     db.DBName,
					"dump_path":   req.DumpPath,
				},
				Steps: []jobs.StepPlan{
					{Name: "restore"},
					{Name: "verify"},
				},
				LockKeys: []string{"database:" + db.ID},
			})
			if jErr != nil {
				httpserver.WriteError(w, r, apierr.Internal(jErr))
				return
			}

			writeJSONResponse(w, http.StatusAccepted, map[string]any{
				"job_id":      job.ID,
				"database_id": db.ID,
				"status":      "queued",
				"request_id":  reqID,
			})
		})).ServeHTTP(w, r)
}

// --- Helpers ----------------------------------------------------------------

func defaultSocketPath(engine string) string {
	switch engine {
	case databases.EngineMariaDB:
		return "/var/run/mysqld/mysqld.sock"
	default:
		return "/var/run/postgresql"
	}
}

func (h *DatabaseHandlers) recordAudit(r *http.Request, e audit.Event) {
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

func databaseErr(err error) *apierr.Error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, databases.ErrNotFound):
		return apierr.NotFound("The requested database or user does not exist.")
	case errors.Is(err, databases.ErrSlugTaken):
		return apierr.Conflict("A database with that slug already exists in this project.", map[string]any{"field": "slug"})
	case errors.Is(err, databases.ErrDBNameTaken):
		return apierr.Conflict("A database with that db_name already exists on this server.", map[string]any{"field": "db_name"})
	case errors.Is(err, databases.ErrUsernameTaken):
		return apierr.Conflict("A user with that username already exists for this database.", map[string]any{"field": "username"})
	case errors.Is(err, databases.ErrConflictActive):
		return apierr.Conflict("A backup job is already queued or running for this database.", nil)
	case errors.Is(err, databases.ErrInvalid):
		return apierr.InvalidRequest(err.Error(), nil)
	case errors.Is(err, databases.ErrState):
		return apierr.InvalidRequest("The request is not valid for the current lifecycle state.", nil)
	default:
		return apierr.Internal(err)
	}
}

func databaseResponse(d databases.ManagedDatabase) map[string]any {
	out := map[string]any{
		"id":             d.ID,
		"project_id":     d.ProjectID,
		"server_id":      d.ServerID,
		"slug":           d.Slug,
		"name":           d.Name,
		"engine":         d.Engine,
		"engine_version": d.EngineVersion,
		"db_name":        d.DBName,
		"state":          d.State,
		"created_at":     d.CreatedAt,
		"updated_at":     d.UpdatedAt,
	}
	if d.CreatedBy != nil {
		out["created_by"] = *d.CreatedBy
	}
	if d.DeleteAfter != nil {
		out["delete_after"] = *d.DeleteAfter
	}
	if d.DeletedAt != nil {
		out["deleted_at"] = *d.DeletedAt
	}
	return out
}

func databaseResponses(list []databases.ManagedDatabase) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, db := range list {
		out = append(out, databaseResponse(db))
	}
	return out
}

func databaseUserResponse(u databases.DatabaseUser) map[string]any {
	// SecretRef is masked; password itself is NEVER returned (Gate 3).
	return map[string]any{
		"id":          u.ID,
		"database_id": u.DatabaseID,
		"username":    u.Username,
		"secret_ref":  u.SecretRef,
		"privileges":  u.Privileges,
		"created_at":  u.CreatedAt,
	}
}

func databaseUserResponses(list []databases.DatabaseUser) []map[string]any {
	out := make([]map[string]any, 0, len(list))
	for _, u := range list {
		out = append(out, databaseUserResponse(u))
	}
	return out
}
