// Package controller: audit log query and export handlers (PRD §36).
package controller

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditLogHandlers provides HTTP access to the append-only audit trail.
type AuditLogHandlers struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// NewAuditLogHandlers builds audit log handlers.
func NewAuditLogHandlers(pool *pgxpool.Pool, now func() time.Time) *AuditLogHandlers {
	if now == nil {
		now = time.Now
	}
	return &AuditLogHandlers{pool: pool, now: now}
}

// Routes registers audit log and revision history endpoints on the mux.
func (h *AuditLogHandlers) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/audit-events", h.handleListAuditEvents)
	mux.HandleFunc("GET /api/v1/revisions", h.handleListRevisions)
	mux.HandleFunc("GET /api/v1/revisions/{id}", h.handleGetRevision)
}

type auditEventRow struct {
	ID             string    `json:"id"`
	Seq            int64     `json:"seq"`
	ActorType      string    `json:"actor_type"`
	ActorID        *string   `json:"actor_id,omitempty"`
	ImpersonatorID *string   `json:"impersonator_id,omitempty"`
	Action         string    `json:"action"`
	ResourceType   string    `json:"resource_type"`
	ResourceID     *string   `json:"resource_id,omitempty"`
	RequestID      *string   `json:"request_id,omitempty"`
	JobID          *string   `json:"job_id,omitempty"`
	RevisionID     *string   `json:"revision_id,omitempty"`
	Result         string    `json:"result"`
	ErrorCode      *string   `json:"error_code,omitempty"`
	Reason         *string   `json:"reason,omitempty"`
	SourceIP       *string   `json:"source_ip,omitempty"`
	UserAgent      *string   `json:"user_agent,omitempty"`
	OccurredAt     time.Time `json:"occurred_at"`
}

// GET /api/v1/audit-events
// Supports ?action=... &resource_type=... &result=... &limit=50 &offset=0 &format=json|csv
func (h *AuditLogHandlers) handleListAuditEvents(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "audit.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			actionFilter := q.Get("action")
			resTypeFilter := q.Get("resource_type")
			resultFilter := q.Get("result")
			format := q.Get("format")

			limit := 50
			if lStr := q.Get("limit"); lStr != "" {
				if parsed, err := strconv.Atoi(lStr); err == nil && parsed > 0 && parsed <= 500 {
					limit = parsed
				}
			}
			offset := 0
			if oStr := q.Get("offset"); oStr != "" {
				if parsed, err := strconv.Atoi(oStr); err == nil && parsed >= 0 {
					offset = parsed
				}
			}

			// Build query with optional filters
			baseQuery := `
				SELECT id, seq, actor_type, actor_id, impersonator_id, action, resource_type,
				       resource_id, request_id, job_id, revision_id, result, error_code, reason,
				       source_ip::text, user_agent, occurred_at
				FROM audit_events
				WHERE ($1 = '' OR action = $1)
				  AND ($2 = '' OR resource_type = $2)
				  AND ($3 = '' OR result = $3)
				ORDER BY occurred_at DESC, seq DESC
				LIMIT $4 OFFSET $5
			`

			rows, err := h.pool.Query(r.Context(), baseQuery, actionFilter, resTypeFilter, resultFilter, limit, offset)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			defer rows.Close()

			var events []auditEventRow
			for rows.Next() {
				var ev auditEventRow
				if err := rows.Scan(
					&ev.ID, &ev.Seq, &ev.ActorType, &ev.ActorID, &ev.ImpersonatorID,
					&ev.Action, &ev.ResourceType, &ev.ResourceID, &ev.RequestID,
					&ev.JobID, &ev.RevisionID, &ev.Result, &ev.ErrorCode, &ev.Reason,
					&ev.SourceIP, &ev.UserAgent, &ev.OccurredAt,
				); err == nil {
					events = append(events, ev)
				}
			}

			if format == "csv" {
				w.Header().Set("Content-Type", "text/csv; charset=utf-8")
				w.Header().Set("Content-Disposition", `attachment; filename="audit_log.csv"`)
				writer := csv.NewWriter(w)
				_ = writer.Write([]string{"seq", "occurred_at", "actor_type", "action", "resource_type", "resource_id", "result", "source_ip"})
				for _, ev := range events {
					resID := ""
					if ev.ResourceID != nil {
						resID = *ev.ResourceID
					}
					srcIP := ""
					if ev.SourceIP != nil {
						srcIP = *ev.SourceIP
					}
					_ = writer.Write([]string{
						fmt.Sprintf("%d", ev.Seq),
						ev.OccurredAt.Format(time.RFC3339),
						ev.ActorType,
						ev.Action,
						ev.ResourceType,
						resID,
						ev.Result,
						srcIP,
					})
				}
				writer.Flush()
				return
			}

			writeJSONResponse(w, http.StatusOK, map[string]any{
				"events":     events,
				"total":      len(events),
				"limit":      limit,
				"offset":     offset,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Revision History Handlers (PRD §36) ──────────────────────────────────────

type revisionSummaryRow struct {
	ID            string     `json:"id"`
	ResourceType  string     `json:"resource_type"`
	ResourceID    string     `json:"resource_id"`
	ActorType     string     `json:"actor_type"`
	ActorID       *string    `json:"actor_id,omitempty"`
	CandidateHash string     `json:"candidate_hash"`
	State         string     `json:"state"`
	GitSyncState  string     `json:"git_sync_state"`
	GitCommitSHA  *string    `json:"git_commit_sha,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	AppliedAt     *time.Time `json:"applied_at,omitempty"`
}

// GET /api/v1/revisions
func (h *AuditLogHandlers) handleListRevisions(w http.ResponseWriter, r *http.Request) {
	authsession.RequirePermission(h.now, "audit.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			q := r.URL.Query()
			resType := q.Get("resource_type")
			resID := q.Get("resource_id")
			state := q.Get("state")

			limit := 50
			if lStr := q.Get("limit"); lStr != "" {
				if parsed, err := strconv.Atoi(lStr); err == nil && parsed > 0 && parsed <= 200 {
					limit = parsed
				}
			}

			rows, err := h.pool.Query(r.Context(), `
				SELECT id, resource_type, resource_id, actor_type, actor_id,
				       candidate_hash, state, git_sync_state, git_commit_sha,
				       created_at, applied_at
				FROM revisions
				WHERE ($1 = '' OR resource_type = $1)
				  AND ($2 = '' OR resource_id = $2)
				  AND ($3 = '' OR state = $3)
				ORDER BY created_at DESC
				LIMIT $4
			`, resType, resID, state, limit)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			defer rows.Close()

			var revs []revisionSummaryRow
			for rows.Next() {
				var row revisionSummaryRow
				if err := rows.Scan(
					&row.ID, &row.ResourceType, &row.ResourceID, &row.ActorType, &row.ActorID,
					&row.CandidateHash, &row.State, &row.GitSyncState, &row.GitCommitSHA,
					&row.CreatedAt, &row.AppliedAt,
				); err == nil {
					revs = append(revs, row)
				}
			}

			writeJSONResponse(w, http.StatusOK, map[string]any{
				"revisions":  revs,
				"total":      len(revs),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// GET /api/v1/revisions/{id}
func (h *AuditLogHandlers) handleGetRevision(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "audit.read", rbac.GlobalScope(), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			type revisionDetail struct {
				ID               string     `json:"id"`
				ResourceType     string     `json:"resource_type"`
				ResourceID       string     `json:"resource_id"`
				ActorType        string     `json:"actor_type"`
				ActorID          *string    `json:"actor_id,omitempty"`
				BaseRevisionID   *string    `json:"base_revision_id,omitempty"`
				Candidate        any        `json:"candidate"`
				Previous         any        `json:"previous,omitempty"`
				CandidateHash    string     `json:"candidate_hash"`
				State            string     `json:"state"`
				ValidationResult any        `json:"validation_result,omitempty"`
				HealthResult     any        `json:"health_result,omitempty"`
				GitSyncState     string     `json:"git_sync_state"`
				GitCommitSHA     *string    `json:"git_commit_sha,omitempty"`
				CreatedAt        time.Time  `json:"created_at"`
				AppliedAt        *time.Time `json:"applied_at,omitempty"`
			}

			var d revisionDetail
			err := h.pool.QueryRow(r.Context(), `
				SELECT id, resource_type, resource_id, actor_type, actor_id, base_revision_id,
				       candidate, previous, candidate_hash, state, validation_result,
				       health_result, git_sync_state, git_commit_sha, created_at, applied_at
				FROM revisions
				WHERE id = $1
			`, id).Scan(
				&d.ID, &d.ResourceType, &d.ResourceID, &d.ActorType, &d.ActorID, &d.BaseRevisionID,
				&d.Candidate, &d.Previous, &d.CandidateHash, &d.State, &d.ValidationResult,
				&d.HealthResult, &d.GitSyncState, &d.GitCommitSHA, &d.CreatedAt, &d.AppliedAt,
			)
			if err != nil {
				httpserver.WriteError(w, r, apierr.NotFound("revision not found"))
				return
			}

			writeJSONResponse(w, http.StatusOK, map[string]any{
				"revision":   d,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}
