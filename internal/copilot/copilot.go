// Package copilot owns the AI Infrastructure Copilot data layer:
// sessions, immutable tool-call audit, change plans, and approval requests.
//
// Security invariants:
//   - copilot_tool_calls is append-only: no UPDATE or DELETE permitted.
//   - The AI cannot bypass RBAC; all mutations require controller-side authorization.
//   - No unrestricted shell tool: tool_name must be in the allowlist checked by the controller.
//   - Risky mutations (risk_level >= high) require an approval before applying.
//   - AI endpoint outage must not impair manual control (no critical path through this package).
package copilot

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors.
var (
	ErrNotFound = errors.New("copilot: not found")
	ErrDenied   = errors.New("copilot: operation denied")
)

// ── Tool name allowlist ───────────────────────────────────────────────────────
// No unrestricted shell. Only read-only analysis and scoped write tools.
var AllowedTools = map[string]bool{
	// Read-only analysis
	"analyze.logs":     true,
	"analyze.metrics":  true,
	"analyze.config":   true,
	"explain.incident": true,
	"explain.alert":    true,
	"suggest.config":   true,
	// Change plan generation (read-only output)
	"plan.generate": true,
	// Scoped mutations (require approval if risk >= high)
	"config.propose": true,
	"config.apply":   true, // requires approved plan
}

// IsAllowedTool returns true if the tool name is in the allowlist.
func IsAllowedTool(name string) bool {
	return AllowedTools[name]
}

// ── Types ─────────────────────────────────────────────────────────────────────

// Session is one copilot analysis/plan conversation thread.
type Session struct {
	ID        string
	ProjectID string
	UserID    string
	State     string // active | completed | cancelled
	Intent    string
	Context   map[string]any
	CreatedAt time.Time
	UpdatedAt time.Time
}

// ToolCall is an immutable audit record of one AI tool invocation.
type ToolCall struct {
	ID         string
	SessionID  string
	ToolName   string
	ToolInput  map[string]any
	ToolOutput map[string]any
	Outcome    string // ok | error | denied | pending_approval
	ErrorMsg   string
	CalledAt   time.Time
}

// Plan is an AI-generated change plan.
type Plan struct {
	ID          string
	SessionID   string
	ProjectID   string
	Title       string
	Description string
	Steps       []any
	RiskLevel   string // low | medium | high | critical
	State       string // draft | pending_approval | approved | rejected | applied | cancelled
	CreatedBy   string
	ReviewedBy  string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Approval is an approval request for a high-risk plan.
type Approval struct {
	ID          string
	PlanID      string
	RequestedBy string
	ReviewedBy  string
	State       string // pending | approved | rejected | expired
	Comment     string
	ExpiresAt   time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ── Store ─────────────────────────────────────────────────────────────────────

// Store is the copilot data store.
type Store struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// New returns a Store backed by pool.
func New(pool *pgxpool.Pool, now func() time.Time) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{pool: pool, now: now}
}

// ── Sessions ──────────────────────────────────────────────────────────────────

// CreateSession opens a new copilot session.
func (s *Store) CreateSession(ctx context.Context, projectID, userID, intent string) (Session, error) {
	var ss Session
	err := s.pool.QueryRow(ctx,
		`INSERT INTO copilot_sessions (project_id, user_id, intent)
		 VALUES ($1, $2, $3)
		 RETURNING id, project_id, user_id, state, intent, context, created_at, updated_at`,
		projectID, userID, intent).
		Scan(&ss.ID, &ss.ProjectID, &ss.UserID, &ss.State, &ss.Intent, &ss.Context, &ss.CreatedAt, &ss.UpdatedAt)
	return ss, err
}

// GetSession returns a session by ID.
func (s *Store) GetSession(ctx context.Context, id string) (Session, error) {
	var ss Session
	err := s.pool.QueryRow(ctx,
		`SELECT id, project_id, user_id, state, intent, context, created_at, updated_at
		 FROM copilot_sessions WHERE id = $1`, id).
		Scan(&ss.ID, &ss.ProjectID, &ss.UserID, &ss.State, &ss.Intent, &ss.Context, &ss.CreatedAt, &ss.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	return ss, err
}

// ListSessions returns recent sessions for a project.
func (s *Store) ListSessions(ctx context.Context, projectID string) ([]Session, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, project_id, user_id, state, intent, context, created_at, updated_at
		 FROM copilot_sessions WHERE project_id = $1 ORDER BY created_at DESC LIMIT 50`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var ss Session
		if err := rows.Scan(&ss.ID, &ss.ProjectID, &ss.UserID, &ss.State, &ss.Intent, &ss.Context, &ss.CreatedAt, &ss.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, ss)
	}
	return out, rows.Err()
}

// CloseSession marks a session as completed or cancelled.
func (s *Store) CloseSession(ctx context.Context, id, state string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE copilot_sessions SET state = $1, updated_at = now() WHERE id = $2`, state, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Tool Calls (append-only audit) ────────────────────────────────────────────

// RecordToolCall appends an immutable tool call audit record.
// Tool name must be in AllowedTools or outcome must be "denied".
func (s *Store) RecordToolCall(ctx context.Context, sessionID, toolName string, input, output map[string]any, outcome, errorMsg string) (ToolCall, error) {
	if input == nil {
		input = map[string]any{}
	}
	if output == nil {
		output = map[string]any{}
	}
	var tc ToolCall
	err := s.pool.QueryRow(ctx,
		`INSERT INTO copilot_tool_calls (session_id, tool_name, tool_input, tool_output, outcome, error_msg)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, session_id, tool_name, tool_input, tool_output, outcome, error_msg, called_at`,
		sessionID, toolName, input, output, outcome, errorMsg).
		Scan(&tc.ID, &tc.SessionID, &tc.ToolName, &tc.ToolInput, &tc.ToolOutput, &tc.Outcome, &tc.ErrorMsg, &tc.CalledAt)
	return tc, err
}

// ListToolCalls returns tool call audit for a session.
func (s *Store) ListToolCalls(ctx context.Context, sessionID string) ([]ToolCall, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, session_id, tool_name, tool_input, tool_output, outcome, error_msg, called_at
		 FROM copilot_tool_calls WHERE session_id = $1 ORDER BY called_at`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ToolCall
	for rows.Next() {
		var tc ToolCall
		if err := rows.Scan(&tc.ID, &tc.SessionID, &tc.ToolName, &tc.ToolInput, &tc.ToolOutput, &tc.Outcome, &tc.ErrorMsg, &tc.CalledAt); err != nil {
			return nil, err
		}
		out = append(out, tc)
	}
	return out, rows.Err()
}

// ── Plans ─────────────────────────────────────────────────────────────────────

// CreatePlan stores an AI-generated change plan.
func (s *Store) CreatePlan(ctx context.Context, sessionID, projectID, title, description, riskLevel, createdBy string, steps []any) (Plan, error) {
	if steps == nil {
		steps = []any{}
	}
	var p Plan
	err := s.pool.QueryRow(ctx,
		`INSERT INTO copilot_plans (session_id, project_id, title, description, risk_level, created_by, steps)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)
		 RETURNING id, session_id, project_id, title, description, steps, risk_level, state, created_by, reviewed_by, created_at, updated_at`,
		sessionID, projectID, title, description, riskLevel, createdBy, steps).
		Scan(&p.ID, &p.SessionID, &p.ProjectID, &p.Title, &p.Description, &p.Steps, &p.RiskLevel,
			&p.State, &p.CreatedBy, &p.ReviewedBy, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

// GetPlan returns a plan by ID.
func (s *Store) GetPlan(ctx context.Context, id string) (Plan, error) {
	var p Plan
	err := s.pool.QueryRow(ctx,
		`SELECT id, session_id, project_id, title, description, steps, risk_level, state, created_by, reviewed_by, created_at, updated_at
		 FROM copilot_plans WHERE id = $1`, id).
		Scan(&p.ID, &p.SessionID, &p.ProjectID, &p.Title, &p.Description, &p.Steps, &p.RiskLevel,
			&p.State, &p.CreatedBy, &p.ReviewedBy, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Plan{}, ErrNotFound
	}
	return p, err
}

// ListPlans returns plans for a project.
func (s *Store) ListPlans(ctx context.Context, projectID string) ([]Plan, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, session_id, project_id, title, description, steps, risk_level, state, created_by, reviewed_by, created_at, updated_at
		 FROM copilot_plans WHERE project_id = $1 ORDER BY created_at DESC LIMIT 50`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Plan
	for rows.Next() {
		var p Plan
		if err := rows.Scan(&p.ID, &p.SessionID, &p.ProjectID, &p.Title, &p.Description, &p.Steps, &p.RiskLevel,
			&p.State, &p.CreatedBy, &p.ReviewedBy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// UpdatePlanState transitions a plan state and optionally records reviewer.
func (s *Store) UpdatePlanState(ctx context.Context, id, state, reviewedBy string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE copilot_plans SET state = $1, reviewed_by = COALESCE(NULLIF($2,''), reviewed_by), updated_at = now() WHERE id = $3`,
		state, reviewedBy, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Approvals ─────────────────────────────────────────────────────────────────

// RequestApproval creates an approval request for a plan.
func (s *Store) RequestApproval(ctx context.Context, planID, requestedBy string) (Approval, error) {
	var a Approval
	err := s.pool.QueryRow(ctx,
		`INSERT INTO copilot_approvals (plan_id, requested_by)
		 VALUES ($1, $2)
		 RETURNING id, plan_id, requested_by, reviewed_by, state, comment, expires_at, created_at, updated_at`,
		planID, requestedBy).
		Scan(&a.ID, &a.PlanID, &a.RequestedBy, &a.ReviewedBy, &a.State, &a.Comment, &a.ExpiresAt, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return Approval{}, err
	}
	// Mark plan as pending_approval.
	_ = s.UpdatePlanState(ctx, planID, "pending_approval", "")
	return a, nil
}

// ReviewApproval updates the state of an approval request.
func (s *Store) ReviewApproval(ctx context.Context, id, state, reviewedBy, comment string) (Approval, error) {
	var a Approval
	err := s.pool.QueryRow(ctx,
		`UPDATE copilot_approvals SET state = $1, reviewed_by = $2, comment = $3, updated_at = now()
		 WHERE id = $4
		 RETURNING id, plan_id, requested_by, reviewed_by, state, comment, expires_at, created_at, updated_at`,
		state, reviewedBy, comment, id).
		Scan(&a.ID, &a.PlanID, &a.RequestedBy, &a.ReviewedBy, &a.State, &a.Comment, &a.ExpiresAt, &a.CreatedAt, &a.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Approval{}, ErrNotFound
	}
	if err != nil {
		return Approval{}, err
	}
	// Propagate approval/rejection to plan.
	planState := "approved"
	if state == "rejected" {
		planState = "rejected"
	}
	_ = s.UpdatePlanState(ctx, a.PlanID, planState, reviewedBy)
	return a, nil
}

// ListApprovals returns approval requests for a plan.
func (s *Store) ListApprovals(ctx context.Context, planID string) ([]Approval, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, plan_id, requested_by, reviewed_by, state, comment, expires_at, created_at, updated_at
		 FROM copilot_approvals WHERE plan_id = $1 ORDER BY created_at DESC`, planID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Approval
	for rows.Next() {
		var a Approval
		if err := rows.Scan(&a.ID, &a.PlanID, &a.RequestedBy, &a.ReviewedBy, &a.State, &a.Comment,
			&a.ExpiresAt, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
