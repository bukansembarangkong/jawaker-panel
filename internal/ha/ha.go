// Package ha owns the HA data layer: server pools, drain state,
// failover events, quorum configs, and failover drills.
//
// Security invariants:
//   - Pool quorum configs never allow split-brain without explicit fencing policy.
//   - Drain operations are recorded before node is removed from active rotation.
//   - Failover events are append-only for audit (never deleted).
package ha

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors.
var (
	ErrNotFound = errors.New("ha: not found")
	ErrConflict = errors.New("ha: already exists")
)

// ── Types ──────────────────────────────────────────────────────────────────────

// ServerPool is a named group of servers for HA/load-balanced ingress.
type ServerPool struct {
	ID          string
	ProjectID   string
	Name        string
	Description string
	Mode        string // active-passive | active-active | canary
	State       string // healthy | degraded | failed | draining
	MinHealthy  int
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// PoolMember is a server assigned to a pool.
type PoolMember struct {
	ID        string
	PoolID    string
	ServerID  string
	Role      string // primary | secondary | member | standby
	State     string // active | draining | drained | failed | offline
	Weight    int
	JoinedAt  time.Time
	UpdatedAt time.Time
}

// DrainRequest tracks a node drain lifecycle.
type DrainRequest struct {
	ID          string
	PoolID      string
	ServerID    string
	InitiatedBy string
	State       string // pending | draining | drained | cancelled | failed
	Reason      string
	StartedAt   *time.Time
	CompletedAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// QuorumConfig holds fencing policy for a pool.
type QuorumConfig struct {
	ID               string
	PoolID           string
	MinVotes         int
	FencingEnabled   bool
	FencingMethod    string // none | power | network | stonith
	SplitBrainPolicy string // pause | demote | shutdown
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// FailoverEvent is an immutable HA state transition log entry.
type FailoverEvent struct {
	ID          string
	PoolID      string
	EventType   string // node_down | node_up | failover | failback | drain_start | drain_complete | quorum_lost | quorum_restored | drill
	ServerID    string
	TriggeredBy string
	Details     map[string]any
	Resolved    bool
	OccurredAt  time.Time
}

// FailoverDrill is a manual or scheduled HA test run.
type FailoverDrill struct {
	ID          string
	PoolID      string
	DrillType   string // manual | scheduled
	State       string // pending | running | passed | failed | cancelled
	InitiatedBy string
	Notes       string
	StartedAt   *time.Time
	CompletedAt *time.Time
	ResultLog   string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// ── Store ──────────────────────────────────────────────────────────────────────

// Store is the HA data store.
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

// ── Server Pools ───────────────────────────────────────────────────────────────

// ListPools returns all server pools for a project.
func (s *Store) ListPools(ctx context.Context, projectID string) ([]ServerPool, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, project_id, name, description, mode, state, min_healthy, created_at, updated_at
		 FROM server_pools WHERE project_id = $1 ORDER BY created_at DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ServerPool
	for rows.Next() {
		var p ServerPool
		if err := rows.Scan(&p.ID, &p.ProjectID, &p.Name, &p.Description, &p.Mode, &p.State,
			&p.MinHealthy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetPool returns a single pool by ID.
func (s *Store) GetPool(ctx context.Context, id string) (ServerPool, error) {
	var p ServerPool
	err := s.pool.QueryRow(ctx,
		`SELECT id, project_id, name, description, mode, state, min_healthy, created_at, updated_at
		 FROM server_pools WHERE id = $1`, id).
		Scan(&p.ID, &p.ProjectID, &p.Name, &p.Description, &p.Mode, &p.State,
			&p.MinHealthy, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ServerPool{}, ErrNotFound
	}
	return p, err
}

// CreatePool creates a new server pool.
func (s *Store) CreatePool(ctx context.Context, projectID, name, description, mode string, minHealthy int) (ServerPool, error) {
	var p ServerPool
	err := s.pool.QueryRow(ctx,
		`INSERT INTO server_pools (project_id, name, description, mode, min_healthy)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, project_id, name, description, mode, state, min_healthy, created_at, updated_at`,
		projectID, name, description, mode, minHealthy).
		Scan(&p.ID, &p.ProjectID, &p.Name, &p.Description, &p.Mode, &p.State,
			&p.MinHealthy, &p.CreatedAt, &p.UpdatedAt)
	if isUniqueViolation(err) {
		return ServerPool{}, ErrConflict
	}
	return p, err
}

// UpdatePoolState updates the operational state of a pool.
func (s *Store) UpdatePoolState(ctx context.Context, id, state string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE server_pools SET state = $1, updated_at = now() WHERE id = $2`, state, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeletePool deletes a pool (members cascade).
func (s *Store) DeletePool(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM server_pools WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Pool Members ───────────────────────────────────────────────────────────────

// ListMembers returns all members of a pool.
func (s *Store) ListMembers(ctx context.Context, poolID string) ([]PoolMember, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, pool_id, server_id, role, state, weight, joined_at, updated_at
		 FROM pool_members WHERE pool_id = $1 ORDER BY joined_at`, poolID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PoolMember
	for rows.Next() {
		var m PoolMember
		if err := rows.Scan(&m.ID, &m.PoolID, &m.ServerID, &m.Role, &m.State, &m.Weight, &m.JoinedAt, &m.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AddMember adds a server to a pool.
func (s *Store) AddMember(ctx context.Context, poolID, serverID, role string, weight int) (PoolMember, error) {
	var m PoolMember
	err := s.pool.QueryRow(ctx,
		`INSERT INTO pool_members (pool_id, server_id, role, weight)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, pool_id, server_id, role, state, weight, joined_at, updated_at`,
		poolID, serverID, role, weight).
		Scan(&m.ID, &m.PoolID, &m.ServerID, &m.Role, &m.State, &m.Weight, &m.JoinedAt, &m.UpdatedAt)
	if isUniqueViolation(err) {
		return PoolMember{}, ErrConflict
	}
	return m, err
}

// UpdateMemberState updates the state of a pool member.
func (s *Store) UpdateMemberState(ctx context.Context, id, state string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE pool_members SET state = $1, updated_at = now() WHERE id = $2`, state, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// RemoveMember removes a server from a pool.
func (s *Store) RemoveMember(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM pool_members WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Drain Requests ─────────────────────────────────────────────────────────────

// CreateDrainRequest opens a drain request for a server in a pool.
func (s *Store) CreateDrainRequest(ctx context.Context, poolID, serverID, initiatedBy, reason string) (DrainRequest, error) {
	var d DrainRequest
	err := s.pool.QueryRow(ctx,
		`INSERT INTO drain_requests (pool_id, server_id, initiated_by, reason)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, pool_id, server_id, initiated_by, state, reason, started_at, completed_at, created_at, updated_at`,
		poolID, serverID, initiatedBy, reason).
		Scan(&d.ID, &d.PoolID, &d.ServerID, &d.InitiatedBy, &d.State, &d.Reason,
			&d.StartedAt, &d.CompletedAt, &d.CreatedAt, &d.UpdatedAt)
	return d, err
}

// UpdateDrainState updates drain request state.
func (s *Store) UpdateDrainState(ctx context.Context, id, state string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE drain_requests SET state = $1, updated_at = now(),
		 started_at   = CASE WHEN $1 = 'draining' THEN now() ELSE started_at END,
		 completed_at = CASE WHEN $1 IN ('drained','cancelled','failed') THEN now() ELSE completed_at END
		 WHERE id = $2`, state, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListDrainRequests returns drain requests for a pool.
func (s *Store) ListDrainRequests(ctx context.Context, poolID string) ([]DrainRequest, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, pool_id, server_id, initiated_by, state, reason, started_at, completed_at, created_at, updated_at
		 FROM drain_requests WHERE pool_id = $1 ORDER BY created_at DESC LIMIT 50`, poolID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DrainRequest
	for rows.Next() {
		var d DrainRequest
		if err := rows.Scan(&d.ID, &d.PoolID, &d.ServerID, &d.InitiatedBy, &d.State, &d.Reason,
			&d.StartedAt, &d.CompletedAt, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ── Quorum Config ──────────────────────────────────────────────────────────────

// UpsertQuorumConfig creates or updates quorum policy for a pool.
func (s *Store) UpsertQuorumConfig(ctx context.Context, poolID string, minVotes int, fencingEnabled bool, fencingMethod, splitBrainPolicy string) (QuorumConfig, error) {
	var q QuorumConfig
	err := s.pool.QueryRow(ctx,
		`INSERT INTO quorum_configs (pool_id, min_votes, fencing_enabled, fencing_method, split_brain_policy)
		 VALUES ($1, $2, $3, $4, $5)
		 ON CONFLICT (pool_id) DO UPDATE SET
		   min_votes = EXCLUDED.min_votes,
		   fencing_enabled = EXCLUDED.fencing_enabled,
		   fencing_method = EXCLUDED.fencing_method,
		   split_brain_policy = EXCLUDED.split_brain_policy,
		   updated_at = now()
		 RETURNING id, pool_id, min_votes, fencing_enabled, fencing_method, split_brain_policy, created_at, updated_at`,
		poolID, minVotes, fencingEnabled, fencingMethod, splitBrainPolicy).
		Scan(&q.ID, &q.PoolID, &q.MinVotes, &q.FencingEnabled, &q.FencingMethod, &q.SplitBrainPolicy, &q.CreatedAt, &q.UpdatedAt)
	return q, err
}

// GetQuorumConfig retrieves quorum config for a pool.
func (s *Store) GetQuorumConfig(ctx context.Context, poolID string) (QuorumConfig, error) {
	var q QuorumConfig
	err := s.pool.QueryRow(ctx,
		`SELECT id, pool_id, min_votes, fencing_enabled, fencing_method, split_brain_policy, created_at, updated_at
		 FROM quorum_configs WHERE pool_id = $1`, poolID).
		Scan(&q.ID, &q.PoolID, &q.MinVotes, &q.FencingEnabled, &q.FencingMethod, &q.SplitBrainPolicy, &q.CreatedAt, &q.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return QuorumConfig{}, ErrNotFound
	}
	return q, err
}

// ── Failover Events ────────────────────────────────────────────────────────────

// RecordFailoverEvent appends an immutable HA event.
func (s *Store) RecordFailoverEvent(ctx context.Context, poolID, eventType, serverID, triggeredBy string, details map[string]any) (FailoverEvent, error) {
	if details == nil {
		details = map[string]any{}
	}
	var ev FailoverEvent
	err := s.pool.QueryRow(ctx,
		`INSERT INTO failover_events (pool_id, event_type, server_id, triggered_by, details)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id, pool_id, event_type, server_id, triggered_by, details, resolved, occurred_at`,
		poolID, eventType, serverID, triggeredBy, details).
		Scan(&ev.ID, &ev.PoolID, &ev.EventType, &ev.ServerID, &ev.TriggeredBy,
			&ev.Details, &ev.Resolved, &ev.OccurredAt)
	return ev, err
}

// ListFailoverEvents returns recent events for a pool.
func (s *Store) ListFailoverEvents(ctx context.Context, poolID string, limit int) ([]FailoverEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx,
		`SELECT id, pool_id, event_type, server_id, triggered_by, details, resolved, occurred_at
		 FROM failover_events WHERE pool_id = $1 ORDER BY occurred_at DESC LIMIT $2`, poolID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FailoverEvent
	for rows.Next() {
		var ev FailoverEvent
		if err := rows.Scan(&ev.ID, &ev.PoolID, &ev.EventType, &ev.ServerID, &ev.TriggeredBy,
			&ev.Details, &ev.Resolved, &ev.OccurredAt); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// ResolveFailoverEvent marks an event as resolved.
func (s *Store) ResolveFailoverEvent(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE failover_events SET resolved = true WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Failover Drills ────────────────────────────────────────────────────────────

// CreateDrill creates a new failover drill.
func (s *Store) CreateDrill(ctx context.Context, poolID, drillType, initiatedBy, notes string) (FailoverDrill, error) {
	var d FailoverDrill
	err := s.pool.QueryRow(ctx,
		`INSERT INTO failover_drills (pool_id, drill_type, initiated_by, notes)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, pool_id, drill_type, state, initiated_by, notes, started_at, completed_at, result_log, created_at, updated_at`,
		poolID, drillType, initiatedBy, notes).
		Scan(&d.ID, &d.PoolID, &d.DrillType, &d.State, &d.InitiatedBy, &d.Notes,
			&d.StartedAt, &d.CompletedAt, &d.ResultLog, &d.CreatedAt, &d.UpdatedAt)
	return d, err
}

// UpdateDrillState updates drill state and result log.
func (s *Store) UpdateDrillState(ctx context.Context, id, state, resultLog string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE failover_drills SET state = $1, result_log = $2, updated_at = now(),
		 started_at   = CASE WHEN $1 = 'running' THEN now() ELSE started_at END,
		 completed_at = CASE WHEN $1 IN ('passed','failed','cancelled') THEN now() ELSE completed_at END
		 WHERE id = $3`, state, resultLog, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListDrills returns drills for a pool.
func (s *Store) ListDrills(ctx context.Context, poolID string) ([]FailoverDrill, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, pool_id, drill_type, state, initiated_by, notes, started_at, completed_at, result_log, created_at, updated_at
		 FROM failover_drills WHERE pool_id = $1 ORDER BY created_at DESC LIMIT 50`, poolID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FailoverDrill
	for rows.Next() {
		var d FailoverDrill
		if err := rows.Scan(&d.ID, &d.PoolID, &d.DrillType, &d.State, &d.InitiatedBy, &d.Notes,
			&d.StartedAt, &d.CompletedAt, &d.ResultLog, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ── helpers ────────────────────────────────────────────────────────────────────

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	var pe interface{ SQLState() string }
	if errors.As(err, &pe) {
		return pe.SQLState() == "23505"
	}
	return false
}
