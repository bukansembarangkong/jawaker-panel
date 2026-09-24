// Package network owns the networking and traffic-control inventory:
// network zones, firewall rules, port forwards, WireGuard peers, and
// the apply log that records every Safe Network Apply attempt.
//
// Security invariant: no private keys are stored. WireGuard records only
// public keys. Firewall rules are recorded as-declared; the agent enforces
// them via iptables/nftables. No query over this package returns a secret.
package network

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors.
var (
	ErrNotFound = errors.New("network: not found")
	ErrInvalid  = errors.New("network: invalid argument")
	ErrConflict = errors.New("network: conflict — port or zone already in use")
)

// Rule state constants.
const (
	StateActive    = "active"
	StateCandidate = "candidate"
	StateArchived  = "archived"
)

// Apply outcome constants.
const (
	OutcomeApplied    = "applied"
	OutcomeRolledBack = "rolled_back"
	OutcomeFailed     = "failed"
)

// Zone is a named trust boundary grouping network interfaces.
type Zone struct {
	ID         string
	ServerID   string
	Name       string
	Kind       string
	Interfaces string
	CreatedAt  time.Time
	DeletedAt  *time.Time
}

// FirewallRule is one iptables/nftables rule in a named chain.
type FirewallRule struct {
	ID          string
	ServerID    string
	Chain       string
	Priority    int
	Protocol    string
	SourceCIDR  string
	DestCIDR    string
	DestPortMin int
	DestPortMax int
	Action      string
	Enabled     bool
	Description string
	State       string
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
}

// PortForward is a DNAT/SNAT port-forwarding rule.
type PortForward struct {
	ID            string
	ServerID      string
	Protocol      string
	ListenAddress string
	ListenPort    int
	DestAddress   string
	DestPort      int
	Enabled       bool
	Description   string
	State         string
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     *time.Time
}

// WireGuardPeer is a peer in the WireGuard management overlay network.
type WireGuardPeer struct {
	ID                  string
	ServerID            string
	PublicKey           string
	Label               string
	AllowedIPs          string
	Endpoint            string
	PersistentKeepalive int
	Enabled             bool
	CreatedAt           time.Time
	UpdatedAt           time.Time
	DeletedAt           *time.Time
}

// ApplyLog records the outcome of one Safe Network Apply attempt.
type ApplyLog struct {
	ID                string
	ServerID          string
	AppliedBy         string
	Outcome           string
	ChangesJSON       []byte
	PreviousStateJSON []byte
	ErrorMessage      string
	CreatedAt         time.Time
}

const zoneColumns = `id, server_id, name, kind, interfaces, created_at, deleted_at`
const ruleColumns = `id, server_id, chain, priority, protocol, source_cidr, dest_cidr, dest_port_min, dest_port_max, action, enabled, description, state, created_at, updated_at, deleted_at`
const forwardColumns = `id, server_id, protocol, listen_address, listen_port, dest_address, dest_port, enabled, description, state, created_at, updated_at, deleted_at`
const peerColumns = `id, server_id, public_key, label, allowed_ips, endpoint, persistent_keepalive, enabled, created_at, updated_at, deleted_at`

// Store owns all networking read/write operations.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore builds a networking store.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// ── Network zones ──────────────────────────────────────────────────────────────

func scanZone(row pgx.Row) (Zone, error) {
	var z Zone
	err := row.Scan(&z.ID, &z.ServerID, &z.Name, &z.Kind, &z.Interfaces, &z.CreatedAt, &z.DeletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Zone{}, ErrNotFound
	}
	if err != nil {
		return Zone{}, fmt.Errorf("network: scan zone: %w", err)
	}
	return z, nil
}

// CreateZoneParams configures zone creation.
type CreateZoneParams struct {
	ServerID   string
	Name       string
	Kind       string
	Interfaces string
}

// CreateZone inserts a new network zone.
func (s *Store) CreateZone(ctx context.Context, p CreateZoneParams) (Zone, error) {
	if strings.TrimSpace(p.ServerID) == "" || strings.TrimSpace(p.Name) == "" {
		return Zone{}, fmt.Errorf("%w: server_id and name are required", ErrInvalid)
	}
	kind := p.Kind
	if kind == "" {
		kind = "custom"
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO network_zones (server_id, name, kind, interfaces)
		VALUES ($1, $2, $3, $4)
		RETURNING %s`, zoneColumns),
		p.ServerID, strings.TrimSpace(p.Name), kind, p.Interfaces)
	return scanZone(row)
}

// GetZone returns one zone by ID.
func (s *Store) GetZone(ctx context.Context, id string) (Zone, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM network_zones WHERE id = $1 AND deleted_at IS NULL`, zoneColumns), id)
	return scanZone(row)
}

// ListZones returns all zones for a server.
func (s *Store) ListZones(ctx context.Context, serverID string) ([]Zone, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT %s FROM network_zones WHERE server_id = $1 AND deleted_at IS NULL ORDER BY name ASC`, zoneColumns), serverID)
	if err != nil {
		return nil, fmt.Errorf("network: list zones: %w", err)
	}
	defer rows.Close()
	return collectZones(rows)
}

func collectZones(rows pgx.Rows) ([]Zone, error) {
	var out []Zone
	for rows.Next() {
		z, err := scanZone(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

// DeleteZone soft-deletes a zone.
func (s *Store) DeleteZone(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE network_zones SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("network: delete zone: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Firewall rules ─────────────────────────────────────────────────────────────

func scanRule(row pgx.Row) (FirewallRule, error) {
	var r FirewallRule
	err := row.Scan(
		&r.ID, &r.ServerID, &r.Chain, &r.Priority, &r.Protocol,
		&r.SourceCIDR, &r.DestCIDR, &r.DestPortMin, &r.DestPortMax,
		&r.Action, &r.Enabled, &r.Description, &r.State,
		&r.CreatedAt, &r.UpdatedAt, &r.DeletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return FirewallRule{}, ErrNotFound
	}
	if err != nil {
		return FirewallRule{}, fmt.Errorf("network: scan rule: %w", err)
	}
	return r, nil
}

// CreateRuleParams configures firewall rule creation.
type CreateRuleParams struct {
	ServerID    string
	Chain       string
	Priority    int
	Protocol    string
	SourceCIDR  string
	DestCIDR    string
	DestPortMin int
	DestPortMax int
	Action      string
	Enabled     bool
	Description string
	// State defaults to candidate so rules are applied explicitly.
	State string
}

// CreateRule inserts a new firewall rule in candidate state.
func (s *Store) CreateRule(ctx context.Context, p CreateRuleParams) (FirewallRule, error) {
	if strings.TrimSpace(p.ServerID) == "" || strings.TrimSpace(p.Chain) == "" {
		return FirewallRule{}, fmt.Errorf("%w: server_id and chain are required", ErrInvalid)
	}
	if p.DestPortMax != 0 && p.DestPortMax < p.DestPortMin {
		return FirewallRule{}, fmt.Errorf("%w: dest_port_max must be >= dest_port_min", ErrInvalid)
	}
	protocol := p.Protocol
	if protocol == "" {
		protocol = "any"
	}
	action := p.Action
	if action == "" {
		action = "accept"
	}
	state := p.State
	if state == "" {
		state = StateCandidate
	}
	priority := p.Priority
	if priority == 0 {
		priority = 100
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO firewall_rules
		  (server_id, chain, priority, protocol, source_cidr, dest_cidr,
		   dest_port_min, dest_port_max, action, enabled, description, state)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING %s`, ruleColumns),
		p.ServerID, strings.TrimSpace(p.Chain), priority, protocol,
		p.SourceCIDR, p.DestCIDR, p.DestPortMin, p.DestPortMax,
		action, p.Enabled, p.Description, state)
	return scanRule(row)
}

// GetRule returns one firewall rule by ID.
func (s *Store) GetRule(ctx context.Context, id string) (FirewallRule, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM firewall_rules WHERE id = $1 AND deleted_at IS NULL`, ruleColumns), id)
	return scanRule(row)
}

// ListRules returns all active+candidate rules for a server.
func (s *Store) ListRules(ctx context.Context, serverID string) ([]FirewallRule, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM firewall_rules
		WHERE server_id = $1 AND deleted_at IS NULL AND state != 'archived'
		ORDER BY chain ASC, priority ASC`, ruleColumns), serverID)
	if err != nil {
		return nil, fmt.Errorf("network: list rules: %w", err)
	}
	defer rows.Close()
	return collectRules(rows)
}

// ListCandidateRules returns only candidate rules for a server (pending apply).
func (s *Store) ListCandidateRules(ctx context.Context, serverID string) ([]FirewallRule, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM firewall_rules
		WHERE server_id = $1 AND state = 'candidate' AND deleted_at IS NULL
		ORDER BY chain ASC, priority ASC`, ruleColumns), serverID)
	if err != nil {
		return nil, fmt.Errorf("network: list candidate rules: %w", err)
	}
	defer rows.Close()
	return collectRules(rows)
}

func collectRules(rows pgx.Rows) ([]FirewallRule, error) {
	var out []FirewallRule
	for rows.Next() {
		r, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ActivateRules transitions candidate rules to active for a server.
// Called after a successful Safe Network Apply.
func (s *Store) ActivateRules(ctx context.Context, serverID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE firewall_rules
		SET state = 'active', updated_at = now()
		WHERE server_id = $1 AND state = 'candidate' AND deleted_at IS NULL`, serverID)
	if err != nil {
		return fmt.Errorf("network: activate rules: %w", err)
	}
	return nil
}

// DeleteRule soft-deletes a firewall rule.
func (s *Store) DeleteRule(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE firewall_rules SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("network: delete rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Port forwards ──────────────────────────────────────────────────────────────

func scanForward(row pgx.Row) (PortForward, error) {
	var f PortForward
	err := row.Scan(
		&f.ID, &f.ServerID, &f.Protocol, &f.ListenAddress, &f.ListenPort,
		&f.DestAddress, &f.DestPort, &f.Enabled, &f.Description, &f.State,
		&f.CreatedAt, &f.UpdatedAt, &f.DeletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return PortForward{}, ErrNotFound
	}
	if err != nil {
		return PortForward{}, fmt.Errorf("network: scan forward: %w", err)
	}
	return f, nil
}

// CreateForwardParams configures port forward creation.
type CreateForwardParams struct {
	ServerID      string
	Protocol      string
	ListenAddress string
	ListenPort    int
	DestAddress   string
	DestPort      int
	Enabled       bool
	Description   string
}

// CreateForward inserts a port forward in candidate state.
// Returns ErrConflict if an active forward already owns the protocol+port.
func (s *Store) CreateForward(ctx context.Context, p CreateForwardParams) (PortForward, error) {
	if strings.TrimSpace(p.ServerID) == "" {
		return PortForward{}, fmt.Errorf("%w: server_id is required", ErrInvalid)
	}
	if p.ListenPort < 1 || p.ListenPort > 65535 {
		return PortForward{}, fmt.Errorf("%w: listen_port must be 1-65535", ErrInvalid)
	}
	if p.DestPort < 1 || p.DestPort > 65535 {
		return PortForward{}, fmt.Errorf("%w: dest_port must be 1-65535", ErrInvalid)
	}
	proto := p.Protocol
	if proto == "" {
		proto = "tcp"
	}
	addr := p.ListenAddress
	if addr == "" {
		addr = "0.0.0.0"
	}

	// Conflict check: no active forward on same server+proto+port.
	var count int
	if err := s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM port_forwards
		WHERE server_id=$1 AND protocol=$2 AND listen_port=$3
		  AND state='active' AND deleted_at IS NULL`,
		p.ServerID, proto, p.ListenPort).Scan(&count); err != nil {
		return PortForward{}, fmt.Errorf("network: conflict check: %w", err)
	}
	if count > 0 {
		return PortForward{}, fmt.Errorf("%w: %s port %d already forwarded", ErrConflict, proto, p.ListenPort)
	}

	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO port_forwards
		  (server_id, protocol, listen_address, listen_port, dest_address, dest_port, enabled, description, state)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'candidate')
		RETURNING %s`, forwardColumns),
		p.ServerID, proto, addr, p.ListenPort, strings.TrimSpace(p.DestAddress), p.DestPort, p.Enabled, p.Description)
	return scanForward(row)
}

// GetForward returns one port forward by ID.
func (s *Store) GetForward(ctx context.Context, id string) (PortForward, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM port_forwards WHERE id = $1 AND deleted_at IS NULL`, forwardColumns), id)
	return scanForward(row)
}

// ListForwards returns all active+candidate forwards for a server.
func (s *Store) ListForwards(ctx context.Context, serverID string) ([]PortForward, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM port_forwards
		WHERE server_id = $1 AND deleted_at IS NULL AND state != 'archived'
		ORDER BY protocol ASC, listen_port ASC`, forwardColumns), serverID)
	if err != nil {
		return nil, fmt.Errorf("network: list forwards: %w", err)
	}
	defer rows.Close()
	return collectForwards(rows)
}

func collectForwards(rows pgx.Rows) ([]PortForward, error) {
	var out []PortForward
	for rows.Next() {
		f, err := scanForward(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ActivateForwards transitions candidate forwards to active.
func (s *Store) ActivateForwards(ctx context.Context, serverID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE port_forwards
		SET state = 'active', updated_at = now()
		WHERE server_id = $1 AND state = 'candidate' AND deleted_at IS NULL`, serverID)
	if err != nil {
		return fmt.Errorf("network: activate forwards: %w", err)
	}
	return nil
}

// DeleteForward soft-deletes a port forward.
func (s *Store) DeleteForward(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE port_forwards SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("network: delete forward: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── WireGuard peers ────────────────────────────────────────────────────────────

func scanPeer(row pgx.Row) (WireGuardPeer, error) {
	var p WireGuardPeer
	err := row.Scan(
		&p.ID, &p.ServerID, &p.PublicKey, &p.Label, &p.AllowedIPs,
		&p.Endpoint, &p.PersistentKeepalive, &p.Enabled,
		&p.CreatedAt, &p.UpdatedAt, &p.DeletedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return WireGuardPeer{}, ErrNotFound
	}
	if err != nil {
		return WireGuardPeer{}, fmt.Errorf("network: scan peer: %w", err)
	}
	return p, nil
}

// CreatePeerParams configures WireGuard peer creation.
type CreatePeerParams struct {
	ServerID            string
	PublicKey           string
	Label               string
	AllowedIPs          string
	Endpoint            string
	PersistentKeepalive int
	Enabled             bool
}

// CreatePeer inserts a WireGuard peer.
func (s *Store) CreatePeer(ctx context.Context, p CreatePeerParams) (WireGuardPeer, error) {
	if strings.TrimSpace(p.ServerID) == "" || strings.TrimSpace(p.PublicKey) == "" {
		return WireGuardPeer{}, fmt.Errorf("%w: server_id and public_key are required", ErrInvalid)
	}
	// WireGuard public keys are base64-encoded 32-byte values → 44 chars.
	if l := len(strings.TrimSpace(p.PublicKey)); l < 40 || l > 48 {
		return WireGuardPeer{}, fmt.Errorf("%w: public_key length must be 40-48 chars", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO wireguard_peers
		  (server_id, public_key, label, allowed_ips, endpoint, persistent_keepalive, enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING %s`, peerColumns),
		p.ServerID, strings.TrimSpace(p.PublicKey), p.Label, p.AllowedIPs,
		p.Endpoint, p.PersistentKeepalive, p.Enabled)
	return scanPeer(row)
}

// GetPeer returns one WireGuard peer by ID.
func (s *Store) GetPeer(ctx context.Context, id string) (WireGuardPeer, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM wireguard_peers WHERE id = $1 AND deleted_at IS NULL`, peerColumns), id)
	return scanPeer(row)
}

// ListPeers returns all enabled WireGuard peers for a server.
func (s *Store) ListPeers(ctx context.Context, serverID string) ([]WireGuardPeer, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT %s FROM wireguard_peers
		WHERE server_id = $1 AND deleted_at IS NULL
		ORDER BY label ASC, created_at ASC`, peerColumns), serverID)
	if err != nil {
		return nil, fmt.Errorf("network: list peers: %w", err)
	}
	defer rows.Close()
	return collectPeers(rows)
}

func collectPeers(rows pgx.Rows) ([]WireGuardPeer, error) {
	var out []WireGuardPeer
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// DeletePeer soft-deletes a WireGuard peer.
func (s *Store) DeletePeer(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE wireguard_peers SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("network: delete peer: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Apply log ──────────────────────────────────────────────────────────────────

// RecordApply inserts one Safe Network Apply outcome record.
func (s *Store) RecordApply(ctx context.Context, serverID, appliedBy, outcome, errorMessage string, changesJSON, previousStateJSON []byte) (ApplyLog, error) {
	if changesJSON == nil {
		changesJSON = []byte("{}")
	}
	if previousStateJSON == nil {
		previousStateJSON = []byte("{}")
	}
	var log ApplyLog
	err := s.pool.QueryRow(ctx, `
		INSERT INTO network_apply_log
		  (server_id, applied_by, outcome, changes_json, previous_state_json, error_message)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id, server_id, applied_by, outcome, changes_json, previous_state_json, error_message, created_at`,
		serverID, appliedBy, outcome, changesJSON, previousStateJSON, errorMessage,
	).Scan(&log.ID, &log.ServerID, &log.AppliedBy, &log.Outcome,
		&log.ChangesJSON, &log.PreviousStateJSON, &log.ErrorMessage, &log.CreatedAt)
	if err != nil {
		return ApplyLog{}, fmt.Errorf("network: record apply: %w", err)
	}
	return log, nil
}

// ListApplyLog returns recent apply attempts for a server (newest first).
func (s *Store) ListApplyLog(ctx context.Context, serverID string, limit int) ([]ApplyLog, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.pool.Query(ctx, `
		SELECT id, server_id, applied_by, outcome, changes_json, previous_state_json, error_message, created_at
		FROM network_apply_log
		WHERE server_id = $1
		ORDER BY created_at DESC
		LIMIT $2`, serverID, limit)
	if err != nil {
		return nil, fmt.Errorf("network: list apply log: %w", err)
	}
	defer rows.Close()
	var out []ApplyLog
	for rows.Next() {
		var l ApplyLog
		if err := rows.Scan(&l.ID, &l.ServerID, &l.AppliedBy, &l.Outcome,
			&l.ChangesJSON, &l.PreviousStateJSON, &l.ErrorMessage, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("network: scan apply log: %w", err)
		}
		out = append(out, l)
	}
	return out, rows.Err()
}
