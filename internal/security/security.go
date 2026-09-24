// Package security owns the Security Center data layer:
// hardening checks, SSH posture snapshots, security events,
// ban entries (fail2ban/crowdsec/manual), and WAF rules.
//
// Security invariant: no credential or secret is stored here.
// All data is observational (read from the node agent) or
// policy-declarative (ban/WAF rules). No query returns a secret.
package security

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
	ErrNotFound = errors.New("security: not found")
	ErrInvalid  = errors.New("security: invalid argument")
	ErrConflict = errors.New("security: conflict — ban already active for this IP")
)

// ── Types ──────────────────────────────────────────────────────────────────────

// HardeningCheck is one actionable finding from a server hardening scan.
type HardeningCheck struct {
	ID          string
	ServerID    string
	CheckName   string
	Category    string
	Severity    string
	Status      string
	Title       string
	Description string
	Remediation string
	ObservedAt  time.Time
	CreatedAt   time.Time
}

// SSHPosture is one SSH configuration snapshot from a server.
type SSHPosture struct {
	ID               string
	ServerID         string
	PermitRootLogin  string
	PasswordAuth     string
	PubkeyAuth       string
	Port             int
	ProtocolVersions string
	ActiveSessions   int
	AuthFailures1h   int
	ObservedAt       time.Time
}

// SecurityEvent is one security-relevant log entry (auth failure, ban, etc.).
type SecurityEvent struct {
	ID         string
	ServerID   string
	Source     string
	Kind       string
	RemoteIP   string
	Country    string
	Service    string
	RawLine    string
	ObservedAt time.Time
}

// BanEntry is one IP ban (fail2ban / crowdsec / manual).
type BanEntry struct {
	ID         string
	ServerID   string
	IP         string
	Source     string
	Reason     string
	ExpiresAt  *time.Time
	BannedAt   time.Time
	UnbannedAt *time.Time
	State      string
	CreatedAt  time.Time
}

// WAFRule is one rate-limit or block rule for the WAF/nginx layer.
type WAFRule struct {
	ID          string
	ServerID    string
	Kind        string
	Pattern     string
	Action      string
	Enabled     bool
	Priority    int
	Description string
	CreatedAt   time.Time
}

// ── Column lists ───────────────────────────────────────────────────────────────

const checkColumns = `id, server_id, check_name, category, severity, status, title, description, remediation, observed_at, created_at`
const sshColumns = `id, server_id, permit_root_login, password_auth, pubkey_auth, port, protocol_versions, active_sessions, auth_failures_1h, observed_at`
const eventColumns = `id, server_id, source, kind, remote_ip, country, service, raw_line, observed_at`
const banColumns = `id, server_id, ip, source, reason, expires_at, banned_at, unbanned_at, state, created_at`
const wafColumns = `id, server_id, kind, pattern, action, enabled, priority, description, created_at`

// ── Store ──────────────────────────────────────────────────────────────────────

// Store owns all security-center read/write operations.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore builds a security store backed by pool.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// ── Hardening checks ──────────────────────────────────────────────────────────

func scanCheck(row pgx.Row) (HardeningCheck, error) {
	var c HardeningCheck
	err := row.Scan(&c.ID, &c.ServerID, &c.CheckName, &c.Category, &c.Severity, &c.Status,
		&c.Title, &c.Description, &c.Remediation, &c.ObservedAt, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return HardeningCheck{}, ErrNotFound
	}
	if err != nil {
		return HardeningCheck{}, fmt.Errorf("security: scan check: %w", err)
	}
	return c, nil
}

// UpsertCheckParams configures a hardening check upsert (replace on re-scan).
type UpsertCheckParams struct {
	ServerID    string
	CheckName   string
	Category    string
	Severity    string
	Status      string
	Title       string
	Description string
	Remediation string
}

// UpsertCheck inserts or replaces a hardening check result for a server.
// On re-scan the previous result for the same (server_id, check_name) is deleted first.
func (s *Store) UpsertCheck(ctx context.Context, p UpsertCheckParams) (HardeningCheck, error) {
	if strings.TrimSpace(p.ServerID) == "" || strings.TrimSpace(p.CheckName) == "" {
		return HardeningCheck{}, fmt.Errorf("%w: server_id and check_name are required", ErrInvalid)
	}
	// Delete stale result, then insert fresh.
	_, _ = s.pool.Exec(ctx,
		`DELETE FROM hardening_checks WHERE server_id = $1 AND check_name = $2`,
		p.ServerID, p.CheckName)
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO hardening_checks
		  (server_id, check_name, category, severity, status, title, description, remediation)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING %s`, checkColumns),
		p.ServerID, p.CheckName, p.Category, p.Severity, p.Status, p.Title, p.Description, p.Remediation)
	return scanCheck(row)
}

// ListChecks returns all hardening checks for a server, newest-observed first.
func (s *Store) ListChecks(ctx context.Context, serverID string) ([]HardeningCheck, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT %s FROM hardening_checks WHERE server_id = $1 ORDER BY severity, observed_at DESC`, checkColumns),
		serverID)
	if err != nil {
		return nil, fmt.Errorf("security: list checks: %w", err)
	}
	defer rows.Close()
	var out []HardeningCheck
	for rows.Next() {
		c, err := scanCheck(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ── SSH posture ────────────────────────────────────────────────────────────────

func scanSSH(row pgx.Row) (SSHPosture, error) {
	var p SSHPosture
	err := row.Scan(&p.ID, &p.ServerID, &p.PermitRootLogin, &p.PasswordAuth, &p.PubkeyAuth,
		&p.Port, &p.ProtocolVersions, &p.ActiveSessions, &p.AuthFailures1h, &p.ObservedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SSHPosture{}, ErrNotFound
	}
	if err != nil {
		return SSHPosture{}, fmt.Errorf("security: scan ssh posture: %w", err)
	}
	return p, nil
}

// RecordSSHPostureParams configures a posture snapshot.
type RecordSSHPostureParams struct {
	ServerID         string
	PermitRootLogin  string
	PasswordAuth     string
	PubkeyAuth       string
	Port             int
	ProtocolVersions string
	ActiveSessions   int
	AuthFailures1h   int
}

// RecordSSHPosture inserts a new SSH posture snapshot.
func (s *Store) RecordSSHPosture(ctx context.Context, p RecordSSHPostureParams) (SSHPosture, error) {
	if strings.TrimSpace(p.ServerID) == "" {
		return SSHPosture{}, fmt.Errorf("%w: server_id is required", ErrInvalid)
	}
	port := p.Port
	if port == 0 {
		port = 22
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO ssh_posture_log
		  (server_id, permit_root_login, password_auth, pubkey_auth, port, protocol_versions, active_sessions, auth_failures_1h)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING %s`, sshColumns),
		p.ServerID, p.PermitRootLogin, p.PasswordAuth, p.PubkeyAuth, port,
		p.ProtocolVersions, p.ActiveSessions, p.AuthFailures1h)
	return scanSSH(row)
}

// LatestSSHPosture returns the most recent SSH posture snapshot for a server.
func (s *Store) LatestSSHPosture(ctx context.Context, serverID string) (SSHPosture, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM ssh_posture_log WHERE server_id = $1 ORDER BY observed_at DESC LIMIT 1`, sshColumns),
		serverID)
	return scanSSH(row)
}

// ── Security events ────────────────────────────────────────────────────────────

func scanEvent(row pgx.Row) (SecurityEvent, error) {
	var e SecurityEvent
	err := row.Scan(&e.ID, &e.ServerID, &e.Source, &e.Kind, &e.RemoteIP,
		&e.Country, &e.Service, &e.RawLine, &e.ObservedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return SecurityEvent{}, ErrNotFound
	}
	if err != nil {
		return SecurityEvent{}, fmt.Errorf("security: scan event: %w", err)
	}
	return e, nil
}

// RecordEventParams configures a security event insertion.
type RecordEventParams struct {
	ServerID string
	Source   string
	Kind     string
	RemoteIP string
	Country  string
	Service  string
	RawLine  string
}

// RecordEvent inserts a new security event.
func (s *Store) RecordEvent(ctx context.Context, p RecordEventParams) (SecurityEvent, error) {
	if strings.TrimSpace(p.ServerID) == "" {
		return SecurityEvent{}, fmt.Errorf("%w: server_id is required", ErrInvalid)
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO security_events (server_id, source, kind, remote_ip, country, service, raw_line)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING %s`, eventColumns),
		p.ServerID, p.Source, p.Kind, p.RemoteIP, p.Country, p.Service, p.RawLine)
	return scanEvent(row)
}

// ListEvents returns recent security events for a server (newest first, limit 200).
func (s *Store) ListEvents(ctx context.Context, serverID string) ([]SecurityEvent, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT %s FROM security_events WHERE server_id = $1 ORDER BY observed_at DESC LIMIT 200`, eventColumns),
		serverID)
	if err != nil {
		return nil, fmt.Errorf("security: list events: %w", err)
	}
	defer rows.Close()
	var out []SecurityEvent
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ── Ban entries ────────────────────────────────────────────────────────────────

func scanBan(row pgx.Row) (BanEntry, error) {
	var b BanEntry
	err := row.Scan(&b.ID, &b.ServerID, &b.IP, &b.Source, &b.Reason,
		&b.ExpiresAt, &b.BannedAt, &b.UnbannedAt, &b.State, &b.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return BanEntry{}, ErrNotFound
	}
	if err != nil {
		return BanEntry{}, fmt.Errorf("security: scan ban: %w", err)
	}
	return b, nil
}

// CreateBanParams configures a new ban.
type CreateBanParams struct {
	ServerID  string
	IP        string
	Source    string
	Reason    string
	ExpiresAt *time.Time
}

// CreateBan inserts a new active ban entry.
// Returns ErrConflict if an active ban already exists for (server_id, ip).
func (s *Store) CreateBan(ctx context.Context, p CreateBanParams) (BanEntry, error) {
	if strings.TrimSpace(p.ServerID) == "" || strings.TrimSpace(p.IP) == "" {
		return BanEntry{}, fmt.Errorf("%w: server_id and ip are required", ErrInvalid)
	}
	src := p.Source
	if src == "" {
		src = "manual"
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO ban_entries (server_id, ip, source, reason, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING %s`, banColumns),
		p.ServerID, p.IP, src, p.Reason, p.ExpiresAt)
	b, err := scanBan(row)
	if err != nil && strings.Contains(err.Error(), "unique") {
		return BanEntry{}, ErrConflict
	}
	return b, err
}

// RemoveBan marks an active ban as removed (unban).
func (s *Store) RemoveBan(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE ban_entries SET state = 'removed', unbanned_at = NOW()
		 WHERE id = $1 AND state = 'active'`, id)
	if err != nil {
		return fmt.Errorf("security: remove ban: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListBans returns all active bans for a server (newest first).
func (s *Store) ListBans(ctx context.Context, serverID string) ([]BanEntry, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT %s FROM ban_entries WHERE server_id = $1 AND state = 'active' ORDER BY banned_at DESC`, banColumns),
		serverID)
	if err != nil {
		return nil, fmt.Errorf("security: list bans: %w", err)
	}
	defer rows.Close()
	var out []BanEntry
	for rows.Next() {
		b, err := scanBan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// ── WAF rules ──────────────────────────────────────────────────────────────────

func scanWAF(row pgx.Row) (WAFRule, error) {
	var w WAFRule
	err := row.Scan(&w.ID, &w.ServerID, &w.Kind, &w.Pattern, &w.Action,
		&w.Enabled, &w.Priority, &w.Description, &w.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return WAFRule{}, ErrNotFound
	}
	if err != nil {
		return WAFRule{}, fmt.Errorf("security: scan waf rule: %w", err)
	}
	return w, nil
}

// CreateWAFRuleParams configures a new WAF rule.
type CreateWAFRuleParams struct {
	ServerID    string
	Kind        string
	Pattern     string
	Action      string
	Enabled     bool
	Priority    int
	Description string
}

// CreateWAFRule inserts a new WAF rule.
func (s *Store) CreateWAFRule(ctx context.Context, p CreateWAFRuleParams) (WAFRule, error) {
	if strings.TrimSpace(p.ServerID) == "" || strings.TrimSpace(p.Pattern) == "" {
		return WAFRule{}, fmt.Errorf("%w: server_id and pattern are required", ErrInvalid)
	}
	kind := p.Kind
	if kind == "" {
		kind = "rate_limit"
	}
	action := p.Action
	if action == "" {
		action = "block"
	}
	prio := p.Priority
	if prio == 0 {
		prio = 100
	}
	row := s.pool.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO waf_rules (server_id, kind, pattern, action, enabled, priority, description)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING %s`, wafColumns),
		p.ServerID, kind, p.Pattern, action, p.Enabled, prio, p.Description)
	return scanWAF(row)
}

// GetWAFRule returns one WAF rule by ID.
func (s *Store) GetWAFRule(ctx context.Context, id string) (WAFRule, error) {
	row := s.pool.QueryRow(ctx, fmt.Sprintf(
		`SELECT %s FROM waf_rules WHERE id = $1`, wafColumns), id)
	return scanWAF(row)
}

// DeleteWAFRule removes a WAF rule permanently.
func (s *Store) DeleteWAFRule(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM waf_rules WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("security: delete waf rule: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListWAFRules returns all WAF rules for a server, ordered by priority.
func (s *Store) ListWAFRules(ctx context.Context, serverID string) ([]WAFRule, error) {
	rows, err := s.pool.Query(ctx, fmt.Sprintf(
		`SELECT %s FROM waf_rules WHERE server_id = $1 ORDER BY priority, created_at`, wafColumns),
		serverID)
	if err != nil {
		return nil, fmt.Errorf("security: list waf rules: %w", err)
	}
	defer rows.Close()
	var out []WAFRule
	for rows.Next() {
		w, err := scanWAF(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}
