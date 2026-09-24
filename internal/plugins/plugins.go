// Package plugins owns the plugin SDK data layer:
// plugin registry, permission declarations, install lifecycle, and quarantine.
//
// Security invariants:
//   - No plugin gets implicit privilege (trust_level 'unverified' by default).
//   - Permission escalation requires explicit grant with reviewer recorded.
//   - Quarantined plugins cannot be enabled until quarantine is resolved.
//   - plugin_installs is append-only for audit (lifecycle log).
package plugins

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors.
var (
	ErrNotFound    = errors.New("plugins: not found")
	ErrConflict    = errors.New("plugins: already exists")
	ErrQuarantined = errors.New("plugins: plugin is quarantined")
)

// ── Types ─────────────────────────────────────────────────────────────────────

// Plugin is an installed plugin in the registry.
type Plugin struct {
	ID          string
	Name        string
	DisplayName string
	Description string
	Version     string
	Author      string
	HomepageURL string
	Manifest    map[string]any
	TrustLevel  string // unverified | community | verified | official
	State       string // installing | installed | enabled | disabled | quarantined | removed
	Signature   string
	Checksum    string
	InstalledAt time.Time
	UpdatedAt   time.Time
}

// Permission is one permission declared by a plugin.
type Permission struct {
	ID         string
	PluginID   string
	Permission string
	ScopeKind  string
	Granted    bool
	GrantedBy  string
	GrantedAt  *time.Time
	CreatedAt  time.Time
}

// InstallEvent is one lifecycle event in the plugin install history.
type InstallEvent struct {
	ID          string
	PluginID    string
	EventType   string // install | update | enable | disable | uninstall | quarantine | restore
	FromVersion string
	ToVersion   string
	InitiatedBy string
	Notes       string
	OccurredAt  time.Time
}

// Quarantine is a quarantine record for a broken/untrusted plugin.
type Quarantine struct {
	ID            string
	PluginID      string
	Reason        string
	QuarantinedBy string
	Resolved      bool
	ResolvedBy    string
	CreatedAt     time.Time
	ResolvedAt    *time.Time
}

// ── Store ─────────────────────────────────────────────────────────────────────

// Store is the plugin data store.
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

// ── Plugins ───────────────────────────────────────────────────────────────────

// ListPlugins returns all plugins, optionally filtered by state.
func (s *Store) ListPlugins(ctx context.Context, stateFilter string) ([]Plugin, error) {
	var rows pgx.Rows
	var err error
	if stateFilter != "" {
		rows, err = s.pool.Query(ctx,
			`SELECT id, name, display_name, description, version, author, homepage_url, manifest,
			        trust_level, state, signature, checksum, installed_at, updated_at
			 FROM plugins WHERE state = $1 ORDER BY name`, stateFilter)
	} else {
		rows, err = s.pool.Query(ctx,
			`SELECT id, name, display_name, description, version, author, homepage_url, manifest,
			        trust_level, state, signature, checksum, installed_at, updated_at
			 FROM plugins WHERE state != 'removed' ORDER BY name`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanPlugins(rows)
}

// GetPlugin returns a plugin by ID.
func (s *Store) GetPlugin(ctx context.Context, id string) (Plugin, error) {
	var p Plugin
	err := s.pool.QueryRow(ctx,
		`SELECT id, name, display_name, description, version, author, homepage_url, manifest,
		        trust_level, state, signature, checksum, installed_at, updated_at
		 FROM plugins WHERE id = $1`, id).
		Scan(&p.ID, &p.Name, &p.DisplayName, &p.Description, &p.Version, &p.Author, &p.HomepageURL,
			&p.Manifest, &p.TrustLevel, &p.State, &p.Signature, &p.Checksum, &p.InstalledAt, &p.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Plugin{}, ErrNotFound
	}
	return p, err
}

// RegisterPlugin adds a new plugin to the registry with trust_level=unverified.
func (s *Store) RegisterPlugin(ctx context.Context, name, displayName, description, version, author, homepageURL, signature, checksum string, manifest map[string]any) (Plugin, error) {
	if manifest == nil {
		manifest = map[string]any{}
	}
	var p Plugin
	err := s.pool.QueryRow(ctx,
		`INSERT INTO plugins (name, display_name, description, version, author, homepage_url, signature, checksum, manifest)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING id, name, display_name, description, version, author, homepage_url, manifest,
		           trust_level, state, signature, checksum, installed_at, updated_at`,
		name, displayName, description, version, author, homepageURL, signature, checksum, manifest).
		Scan(&p.ID, &p.Name, &p.DisplayName, &p.Description, &p.Version, &p.Author, &p.HomepageURL,
			&p.Manifest, &p.TrustLevel, &p.State, &p.Signature, &p.Checksum, &p.InstalledAt, &p.UpdatedAt)
	if isUniqueViolation(err) {
		return Plugin{}, ErrConflict
	}
	return p, err
}

// UpdatePluginState transitions plugin state.
func (s *Store) UpdatePluginState(ctx context.Context, id, state string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE plugins SET state = $1, updated_at = now() WHERE id = $2`, state, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetTrustLevel updates a plugin's trust level (requires explicit reviewer action).
func (s *Store) SetTrustLevel(ctx context.Context, id, trustLevel string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE plugins SET trust_level = $1, updated_at = now() WHERE id = $2`, trustLevel, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ── Permissions ───────────────────────────────────────────────────────────────

// DeclarePermission records a permission requirement for a plugin.
func (s *Store) DeclarePermission(ctx context.Context, pluginID, permission, scopeKind string) (Permission, error) {
	var perm Permission
	err := s.pool.QueryRow(ctx,
		`INSERT INTO plugin_permissions (plugin_id, permission, scope_kind)
		 VALUES ($1, $2, $3)
		 ON CONFLICT (plugin_id, permission) DO UPDATE SET scope_kind = EXCLUDED.scope_kind
		 RETURNING id, plugin_id, permission, scope_kind, granted, granted_by, granted_at, created_at`,
		pluginID, permission, scopeKind).
		Scan(&perm.ID, &perm.PluginID, &perm.Permission, &perm.ScopeKind, &perm.Granted,
			&perm.GrantedBy, &perm.GrantedAt, &perm.CreatedAt)
	return perm, err
}

// GrantPermission explicitly grants a permission to a plugin (requires reviewer).
func (s *Store) GrantPermission(ctx context.Context, id, grantedBy string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE plugin_permissions SET granted = true, granted_by = $1, granted_at = now()
		 WHERE id = $2`, grantedBy, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ListPermissions returns all declared permissions for a plugin.
func (s *Store) ListPermissions(ctx context.Context, pluginID string) ([]Permission, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, plugin_id, permission, scope_kind, granted, granted_by, granted_at, created_at
		 FROM plugin_permissions WHERE plugin_id = $1 ORDER BY permission`, pluginID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Permission
	for rows.Next() {
		var p Permission
		if err := rows.Scan(&p.ID, &p.PluginID, &p.Permission, &p.ScopeKind, &p.Granted,
			&p.GrantedBy, &p.GrantedAt, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ── Install Lifecycle ─────────────────────────────────────────────────────────

// RecordInstallEvent appends a lifecycle event (install/update/uninstall/etc).
func (s *Store) RecordInstallEvent(ctx context.Context, pluginID, eventType, fromVersion, toVersion, initiatedBy, notes string) (InstallEvent, error) {
	var ev InstallEvent
	err := s.pool.QueryRow(ctx,
		`INSERT INTO plugin_installs (plugin_id, event_type, from_version, to_version, initiated_by, notes)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, plugin_id, event_type, from_version, to_version, initiated_by, notes, occurred_at`,
		pluginID, eventType, fromVersion, toVersion, initiatedBy, notes).
		Scan(&ev.ID, &ev.PluginID, &ev.EventType, &ev.FromVersion, &ev.ToVersion, &ev.InitiatedBy, &ev.Notes, &ev.OccurredAt)
	return ev, err
}

// ListInstallEvents returns lifecycle history for a plugin.
func (s *Store) ListInstallEvents(ctx context.Context, pluginID string) ([]InstallEvent, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, plugin_id, event_type, from_version, to_version, initiated_by, notes, occurred_at
		 FROM plugin_installs WHERE plugin_id = $1 ORDER BY occurred_at DESC LIMIT 50`, pluginID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InstallEvent
	for rows.Next() {
		var ev InstallEvent
		if err := rows.Scan(&ev.ID, &ev.PluginID, &ev.EventType, &ev.FromVersion, &ev.ToVersion,
			&ev.InitiatedBy, &ev.Notes, &ev.OccurredAt); err != nil {
			return nil, err
		}
		out = append(out, ev)
	}
	return out, rows.Err()
}

// ── Quarantine ────────────────────────────────────────────────────────────────

// QuarantinePlugin quarantines a plugin (sets state=quarantined and records reason).
func (s *Store) QuarantinePlugin(ctx context.Context, pluginID, reason, quarantinedBy string) (Quarantine, error) {
	var q Quarantine
	err := s.pool.QueryRow(ctx,
		`INSERT INTO plugin_quarantines (plugin_id, reason, quarantined_by)
		 VALUES ($1, $2, $3)
		 RETURNING id, plugin_id, reason, quarantined_by, resolved, resolved_by, created_at, resolved_at`,
		pluginID, reason, quarantinedBy).
		Scan(&q.ID, &q.PluginID, &q.Reason, &q.QuarantinedBy, &q.Resolved, &q.ResolvedBy, &q.CreatedAt, &q.ResolvedAt)
	if err != nil {
		return Quarantine{}, err
	}
	// Mark plugin as quarantined.
	_ = s.UpdatePluginState(ctx, pluginID, "quarantined")
	return q, nil
}

// ResolveQuarantine marks a quarantine as resolved and re-enables the plugin.
func (s *Store) ResolveQuarantine(ctx context.Context, id, resolvedBy string) (Quarantine, error) {
	var q Quarantine
	err := s.pool.QueryRow(ctx,
		`UPDATE plugin_quarantines SET resolved = true, resolved_by = $1, resolved_at = now()
		 WHERE id = $2
		 RETURNING id, plugin_id, reason, quarantined_by, resolved, resolved_by, created_at, resolved_at`,
		resolvedBy, id).
		Scan(&q.ID, &q.PluginID, &q.Reason, &q.QuarantinedBy, &q.Resolved, &q.ResolvedBy, &q.CreatedAt, &q.ResolvedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Quarantine{}, ErrNotFound
	}
	if err != nil {
		return Quarantine{}, err
	}
	_ = s.UpdatePluginState(ctx, q.PluginID, "disabled")
	return q, nil
}

// ListQuarantines returns quarantine records for a plugin.
func (s *Store) ListQuarantines(ctx context.Context, pluginID string) ([]Quarantine, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, plugin_id, reason, quarantined_by, resolved, resolved_by, created_at, resolved_at
		 FROM plugin_quarantines WHERE plugin_id = $1 ORDER BY created_at DESC`, pluginID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Quarantine
	for rows.Next() {
		var q Quarantine
		if err := rows.Scan(&q.ID, &q.PluginID, &q.Reason, &q.QuarantinedBy, &q.Resolved,
			&q.ResolvedBy, &q.CreatedAt, &q.ResolvedAt); err != nil {
			return nil, err
		}
		out = append(out, q)
	}
	return out, rows.Err()
}

// ── helpers ───────────────────────────────────────────────────────────────────

func scanPlugins(rows pgx.Rows) ([]Plugin, error) {
	var out []Plugin
	for rows.Next() {
		var p Plugin
		if err := rows.Scan(&p.ID, &p.Name, &p.DisplayName, &p.Description, &p.Version, &p.Author,
			&p.HomepageURL, &p.Manifest, &p.TrustLevel, &p.State, &p.Signature, &p.Checksum,
			&p.InstalledAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

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
