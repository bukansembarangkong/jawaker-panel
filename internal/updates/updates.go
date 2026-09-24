// Package updates owns the update platform data layer:
// release discovery, snapshots, update jobs, canary rollouts, module updates.
//
// Invariant: no secret or credential stored here. Artifact verification
// happens inside the node executor; only the outcome is recorded.
package updates

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors.
var (
	ErrNotFound = errors.New("updates: not found")
	ErrConflict = errors.New("updates: version already recorded for this channel")
)

// ── Types ──────────────────────────────────────────────────────────────────────

// Release is a discovered GitHub Release.
type Release struct {
	ID           string
	Channel      string
	Version      string
	Tag          string
	Notes        string
	ArtifactURL  string
	ChecksumURL  string
	SignatureURL string
	PublishedAt  time.Time
	DiscoveredAt time.Time
	Compatible   *bool // nil = not yet checked
}

// Snapshot is a recovery point taken before applying an update.
type Snapshot struct {
	ID         string
	ReleaseID  string
	State      string
	Manifest   map[string]any
	SnapshotAt *time.Time
	Notes      string
	CreatedAt  time.Time
}

// Job tracks one update apply attempt.
type Job struct {
	ID           string
	ReleaseID    string
	SnapshotID   *string
	State        string
	TriggeredBy  string
	StartedAt    *time.Time
	CompletedAt  *time.Time
	ErrorMessage string
	CreatedAt    time.Time
}

// CanaryEntry tracks per-server state within a fleet canary rollout.
type CanaryEntry struct {
	ID           string
	JobID        string
	ServerID     string
	State        string
	StartedAt    *time.Time
	CompletedAt  *time.Time
	ErrorMessage string
}

// ModuleUpdate records version state for one module.
type ModuleUpdate struct {
	ID          string
	ModuleName  string
	CurrentVer  string
	LatestVer   *string
	State       string
	LastChecked *time.Time
	UpdatedAt   *time.Time
	CreatedAt   time.Time
}

// ── Store ──────────────────────────────────────────────────────────────────────

// Store is the updates data-access layer.
type Store struct{ pool *pgxpool.Pool }

// New creates a Store backed by pool.
func New(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }

// ── Release ────────────────────────────────────────────────────────────────────

const releaseColumns = `id, channel, version, tag, notes, artifact_url, checksum_url,
    signature_url, published_at, discovered_at, compatible`

func scanRelease(row pgx.Row) (*Release, error) {
	r := &Release{}
	err := row.Scan(&r.ID, &r.Channel, &r.Version, &r.Tag, &r.Notes,
		&r.ArtifactURL, &r.ChecksumURL, &r.SignatureURL,
		&r.PublishedAt, &r.DiscoveredAt, &r.Compatible)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// UpsertRelease inserts or updates a release (idempotent on channel+version).
func (s *Store) UpsertRelease(ctx context.Context, r Release) (*Release, error) {
	row := s.pool.QueryRow(ctx, `
		INSERT INTO update_releases
		    (channel, version, tag, notes, artifact_url, checksum_url, signature_url, published_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (channel, version) DO UPDATE
		    SET tag=EXCLUDED.tag, notes=EXCLUDED.notes,
		        artifact_url=EXCLUDED.artifact_url, checksum_url=EXCLUDED.checksum_url,
		        signature_url=EXCLUDED.signature_url, published_at=EXCLUDED.published_at
		RETURNING `+releaseColumns,
		r.Channel, r.Version, r.Tag, r.Notes,
		r.ArtifactURL, r.ChecksumURL, r.SignatureURL, r.PublishedAt)
	return scanRelease(row)
}

// SetCompatible records compatibility preflight result for a release.
func (s *Store) SetCompatible(ctx context.Context, id string, ok bool) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE update_releases SET compatible=$1 WHERE id=$2`, ok, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// GetRelease fetches one release by ID.
func (s *Store) GetRelease(ctx context.Context, id string) (*Release, error) {
	return scanRelease(s.pool.QueryRow(ctx,
		`SELECT `+releaseColumns+` FROM update_releases WHERE id=$1`, id))
}

// ListReleases returns releases for a channel, newest first.
func (s *Store) ListReleases(ctx context.Context, channel string) ([]*Release, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+releaseColumns+`
		 FROM update_releases
		 WHERE ($1='' OR channel=$1)
		 ORDER BY published_at DESC LIMIT 50`, channel)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Release
	for rows.Next() {
		r := &Release{}
		if err := rows.Scan(&r.ID, &r.Channel, &r.Version, &r.Tag, &r.Notes,
			&r.ArtifactURL, &r.ChecksumURL, &r.SignatureURL,
			&r.PublishedAt, &r.DiscoveredAt, &r.Compatible); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ── Snapshot ───────────────────────────────────────────────────────────────────

// CreateSnapshot creates a new snapshot record.
func (s *Store) CreateSnapshot(ctx context.Context, releaseID, notes string) (*Snapshot, error) {
	snap := &Snapshot{}
	manifest := map[string]any{}
	manifestJSON, _ := json.Marshal(manifest)
	err := s.pool.QueryRow(ctx, `
		INSERT INTO update_snapshots (release_id, notes, manifest)
		VALUES ($1,$2,$3)
		RETURNING id, release_id, state, manifest, snapshot_at, notes, created_at`,
		releaseID, notes, manifestJSON).
		Scan(&snap.ID, &snap.ReleaseID, &snap.State, (*[]byte)(nil),
			&snap.SnapshotAt, &snap.Notes, &snap.CreatedAt)
	snap.Manifest = manifest
	return snap, err
}

// UpdateSnapshotState transitions snapshot to a new state, optionally recording manifest.
func (s *Store) UpdateSnapshotState(ctx context.Context, id, state string, manifest map[string]any) error {
	var manifestJSON []byte
	if manifest != nil {
		manifestJSON, _ = json.Marshal(manifest)
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE update_snapshots
		SET state=$1,
		    manifest=COALESCE($2::jsonb, manifest),
		    snapshot_at=CASE WHEN $1='ready' THEN NOW() ELSE snapshot_at END
		WHERE id=$3`, state, manifestJSON, id)
	return err
}

// GetSnapshot fetches one snapshot.
func (s *Store) GetSnapshot(ctx context.Context, id string) (*Snapshot, error) {
	snap := &Snapshot{}
	var manifestRaw []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, release_id, state, manifest, snapshot_at, notes, created_at
		FROM update_snapshots WHERE id=$1`, id).
		Scan(&snap.ID, &snap.ReleaseID, &snap.State, &manifestRaw,
			&snap.SnapshotAt, &snap.Notes, &snap.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(manifestRaw, &snap.Manifest)
	return snap, nil
}

// ── Job ────────────────────────────────────────────────────────────────────────

// CreateJob creates an update job record.
func (s *Store) CreateJob(ctx context.Context, releaseID, triggeredBy string) (*Job, error) {
	job := &Job{}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO update_jobs (release_id, triggered_by)
		VALUES ($1,$2)
		RETURNING id, release_id, snapshot_id, state, triggered_by,
		          started_at, completed_at, error_message, created_at`,
		releaseID, triggeredBy).
		Scan(&job.ID, &job.ReleaseID, &job.SnapshotID, &job.State, &job.TriggeredBy,
			&job.StartedAt, &job.CompletedAt, &job.ErrorMessage, &job.CreatedAt)
	return job, err
}

// UpdateJobState transitions an update job to a new state.
func (s *Store) UpdateJobState(ctx context.Context, id, state, errMsg string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE update_jobs
		SET state=$1,
		    error_message=NULLIF($2,''),
		    started_at=CASE WHEN $1='preflight' AND started_at IS NULL THEN NOW() ELSE started_at END,
		    completed_at=CASE WHEN $1 IN ('done','failed','rolled_back') THEN NOW() ELSE completed_at END
		WHERE id=$3`, state, errMsg, id)
	return err
}

// AttachSnapshot links a snapshot to a job.
func (s *Store) AttachSnapshot(ctx context.Context, jobID, snapshotID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE update_jobs SET snapshot_id=$1 WHERE id=$2`, snapshotID, jobID)
	return err
}

// GetJob fetches one job.
func (s *Store) GetJob(ctx context.Context, id string) (*Job, error) {
	job := &Job{}
	err := s.pool.QueryRow(ctx, `
		SELECT id, release_id, snapshot_id, state, triggered_by,
		       started_at, completed_at, error_message, created_at
		FROM update_jobs WHERE id=$1`, id).
		Scan(&job.ID, &job.ReleaseID, &job.SnapshotID, &job.State, &job.TriggeredBy,
			&job.StartedAt, &job.CompletedAt, &job.ErrorMessage, &job.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return job, err
}

// ListJobs returns update jobs, newest first.
func (s *Store) ListJobs(ctx context.Context) ([]*Job, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, release_id, snapshot_id, state, triggered_by,
		       started_at, completed_at, error_message, created_at
		FROM update_jobs ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Job
	for rows.Next() {
		j := &Job{}
		if err := rows.Scan(&j.ID, &j.ReleaseID, &j.SnapshotID, &j.State, &j.TriggeredBy,
			&j.StartedAt, &j.CompletedAt, &j.ErrorMessage, &j.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// ── Canary ─────────────────────────────────────────────────────────────────────

// UpsertCanaryEntry records or updates a canary rollout entry for one server.
func (s *Store) UpsertCanaryEntry(ctx context.Context, jobID, serverID, state, errMsg string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO canary_rollouts (job_id, server_id, state, error_message)
		VALUES ($1,$2,$3,NULLIF($4,''))
		ON CONFLICT (job_id, server_id) DO UPDATE
		    SET state=EXCLUDED.state,
		        error_message=EXCLUDED.error_message,
		        started_at=CASE WHEN EXCLUDED.state='applying' AND canary_rollouts.started_at IS NULL
		                        THEN NOW() ELSE canary_rollouts.started_at END,
		        completed_at=CASE WHEN EXCLUDED.state IN ('done','failed','paused')
		                          THEN NOW() ELSE canary_rollouts.completed_at END`,
		jobID, serverID, state, errMsg)
	return err
}

// ListCanaryEntries lists all canary entries for a job.
func (s *Store) ListCanaryEntries(ctx context.Context, jobID string) ([]*CanaryEntry, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, job_id, server_id, state, started_at, completed_at, error_message
		FROM canary_rollouts WHERE job_id=$1 ORDER BY id`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CanaryEntry
	for rows.Next() {
		e := &CanaryEntry{}
		if err := rows.Scan(&e.ID, &e.JobID, &e.ServerID, &e.State,
			&e.StartedAt, &e.CompletedAt, &e.ErrorMessage); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ── Module updates ─────────────────────────────────────────────────────────────

// UpsertModule records or refreshes module version info.
func (s *Store) UpsertModule(ctx context.Context, name, currentVer string, latestVer *string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO module_updates (module_name, current_ver, latest_ver, last_checked)
		VALUES ($1,$2,$3,NOW())
		ON CONFLICT (module_name) DO UPDATE
		    SET current_ver=EXCLUDED.current_ver,
		        latest_ver=EXCLUDED.latest_ver,
		        last_checked=NOW()`,
		name, currentVer, latestVer)
	return err
}

// SetModuleState transitions module update state.
func (s *Store) SetModuleState(ctx context.Context, name, state string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE module_updates
		SET state=$1,
		    updated_at=CASE WHEN $1='done' THEN NOW() ELSE updated_at END
		WHERE module_name=$2`, state, name)
	return err
}

// ListModules returns all tracked modules.
func (s *Store) ListModules(ctx context.Context) ([]*ModuleUpdate, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, module_name, current_ver, latest_ver, state, last_checked, updated_at, created_at
		FROM module_updates ORDER BY module_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ModuleUpdate
	for rows.Next() {
		m := &ModuleUpdate{}
		if err := rows.Scan(&m.ID, &m.ModuleName, &m.CurrentVer, &m.LatestVer,
			&m.State, &m.LastChecked, &m.UpdatedAt, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
