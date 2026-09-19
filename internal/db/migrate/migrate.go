// Package migrate implements the control-plane SQL migration runner.
//
// Guarantees (DATABASE.md §13, CONTRIBUTING.md §6):
//   - migrations are ordered by numeric version prefix and applied once;
//   - each migration runs in its own transaction; a failure leaves the
//     database at the last good version with an actionable error;
//   - applied migrations are immutable: a checksum mismatch is a hard error,
//     never silently re-applied or ignored;
//   - an advisory lock serializes concurrent migrators (multi-replica
//     controller upgrades);
//   - migrations are forward-only by design. Binary rollback does NOT reverse
//     schema changes; recovery relies on database backups (documented, not
//     pretended — AGENTS.md §3.12).
package migrate

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// advisoryLockKey is a fixed application-wide lock ID serializing migrators.
// Arbitrary constant reserved for JAWAKER migrations; documented here so it is
// never accidentally reused by another subsystem.
const advisoryLockKey int64 = 0x4A41_574D_4947 // "JAWMIG"

// fileNamePattern enforces NNNN_snake_case.sql so ordering and intent are
// unambiguous. Malformed names are errors, not silently skipped.
var fileNamePattern = regexp.MustCompile(`^([0-9]{4})_([a-z0-9_]+)\.sql$`)

// isMigrationCandidate reports whether a file should be strictly validated as
// a migration. Dotfiles (e.g. .keep) and documentation are ignored; anything
// that looks like a migration (digit-prefixed or .sql-suffixed) IS validated,
// so typos like 0001_foo.sql.bak fail loudly instead of being silently
// skipped and forgotten.
func isMigrationCandidate(name string) bool {
	if strings.HasPrefix(name, ".") {
		return false
	}
	if name == "README.md" {
		return false
	}
	return strings.HasSuffix(name, ".sql") || (name[0] >= '0' && name[0] <= '9')
}

// Migration is a single parsed SQL migration file.
type Migration struct {
	// Version is the numeric prefix; ordering key, stored in the DB.
	Version int64
	// Name is the full file name (e.g. 0001_enable_citext.sql).
	Name string
	// SQL is the migration body.
	SQL []byte
	// Checksum is the SHA-256 hex digest of SQL, recorded at apply time.
	Checksum string
}

// Parse reads and validates every *.sql migration from fsys, sorted by
// numeric version. It performs no I/O beyond the filesystem, making the
// ordering/validation rules unit-testable without a database.
func Parse(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("migrate: read migration dir: %w", err)
	}

	byVersion := make(map[int64]string)
	migrations := make([]Migration, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !isMigrationCandidate(entry.Name()) {
			continue
		}
		m := fileNamePattern.FindStringSubmatch(entry.Name())
		if m == nil {
			return nil, fmt.Errorf(
				"migrate: invalid migration name %q: want NNNN_snake_case.sql (4-digit zero-padded version, lowercase)",
				entry.Name())
		}
		version, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("migrate: bad version in %q: %w", entry.Name(), err)
		}
		if prev, dup := byVersion[version]; dup {
			return nil, fmt.Errorf("migrate: duplicate version %d: %q and %q", version, prev, entry.Name())
		}
		byVersion[version] = entry.Name()

		sqlBytes, err := fs.ReadFile(fsys, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("migrate: read %q: %w", entry.Name(), err)
		}
		sum := sha256.Sum256(sqlBytes)
		migrations = append(migrations, Migration{
			Version:  version,
			Name:     entry.Name(),
			SQL:      sqlBytes,
			Checksum: hex.EncodeToString(sum[:]),
		})
	}

	// Numeric sort, NOT lexicographic: 0010 must follow 0009, and a future
	// 5-digit version must still order correctly.
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].Version < migrations[j].Version })
	return migrations, nil
}

// Migrator applies migrations from an embedded filesystem to PostgreSQL.
type Migrator struct {
	migrations []Migration
	log        *slog.Logger
}

// New parses fsys and returns a ready Migrator. Parse errors surface here so
// a malformed migration directory fails the build of the release binary's
// startup, not a later deploy step.
func New(fsys fs.FS, log *slog.Logger) (*Migrator, error) {
	if log == nil {
		return nil, errors.New("migrate: logger is required")
	}
	parsed, err := Parse(fsys)
	if err != nil {
		return nil, err
	}
	return &Migrator{migrations: parsed, log: log}, nil
}

// Migrations exposes the parsed set (diagnostics, tests).
func (m *Migrator) Migrations() []Migration { return m.migrations }

const createSchema = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    bigint PRIMARY KEY,
    name       text NOT NULL,
    checksum   text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
)`

// Up applies all pending migrations under an advisory lock and verifies the
// checksums of previously applied ones. It returns the names of migrations
// applied by this call.
func (m *Migrator) Up(ctx context.Context, pool *pgxpool.Pool) ([]string, error) {
	if pool == nil {
		return nil, errors.New("migrate: pool is required")
	}

	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("migrate: acquire connection: %w", err)
	}
	defer conn.Release()

	// Session-level advisory lock: a second migrator (e.g. another controller
	// replica during a rolling upgrade) blocks here instead of double-applying.
	if _, err = conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, advisoryLockKey); err != nil {
		return nil, fmt.Errorf("migrate: acquire advisory lock: %w", err)
	}
	defer func() {
		// Best-effort unlock; the lock also dies with the session. Use a
		// detached context so unlock still runs if ctx was canceled.
		unlockCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, unlockErr := conn.Exec(unlockCtx, `SELECT pg_advisory_unlock($1)`, advisoryLockKey); unlockErr != nil {
			m.log.Warn("migration advisory unlock failed; lock releases with session", "error", unlockErr)
		}
	}()

	if _, err = conn.Exec(ctx, createSchema); err != nil {
		return nil, fmt.Errorf("migrate: ensure schema_migrations: %w", err)
	}

	applied, err := loadApplied(ctx, conn)
	if err != nil {
		return nil, err
	}

	var newlyApplied []string
	for _, mig := range m.migrations {
		if prev, ok := applied[mig.Version]; ok {
			if prev.checksum != mig.Checksum {
				return newlyApplied, fmt.Errorf(
					"migrate: checksum mismatch for %s (version %d): applied=%s file=%s — "+
						"released migrations are immutable; add a NEW migration instead of editing history "+
						"(see docs/contributing.md)",
					prev.name, mig.Version, prev.checksum, mig.Checksum)
			}
			continue
		}

		m.log.Info("applying migration", "version", mig.Version, "name", mig.Name)
		if err := applyOne(ctx, conn, mig); err != nil {
			return newlyApplied, err
		}
		newlyApplied = append(newlyApplied, mig.Name)
	}
	return newlyApplied, nil
}

type appliedRow struct {
	name     string
	checksum string
}

func loadApplied(ctx context.Context, conn *pgxpool.Conn) (map[int64]appliedRow, error) {
	rows, err := conn.Query(ctx, `SELECT version, name, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("migrate: load applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[int64]appliedRow)
	for rows.Next() {
		var version int64
		var row appliedRow
		if err := rows.Scan(&version, &row.name, &row.checksum); err != nil {
			return nil, fmt.Errorf("migrate: scan schema_migrations: %w", err)
		}
		applied[version] = row
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("migrate: iterate schema_migrations: %w", err)
	}
	return applied, nil
}

// applyOne executes a single migration and its bookkeeping insert in one
// transaction: either both land or neither does.
//
// The transaction runs on the SAME connection that holds the advisory lock.
// Acquiring a second connection from the pool here can deadlock under pool
// exhaustion: N concurrent migrators each holding one locked connection and
// each waiting for a second one starve the pool permanently. This was caught
// by TestConcurrentMigratorsSerializeViaAdvisoryLock (regression coverage).
func applyOne(ctx context.Context, conn *pgxpool.Conn, mig Migration) error {
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("migrate: begin tx for %s: %w", mig.Name, err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after commit

	if _, err := tx.Exec(ctx, string(mig.SQL)); err != nil {
		return fmt.Errorf("migrate: apply %s: %w", mig.Name, err)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`,
		mig.Version, mig.Name, mig.Checksum); err != nil {
		return fmt.Errorf("migrate: record %s: %w", mig.Name, err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("migrate: commit %s: %w", mig.Name, err)
	}
	return nil
}
