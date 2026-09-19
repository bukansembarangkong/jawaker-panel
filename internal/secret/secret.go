// Package secret stores and retrieves secret values at rest.
//
// SECURITY.md §8: secret VALUES live in the secret subsystem, never in
// configuration tables, never in logs, never in revisions. Other tables store a
// `secret://...` reference (see migrations 0002 and 0006).
//
// Threat model this addresses: a database dump, a replica, or a backup file
// falling into the wrong hands. The master key lives in the process
// environment, so ciphertext without that key is inert. It does NOT protect
// against an attacker who already controls the running process — at that point
// the key is in memory, and no column-level scheme changes that.
//
// Envelope format. Every field is bound together as AEAD associated data, so a
// ciphertext cannot be moved to another reference or reinterpreted under
// another key version:
//
//	version(1) || key_version(4) || nonce(12) || ciphertext+tag
package secret

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Errors returned by the store.
var (
	// ErrNotFound means no secret exists for the reference.
	ErrNotFound = errors.New("secret: not found")
	// ErrDecrypt means the envelope could not be authenticated or decrypted. It
	// deliberately does not say whether the ciphertext was corrupt, the
	// associated data mismatched, or the key was wrong: those distinctions help
	// an attacker and never help an operator.
	ErrDecrypt = errors.New("secret: cannot decrypt")
	// ErrNoKey means no master key is configured for the required version. This
	// is the "a rotation dropped a key too early" failure, so it is reported
	// distinctly from ErrDecrypt.
	ErrNoKey = errors.New("secret: no master key available")
	// ErrInvalidRef means a reference is malformed.
	ErrInvalidRef = errors.New("secret: invalid reference")
	// ErrAlreadyExists means a Create found an existing value.
	ErrAlreadyExists = errors.New("secret: already exists")
)

// envelopeVersion is the current wire format version. It exists so a future
// format change stays distinguishable from rows already written.
const envelopeVersion byte = 1

// nonceLength is the AES-GCM standard nonce size.
const nonceLength = 12

// keyLength is the AES-256 key size in bytes.
const keyLength = 32

// maxRefLen bounds a reference, which may be operator-supplied.
const maxRefLen = 512

// Store seals and opens secret values.
//
// Safe for concurrent use. The key set is immutable after construction, so a
// key rotation builds a NEW Store rather than mutating a running one: a
// half-applied mutation is how a live process ends up unable to read its own
// secrets.
type Store struct {
	keys map[int]cipher.AEAD
	// currentVersion is used for new writes: the highest configured version.
	currentVersion int
	db             *pgxpool.Pool
	now            func() time.Time
	// encryptions counts values sealed by this process, which gives a rotation
	// a simple completion signal.
	encryptions atomic.Int64
}

// Options configures New.
type Options struct {
	// DB is the control-plane pool. Required.
	DB *pgxpool.Pool
	// Keys maps key version -> base64 32-byte key. At least one entry is
	// required. Multiple entries exist so a rotation can read old ciphertext
	// while writing new.
	Keys map[int]string
	// Now supplies the clock; zero means time.Now.
	Now func() time.Time
}

// New builds a Store.
func New(opts Options) (*Store, error) {
	if opts.DB == nil {
		return nil, errors.New("secret: database is required")
	}
	if len(opts.Keys) == 0 {
		return nil, errors.New("secret: at least one master key is required")
	}

	keys := make(map[int]cipher.AEAD, len(opts.Keys))
	highest := 0
	for version, encoded := range opts.Keys {
		if version <= 0 {
			return nil, fmt.Errorf("secret: key version %d must be positive", version)
		}
		aead, err := newAEAD(encoded)
		if err != nil {
			return nil, fmt.Errorf("secret: key version %d: %w", version, err)
		}
		keys[version] = aead
		if version > highest {
			highest = version
		}
	}

	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Store{keys: keys, currentVersion: highest, db: opts.DB, now: now}, nil
}

// newAEAD decodes a base64 key and returns an AES-256-GCM AEAD.
//
// The key length is ENFORCED, not inferred. A 16-byte key would silently mean
// AES-128, and "we thought it was 256-bit" is not a discovery anyone wants to
// make during an incident.
func newAEAD(encoded string) (cipher.AEAD, error) {
	trimmed := strings.TrimSpace(encoded)
	raw, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		// Also accept unpadded base64, which is what a generated key often
		// looks like when copied out of a config file.
		raw, err = base64.RawStdEncoding.DecodeString(trimmed)
		if err != nil {
			return nil, errors.New("key is not valid base64")
		}
	}
	if len(raw) != keyLength {
		return nil, fmt.Errorf("key must decode to %d bytes for AES-256, got %d", keyLength, len(raw))
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, fmt.Errorf("aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	return aead, nil
}

// CurrentKeyVersion reports the version used for new writes.
func (s *Store) CurrentKeyVersion() int { return s.currentVersion }

// KeyVersions reports the versions this Store can read (rotation diagnostics).
func (s *Store) KeyVersions() []int {
	out := make([]int, 0, len(s.keys))
	for v := range s.keys {
		out = append(out, v)
	}
	return out
}

// Encryptions reports how many values this process has sealed.
func (s *Store) Encryptions() int64 { return s.encryptions.Load() }

// associatedData binds an envelope to its reference and key version. Including
// both means a ciphertext copied into another row, or reinterpreted under
// another key version, fails authentication rather than decrypting to something
// wrong.
func associatedData(ref string, keyVersion int) ([]byte, error) {
	ad := make([]byte, 0, len(ref)+5)
	ad = append(ad, envelopeVersion)
	v, err := encodeKeyVersion(keyVersion)
	if err != nil {
		return nil, err
	}
	ad = append(ad, v[:]...)
	ad = append(ad, ref...)
	return ad, nil
}

// encodeKeyVersion packs a key version into the 4-byte envelope field. A version
// outside that range is rejected rather than truncated, because a truncated
// version would silently mis-bind the envelope and make the value unreadable.
func encodeKeyVersion(version int) ([4]byte, error) {
	var buf [4]byte
	if version < 1 || version > maxKeyVersion {
		return buf, fmt.Errorf("secret: key version %d is out of range (1..%d)", version, maxKeyVersion)
	}
	binary.BigEndian.PutUint32(buf[:], uint32(version))
	return buf, nil
}

// seal produces the envelope for a plaintext value.
func (s *Store) seal(ref, plaintext string) ([]byte, error) {
	if err := ValidateRef(ref); err != nil {
		return nil, err
	}
	version := s.currentVersion
	aead, ok := s.keys[version]
	if !ok {
		return nil, fmt.Errorf("%w: version %d", ErrNoKey, version)
	}

	nonce := make([]byte, nonceLength)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("secret: read nonce entropy: %w", err)
	}

	ad, err := associatedData(ref, version)
	if err != nil {
		return nil, err
	}
	vbuf, err := encodeKeyVersion(version)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, 1+4+nonceLength+len(plaintext)+aead.Overhead())
	out = append(out, envelopeVersion)
	out = append(out, vbuf[:]...)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, []byte(plaintext), ad)

	s.encryptions.Add(1)
	return out, nil
}

// open decrypts an envelope.
func (s *Store) open(ref string, envelope []byte) (string, error) {
	if len(envelope) < 1+4+nonceLength {
		return "", ErrDecrypt
	}
	if envelope[0] != envelopeVersion {
		return "", fmt.Errorf("%w: unsupported envelope version %d", ErrDecrypt, envelope[0])
	}
	version := int(binary.BigEndian.Uint32(envelope[1:5]))
	aead, ok := s.keys[version]
	if !ok {
		return "", fmt.Errorf("%w: version %d", ErrNoKey, version)
	}
	nonce := envelope[5 : 5+nonceLength]
	ciphertext := envelope[5+nonceLength:]
	ad, err := associatedData(ref, version)
	if err != nil {
		// The version came out of the envelope itself, so it is always
		// encodable; reaching here means the envelope is malformed.
		return "", ErrDecrypt
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, ad)
	if err != nil {
		return "", ErrDecrypt
	}
	return string(plaintext), nil
}

// ValidateRef checks a `secret://` reference.
//
// The grammar is enforced so a reference can safely appear in a URI, a log
// line, or a path-mapping consumer without further escaping, and so the
// reference namespace stays predictable for operators.
func ValidateRef(ref string) error {
	const prefix = "secret://"
	if !strings.HasPrefix(ref, prefix) {
		return fmt.Errorf("%w: %q must start with %s", ErrInvalidRef, ref, prefix)
	}
	if len(ref) > maxRefLen {
		return fmt.Errorf("%w: reference is longer than %d bytes", ErrInvalidRef, maxRefLen)
	}
	path := ref[len(prefix):]
	if path == "" {
		return fmt.Errorf("%w: %q has no path", ErrInvalidRef, ref)
	}
	for _, c := range path {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '/' || c == '-' || c == '_' || c == '.':
		default:
			return fmt.Errorf("%w: %q contains %q, which is not allowed", ErrInvalidRef, ref, c)
		}
	}
	// A ".." segment would let a reference escape its namespace in any consumer
	// that maps references onto paths.
	if strings.Contains(path, "..") {
		return fmt.Errorf("%w: %q must not contain a parent segment", ErrInvalidRef, ref)
	}
	return nil
}

// maxKeyVersion is the largest key version the 4-byte envelope field can hold.
// Bounding it here means the encoding can never silently truncate a version,
// which would make a value unreadable after a rotation.
const maxKeyVersion = 1<<31 - 1

// Set stores or replaces a secret value. Replacing is a rotation of that value,
// so rotated_at is stamped and the previous ciphertext is discarded.
func (s *Store) Set(ctx context.Context, ref, plaintext, description string) error {
	envelope, err := s.seal(ref, plaintext)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `
		INSERT INTO secret_values (secret_ref, ciphertext, key_version, description)
		VALUES ($1, $2, $3, COALESCE($4, ''))
		ON CONFLICT (secret_ref) DO UPDATE SET
		    ciphertext = EXCLUDED.ciphertext,
		    key_version = EXCLUDED.key_version,
		    description = EXCLUDED.description,
		    rotated_at = now()`,
		ref, envelope, s.currentVersion, description)
	if err != nil {
		return fmt.Errorf("secret: store %s: %w", ref, err)
	}
	return nil
}

// Create stores a secret that must not already exist, so a caller that meant to
// generate a new credential cannot silently overwrite an existing one.
func (s *Store) Create(ctx context.Context, ref, plaintext, description string) error {
	envelope, err := s.seal(ref, plaintext)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(ctx, `
		INSERT INTO secret_values (secret_ref, ciphertext, key_version, description)
		VALUES ($1, $2, $3, COALESCE($4, ''))`,
		ref, envelope, s.currentVersion, description)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("%w: %s", ErrAlreadyExists, ref)
		}
		return fmt.Errorf("secret: create %s: %w", ref, err)
	}
	return nil
}

// Open retrieves and decrypts a secret value.
//
// The read-timestamp update is best-effort: the caller asked for a value, and a
// diagnostics column being unwritable is not a reason to deny them the secret
// they are entitled to.
func (s *Store) Open(ctx context.Context, ref string) (string, error) {
	if err := ValidateRef(ref); err != nil {
		return "", err
	}
	var envelope []byte
	err := s.db.QueryRow(ctx,
		`SELECT ciphertext FROM secret_values WHERE secret_ref = $1`, ref).Scan(&envelope)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", fmt.Errorf("%w: %s", ErrNotFound, ref)
	}
	if err != nil {
		return "", fmt.Errorf("secret: load %s: %w", ref, err)
	}

	plaintext, err := s.open(ref, envelope)
	if err != nil {
		return "", fmt.Errorf("secret: open %s: %w", ref, err)
	}

	_, _ = s.db.Exec(ctx,
		`UPDATE secret_values SET last_read_at = $2 WHERE secret_ref = $1`, ref, s.now())
	return plaintext, nil
}

// Exists reports whether a reference resolves to a stored value, WITHOUT
// decrypting it. Used by validation paths that only need to know a referenced
// secret is present.
func (s *Store) Exists(ctx context.Context, ref string) (bool, error) {
	if err := ValidateRef(ref); err != nil {
		return false, err
	}
	var exists bool
	if err := s.db.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM secret_values WHERE secret_ref = $1)`, ref).Scan(&exists); err != nil {
		return false, fmt.Errorf("secret: check %s: %w", ref, err)
	}
	return exists, nil
}

// Delete removes a secret value permanently.
//
// Unlike audit rows, retired secret values are deleted rather than retained:
// they have no historical value once their owners are gone, and keeping retired
// ciphertext only enlarges the blast radius of a key compromise. The audit trail
// records that the secret existed and when it was removed.
func (s *Store) Delete(ctx context.Context, ref string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM secret_values WHERE secret_ref = $1`, ref)
	if err != nil {
		return fmt.Errorf("secret: delete %s: %w", ref, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, ref)
	}
	return nil
}

// Metadata describes a stored secret without exposing its value.
type Metadata struct {
	Ref         string
	KeyVersion  int
	Description string
	CreatedAt   time.Time
	RotatedAt   *time.Time
	LastReadAt  *time.Time
}

// Describe returns the metadata for a reference without decrypting it.
func (s *Store) Describe(ctx context.Context, ref string) (Metadata, error) {
	if err := ValidateRef(ref); err != nil {
		return Metadata{}, err
	}
	var m Metadata
	err := s.db.QueryRow(ctx, `
		SELECT secret_ref, key_version, COALESCE(description, ''),
		       created_at, rotated_at, last_read_at
		FROM secret_values WHERE secret_ref = $1`, ref).
		Scan(&m.Ref, &m.KeyVersion, &m.Description, &m.CreatedAt, &m.RotatedAt, &m.LastReadAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Metadata{}, fmt.Errorf("%w: %s", ErrNotFound, ref)
	}
	if err != nil {
		return Metadata{}, fmt.Errorf("secret: describe %s: %w", ref, err)
	}
	return m, nil
}

// NeedsRotation reports whether a secret was sealed under an older key version.
func (s *Store) NeedsRotation(ctx context.Context, ref string) (bool, error) {
	m, err := s.Describe(ctx, ref)
	if err != nil {
		return false, err
	}
	return m.KeyVersion != s.currentVersion, nil
}

// Reencrypt rotates one secret onto the current key version.
//
// Re-sealing requires the plaintext, so this is the one operation that reads a
// secret during rotation. It fails rather than storing an envelope it could not
// verify, so a failed rotation cannot leave a value that neither the old nor the
// new key can open.
func (s *Store) Reencrypt(ctx context.Context, ref string) error {
	plaintext, err := s.Open(ctx, ref)
	if err != nil {
		return err
	}
	envelope, err := s.seal(ref, plaintext)
	if err != nil {
		return err
	}
	tag, err := s.db.Exec(ctx, `
		UPDATE secret_values
		SET ciphertext = $2, key_version = $3, rotated_at = now()
		WHERE secret_ref = $1`, ref, envelope, s.currentVersion)
	if err != nil {
		return fmt.Errorf("secret: reencrypt %s: %w", ref, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s", ErrNotFound, ref)
	}
	return nil
}

// GenerateKey returns a fresh base64 AES-256 key for an operator to configure,
// so the documented runbook does not depend on whatever tooling happens to be
// installed on the host.
func GenerateKey() (string, error) {
	raw := make([]byte, keyLength)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("secret: read entropy: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}
