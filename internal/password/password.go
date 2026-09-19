// Package password hashes and verifies passwords with argon2id.
//
// SECURITY.md s3 requires "a current memory-hard scheme approved at
// implementation time"; argon2id is the Password Hashing Competition winner
// and the OWASP-recommended default. Parameters are stored INSIDE the encoded
// hash, so raising them later still verifies old hashes and rehashing can be
// driven per-user on next successful login.
//
// golang.org/x/crypto/argon2 is used rather than a wrapper library: it is the
// reference implementation, has no transitive surface of its own, and the
// encoding format is ours to control.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Parameters chosen for interactive authentication on small VPS hardware:
// 64 MiB memory, 1 pass, 4 lanes. This is the OWASP minimum configuration
// (m=47104 KiB t=1 p=1) rounded up to a power-of-two memory cost. Raising
// these is a config change, not a data migration, because each hash records
// the parameters it was produced with.
type Params struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultParams is the parameter set used for new hashes.
func DefaultParams() Params {
	return Params{
		MemoryKiB:   64 * 1024,
		Iterations:  1,
		Parallelism: 4,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Limits bound what a verifier will accept from stored data, so a corrupted
// or malicious hash string cannot make the server allocate absurd memory
// (SECURITY.md s15: bounded parser workloads).
const (
	maxMemoryKiB  = 1024 * 1024 // 1 GiB
	maxIterations = 10
	maxParallel   = 64
	maxKeyLength  = 128
)

var (
	// ErrMismatch is returned when the password does not match.
	ErrMismatch = errors.New("password: does not match")
	// ErrInvalidHash is returned when a stored hash cannot be parsed.
	ErrInvalidHash = errors.New("password: stored hash is malformed")
)

// Hash produces an encoded argon2id hash:
//
//	$argon2id$v=19$m=65536,t=1,p=4$<base64 salt>$<base64 key>
//
// The string is self-describing so verification never depends on the
// parameters current at verification time.
func Hash(plaintext string, p Params) (string, error) {
	if plaintext == "" {
		return "", errors.New("password: plaintext is required")
	}
	if err := p.validate(); err != nil {
		return "", err
	}

	salt := make([]byte, p.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: read salt entropy: %w", err)
	}

	key := argon2.IDKey([]byte(plaintext), salt, p.Iterations, p.MemoryKiB, p.Parallelism, p.KeyLength)
	return encode(p, salt, key), nil
}

// Verify checks plaintext against an encoded hash and reports whether the hash
// was produced with outdated parameters (so the caller can transparently
// rehash on successful login).
//
// It always compares digests in constant time, and never short-circuits on
// parameter differences, so verification timing does not leak hash metadata.
func Verify(plaintext, encoded string, current Params) (ok bool, needsRehash bool, err error) {
	p, salt, want, err := decode(encoded)
	if err != nil {
		return false, false, err
	}

	// decode() bounded p.KeyLength, so this conversion cannot overflow and the
	// allocation size carries no attacker-controlled magnitude.
	got := argon2.IDKey([]byte(plaintext), salt, p.Iterations, p.MemoryKiB, p.Parallelism, p.KeyLength)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false, ErrMismatch
	}

	// Only reached on a successful match, so this cannot be used as an oracle.
	needsRehash = p.MemoryKiB < current.MemoryKiB ||
		p.Iterations < current.Iterations ||
		p.Parallelism < current.Parallelism
	return true, needsRehash, nil
}

func encode(p Params, salt, key []byte) string {
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))
}

func decode(encoded string) (Params, []byte, []byte, error) {
	parts := strings.Split(encoded, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, key]
	if len(parts) != 6 || parts[0] != "" {
		return Params{}, nil, nil, ErrInvalidHash
	}
	if parts[1] != "argon2id" {
		return Params{}, nil, nil, fmt.Errorf("%w: unsupported algorithm %q", ErrInvalidHash, parts[1])
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: bad version field", ErrInvalidHash)
	}
	if version != argon2.Version {
		return Params{}, nil, nil, fmt.Errorf("%w: unsupported argon2 version %d", ErrInvalidHash, version)
	}

	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Iterations, &p.Parallelism); err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: bad parameters field", ErrInvalidHash)
	}
	if err := p.validateBounds(); err != nil {
		return Params{}, nil, nil, err
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: bad salt encoding", ErrInvalidHash)
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, fmt.Errorf("%w: bad key encoding", ErrInvalidHash)
	}
	if len(salt) == 0 || len(key) == 0 {
		return Params{}, nil, nil, ErrInvalidHash
	}
	// The decoded key length comes from stored data, so bound it before it
	// sizes an argon2 allocation. keyLen is provably <= maxKeyLength here,
	// which also makes the uint32 conversion below overflow-free.
	keyLen := len(key)
	if keyLen > maxKeyLength {
		return Params{}, nil, nil, fmt.Errorf("%w: key length %d exceeds maximum %d",
			ErrInvalidHash, keyLen, maxKeyLength)
	}
	p.KeyLength = uint32(keyLen)
	return p, salt, key, nil
}

// validate checks a parameter set destined for hashing. Unlike
// validateBounds it also requires the salt/key sizes, which are only
// meaningful when producing a new hash.
func (p Params) validate() error {
	if err := p.validateBounds(); err != nil {
		return err
	}
	if p.SaltLength == 0 {
		return errors.New("password: salt length must be positive")
	}
	if p.KeyLength == 0 {
		return errors.New("password: key length must be positive")
	}
	return nil
}

// validateBounds enforces the limits that must hold for ANY parameter set,
// including one parsed out of stored data. This is the check that stops a
// corrupt or hostile hash string from driving unbounded resource use.
func (p Params) validateBounds() error {
	switch {
	case p.MemoryKiB == 0 || p.MemoryKiB > maxMemoryKiB:
		return fmt.Errorf("password: memory cost %d out of range (1..%d KiB)", p.MemoryKiB, maxMemoryKiB)
	case p.Iterations == 0 || p.Iterations > maxIterations:
		return fmt.Errorf("password: iteration count %d out of range (1..%d)", p.Iterations, maxIterations)
	case p.Parallelism == 0 || p.Parallelism > maxParallel:
		return fmt.Errorf("password: parallelism %d out of range (1..%d)", p.Parallelism, maxParallel)
	case p.KeyLength > maxKeyLength:
		return fmt.Errorf("password: key length %d exceeds maximum %d", p.KeyLength, maxKeyLength)
	}
	return nil
}
