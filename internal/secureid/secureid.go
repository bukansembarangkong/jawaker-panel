// Package secureid generates cryptographically random identifiers and tokens.
//
// All identifiers are opaque and unguessable (DATABASE.md s4: sequential IDs
// must never be a security boundary). Uses crypto/rand exclusively; a failure
// to read entropy is treated as fatal because every alternative is insecure
// (SECURITY.md s10: weak token generation is a rejected pattern).
package secureid

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// Token lengths. 32 bytes = 256 bits of entropy, which stays safely beyond
// brute-force reach while keeping cookies and log lines compact.
const (
	sessionTokenBytes = 32
	enrollmentBytes   = 32
	apiTokenBytes     = 32
	recoveryCodeBytes = 10 // short enough to transcribe by hand
)

// SessionToken returns a URL-safe opaque session token. Only its SHA-256
// digest is persisted, so a database read cannot be replayed as a live
// session.
func SessionToken() (token string, tokenHash []byte, err error) {
	raw, err := randomBytes(sessionTokenBytes)
	if err != nil {
		return "", nil, err
	}
	return encodeToken(raw), HashToken(raw), nil
}

// EnrollmentToken returns a single-use node enrollment token. Shown to the
// operator exactly once; the server keeps only the digest.
func EnrollmentToken() (token string, tokenHash []byte, err error) {
	raw, err := randomBytes(enrollmentBytes)
	if err != nil {
		return "", nil, err
	}
	// Prefix aids log correlation and prevents confusion with other tokens.
	return "jwenroll_" + encodeToken(raw), HashToken(raw), nil
}

// APIToken returns a personal/service API token with a readable prefix.
// The prefix is the only non-secret part and may appear in logs.
func APIToken(prefix string) (token string, tokenHash []byte, err error) {
	if prefix == "" {
		return "", nil, fmt.Errorf("secureid: prefix is required")
	}
	raw, err := randomBytes(apiTokenBytes)
	if err != nil {
		return "", nil, err
	}
	return prefix + "_" + encodeToken(raw), HashToken(raw), nil
}

// RecoveryCode returns one human-transcribable recovery code plus its digest.
// Codes use an unambiguous alphabet (no 0/O, 1/l/I) so a user reading one
// aloud over the phone is not corrupted.
func RecoveryCode() (code string, codeHash []byte, err error) {
	raw, err := randomBytes(recoveryCodeBytes)
	if err != nil {
		return "", nil, err
	}
	code = encodeRecovery(raw)
	return code, HashToken([]byte(code)), nil
}

// RequestID returns a correlation identifier with the req_ prefix, matching
// the charset the HTTP layer accepts from clients.
func RequestID() (string, error) {
	raw, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	return "req_" + hex.EncodeToString(raw), nil
}

// HashToken returns the SHA-256 digest used for at-rest token storage.
// Tokens are high-entropy random values, so a fast hash is appropriate here
// (unlike passwords, which use a memory-hard KDF).
func HashToken(raw []byte) []byte {
	sum := sha256.Sum256(raw)
	return sum[:]
}

// unambiguousAlphabet excludes visually confusable characters.
const unambiguousAlphabet = "23456789abcdefghijkmnpqrstuvwxyz"

// encodeRecovery maps random bytes onto the unambiguous alphabet and formats
// them in groups for readability, e.g. "k7qm-t3vx-p9zr-h2nw-b4cd".
func encodeRecovery(raw []byte) string {
	out := make([]byte, 0, len(raw)+4)
	for i, b := range raw {
		if i > 0 && i%4 == 0 {
			out = append(out, '-')
		}
		out = append(out, unambiguousAlphabet[int(b)%len(unambiguousAlphabet)])
	}
	return string(out)
}

// encodeToken renders bytes as unpadded base64url: compact and URL/cookie safe.
func encodeToken(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

// randomBytes is the single entropy source. It deliberately does not fall
// back to any non-crypto generator.
func randomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, fmt.Errorf("secureid: invalid length %d", n)
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("secureid: read entropy: %w", err)
	}
	return buf, nil
}
