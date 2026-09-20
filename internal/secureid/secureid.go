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
	"errors"
	"fmt"
	"strings"
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
	return enrollmentTokenPrefix + encodeToken(raw), HashToken(raw), nil
}

// enrollmentTokenPrefix is the readable part of an enrollment token. Exported
// through EnrollmentTokenPrefix so a consumer validating the token's SHAPE does
// not have to repeat the literal and drift from it.
const enrollmentTokenPrefix = "jwenroll_"

// EnrollmentTokenPrefix is the non-secret prefix of an enrollment token.
func EnrollmentTokenPrefix() string { return enrollmentTokenPrefix }

// HashEnrollmentToken returns the stored digest for a PRESENTED enrollment
// token, which is the form a node submits.
//
// It lives here, beside the generator, for one reason: the digest must be
// computed over the same bytes the generator hashed. Computing it anywhere else
// means two definitions of the canonical form that can silently drift, which is
// exactly the bug that made recovery codes unredeemable in Phase 1 — generation
// hashed one form and lookup hashed another, so every valid code was refused.
// Keeping both halves in one file makes that class of defect impossible to
// reintroduce without deleting this function.
func HashEnrollmentToken(token string) ([]byte, error) {
	trimmed := strings.TrimSpace(token)
	body, ok := strings.CutPrefix(trimmed, enrollmentTokenPrefix)
	if !ok {
		return nil, fmt.Errorf("secureid: token does not start with %s", enrollmentTokenPrefix)
	}
	if body == "" {
		return nil, errors.New("secureid: enrollment token has no body")
	}
	// The digest is over the DECODED entropy, matching what EnrollmentToken
	// stored. Hashing the encoded text would produce a different value and every
	// lookup would miss.
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("secureid: decode enrollment token: %w", err)
	}
	if len(raw) != enrollmentBytes {
		return nil, fmt.Errorf("secureid: enrollment token body is %d bytes, expected %d", len(raw), enrollmentBytes)
	}
	return HashToken(raw), nil
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
//
// The digest is computed over the CANONICAL form (see CanonicalRecoveryCode),
// not over the grouped display form. Hashing the display form does not work:
// the separators are presentation, and a lookup would have to reproduce them
// exactly, so any user who typed the code without its hyphens — or in capitals —
// would be told their own code is wrong.
func RecoveryCode() (code string, codeHash []byte, err error) {
	raw, err := randomBytes(recoveryCodeBytes)
	if err != nil {
		return "", nil, err
	}
	code = encodeRecovery(raw)
	return code, HashToken([]byte(CanonicalRecoveryCode(code))), nil
}

// CanonicalRecoveryCode folds a code as a user might type it onto the single
// form the digest was taken over. Lookup and generation MUST agree on this
// definition, so it lives in one place.
func CanonicalRecoveryCode(code string) string {
	c := strings.ToLower(strings.TrimSpace(code))
	c = strings.ReplaceAll(c, " ", "")
	c = strings.ReplaceAll(c, "-", "")
	return c
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

// CSRFToken returns an opaque anti-forgery nonce for the double-submit cookie
// pattern.
//
// It is deliberately NOT shaped like a credential: no prefix, and no digest is
// stored, because the value is compared against the echoed header rather than
// looked up in a database. Giving it an api-token prefix would make it look
// like a bearer secret in logs and secret scanners for no benefit.
func CSRFToken() (string, error) {
	raw, err := randomBytes(sessionTokenBytes)
	if err != nil {
		return "", err
	}
	return encodeToken(raw), nil
}

// HashSessionToken returns the stored digest for a PRESENTED session token,
// which is the form a cookie carries. It is the exact inverse of the encoding
// SessionToken produced, so a lookup can never drift from the storage format.
//
// The digest is computed over the decoded entropy, not over the encoded text:
// hashing the string would produce a different value than the one stored.
func HashSessionToken(token string) ([]byte, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(token))
	if err != nil {
		return nil, fmt.Errorf("secureid: decode session token: %w", err)
	}
	if len(raw) == 0 {
		return nil, errors.New("secureid: session token is empty")
	}
	return HashToken(raw), nil
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
