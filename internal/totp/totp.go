// Package totp implements RFC 6238 time-based one-time passwords and RFC 4226
// HOTP, using only the standard library.
//
// Implemented directly rather than via a dependency: the algorithm is small and
// fully specified, and authentication code is exactly where an unaudited
// transitive dependency is least welcome. SHA-1 is the interoperable default
// (every authenticator app assumes it); the choice is deliberate, not an
// oversight — it is an HMAC, not a collision-sensitive hash.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	// SHA-1 is mandated by RFC 6238 as the interoperable TOTP default and every
	// authenticator app assumes it. It is used here only inside an HMAC, where
	// the collision weakness the blocklist targets does not apply.
	"crypto/sha1" //nolint:gosec // RFC 6238 default; HMAC-SHA1 is not collision-sensitive
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
)

// Algorithm is the HMAC hash family used for the code.
type Algorithm string

const (
	// AlgorithmSHA1 is the interoperable default. Every authenticator app
	// supports it, so it is the only safe choice unless the enrollment flow
	// explicitly negotiated otherwise.
	AlgorithmSHA1   Algorithm = "SHA1"
	AlgorithmSHA256 Algorithm = "SHA256"
	AlgorithmSHA512 Algorithm = "SHA512"
)

// Digits is the code length. 6 is compatible with all authenticator apps; 8 is
// permitted by RFC 6238.
type Digits int

const (
	Digits6 Digits = 6
	Digits8 Digits = 8
)

// DefaultPeriod is the RFC 6238 time step in seconds.
const DefaultPeriod = 30

// DefaultSkew is how many steps on either side of now are accepted.
//
// One step of tolerance is standard and necessary: client clocks drift, and
// rejecting a code because the phone is 20 seconds off makes the feature
// unusable. Since a consumed step is recorded (see identity.ConsumeTOTPStep),
// widening the window does not widen replay.
const DefaultSkew = 1

// SecretBytes is the length of a generated shared secret. 20 bytes (160 bits)
// is the RFC 4226 recommendation and matches SHA-1's block size.
const SecretBytes = 20

// Errors returned by Validate.
var (
	// ErrCodeInvalid means the supplied code does not match any accepted step.
	ErrCodeInvalid = errors.New("totp: code is invalid")
	// ErrMalformedSecret means the stored secret cannot be decoded.
	ErrMalformedSecret = errors.New("totp: secret is malformed")
	// ErrUnsupportedAlgorithm means the enrollment names an unknown hash.
	ErrUnsupportedAlgorithm = errors.New("totp: unsupported algorithm")
)

// Config describes an enrollment's parameters. It is stored alongside the
// secret so a future parameter change does not invalidate existing enrollments.
type Config struct {
	Algorithm Algorithm
	Digits    Digits
	Period    int
	// Skew is the acceptance window in steps on each side. Zero means
	// DefaultSkew.
	Skew int
}

// DefaultConfig returns the interoperable parameter set.
func DefaultConfig() Config {
	return Config{
		Algorithm: AlgorithmSHA1,
		Digits:    Digits6,
		Period:    DefaultPeriod,
		Skew:      DefaultSkew,
	}
}

func (c Config) withDefaults() Config {
	if c.Algorithm == "" {
		c.Algorithm = AlgorithmSHA1
	}
	if c.Digits == 0 {
		c.Digits = Digits6
	}
	if c.Period == 0 {
		c.Period = DefaultPeriod
	}
	if c.Skew == 0 {
		c.Skew = DefaultSkew
	}
	return c
}

// validate rejects configurations that cannot produce interoperable codes.
func (c Config) validate() error {
	switch c.Algorithm {
	case AlgorithmSHA1, AlgorithmSHA256, AlgorithmSHA512:
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, c.Algorithm)
	}
	if c.Digits != Digits6 && c.Digits != Digits8 {
		return fmt.Errorf("totp: %d digits is not 6 or 8", c.Digits)
	}
	if c.Period <= 0 || c.Period > 300 {
		return fmt.Errorf("totp: period %d is out of range (1..300 seconds)", c.Period)
	}
	if c.Skew < 0 || c.Skew > 10 {
		return fmt.Errorf("totp: skew %d is out of range (0..10 steps)", c.Skew)
	}
	return nil
}

func (c Config) hash() func() hash.Hash {
	switch c.Algorithm {
	case AlgorithmSHA256:
		return sha256.New
	case AlgorithmSHA512:
		return sha512.New
	default:
		return sha1.New
	}
}

// GenerateSecret returns a new random shared secret in base32 (no padding),
// which is the form authenticator apps and provisioning URIs expect.
func GenerateSecret() (string, error) {
	buf := make([]byte, SecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("totp: read entropy: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// decodeSecret accepts the base32 form used by authenticator apps. It tolerates
// lowercase, spaces, and missing padding, because users transcribe these by
// hand and rejecting "abcdef gh" for a formatting reason helps nobody. It still
// rejects a secret that does not decode to bytes.
func decodeSecret(secret string) ([]byte, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	normalized = strings.TrimRight(normalized, "=")
	if normalized == "" {
		return nil, ErrMalformedSecret
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformedSecret, err)
	}
	if len(raw) == 0 {
		return nil, ErrMalformedSecret
	}
	return raw, nil
}

// Code computes the code for a specific time step.
func Code(secret string, step int64, cfg Config) (string, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return "", err
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return codeFromKey(key, step, cfg), nil
}

// codeFromKey is the HOTP truncation from RFC 4226 §5.3.
func codeFromKey(key []byte, counter int64, cfg Config) string {
	// RFC 4226 §5.2 packs the counter as a big-endian 64-bit integer. A
	// negative counter is not meaningful — it would silently alias a large
	// positive one — so it is clamped to zero, which also makes the uint64
	// conversion provably well-defined.
	if counter < 0 {
		counter = 0
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))

	mac := hmac.New(cfg.hash(), key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)

	// Dynamic truncation: the low nibble of the last byte selects the offset.
	offset := sum[len(sum)-1] & 0x0f
	value := int64(sum[offset]&0x7f)<<24 |
		int64(sum[offset+1])<<16 |
		int64(sum[offset+2])<<8 |
		int64(sum[offset+3])

	mod := int64(1)
	for i := 0; i < int(cfg.Digits); i++ {
		mod *= 10
	}
	value %= mod

	format := fmt.Sprintf("%%0%dd", int(cfg.Digits))
	return fmt.Sprintf(format, value)
}

// StepFor returns the time step that contains t.
func StepFor(t time.Time, cfg Config) int64 {
	cfg = cfg.withDefaults()
	if cfg.Period <= 0 {
		cfg.Period = DefaultPeriod
	}
	return t.Unix() / int64(cfg.Period)
}

// Validate checks a supplied code and returns the time step it matched.
//
// The returned step is what the caller records to prevent replay: accepting a
// code without recording its step would let the same code be reused for the
// remainder of its window.
//
// Verification is constant-time across the whole acceptance window: every
// candidate step is compared even after a match is found, so response timing
// does not reveal which step matched (and therefore nothing about clock skew,
// which is a fingerprinting signal).
func Validate(secret, code string, now time.Time) (int64, error) {
	return ValidateWith(secret, code, now, DefaultConfig())
}

// ValidateWith is Validate with explicit parameters.
func ValidateWith(secret, code string, now time.Time, cfg Config) (int64, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return 0, err
	}

	code = strings.TrimSpace(code)
	// A wrong-length code is rejected before any HMAC work, which also prevents
	// padding tricks that could make a short code compare in the attacker's favor.
	if len(code) != int(cfg.Digits) {
		return 0, ErrCodeInvalid
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			return 0, ErrCodeInvalid
		}
	}

	key, err := decodeSecret(secret)
	if err != nil {
		return 0, err
	}

	center := StepFor(now, cfg)
	var matched int64
	found := false
	for offset := -cfg.Skew; offset <= cfg.Skew; offset++ {
		step := center + int64(offset)
		candidate := codeFromKey(key, step, cfg)
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			if !found {
				matched = step
				found = true
			}
		}
	}
	if !found {
		return 0, ErrCodeInvalid
	}
	return matched, nil
}

// ProvisioningURI builds the otpauth:// URI an authenticator app scans.
//
// The issuer and account are URL-escaped rather than interpolated raw: an
// account name is operator-supplied data, and an unescaped "&" would silently
// corrupt the URI (or inject an extra parameter).
func ProvisioningURI(issuer, account, secret string, cfg Config) (string, error) {
	cfg = cfg.withDefaults()
	if err := cfg.validate(); err != nil {
		return "", err
	}
	if strings.TrimSpace(issuer) == "" {
		return "", errors.New("totp: issuer is required")
	}
	if strings.TrimSpace(account) == "" {
		return "", errors.New("totp: account is required")
	}
	if _, err := decodeSecret(secret); err != nil {
		return "", err
	}

	label := escape(issuer) + ":" + escape(account)
	params := "secret=" + secret +
		"&issuer=" + escape(issuer) +
		"&algorithm=" + string(cfg.Algorithm) +
		fmt.Sprintf("&digits=%d&period=%d", cfg.Digits, cfg.Period)
	return "otpauth://totp/" + label + "?" + params, nil
}

// escape percent-encodes everything outside the unreserved set, matching what
// authenticator apps expect in a URI label.
func escape(s string) string {
	const unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}
