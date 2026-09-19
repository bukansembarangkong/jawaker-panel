package secret

import (
	"bytes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// keyRing builds a Store without a database so the envelope properties — which
// are the security-relevant part — can be tested in isolation. The DB-backed
// methods are exercised by the integration tests.
func keyRing(t *testing.T, keys map[int]string) *Store {
	t.Helper()
	aeads := make(map[int]cipher.AEAD, len(keys))
	highest := 0
	for version, encoded := range keys {
		aead, err := newAEAD(encoded)
		if err != nil {
			t.Fatalf("newAEAD(version %d): %v", version, err)
		}
		aeads[version] = aead
		if version > highest {
			highest = version
		}
	}
	return &Store{keys: aeads, currentVersion: highest}
}

func newTestKey(t *testing.T) string {
	t.Helper()
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}

func TestSealOpenRoundTrip(t *testing.T) {
	s := keyRing(t, map[int]string{1: newTestKey(t)})
	const ref = "secret://totp/owner"

	envelope, err := s.seal(ref, "JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Contains(envelope, []byte("JBSWY3DPEHPK3PXP")) {
		t.Fatal("plaintext appears in the envelope")
	}

	got, err := s.open(ref, envelope)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if got != "JBSWY3DPEHPK3PXP" {
		t.Errorf("open = %q, want the original plaintext", got)
	}
}

// Nonces must never repeat, or AES-GCM loses its confidentiality guarantee and
// two values sealed under one key could be XOR-compared.
func TestSealUsesFreshNonce(t *testing.T) {
	s := keyRing(t, map[int]string{1: newTestKey(t)})
	const ref = "secret://k"

	first, err := s.seal(ref, "same-plaintext")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	second, err := s.seal(ref, "same-plaintext")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("identical envelopes for identical plaintext; the nonce is reused")
	}
	// Both must still open to the same value.
	for i, env := range [][]byte{first, second} {
		got, err := s.open(ref, env)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		if got != "same-plaintext" {
			t.Errorf("open %d = %q", i, got)
		}
	}
}

// The reference is bound as associated data, so a ciphertext moved to another
// row must fail to authenticate rather than decrypting to a value that belongs
// to a different secret.
func TestEnvelopeIsBoundToItsReference(t *testing.T) {
	s := keyRing(t, map[int]string{1: newTestKey(t)})

	envelope, err := s.seal("secret://totp/alice", "alice-secret")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Same key, different reference: must fail.
	if _, err := s.open("secret://totp/bob", envelope); err == nil {
		t.Fatal("ciphertext opened under a different reference")
	}
}

// The key version is bound as associated data, so reinterpreting an envelope
// under another version fails instead of silently decrypting with the wrong key.
func TestEnvelopeIsBoundToItsKeyVersion(t *testing.T) {
	key := newTestKey(t)
	s := keyRing(t, map[int]string{1: key, 2: newTestKey(t)})
	const ref = "secret://k"

	envelope, err := s.seal(ref, "value") // seals under version 2 (highest)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if envelope[0] != envelopeVersion {
		t.Fatalf("envelope version byte = %d, want %d", envelope[0], envelopeVersion)
	}
	// Tamper with the version field: authentication must fail rather than
	// decrypting under the other key.
	tampered := append([]byte(nil), envelope...)
	tampered[4] = 1
	if _, err := s.open(ref, tampered); err == nil {
		t.Fatal("tampered key version accepted")
	}
}

// A corrupted ciphertext must be rejected by the AEAD tag, never returned as
// garbage plaintext.
func TestTamperedCiphertextRejected(t *testing.T) {
	s := keyRing(t, map[int]string{1: newTestKey(t)})
	const ref = "secret://k"

	envelope, err := s.seal(ref, "value")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	for _, idx := range []int{len(envelope) - 1, len(envelope) - 5, 6, 0} {
		tampered := append([]byte(nil), envelope...)
		tampered[idx] ^= 0x01
		if _, err := s.open(ref, tampered); err == nil {
			t.Errorf("flipped bit at index %d accepted", idx)
		}
	}
}

func TestOpenRejectsTruncatedEnvelope(t *testing.T) {
	s := keyRing(t, map[int]string{1: newTestKey(t)})
	for _, bad := range [][]byte{nil, {}, {1}, {1, 0, 0, 0, 1}, bytes.Repeat([]byte{1}, 10)} {
		if _, err := s.open("secret://k", bad); err == nil {
			t.Errorf("envelope of %d bytes accepted", len(bad))
		}
	}
}

// A rotation happens by adding a new key version while keeping the old one
// readable. Values sealed under the old version must still open, and new writes
// must use the new version.
func TestKeyRotationReadsOldAndWritesNew(t *testing.T) {
	oldKey, newKey := newTestKey(t), newTestKey(t)
	oldStore := keyRing(t, map[int]string{1: oldKey})
	const ref = "secret://k"

	legacy, err := oldStore.seal(ref, "legacy-value")
	if err != nil {
		t.Fatalf("seal with old key: %v", err)
	}

	// Rotated key ring: version 2 for writes, version 1 retained for reads.
	rotated := keyRing(t, map[int]string{1: oldKey, 2: newKey})
	if rotated.CurrentKeyVersion() != 2 {
		t.Errorf("current version = %d, want 2", rotated.CurrentKeyVersion())
	}
	got, err := rotated.open(ref, legacy)
	if err != nil {
		t.Fatalf("open legacy after rotation: %v", err)
	}
	if got != "legacy-value" {
		t.Errorf("legacy value = %q", got)
	}

	fresh, err := rotated.seal(ref, "new-value")
	if err != nil {
		t.Fatalf("seal with new key: %v", err)
	}
	if fresh[4] != 2 {
		t.Errorf("new envelope key version = %d, want 2", fresh[4])
	}

	// Dropping the old key too early makes legacy values unreadable, which must
	// be reported as a MISSING KEY rather than as generic decryption failure, so
	// an operator can tell "restore the old key" from "the data is corrupt".
	withoutOld := keyRing(t, map[int]string{2: newKey})
	if _, err := withoutOld.open(ref, legacy); !errors.Is(err, ErrNoKey) {
		t.Errorf("dropped-key error = %v, want ErrNoKey", err)
	}
}

func TestNewRejectsBadKeys(t *testing.T) {
	// 16-byte key: AES-128. Refused rather than silently accepted, because
	// "we thought it was 256-bit" is not a discovery anyone wants mid-incident.
	short := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 16))
	if _, err := newAEAD(short); err == nil {
		t.Error("16-byte key accepted")
	}
	if _, err := newAEAD(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 33))); err == nil {
		t.Error("33-byte key accepted")
	}
	if _, err := newAEAD("!!!not base64!!!"); err == nil {
		t.Error("garbage key accepted")
	}
	// A correct 32-byte key works in both padded and unpadded base64.
	raw := bytes.Repeat([]byte{7}, 32)
	if _, err := newAEAD(base64.StdEncoding.EncodeToString(raw)); err != nil {
		t.Errorf("padded key rejected: %v", err)
	}
	if _, err := newAEAD(base64.RawStdEncoding.EncodeToString(raw)); err != nil {
		t.Errorf("unpadded key rejected: %v", err)
	}
}

func TestGenerateKeyIs32Bytes(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		key, err := GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		if _, dup := seen[key]; dup {
			t.Fatal("duplicate key generated")
		}
		seen[key] = struct{}{}

		raw, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			t.Fatalf("generated key is not base64: %v", err)
		}
		if len(raw) != 32 {
			t.Errorf("key length = %d bytes, want 32", len(raw))
		}
	}
}

// References reach SQL parameters and appear in config, so the grammar is
// enforced rather than assumed.
func TestValidateRef(t *testing.T) {
	valid := []string{
		"secret://totp/owner",
		"secret://project/tokokong/mysql",
		"secret://a",
		"secret://A-b_c.d/e",
	}
	for _, ref := range valid {
		if err := ValidateRef(ref); err != nil {
			t.Errorf("ValidateRef(%q) = %v, want nil", ref, err)
		}
	}

	invalid := []string{
		"",
		"totp/owner",             // missing scheme
		"secret:/totp",           // one slash
		"secret://",              // no path
		"secret://../etc/passwd", // traversal
		"secret://a b",           // space
		"secret://a;drop",        // SQL-ish metacharacter
		"secret://a'quote",       // quote
		"secret://a?query=1",     // query separator
		"secret://a#" + "frag",   // fragment
	}
	for _, ref := range invalid {
		if err := ValidateRef(ref); err == nil {
			t.Errorf("ValidateRef(%q) accepted, want rejection", ref)
		}
	}

	// Length is bounded.
	long := "secret://" + strings.Repeat("a", maxRefLen)
	if err := ValidateRef(long); err == nil {
		t.Error("over-long reference accepted")
	}
}

func TestNewRejectsIncompleteOptions(t *testing.T) {
	if _, err := New(Options{Keys: map[int]string{1: newTestKey(t)}}); err == nil {
		t.Error("missing database accepted")
	}
	if _, err := New(Options{}); err == nil {
		t.Error("missing keys accepted")
	}
	if _, err := New(Options{Keys: map[int]string{0: newTestKey(t)}}); err == nil {
		t.Error("zero key version accepted")
	}
}
