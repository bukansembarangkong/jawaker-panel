package password

import (
	"errors"
	"strings"
	"testing"
)

// testParams keeps the unit suite fast while exercising the same code paths;
// production parameters are validated separately below.
func testParams() Params {
	return Params{MemoryKiB: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

func TestHashAndVerifyRoundTrip(t *testing.T) {
	enc, err := Hash("correct horse battery staple", testParams())
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$") {
		t.Errorf("encoded hash = %q, want argon2id v19 prefix", enc)
	}

	ok, needsRehash, err := Verify("correct horse battery staple", enc, testParams())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("correct password rejected")
	}
	if needsRehash {
		t.Error("hash produced with current params should not need rehash")
	}
}

func TestVerifyRejectsWrongPassword(t *testing.T) {
	enc, err := Hash("correct horse battery staple", testParams())
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, _, err := Verify("wrong horse battery staple", enc, testParams())
	if ok {
		t.Error("wrong password accepted")
	}
	if err != ErrMismatch {
		t.Errorf("err = %v, want ErrMismatch", err)
	}
}

func TestHashesAreSalted(t *testing.T) {
	a, err := Hash("same-password", testParams())
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	b, err := Hash("same-password", testParams())
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if a == b {
		t.Error("identical passwords produced identical hashes; salt missing or reused")
	}
	// Both must still verify, proving the salt is carried in the encoding.
	for _, enc := range []string{a, b} {
		if ok, _, err := Verify("same-password", enc, testParams()); err != nil || !ok {
			t.Errorf("Verify(%q) = %v, %v; want true, nil", enc, ok, err)
		}
	}
}

func TestNeedsRehashWhenParamsRaise(t *testing.T) {
	weak := testParams()
	enc, err := Hash("pw", weak)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}

	stronger := weak
	stronger.MemoryKiB = weak.MemoryKiB * 2
	ok, needsRehash, err := Verify("pw", enc, stronger)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Error("hash must still verify under raised parameters")
	}
	if !needsRehash {
		t.Error("weaker hash should be flagged for rehash")
	}
}

func TestRejectsEmptyPlaintext(t *testing.T) {
	if _, err := Hash("", testParams()); err == nil {
		t.Error("empty password accepted")
	}
}

func TestMalformedHashesRejected(t *testing.T) {
	cases := map[string]string{
		"empty":           "",
		"not a hash":      "hunter2",
		"wrong algorithm": "$bcrypt$v=19$m=1,t=1,p=1$c2FsdA$a2V5",
		"missing fields":  "$argon2id$v=19$m=8192,t=1,p=1",
		"bad base64 salt": "$argon2id$v=19$m=8192,t=1,p=1$!!!notbase64!!!$a2V5",
		"bad version":     "$argon2id$v=99$m=8192,t=1,p=1$c2FsdA$a2V5",
		"empty salt":      "$argon2id$v=19$m=8192,t=1,p=1$$a2V5",
		"empty key":       "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$",
		"garbage params":  "$argon2id$v=19$notparams$c2FsdA$a2V5",
		"trailing fields": "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$a2V5$extra",
	}
	for label, enc := range cases {
		t.Run(label, func(t *testing.T) {
			ok, _, err := Verify("anything", enc, testParams())
			if ok {
				t.Errorf("malformed hash accepted")
			}
			if err == nil {
				t.Errorf("malformed hash returned nil error")
			}
		})
	}
}

// A stored hash must not be able to force the server into unbounded resource
// use. Malicious/corrupt parameters have to be refused before deriving.
func TestStoredParametersAreBounded(t *testing.T) {
	cases := map[string]string{
		"huge memory":      "$argon2id$v=19$m=999999999,t=1,p=1$c2FsdA$a2V5",
		"huge iterations":  "$argon2id$v=19$m=8192,t=999999,p=1$c2FsdA$a2V5",
		"huge parallelism": "$argon2id$v=19$m=8192,t=1,p=999$c2FsdA$a2V5",
		"zero memory":      "$argon2id$v=19$m=0,t=1,p=1$c2FsdA$a2V5",
		"zero parallelism": "$argon2id$v=19$m=8192,t=1,p=0$c2FsdA$a2V5",
		// 200-byte decoded key: exceeds maxKeyLength (128) and would otherwise
		// size an unbounded argon2 output allocation.
		"oversized key": "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$" + strings.Repeat("a2V5", 50),
	}
	for label, enc := range cases {
		t.Run(label, func(t *testing.T) {
			if ok, _, err := Verify("pw", enc, testParams()); ok || err == nil {
				t.Errorf("unbounded parameters accepted (ok=%v err=%v)", ok, err)
			}
		})
	}
}

// The key length used to be derived from the decoded bytes with no upper
// bound, so a stored hash could request an arbitrarily large argon2 output.
// decode must reject it before any derivation happens.
func TestOversizedStoredKeyIsRejected(t *testing.T) {
	enc := "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA$" + strings.Repeat("a2V5", 50)
	if _, _, _, err := decode(enc); err == nil {
		t.Fatal("decode accepted an oversized key")
	} else if !errors.Is(err, ErrInvalidHash) {
		t.Errorf("err = %v, want ErrInvalidHash", err)
	}
}

func TestDefaultParamsWithinPolicy(t *testing.T) {
	p := DefaultParams()
	if err := p.validate(); err != nil {
		t.Fatalf("DefaultParams invalid: %v", err)
	}
	// OWASP minimum for argon2id is m=47104 KiB, t=1, p=1.
	if p.MemoryKiB < 47104 {
		t.Errorf("memory cost %d KiB below OWASP minimum 47104", p.MemoryKiB)
	}
	if p.Iterations < 1 || p.Parallelism < 1 {
		t.Errorf("iterations=%d parallelism=%d must be >= 1", p.Iterations, p.Parallelism)
	}
	if p.SaltLength < 16 || p.KeyLength < 32 {
		t.Errorf("salt=%d key=%d too short", p.SaltLength, p.KeyLength)
	}
}

func TestDefaultParamsRoundTrip(t *testing.T) {
	enc, err := Hash("production-strength-password", DefaultParams())
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, _, err := Verify("production-strength-password", enc, DefaultParams())
	if err != nil || !ok {
		t.Errorf("Verify = %v, %v; want true, nil", ok, err)
	}
}

func BenchmarkHashDefaultParams(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := Hash("benchmark-password", DefaultParams()); err != nil {
			b.Fatal(err)
		}
	}
}
