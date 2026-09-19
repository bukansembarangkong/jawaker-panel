package secureid

import (
	"strings"
	"testing"
)

func TestSessionTokenUniquenessAndHashSeparation(t *testing.T) {
	seen := make(map[string]struct{}, 2000)
	for i := 0; i < 2000; i++ {
		token, hash, err := SessionToken()
		if err != nil {
			t.Fatalf("SessionToken: %v", err)
		}
		if _, dup := seen[token]; dup {
			t.Fatalf("duplicate session token generated: %q", token)
		}
		seen[token] = struct{}{}

		if len(hash) != sha256Len {
			t.Fatalf("hash length = %d, want %d", len(hash), sha256Len)
		}
		// The stored digest must not reveal or equal the token.
		if strings.Contains(string(hash), token) {
			t.Fatal("hash contains token material")
		}
	}
}

func TestHashTokenIsDeterministicAndDistinct(t *testing.T) {
	a := HashToken([]byte("token-a"))
	b := HashToken([]byte("token-a"))
	c := HashToken([]byte("token-b"))
	if string(a) != string(b) {
		t.Error("same input produced different digests")
	}
	if string(a) == string(c) {
		t.Error("different inputs produced the same digest")
	}
}

func TestEnrollmentTokenPrefixAndUniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 500)
	for i := 0; i < 500; i++ {
		token, hash, err := EnrollmentToken()
		if err != nil {
			t.Fatalf("EnrollmentToken: %v", err)
		}
		if !strings.HasPrefix(token, "jwenroll_") {
			t.Fatalf("token %q missing enrollment prefix", token)
		}
		if _, dup := seen[token]; dup {
			t.Fatalf("duplicate enrollment token: %q", token)
		}
		seen[token] = struct{}{}
		if len(hash) != sha256Len {
			t.Fatalf("hash length = %d, want %d", len(hash), sha256Len)
		}
	}
}

func TestAPITokenRequiresPrefix(t *testing.T) {
	if _, _, err := APIToken(""); err == nil {
		t.Error("APIToken with empty prefix should fail")
	}
	token, hash, err := APIToken("jwsvc")
	if err != nil {
		t.Fatalf("APIToken: %v", err)
	}
	if !strings.HasPrefix(token, "jwsvc_") {
		t.Errorf("token %q missing prefix", token)
	}
	if len(hash) != sha256Len {
		t.Errorf("hash length = %d, want %d", len(hash), sha256Len)
	}
}

func TestRecoveryCodeIsTranscribable(t *testing.T) {
	seen := make(map[string]struct{}, 500)
	for i := 0; i < 500; i++ {
		code, hash, err := RecoveryCode()
		if err != nil {
			t.Fatalf("RecoveryCode: %v", err)
		}
		// Ambiguous characters must never appear in a code a human reads aloud.
		for _, bad := range []string{"0", "1", "O", "I", "l"} {
			if strings.Contains(code, bad) {
				t.Fatalf("recovery code %q contains ambiguous character %q", code, bad)
			}
		}
		if _, dup := seen[code]; dup {
			t.Fatalf("duplicate recovery code: %q", code)
		}
		seen[code] = struct{}{}

		// Hash must be over the DISPLAYED code so lookup works after the user
		// re-types it.
		if string(HashToken([]byte(code))) != string(hash) {
			t.Fatal("stored hash does not match the displayed code")
		}
	}
}

func TestRecoveryCodeFormat(t *testing.T) {
	code, _, err := RecoveryCode()
	if err != nil {
		t.Fatalf("RecoveryCode: %v", err)
	}
	parts := strings.Split(code, "-")
	if len(parts) < 2 {
		t.Errorf("recovery code %q is not grouped for readability", code)
	}
}

func TestRequestIDMatchesAcceptedCharset(t *testing.T) {
	for i := 0; i < 200; i++ {
		id, err := RequestID()
		if err != nil {
			t.Fatalf("RequestID: %v", err)
		}
		if !strings.HasPrefix(id, "req_") {
			t.Fatalf("id %q missing req_ prefix", id)
		}
		for _, c := range id {
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '_', c == '-':
			default:
				t.Fatalf("id %q contains %q outside the accepted charset", id, c)
			}
		}
	}
}

const sha256Len = 32
