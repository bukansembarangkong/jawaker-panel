package apitoken

import (
	"strings"
	"testing"
)

func TestGeneratePlaintext(t *testing.T) {
	plain, hash, prefix, err := GeneratePlaintext()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(plain, "jwk_") {
		t.Errorf("expected token to start with jwk_, got %s", plain)
	}
	if len(hash) != 32 {
		t.Errorf("expected 32-byte sha256 hash, got %d", len(hash))
	}
	if !strings.HasPrefix(plain, prefix) {
		t.Errorf("expected prefix %s to match start of %s", prefix, plain)
	}
}
