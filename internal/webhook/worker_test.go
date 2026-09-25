package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestComputeHMAC(t *testing.T) {
	secret := "secret123"
	payload := []byte(`{"event":"test"}`)

	sig := computeHMAC(payload, secret)
	if sig == "" {
		t.Fatal("expected non-empty signature")
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))

	if sig != expected {
		t.Errorf("got %s, want %s", sig, expected)
	}
}

func TestBackoffDelay(t *testing.T) {
	tests := []struct {
		attempt int
		want    time.Duration
	}{
		{0, 10 * time.Second},
		{1, 10 * time.Second},
		{2, 20 * time.Second},
		{3, 40 * time.Second},
		{10, 10 * time.Minute}, // capped at maxDelay
	}

	for _, tt := range tests {
		got := backoffDelay(tt.attempt)
		if got != tt.want {
			t.Errorf("backoffDelay(%d) = %v, want %v", tt.attempt, got, tt.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	long := "this is a very long string that should be truncated"
	short := truncate(long, 10)
	if len(short) != 10 {
		t.Errorf("got len %d, want 10", len(short))
	}
	if short != "this is a " {
		t.Errorf("got %q, want %q", short, "this is a ")
	}
}
