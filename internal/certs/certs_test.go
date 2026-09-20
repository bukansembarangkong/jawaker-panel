package certs

import (
	"testing"
	"time"
)

func TestCertificateUsable(t *testing.T) {
	cases := []struct {
		state   string
		deleted bool
		want    bool
	}{
		{StateActive, false, true},
		{StateExpiring, false, true},
		{StateExpired, false, false},
		{StateRevoked, false, false},
		{StateSuperseded, false, false},
		{StateActive, true, false}, // tombstoned = not live
	}
	for _, tc := range cases {
		var del *time.Time
		if tc.deleted {
			now := time.Now()
			del = &now
		}
		c := Certificate{State: tc.state, DeletedAt: del}
		if got := c.Usable(); got != tc.want {
			t.Errorf("state=%q deleted=%v Usable()=%v, want %v", tc.state, tc.deleted, got, tc.want)
		}
	}
}

func TestCertificateLive(t *testing.T) {
	c := Certificate{}
	if !c.Live() {
		t.Error("zero-value Certificate.Live() = false, want true")
	}
	now := time.Now()
	c.DeletedAt = &now
	if c.Live() {
		t.Error("tombstoned Certificate.Live() = true, want false")
	}
}

func TestDefaultRenewalWindowIsNonZero(t *testing.T) {
	if DefaultRenewalWindow <= 0 {
		t.Errorf("DefaultRenewalWindow = %v, want positive", DefaultRenewalWindow)
	}
}

func TestCertColumnsWithPrefixProducesQualifiedList(t *testing.T) {
	got := certColumnsWithPrefix("c")
	if got == "" {
		t.Fatal("certColumnsWithPrefix returned empty string")
	}
	// Every column must have the prefix c.
	for _, col := range []string{"c.id", "c.project_id", "c.issued_at", "c.not_after", "c.state", "c.secret_ref"} {
		found := false
		for _, part := range splitComma(got) {
			if part == col {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("column %q not found in certColumnsWithPrefix output: %s", col, got)
		}
	}
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, trimSpace(s[start:i]))
			start = i + 1
		}
	}
	out = append(out, trimSpace(s[start:]))
	return out
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n') {
		end--
	}
	return s[start:end]
}
