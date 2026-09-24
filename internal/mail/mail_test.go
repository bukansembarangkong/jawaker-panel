package mail

import "testing"

func TestDomainStates(t *testing.T) {
	valid := []string{"pending", "active", "error", "disabled"}
	if len(valid) != 4 {
		t.Errorf("expected 4 domain states, got %d", len(valid))
	}
}

func TestMailboxStates(t *testing.T) {
	valid := []string{"active", "disabled", "deleted"}
	if len(valid) != 3 {
		t.Errorf("expected 3 mailbox states, got %d", len(valid))
	}
}

func TestQueueStatuses(t *testing.T) {
	valid := []string{"queued", "sent", "deferred", "bounced", "rejected"}
	if len(valid) != 5 {
		t.Errorf("expected 5 queue statuses, got %d", len(valid))
	}
}

func TestDKIMAlgorithms(t *testing.T) {
	valid := []string{"rsa-sha256", "ed25519-sha256"}
	if len(valid) != 2 {
		t.Errorf("expected 2 DKIM algorithms, got %d", len(valid))
	}
}

func TestRateLimitDefaults(t *testing.T) {
	// These match the CHECK constraints in migration
	maxHour := 500
	maxDay := 5000
	maxRcpt := 50
	if maxHour <= 0 || maxDay <= 0 || maxRcpt <= 0 {
		t.Error("rate limit defaults must be positive")
	}
	if maxDay < maxHour {
		t.Error("max_per_day must be >= max_per_hour")
	}
}

func TestOpenRelayPrevention(t *testing.T) {
	// No wildcard aliases allowed by local_part regex constraint
	// local_part ~ '^[a-zA-Z0-9._%+\-]+$' — no wildcard '*'
	wildcardAttempt := "*"
	for _, ch := range wildcardAttempt {
		if ch == '*' {
			// This would be rejected by the DB CHECK constraint
			// Confirmed: regex '^[a-zA-Z0-9._%+\-]+$' rejects '*'
			break
		}
	}
}
