package security_test

import (
	"context"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/security"
)

// Compile-time interface checks (no DB required).

func TestUpsertCheckParams_Validation(t *testing.T) {
	s := security.NewStore(nil)
	_, err := s.UpsertCheck(context.Background(), security.UpsertCheckParams{
		ServerID:  "",
		CheckName: "sshd_root_login",
	})
	if err == nil {
		t.Fatal("expected error for empty server_id")
	}
}

func TestRecordSSHPostureParams_Validation(t *testing.T) {
	s := security.NewStore(nil)
	_, err := s.RecordSSHPosture(context.Background(), security.RecordSSHPostureParams{
		ServerID: "",
	})
	if err == nil {
		t.Fatal("expected error for empty server_id")
	}
}

func TestRecordEventParams_Validation(t *testing.T) {
	s := security.NewStore(nil)
	_, err := s.RecordEvent(context.Background(), security.RecordEventParams{
		ServerID: "",
		Kind:     "auth_fail",
	})
	if err == nil {
		t.Fatal("expected error for empty server_id")
	}
}

func TestCreateBanParams_Validation(t *testing.T) {
	s := security.NewStore(nil)
	_, err := s.CreateBan(context.Background(), security.CreateBanParams{
		ServerID: "srv-1",
		IP:       "",
	})
	if err == nil {
		t.Fatal("expected error for empty ip")
	}
}

func TestCreateWAFRuleParams_Validation(t *testing.T) {
	s := security.NewStore(nil)
	_, err := s.CreateWAFRule(context.Background(), security.CreateWAFRuleParams{
		ServerID: "srv-1",
		Pattern:  "",
	})
	if err == nil {
		t.Fatal("expected error for empty pattern")
	}
}

// Struct field existence checks.
func TestBanEntryFields(t *testing.T) {
	b := security.BanEntry{
		ID:       "ban-1",
		ServerID: "srv-1",
		IP:       "1.2.3.4",
		Source:   "manual",
		State:    "active",
		BannedAt: time.Now(),
	}
	if b.ID == "" {
		t.Fatal("ID must be set")
	}
}

func TestHardeningCheckFields(t *testing.T) {
	c := security.HardeningCheck{
		ID:        "chk-1",
		CheckName: "sshd_root_login",
		Severity:  "high",
		Status:    "fail",
	}
	if c.CheckName == "" {
		t.Fatal("CheckName must be set")
	}
}
