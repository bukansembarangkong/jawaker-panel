package nodewire

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ── sec.hardening.scan ─────────────────────────────────────────────────────────

// SecHardeningScanInput is the input for sec.hardening.scan.
// An empty input runs all categories.
type SecHardeningScanInput struct {
	// Categories restricts which check categories to run.
	// Valid values: os, ssh, firewall, packages, services, network.
	// Empty means all categories.
	Categories []string `json:"categories,omitempty"`
}

// Validate checks input.
func (in SecHardeningScanInput) Validate() error {
	valid := map[string]bool{
		"os": true, "ssh": true, "firewall": true,
		"packages": true, "services": true, "network": true,
	}
	for _, c := range in.Categories {
		if !valid[c] {
			return fmt.Errorf("categories: unknown category %q", c)
		}
	}
	return nil
}

// HardeningFinding is one finding from the hardening scan.
type HardeningFinding struct {
	CheckName   string `json:"check_name"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	Status      string `json:"status"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Remediation string `json:"remediation"`
}

// SecHardeningScanResult is the output of sec.hardening.scan.
type SecHardeningScanResult struct {
	Findings   []HardeningFinding `json:"findings"`
	Total      int                `json:"total"`
	ObservedAt time.Time          `json:"observed_at"`
	RequestID  string             `json:"request_id"`
}

// ── sec.ssh.posture ────────────────────────────────────────────────────────────

// SecSSHPostureInput is the input for sec.ssh.posture.
// No configuration; the agent reads /etc/ssh/sshd_config.
type SecSSHPostureInput struct{}

// Validate is a no-op (no input).
func (SecSSHPostureInput) Validate() error { return nil }

// SecSSHPostureResult is the output of sec.ssh.posture.
type SecSSHPostureResult struct {
	PermitRootLogin  string    `json:"permit_root_login"`
	PasswordAuth     string    `json:"password_auth"`
	PubkeyAuth       string    `json:"pubkey_auth"`
	Port             int       `json:"port"`
	ProtocolVersions string    `json:"protocol_versions"`
	ActiveSessions   int       `json:"active_sessions"`
	AuthFailures1h   int       `json:"auth_failures_1h"`
	ObservedAt       time.Time `json:"observed_at"`
	RequestID        string    `json:"request_id"`
}

// ── sec.ban.list ───────────────────────────────────────────────────────────────

// SecBanListInput is the input for sec.ban.list.
// Source restricts to a specific ban adapter (fail2ban, crowdsec).
type SecBanListInput struct {
	Source string `json:"source,omitempty"`
}

// Validate checks input.
func (in SecBanListInput) Validate() error {
	if in.Source != "" {
		switch in.Source {
		case "fail2ban", "crowdsec":
		default:
			return errors.New("source: must be fail2ban or crowdsec")
		}
	}
	return nil
}

// BannedIP is one entry returned by sec.ban.list.
type BannedIP struct {
	IP        string     `json:"ip"`
	Source    string     `json:"source"`
	Jail      string     `json:"jail,omitempty"`
	BannedAt  *time.Time `json:"banned_at,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// SecBanListResult is the output of sec.ban.list.
type SecBanListResult struct {
	Bans       []BannedIP `json:"bans"`
	Total      int        `json:"total"`
	ObservedAt time.Time  `json:"observed_at"`
	RequestID  string     `json:"request_id"`
}

// ── sec.ban.add ───────────────────────────────────────────────────────────────

// SecBanAddInput is the input for sec.ban.add (PRD §21).
type SecBanAddInput struct {
	IP     string `json:"ip"`
	Source string `json:"source"` // fail2ban | crowdsec | iptables
	Reason string `json:"reason,omitempty"`
}

func (in SecBanAddInput) Validate() error {
	if strings.TrimSpace(in.IP) == "" {
		return errors.New("nodewire: ip is required")
	}
	switch in.Source {
	case "fail2ban", "crowdsec", "iptables", "":
	default:
		return errors.New("nodewire: source must be fail2ban, crowdsec, or iptables")
	}
	return nil
}

// SecBanAddResult is the result of sec.ban.add.
type SecBanAddResult struct {
	Banned bool   `json:"banned"`
	IP     string `json:"ip"`
	Source string `json:"source"`
}

// ── sec.ban.remove ────────────────────────────────────────────────────────────

// SecBanRemoveInput is the input for sec.ban.remove (PRD §21).
type SecBanRemoveInput struct {
	IP     string `json:"ip"`
	Source string `json:"source"` // fail2ban | crowdsec | iptables | all
}

func (in SecBanRemoveInput) Validate() error {
	if strings.TrimSpace(in.IP) == "" {
		return errors.New("nodewire: ip is required")
	}
	return nil
}

// SecBanRemoveResult is the result of sec.ban.remove.
type SecBanRemoveResult struct {
	Removed bool   `json:"removed"`
	IP      string `json:"ip"`
	Source  string `json:"source"`
}
