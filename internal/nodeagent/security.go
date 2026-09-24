package nodeagent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// Binary candidates for security tools.
var (
	fail2banClientCandidates = []string{"/usr/bin/fail2ban-client", "/usr/local/bin/fail2ban-client"}
	cscliCandidates          = []string{"/usr/bin/cscli", "/usr/local/bin/cscli"}
	ssCandidatesSec          = []string{"/bin/ss", "/usr/bin/ss", "/sbin/ss"}
)

// ── sec.hardening.scan ─────────────────────────────────────────────────────────

// SecHardeningScan reads system configuration files to produce hardening findings.
// No shell commands are executed that modify state; all reads are confined to
// the paths declared in the registry descriptor.
func (e *Executors) SecHardeningScan(ctx context.Context, in nodewire.SecHardeningScanInput) (nodewire.SecHardeningScanResult, error) {
	if !supportedOS() {
		return nodewire.SecHardeningScanResult{}, notAvailable("security scanning is supported on Linux only")
	}

	cats := map[string]bool{}
	if len(in.Categories) == 0 {
		for _, c := range []string{"os", "ssh", "firewall", "packages", "services", "network"} {
			cats[c] = true
		}
	} else {
		for _, c := range in.Categories {
			cats[c] = true
		}
	}

	var findings []nodewire.HardeningFinding

	if cats["ssh"] {
		findings = append(findings, hardenSSHChecks()...)
	}
	if cats["os"] {
		findings = append(findings, hardenOSChecks()...)
	}

	return nodewire.SecHardeningScanResult{
		Findings:   findings,
		Total:      len(findings),
		ObservedAt: e.now().UTC(),
	}, nil
}

// hardenSSHChecks reads /etc/ssh/sshd_config and returns findings.
func hardenSSHChecks() []nodewire.HardeningFinding {
	var out []nodewire.HardeningFinding

	cfg := parseSshdConfig("/etc/ssh/sshd_config")

	// PermitRootLogin
	val := strings.ToLower(cfg["permitrootlogin"])
	if val == "" {
		val = "yes" // OpenSSH default
	}
	status := "pass"
	if val != "no" && val != "prohibit-password" && val != "forced-commands-only" {
		status = "fail"
	}
	out = append(out, nodewire.HardeningFinding{
		CheckName:   "sshd_permit_root_login",
		Category:    "ssh",
		Severity:    "high",
		Status:      status,
		Title:       "SSH PermitRootLogin",
		Description: "Current value: " + val,
		Remediation: "Set PermitRootLogin no or prohibit-password in /etc/ssh/sshd_config",
	})

	// PasswordAuthentication
	passAuth := strings.ToLower(cfg["passwordauthentication"])
	if passAuth == "" {
		passAuth = "yes"
	}
	passStatus := "pass"
	if passAuth == "yes" {
		passStatus = "warn"
	}
	out = append(out, nodewire.HardeningFinding{
		CheckName:   "sshd_password_auth",
		Category:    "ssh",
		Severity:    "medium",
		Status:      passStatus,
		Title:       "SSH PasswordAuthentication",
		Description: "Current value: " + passAuth,
		Remediation: "Set PasswordAuthentication no and use public key authentication only",
	})

	// Protocol (deprecated in modern OpenSSH but check anyway)
	protocol := cfg["protocol"]
	if protocol != "" && protocol != "2" {
		out = append(out, nodewire.HardeningFinding{
			CheckName:   "sshd_protocol_v1",
			Category:    "ssh",
			Severity:    "critical",
			Status:      "fail",
			Title:       "SSH Protocol 1 enabled",
			Description: "Protocol " + protocol + " is configured",
			Remediation: "Remove Protocol directive (modern OpenSSH defaults to Protocol 2 only) or set Protocol 2",
		})
	}

	return out
}

// hardenOSChecks performs basic OS hardening checks.
func hardenOSChecks() []nodewire.HardeningFinding {
	var out []nodewire.HardeningFinding

	// Check /etc/passwd for UID 0 accounts other than root.
	if data, err := os.ReadFile("/etc/passwd"); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		var rootAccounts []string
		for scanner.Scan() {
			line := scanner.Text()
			parts := strings.Split(line, ":")
			if len(parts) >= 4 && parts[2] == "0" && parts[0] != "root" {
				rootAccounts = append(rootAccounts, parts[0])
			}
		}
		status := "pass"
		desc := "No non-root UID 0 accounts found"
		remediation := ""
		if len(rootAccounts) > 0 {
			status = "fail"
			desc = "Non-root UID 0 accounts: " + strings.Join(rootAccounts, ", ")
			remediation = "Remove or change the UID of non-root accounts with UID 0"
		}
		out = append(out, nodewire.HardeningFinding{
			CheckName:   "os_uid0_accounts",
			Category:    "os",
			Severity:    "critical",
			Status:      status,
			Title:       "Non-root UID 0 accounts",
			Description: desc,
			Remediation: remediation,
		})
	}

	// Check if /etc/shadow is world-readable.
	if fi, err := os.Stat("/etc/shadow"); err == nil {
		mode := fi.Mode()
		status := "pass"
		if mode&0o004 != 0 {
			status = "fail"
		}
		out = append(out, nodewire.HardeningFinding{
			CheckName:   "os_shadow_permissions",
			Category:    "os",
			Severity:    "high",
			Status:      status,
			Title:       "/etc/shadow world-readable",
			Description: fmt.Sprintf("Mode: %v", mode),
			Remediation: "Run: chmod 640 /etc/shadow",
		})
	}

	return out
}

// parseSshdConfig reads /etc/ssh/sshd_config and returns key→value pairs (lowercase keys).
func parseSshdConfig(path string) map[string]string {
	out := map[string]string{}
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is the hardcoded sshd_config constant, not user input
	if err != nil {
		return out
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			out[strings.ToLower(parts[0])] = parts[1]
		}
	}
	return out
}

// ── sec.ssh.posture ────────────────────────────────────────────────────────────

// SecSSHPosture reads the sshd_config and active session count.
func (e *Executors) SecSSHPosture(ctx context.Context, _ nodewire.SecSSHPostureInput) (nodewire.SecSSHPostureResult, error) {
	if !supportedOS() {
		return nodewire.SecSSHPostureResult{}, notAvailable("SSH posture is supported on Linux only")
	}

	cfg := parseSshdConfig("/etc/ssh/sshd_config")

	port := 22
	if p, err := strconv.Atoi(cfg["port"]); err == nil && p > 0 {
		port = p
	}

	// Count active SSH sessions via 'ss -tnp' and filter for sshd.
	activeSessions := 0
	ss := resolveTool(ssCandidatesSec)
	if ss != "" {
		e.spawns.Add(1)
		if res, err := e.cmdRunner(ctx, CommandSpec{Path: ss, Args: []string{"-tnp"}}); err == nil {
			scanner := bufio.NewScanner(strings.NewReader(res.Stdout))
			for scanner.Scan() {
				if strings.Contains(scanner.Text(), "sshd") {
					activeSessions++
				}
			}
		}
	}

	// Count auth failures in the last hour from /var/log/auth.log.
	authFailures := countAuthFailures1h()

	return nodewire.SecSSHPostureResult{
		PermitRootLogin:  valOrDefault(cfg["permitrootlogin"], "yes"),
		PasswordAuth:     valOrDefault(cfg["passwordauthentication"], "yes"),
		PubkeyAuth:       valOrDefault(cfg["pubkeyauthentication"], "yes"),
		Port:             port,
		ProtocolVersions: valOrDefault(cfg["protocol"], "2"),
		ActiveSessions:   activeSessions,
		AuthFailures1h:   authFailures,
		ObservedAt:       e.now().UTC(),
	}, nil
}

// countAuthFailures1h reads /var/log/auth.log and counts failures in the last hour.
// ponytail: only reads first 50k lines; use journalctl for full coverage when needed.
func countAuthFailures1h() int {
	data, err := os.ReadFile("/var/log/auth.log")
	if err != nil {
		return 0
	}
	cutoff := time.Now().UTC().Add(-time.Hour)
	count := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	lines := 0
	for scanner.Scan() && lines < 50000 {
		lines++
		line := scanner.Text()
		if !strings.Contains(line, "Failed password") && !strings.Contains(line, "authentication failure") {
			continue
		}
		// Lines have prefix like: "Sep 24 12:34:56"
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		ts := strings.Join(parts[:3], " ")
		t, err := time.Parse("Jan 2 15:04:05", ts)
		if err != nil {
			continue
		}
		// Inject current year (auth.log omits year).
		t = t.AddDate(time.Now().Year()-t.Year(), 0, 0)
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

func valOrDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// ── sec.ban.list ───────────────────────────────────────────────────────────────

// SecBanList reads the active ban list from fail2ban and/or crowdsec.
func (e *Executors) SecBanList(ctx context.Context, in nodewire.SecBanListInput) (nodewire.SecBanListResult, error) {
	if !supportedOS() {
		return nodewire.SecBanListResult{}, notAvailable("ban list is supported on Linux only")
	}

	var bans []nodewire.BannedIP
	now := e.now().UTC()

	wantFail2ban := in.Source == "" || in.Source == "fail2ban"
	wantCrowdSec := in.Source == "" || in.Source == "crowdsec"

	if wantFail2ban {
		bans = append(bans, readFail2banBans(ctx, e)...)
	}
	if wantCrowdSec {
		bans = append(bans, readCrowdSecBans(ctx, e)...)
	}

	return nodewire.SecBanListResult{
		Bans:       bans,
		Total:      len(bans),
		ObservedAt: now,
	}, nil
}

// readFail2banBans reads bans from fail2ban-client.
func readFail2banBans(ctx context.Context, e *Executors) []nodewire.BannedIP {
	client := resolveTool(fail2banClientCandidates)
	if client == "" {
		return nil
	}

	// List jails first.
	e.spawns.Add(1)
	jailsRes, err := e.cmdRunner(ctx, CommandSpec{Path: client, Args: []string{"status"}})
	if err != nil {
		return nil
	}

	var jails []string
	for _, line := range strings.Split(jailsRes.Stdout, "\n") {
		if strings.Contains(line, "Jail list:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				for _, j := range strings.Split(parts[1], ",") {
					j = strings.TrimSpace(j)
					if j != "" {
						jails = append(jails, j)
					}
				}
			}
		}
	}

	var bans []nodewire.BannedIP
	for _, jail := range jails {
		e.spawns.Add(1)
		res, err := e.cmdRunner(ctx, CommandSpec{Path: client, Args: []string{"status", jail}})
		if err != nil {
			continue
		}
		for _, line := range strings.Split(res.Stdout, "\n") {
			if strings.Contains(line, "Banned IP list:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					for _, ip := range strings.Fields(parts[1]) {
						bans = append(bans, nodewire.BannedIP{
							IP:     ip,
							Source: "fail2ban",
							Jail:   jail,
						})
					}
				}
			}
		}
	}
	return bans
}

// readCrowdSecBans reads bans from cscli.
func readCrowdSecBans(ctx context.Context, e *Executors) []nodewire.BannedIP {
	cscli := resolveTool(cscliCandidates)
	if cscli == "" {
		return nil
	}

	e.spawns.Add(1)
	res, err := e.cmdRunner(ctx, CommandSpec{Path: cscli, Args: []string{"decisions", "list", "-o", "json"}})
	if err != nil {
		return nil
	}

	// Parse JSON array: [{value, type, duration, ...}]
	type decision struct {
		Value    string `json:"value"`
		Type     string `json:"type"`
		Duration string `json:"duration"`
	}
	var decisions []decision
	if err := json.Unmarshal([]byte(res.Stdout), &decisions); err != nil {
		return nil
	}

	var bans []nodewire.BannedIP
	for _, d := range decisions {
		if d.Type == "ban" || d.Type == "" {
			bans = append(bans, nodewire.BannedIP{
				IP:     d.Value,
				Source: "crowdsec",
			})
		}
	}
	return bans
}
