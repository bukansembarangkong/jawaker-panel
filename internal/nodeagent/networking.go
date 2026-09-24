package nodeagent

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// pingCandidates is the fixed binary search list for ping.
var pingCandidates = []string{"/bin/ping", "/usr/bin/ping"}

// tracerouteCandidates is the fixed binary search list for traceroute.
var tracerouteCandidates = []string{"/usr/bin/traceroute", "/usr/sbin/traceroute"}

// iptablesSaveCandidates is the fixed binary search list for iptables-save.
var iptablesSaveCandidates = []string{"/sbin/iptables-save", "/usr/sbin/iptables-save"}

// ssCandidates is the fixed binary search list for ss (socket statistics).
var ssCandidates = []string{"/bin/ss", "/usr/bin/ss", "/sbin/ss"}

// ── net.firewall.list ──────────────────────────────────────────────────────────

// NetFirewallList reads the iptables ruleset for the requested table via
// iptables-save. The output is parsed into chains and rules; no shell is used.
// iptables-save is invoked with the table flag only; no user-supplied text
// reaches its argv.
func (e *Executors) NetFirewallList(ctx context.Context, in nodewire.NetFirewallListInput) (nodewire.NetFirewallListResult, error) {
	if !supportedOS() {
		return nodewire.NetFirewallListResult{}, notAvailable("network operations are supported on Linux only")
	}

	iptablesSave := resolveTool(iptablesSaveCandidates)
	if iptablesSave == "" {
		return nodewire.NetFirewallListResult{}, notAvailable("iptables-save is not installed on this host")
	}

	table := in.Table
	if table == "" {
		table = "filter"
	}

	e.spawns.Add(1)
	result, err := e.cmdRunner(ctx, CommandSpec{
		Path: iptablesSave,
		Args: []string{"-t", table},
	})
	if err != nil {
		return nodewire.NetFirewallListResult{}, classifyCommandError(err, "iptables-save")
	}

	chains := parseIptablesSaveOutput(table, result.Stdout)
	return nodewire.NetFirewallListResult{
		Chains:     chains,
		ObservedAt: e.now().UTC(),
	}, nil
}

// parseIptablesSaveOutput parses the text output of iptables-save into chains.
// Format example:
//
//	*filter
//	:INPUT ACCEPT [0:0]
//	:FORWARD DROP [0:0]
//	-A INPUT -p tcp --dport 22 -j ACCEPT
//	COMMIT
func parseIptablesSaveOutput(table, out string) []nodewire.FirewallChain {
	chainMap := map[string]*nodewire.FirewallChain{}
	ruleNum := map[string]int{}

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line == "COMMIT" || strings.HasPrefix(line, "#") {
			continue
		}
		// :CHAIN POLICY [packets:bytes]
		if strings.HasPrefix(line, ":") {
			parts := strings.Fields(line[1:])
			if len(parts) >= 1 {
				name := parts[0]
				policy := ""
				if len(parts) >= 2 && parts[1] != "-" {
					policy = parts[1]
				}
				chainMap[name] = &nodewire.FirewallChain{
					Table:  table,
					Chain:  name,
					Policy: policy,
				}
			}
			continue
		}
		// -A CHAIN <rule options>
		if strings.HasPrefix(line, "-A ") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			chainName := fields[1]
			ch, ok := chainMap[chainName]
			if !ok {
				ch = &nodewire.FirewallChain{Table: table, Chain: chainName}
				chainMap[chainName] = ch
			}
			ruleNum[chainName]++
			row := parseRuleFields(fields[2:], ruleNum[chainName])
			ch.Rules = append(ch.Rules, row)
		}
	}

	out2 := make([]nodewire.FirewallChain, 0, len(chainMap))
	for _, ch := range chainMap {
		out2 = append(out2, *ch)
	}
	return out2
}

// parseRuleFields parses the options part of an iptables rule line.
func parseRuleFields(fields []string, num int) nodewire.FirewallRuleRow {
	row := nodewire.FirewallRuleRow{
		Num:         num,
		Protocol:    "all",
		Source:      "0.0.0.0/0",
		Destination: "0.0.0.0/0",
	}
	var opts []string
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		switch f {
		case "-j", "--jump":
			if i+1 < len(fields) {
				row.Target = fields[i+1]
				i++
			}
		case "-p", "--protocol":
			if i+1 < len(fields) {
				row.Protocol = fields[i+1]
				i++
			}
		case "-s", "--source":
			if i+1 < len(fields) {
				row.Source = fields[i+1]
				i++
			}
		case "-d", "--destination":
			if i+1 < len(fields) {
				row.Destination = fields[i+1]
				i++
			}
		default:
			opts = append(opts, f)
		}
	}
	row.Options = strings.Join(opts, " ")
	return row
}

// ── net.port.inventory ────────────────────────────────────────────────────────

// NetPortInventory runs 'ss -tlunp' (or filtered by protocol) to list all
// listening sockets. The binary is resolved from a fixed candidate list; no
// shell is used and no user-supplied text reaches the argv.
func (e *Executors) NetPortInventory(ctx context.Context, in nodewire.NetPortInventoryInput) (nodewire.NetPortInventoryResult, error) {
	if !supportedOS() {
		return nodewire.NetPortInventoryResult{}, notAvailable("network operations are supported on Linux only")
	}

	ssBin := resolveTool(ssCandidates)
	if ssBin == "" {
		return nodewire.NetPortInventoryResult{}, notAvailable("ss is not installed on this host")
	}

	// Build argv: ss -lnp + protocol flags.
	// -l: listening, -n: numeric ports, -p: show process.
	args := []string{"-lnp"}
	switch in.Protocol {
	case "tcp":
		args = append(args, "-t")
	case "udp":
		args = append(args, "-u")
	default:
		// both
		args = append(args, "-t", "-u")
	}

	e.spawns.Add(1)
	result, err := e.cmdRunner(ctx, CommandSpec{
		Path: ssBin,
		Args: args,
	})
	if err != nil {
		return nodewire.NetPortInventoryResult{}, classifyCommandError(err, "ss")
	}

	ports := parseSSOutput(result.Stdout)
	return nodewire.NetPortInventoryResult{
		Ports:      ports,
		ObservedAt: e.now().UTC(),
	}, nil
}

// parseSSOutput parses the output of 'ss -lnp[-t][-u]'.
// Output format:
//
//	Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
//	tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*       users:(("sshd",pid=1234,fd=3))
func parseSSOutput(out string) []nodewire.ListeningPort {
	var ports []nodewire.ListeningPort
	scanner := bufio.NewScanner(strings.NewReader(out))
	first := true
	for scanner.Scan() {
		line := scanner.Text()
		if first {
			first = false
			continue // skip header
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := strings.ToLower(fields[0])
		if proto != "tcp" && proto != "udp" {
			continue
		}
		// fields[3] is Local Address:Port e.g. 0.0.0.0:22 or [::]:22
		localField := fields[4]
		addr, portStr := splitAddrPort(localField)
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			continue
		}

		entry := nodewire.ListeningPort{
			Protocol:     proto,
			LocalAddress: addr,
			LocalPort:    port,
		}

		// Parse process: users:(("sshd",pid=1234,fd=3))
		if len(fields) >= 6 {
			entry.PID, entry.ProcessName = parseSSProcess(fields[len(fields)-1])
		}

		ports = append(ports, entry)
	}
	return ports
}

// splitAddrPort splits "0.0.0.0:22" or "[::1]:80" into addr and port.
func splitAddrPort(s string) (addr, port string) {
	if len(s) > 0 && s[0] == '[' {
		// IPv6
		end := strings.LastIndex(s, "]")
		if end < 0 {
			return s, ""
		}
		addr = s[1:end]
		rest := s[end+1:]
		if len(rest) > 1 && rest[0] == ':' {
			port = rest[1:]
		}
		return addr, port
	}
	// IPv4
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return s, ""
	}
	return s[:i], s[i+1:]
}

// parseSSProcess extracts PID and name from ss process field like:
// users:(("sshd",pid=1234,fd=3))
func parseSSProcess(s string) (pid int, name string) {
	// Find first quoted name.
	start := strings.Index(s, "(\"")
	end := strings.Index(s, "\",")
	if start >= 0 && end > start {
		name = s[start+2 : end]
	}
	// Find pid=N.
	pidIdx := strings.Index(s, "pid=")
	if pidIdx >= 0 {
		rest := s[pidIdx+4:]
		comma := strings.IndexAny(rest, ",)")
		if comma > 0 {
			pid, _ = strconv.Atoi(rest[:comma])
		}
	}
	return pid, name
}

// ── net.diag ──────────────────────────────────────────────────────────────────

// NetDiag runs a confined ping or traceroute to the validated target.
// The target is validated by the wire layer before this is called. The tool
// binary is resolved from a fixed candidate list; no shell is used.
func (e *Executors) NetDiag(ctx context.Context, in nodewire.NetDiagInput) (nodewire.NetDiagResult, error) {
	if !supportedOS() {
		return nodewire.NetDiagResult{}, notAvailable("network diagnostics are supported on Linux only")
	}

	// Validate again at executor boundary (defense-in-depth).
	if !nodewire.ValidNetDiagTarget(in.Target) {
		return nodewire.NetDiagResult{}, &nodewire.Error{
			Code:    nodewire.CodeInvalidInput,
			Message: "target contains characters that are not safe to pass to network diagnostic tools",
		}
	}

	var toolPath string
	var args []string

	switch in.Mode {
	case "ping":
		toolPath = resolveTool(pingCandidates)
		if toolPath == "" {
			return nodewire.NetDiagResult{}, notAvailable("ping is not installed on this host")
		}
		// -c 4: 4 packets; -W 2: 2s timeout per probe; -n: no DNS reverse lookup.
		args = []string{"-c", "4", "-W", "2", "-n", "--", in.Target}
	case "trace":
		toolPath = resolveTool(tracerouteCandidates)
		if toolPath == "" {
			return nodewire.NetDiagResult{}, notAvailable("traceroute is not installed on this host")
		}
		// -m 15: max 15 hops; -w 2: 2s per probe; -n: no DNS.
		args = []string{"-m", "15", "-w", "2", "-n", "--", in.Target}
	default:
		return nodewire.NetDiagResult{}, &nodewire.Error{
			Code:    nodewire.CodeInvalidInput,
			Message: fmt.Sprintf("unknown mode %q: must be ping or trace", in.Mode),
		}
	}

	e.spawns.Add(1)
	result, err := e.cmdRunner(ctx, CommandSpec{
		Path: toolPath,
		Args: args,
	})

	// For diagnostic ops a non-zero exit (e.g. no reply) is a result, not an error.
	// We still surface the output and set Success=false.
	output := result.Stdout
	if result.Stderr != "" {
		output += result.Stderr
	}
	success := err == nil

	return nodewire.NetDiagResult{
		Mode:       in.Mode,
		Target:     in.Target,
		Output:     output,
		Success:    success,
		ObservedAt: e.now().UTC(),
	}, nil
}

// ── helpers ────────────────────────────────────────────────────────────────────

// resolveTool returns the first executable path from candidates using the same
// resolveProgram logic as other executors (no PATH, explicit list, executable bit).
func resolveTool(candidates []string) string {
	p, ok := resolveProgram(candidates...)
	if !ok {
		return ""
	}
	return p
}
