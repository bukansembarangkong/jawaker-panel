package nodewire

import (
	"errors"
	"time"
)

// ── net.firewall.list ──────────────────────────────────────────────────────────

// NetFirewallListInput is the input for net.firewall.list.
// An empty input returns all chains; Table selects an iptables table.
type NetFirewallListInput struct {
	// Table is the iptables table name: "filter", "nat", or "mangle".
	// Empty means "filter".
	Table string `json:"table,omitempty"`
}

// Validate checks input.
func (in NetFirewallListInput) Validate() error {
	if in.Table != "" {
		switch in.Table {
		case "filter", "nat", "mangle":
		default:
			return errors.New("table must be one of: filter, nat, mangle")
		}
	}
	return nil
}

// FirewallChain is one iptables chain returned by net.firewall.list.
type FirewallChain struct {
	// Table is the iptables table (filter/nat/mangle).
	Table string `json:"table"`
	// Chain is the chain name (INPUT, OUTPUT, FORWARD, or custom).
	Chain string `json:"chain"`
	// Policy is the default chain policy (ACCEPT, DROP, or empty for custom).
	Policy string `json:"policy,omitempty"`
	// Rules are the rules in declaration order.
	Rules []FirewallRuleRow `json:"rules"`
}

// FirewallRuleRow is one iptables rule line.
type FirewallRuleRow struct {
	// Num is the 1-based rule number within the chain.
	Num int `json:"num"`
	// Target is the rule target: ACCEPT, DROP, REJECT, LOG, chain name.
	Target string `json:"target"`
	// Protocol is the matched protocol: tcp, udp, icmp, all.
	Protocol string `json:"protocol"`
	// Source is the matched source CIDR or "0.0.0.0/0" for any.
	Source string `json:"source"`
	// Destination is the matched destination CIDR or "0.0.0.0/0" for any.
	Destination string `json:"destination"`
	// Options is the raw options string (dport, state, etc.) for display.
	Options string `json:"options,omitempty"`
}

// NetFirewallListResult is the output of net.firewall.list.
type NetFirewallListResult struct {
	Chains     []FirewallChain `json:"chains"`
	ObservedAt time.Time       `json:"observed_at"`
}

// ── net.port.inventory ────────────────────────────────────────────────────────

// NetPortInventoryInput is the input for net.port.inventory.
type NetPortInventoryInput struct {
	// Protocol filters to "tcp", "udp", or "" for both.
	Protocol string `json:"protocol,omitempty"`
}

// Validate checks input.
func (in NetPortInventoryInput) Validate() error {
	if in.Protocol != "" && in.Protocol != "tcp" && in.Protocol != "udp" {
		return errors.New("protocol must be tcp, udp, or empty for both")
	}
	return nil
}

// ListeningPort describes one bound socket on the node.
type ListeningPort struct {
	// Protocol is "tcp" or "udp".
	Protocol string `json:"protocol"`
	// LocalAddress is the bound address (e.g. "0.0.0.0" or "::").
	LocalAddress string `json:"local_address"`
	// LocalPort is the bound port number.
	LocalPort int `json:"local_port"`
	// PID is the owning process ID (0 if not available).
	PID int `json:"pid,omitempty"`
	// ProcessName is the owning process name (empty if not available).
	ProcessName string `json:"process_name,omitempty"`
}

// NetPortInventoryResult is the output of net.port.inventory.
type NetPortInventoryResult struct {
	Ports      []ListeningPort `json:"ports"`
	ObservedAt time.Time       `json:"observed_at"`
}

// ── net.diag ──────────────────────────────────────────────────────────────────

// NetDiagInput is the input for net.diag.
// The target must be an IP address or a hostname that resolves to one.
// Raw shell metacharacters are rejected before the process is spawned.
type NetDiagInput struct {
	// Target is the IP address or hostname to probe.
	Target string `json:"target"`
	// Mode selects the diagnostic: "ping" or "trace".
	// ping: sends 4 ICMP echo requests.
	// trace: runs traceroute (up to 15 hops, 2s per hop).
	Mode string `json:"mode"`
}

// Validate checks that input is safe to forward to the executor.
func (in NetDiagInput) Validate() error {
	var errs []error
	if in.Target == "" {
		errs = append(errs, errors.New("target is required"))
	} else if !ValidNetDiagTarget(in.Target) {
		errs = append(errs, errors.New("target contains characters that are not safe to pass to the system network tools"))
	}
	switch in.Mode {
	case "ping", "trace":
	case "":
		errs = append(errs, errors.New("mode is required: ping or trace"))
	default:
		errs = append(errs, errors.New("mode must be ping or trace"))
	}
	return errors.Join(errs...)
}

// ValidNetDiagTarget reports whether s is safe to pass as a network diagnostic
// target argument. Allows IP addresses and hostnames (a-z, A-Z, 0-9, . : -).
// Rejects anything else so the target cannot inject arguments.
func ValidNetDiagTarget(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, c := range s {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '.' || c == ':' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}

// NetDiagResult is the output of net.diag.
type NetDiagResult struct {
	// Mode echoes the requested mode.
	Mode string `json:"mode"`
	// Target echoes the target.
	Target string `json:"target"`
	// Output is the raw output of ping or traceroute, redacted of any
	// sensitive-looking IP ranges by the executor before leaving the agent.
	Output string `json:"output"`
	// Success reports whether the probe succeeded (ICMP reply received for
	// ping; at least one hop responded for trace).
	Success bool `json:"success"`
	// ObservedAt is when the result was collected.
	ObservedAt time.Time `json:"observed_at"`
}
