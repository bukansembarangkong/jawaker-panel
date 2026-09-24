package nodeagent

import (
	"context"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
)

// --- ValidNetDiagTarget -------------------------------------------------------

func TestValidNetDiagTargetAcceptsIPv4(t *testing.T) {
	if !nodewire.ValidNetDiagTarget("192.168.1.1") {
		t.Error("expected IPv4 address to be valid")
	}
}

func TestValidNetDiagTargetAcceptsIPv6(t *testing.T) {
	if !nodewire.ValidNetDiagTarget("::1") {
		t.Error("expected IPv6 loopback to be valid")
	}
}

func TestValidNetDiagTargetAcceptsHostname(t *testing.T) {
	if !nodewire.ValidNetDiagTarget("example.com") {
		t.Error("expected hostname to be valid")
	}
}

func TestValidNetDiagTargetRejectsShellMetachars(t *testing.T) {
	bad := []string{
		"example.com; rm -rf /",
		"$(echo)",
		"host name",
		"host`whoami`",
		"host|cat /etc/passwd",
		"",
	}
	for _, s := range bad {
		if nodewire.ValidNetDiagTarget(s) {
			t.Errorf("expected %q to be invalid", s)
		}
	}
}

// --- parseSSOutput ------------------------------------------------------------

func TestParseSSOutputParsesListeningTCP(t *testing.T) {
	// Typical ss -lntp output line.
	out := "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n" +
		"tcp   LISTEN 0      128    0.0.0.0:22            0.0.0.0:*      users:((\"sshd\",pid=1234,fd=3))\n"

	ports := parseSSOutput(out)
	if len(ports) != 1 {
		t.Fatalf("port count = %d, want 1", len(ports))
	}
	p := ports[0]
	if p.Protocol != "tcp" {
		t.Errorf("protocol = %q, want tcp", p.Protocol)
	}
	if p.LocalPort != 22 {
		t.Errorf("local_port = %d, want 22", p.LocalPort)
	}
	if p.ProcessName != "sshd" {
		t.Errorf("process_name = %q, want sshd", p.ProcessName)
	}
	if p.PID != 1234 {
		t.Errorf("pid = %d, want 1234", p.PID)
	}
}

func TestParseSSOutputSkipsHeader(t *testing.T) {
	out := "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
	ports := parseSSOutput(out)
	if len(ports) != 0 {
		t.Errorf("port count = %d, want 0 (header only)", len(ports))
	}
}

// --- parseIptablesSaveOutput -------------------------------------------------

func TestParseIptablesSaveOutputParsesChain(t *testing.T) {
	out := "*filter\n" +
		":INPUT ACCEPT [0:0]\n" +
		":FORWARD DROP [0:0]\n" +
		"-A INPUT -p tcp --dport 22 -j ACCEPT\n" +
		"COMMIT\n"

	chains := parseIptablesSaveOutput("filter", out)
	if len(chains) == 0 {
		t.Fatal("expected at least one chain")
	}

	var inputChain *nodewire.FirewallChain
	for i := range chains {
		if chains[i].Chain == "INPUT" {
			inputChain = &chains[i]
		}
	}
	if inputChain == nil {
		t.Fatal("INPUT chain not found")
	}
	if inputChain.Policy != "ACCEPT" {
		t.Errorf("INPUT policy = %q, want ACCEPT", inputChain.Policy)
	}
	if len(inputChain.Rules) != 1 {
		t.Errorf("INPUT rule count = %d, want 1", len(inputChain.Rules))
	}
}

// --- NetFirewallList rejects non-Linux ---------------------------------------

func TestNetFirewallListRejectsNonLinux(t *testing.T) {
	if supportedOS() {
		t.Skip("only relevant on non-Linux")
	}
	e := &Executors{now: func() time.Time { return time.Now() }}
	_, err := e.NetFirewallList(context.Background(), nodewire.NetFirewallListInput{})
	if err == nil {
		t.Fatal("expected error on non-Linux, got nil")
	}
}

// --- NetPortInventory rejects non-Linux --------------------------------------

func TestNetPortInventoryRejectsNonLinux(t *testing.T) {
	if supportedOS() {
		t.Skip("only relevant on non-Linux")
	}
	e := &Executors{now: func() time.Time { return time.Now() }}
	_, err := e.NetPortInventory(context.Background(), nodewire.NetPortInventoryInput{})
	if err == nil {
		t.Fatal("expected error on non-Linux, got nil")
	}
}

// --- NetDiag rejects invalid target before cmdRunner -------------------------

func TestNetDiagRejectsInvalidTarget(t *testing.T) {
	if !supportedOS() {
		t.Skip("network diagnostics require Linux")
	}
	e := &Executors{
		now: func() time.Time { return time.Now() },
		cmdRunner: func(_ context.Context, _ CommandSpec) (CommandResult, error) {
			panic("cmdRunner must not be called on invalid target")
		},
	}
	_, err := e.NetDiag(context.Background(), nodewire.NetDiagInput{
		Target: "bad target with spaces",
		Mode:   "ping",
	})
	if err == nil {
		t.Fatal("expected error on invalid target, got nil")
	}
}
