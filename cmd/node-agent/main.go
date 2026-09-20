// Command jawaker-node-agent is the daemon that runs on a MANAGED server.
//
// It has two subcommands, and the split is a security boundary rather than a
// convenience:
//
//	enroll  runs ONCE, with a one-time token, and writes the node's identity.
//	        It is the only moment the agent talks to the controller without a
//	        certificate, so it is also the only moment the operator has to be
//	        present.
//	run     runs forever, using the pinned identity, and executes typed
//	        operations from the closed registry. It refuses to start without an
//	        identity rather than enrolling implicitly: an agent that could enroll
//	        itself would let anything that can reach the controller join the fleet.
//
// ARCHITECTURE.md §13 requires that a controller outage change nothing about this
// host's workloads. The run loop therefore has no controller-outage failure mode:
// heartbeats fail and are logged, the listener keeps serving, and nothing local is
// ever signaled, stopped or restarted except in response to an authenticated
// operation.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/logging"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodeagent"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/version"
)

// defaultStateDir is where the identity lives. It is a fixed, root-only path
// rather than a configurable one: the directory holds the private key that is
// this node's only proof of identity, and making it configurable invites a
// deployment where it lands somewhere group-readable.
const defaultStateDir = "/var/lib/jawaker-node"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "jawaker-node-agent:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "enroll":
		return runEnroll(args[1:])
	case "run":
		return runAgent(args[1:])
	case "doctor":
		return runDoctor(args[1:])
	case "version":
		fmt.Println(version.String())
		return nil
	case "-h", "--help", "help":
		usage()
		return nil
	default:
		return usageError()
	}
}

func usageError() error {
	usage()
	return errors.New("expected one of: enroll, run, doctor, version")
}

func usage() {
	fmt.Fprint(os.Stderr, `jawaker-node-agent — the JAWAKER managed-server agent

Usage:
  jawaker-node-agent enroll [flags]   exchange a one-time token for an identity
  jawaker-node-agent run [flags]      run the agent using the stored identity
  jawaker-node-agent doctor [flags]   report what is wrong with this node
  jawaker-node-agent version          print the build version

Enroll flags:
  -controller URL          controller HTTPS base URL (required)
  -token TOKEN             one-time enrollment token (required)
  -fingerprint HEX         pinned controller root fingerprint (required)
  -node-address HOST:PORT  where this agent will listen (required)
  -state-dir DIR           state directory (default `+defaultStateDir+`)

Run flags:
  -listen ADDR             address to listen on (required)
  -state-dir DIR           state directory (default `+defaultStateDir+`)

Doctor flags:
  -state-dir DIR           state directory to inspect (default `+defaultStateDir+`)
  -json                    emit the report as JSON instead of text
  -skip-connectivity       omit the controller reachability probe
  -connect-timeout DUR     how long to wait for the controller (default 5s)
`)
}

// --- enroll -------------------------------------------------------------------

func runEnroll(args []string) error {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	controllerURL := fs.String("controller", "", "controller HTTPS base URL")
	token := fs.String("token", "", "one-time enrollment token")
	fingerprint := fs.String("fingerprint", "", "pinned controller root fingerprint (hex)")
	nodeAddress := fs.String("node-address", "", "host:port this agent will listen on")
	stateDir := fs.String("state-dir", defaultStateDir, "state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger, err := logging.New(logging.Options{Component: "node-agent", Level: "info", Format: "text"})
	if err != nil {
		return err
	}

	// The fingerprint is REQUIRED, and this is the one step in the whole design
	// that cannot use mutual TLS. Without the pin, whoever can answer the
	// enrollment address could hand this node its own root and become its
	// permanently trusted controller. Refusing to enroll without it is the
	// difference between a trust decision and a hope.
	if strings.TrimSpace(*fingerprint) == "" {
		return errors.New("enrollment requires -fingerprint: without the pinned controller fingerprint, " +
			"whoever answers this request would become this node's trusted controller")
	}

	osFamily, osVersion := detectHost()
	state, err := nodeagent.Enroll(context.Background(), nodeagent.EnrollOptions{
		ControllerURL:                 *controllerURL,
		Token:                         *token,
		ExpectedControllerFingerprint: *fingerprint,
		StateDir:                      *stateDir,
		AgentVersion:                  version.String(),
		OSFamily:                      osFamily,
		OSVersion:                     osVersion,
		NodeAddress:                   *nodeAddress,
	})
	if err != nil {
		return err
	}
	logger.Info("enrolled",
		"server_id", state.ServerID,
		"controller_id", state.ControllerID,
		"state_dir", state.Dir,
		"certificate_expires", state.Identity.Cert().NotAfter.UTC())
	return nil
}

// detectHost reads the OS identity for the enrollment report from fixed paths.
func detectHost() (family, hostVersion string) {
	if raw, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
			if !ok {
				continue
			}
			value = strings.Trim(strings.TrimSpace(value), `"'`)
			switch strings.TrimSpace(key) {
			case "ID":
				family = value
			case "VERSION_ID":
				hostVersion = value
			}
		}
	}
	return family, hostVersion
}

// --- run ----------------------------------------------------------------------

func runAgent(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	listen := fs.String("listen", "", "address to listen on (required)")
	stateDir := fs.String("state-dir", defaultStateDir, "state directory")
	if err := fs.Parse(args); err != nil {
		return err
	}

	logger, err := logging.New(logging.Options{Component: "node-agent", Level: "info", Format: "text"})
	if err != nil {
		return err
	}

	// Loading validates that the identity, the pinned root and the configuration
	// agree. A disagreement is refused here rather than discovered at the first
	// heartbeat, where the message would name the symptom instead of the cause.
	state, err := nodeagent.LoadState(*stateDir)
	if err != nil {
		return err
	}
	if *listen == "" {
		return errors.New("-listen is required: the agent must bind the address the controller recorded " +
			"for it, or it will be enrolled and unreachable")
	}

	executors := nodeagent.NewExecutors(nodeagent.ExecutorOptions{AgentVersion: version.String()})
	if executors.SystemctlPath() == "" {
		// Reported plainly rather than hidden. Service operations are refused,
		// which is the honest answer; pretending otherwise would produce a panel
		// button that always fails.
		logger.Warn("systemd is not available on this host: service operations will be reported as unsupported and refused")
	}

	agent, err := nodeagent.NewAgent(nodeagent.AgentOptions{
		State:     state,
		Executors: executors,
		Logger:    logger,
	})
	if err != nil {
		return err
	}

	heartbeats, err := nodeagent.NewHeartbeatClient(nodeagent.HeartbeatOptions{
		State:    state,
		Exec:     executors,
		Logger:   logger,
		Interval: nodeagent.DefaultHeartbeatInterval,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The heartbeat loop runs FIRST and always. If the controller is unreachable
	// it logs and retries; nothing here can stop the listener or touch a hosted
	// process, which is what makes a controller outage a non-event on this host.
	go heartbeats.Run(ctx)

	logger.Info("node agent starting",
		"server_id", state.ServerID,
		"controller", state.ControllerAddress,
		"operations", operationNames(agent.Served()))

	listenerErr := make(chan error, 1)
	go func() { listenerErr <- agent.ListenAndServe(ctx, *listen) }()

	select {
	case err := <-listenerErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	case <-ctx.Done():
		logger.Info("shutdown signal received; local workloads are left running")
	}

	// A bounded wait for the listener to drain. The agent does not wait
	// indefinitely for an in-flight operation: every operation is already bounded
	// by its own deadline.
	select {
	case err := <-listenerErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	case <-time.After(10 * time.Second):
		logger.Warn("shutdown deadline reached; exiting")
	}
	logger.Info("shutdown complete")
	return nil
}

// operationNames renders the served set for the startup log, so an operator can
// see which operations this node will actually accept.
func operationNames(served map[nodewire.Operation]bool) []string {
	out := make([]string, 0, len(served))
	for op := range served {
		out = append(out, string(op))
	}
	return out
}
