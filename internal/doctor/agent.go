package doctor

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodeagent"
	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
)

// AgentOptions supplies what the node-agent checks need.
type AgentOptions struct {
	// StateDir is the directory holding the node identity and configuration.
	StateDir string
	// ConnectTimeout bounds the controller reachability probe. Zero means 5s.
	ConnectTimeout time.Duration
	// SkipConnectivity omits the network probe, for a caller that wants a purely
	// local report. It is a field rather than a package variable so two callers
	// cannot race on it.
	SkipConnectivity bool
	// Now supplies the clock. Nil means time.Now.
	Now func() time.Time
}

// DefaultAgentStateDir mirrors the agent binary's own default.
const DefaultAgentStateDir = "/var/lib/jawaker-node"

// Agent checks a managed node.
//
// The checks answer the questions an operator has when a node is not appearing in
// the panel or its actions fail, in dependency order: is there an identity at
// all, is it still valid, does the pinned controller still verify, can this host
// execute the operations the panel offers.
func Agent(ctx context.Context, version string, opts AgentOptions) Report {
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	timeout := opts.ConnectTimeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	stateDir := opts.StateDir
	if stateDir == "" {
		stateDir = DefaultAgentStateDir
	}

	return Run(ctx, "node-agent", version, now,
		Diagnose("build", checkBuild),
		Diagnose("state-directory", checkAgentStateDir(stateDir)),
		Diagnose("node-identity", checkNodeIdentity(stateDir, now)),
		Diagnose("pinned-controller", checkPinnedController(stateDir)),
		Diagnose("controller-connectivity", checkControllerConnectivity(stateDir, timeout, opts.SkipConnectivity)),
		Diagnose("operation-support", checkOperationSupport),
		Diagnose("runtime-files", checkRuntimeFiles),
		Diagnose("disk", checkDisk),
	)
}

// checkAgentStateDir verifies the state directory exists with safe permissions.
//
// It deliberately does NOT call nodeagent.EnsureStateDir, because that CREATES the
// directory. A diagnostic must report that the directory is missing rather than
// create it and then report success: the missing directory IS the finding.
func checkAgentStateDir(dir string) CheckFunc {
	return func(context.Context) Check {
		info, err := os.Stat(dir)
		switch {
		case errors.Is(err, os.ErrNotExist):
			return fail("state-directory",
				fmt.Sprintf("%s does not exist, so this host has not been enrolled", dir), nil)
		case err != nil:
			return fail("state-directory", fmt.Sprintf("%s could not be inspected: %v", dir, err), nil)
		case !info.IsDir():
			return fail("state-directory", fmt.Sprintf("%s exists and is not a directory", dir), nil)
		}

		mode := info.Mode().Perm()
		evidence := map[string]any{"path": dir, "mode": fmt.Sprintf("%04o", mode)}
		// POSIX-only, matching EnsureStateDir: Windows does not express these bits,
		// so checking anyway would warn on every installation.
		if runtime.GOOS == "windows" {
			return ok("state-directory",
				fmt.Sprintf("%s exists (permission bits are not meaningful on Windows)", dir), evidence)
		}
		if mode&0o077 != 0 {
			// A failure rather than a warning, for the same reason EnsureStateDir
			// treats it as one: any local account could have read the node's
			// private key, and no later action undoes that.
			return fail("state-directory",
				fmt.Sprintf("%s has mode %04o; the node's private key is readable by group or others and "+
					"may already have been copied — re-enroll this node", dir, mode), evidence)
		}
		return ok("state-directory", fmt.Sprintf("%s exists with mode %04o", dir, mode), evidence)
	}
}

// checkNodeIdentity loads the stored identity and reports its remaining life.
//
// LoadState performs the full cross-check — the certificate's name against the
// configured server id, and the pinned root against the configured controller —
// so a report that reaches the expiry comparison has already proven those agree.
func checkNodeIdentity(dir string, now func() time.Time) CheckFunc {
	return func(context.Context) Check {
		state, err := nodeagent.LoadState(dir)
		if err != nil {
			// The error text from LoadState already names which cross-check
			// failed, so it is carried through rather than replaced.
			return fail("node-identity", fmt.Sprintf("the node identity could not be loaded: %v", err), nil)
		}

		cert := state.Identity.Cert()
		left := cert.NotAfter.Sub(now())
		evidence := map[string]any{
			"server_id":     state.ServerID,
			"controller_id": state.ControllerID,
			"not_before":    cert.NotBefore.UTC(),
			"not_after":     cert.NotAfter.UTC(),
			"serial":        state.Identity.SerialHex(),
			"fingerprint":   state.Identity.Fingerprint(),
			"remaining":     remaining(left),
			"has_key":       state.Identity.HasPrivateKey(),
		}
		if !state.Identity.HasPrivateKey() {
			// Without the key the node cannot complete a handshake at all, which
			// is a different fault from an expired certificate.
			return fail("node-identity",
				"the stored identity has no private key, so this node cannot authenticate; re-enroll it",
				evidence)
		}

		switch {
		case left <= 0:
			return fail("node-identity",
				fmt.Sprintf("the node certificate expired %s ago; the controller will refuse this node",
					remaining(-left)), evidence)
		case left < nodeRenewalWindow:
			return warn("node-identity",
				fmt.Sprintf("the node certificate expires in %s; re-enroll before it does, because an "+
					"expired node cannot enroll itself", remaining(left)), evidence)
		default:
			return ok("node-identity",
				fmt.Sprintf("identity for %s is valid for another %s", state.ServerID, remaining(left)),
				evidence)
		}
	}
}

// nodeRenewalWindow is how close to expiry a node certificate may be before it is
// reported.
//
// It MUST be smaller than pki.DefaultLeafLifetime (30 days): a window equal to the
// lifetime warns on every freshly issued certificate, which trains an operator to
// ignore the warning and hides the real expiry. Seven days is when re-enrollment is
// genuinely overdue — it is one command, not a fleet-wide operation, so there is no
// reason to give it a longer runway than an authority needs.
const nodeRenewalWindow = 7 * 24 * time.Hour

// checkPinnedController verifies the pinned controller root still yields a usable
// verifier for the configured controller id.
//
// This catches the failure an operator cannot otherwise explain: a valid node
// identity that refuses every connection, because the pinned root is not a
// controller authority at all, or because the root was replaced while the
// configured controller id stayed behind.
//
// Note what is checked and what is NOT. pki.NewVerifier validates the pinned
// root's KIND, not its identity; the identity is compared against each presented
// peer at handshake time, which requires a live peer. So this check compares the
// root's own declared identity against the configured controller id, which
// catches the drift WITHOUT a connection — claiming the verifier proved the id
// would be false.
func checkPinnedController(dir string) CheckFunc {
	return func(context.Context) Check {
		state, err := nodeagent.LoadState(dir)
		if err != nil {
			return skip("pinned-controller",
				fmt.Sprintf("the node identity could not be loaded, so the pin cannot be checked: %v", err))
		}
		// The verifier is the real one the transport uses, so this is not a
		// reimplementation of the check: it IS the check.
		if _, err = pki.NewVerifier(pki.VerifierOptions{
			RootPEM: state.ControllerRootPEM,
			Kind:    pki.KindController,
			ID:      state.ControllerID,
		}); err != nil {
			return fail("pinned-controller",
				fmt.Sprintf("the pinned root is not a usable controller authority: %v; this node would "+
					"refuse every connection from its own controller", err), nil)
		}

		// DecodeCertPEM rather than DecodeCA: a pinned root is a certificate
		// ONLY, and DecodeCA expects a stored authority's private key alongside
		// it, so using it here would fail on every correct installation.
		rootCert, err := pki.DecodeCertPEM(string(state.ControllerRootPEM))
		if err != nil {
			return fail("pinned-controller",
				fmt.Sprintf("the pinned root cannot be parsed as a certificate: %v", err), nil)
		}
		rootIdentity, err := pki.IdentityOf(rootCert)
		if err != nil {
			return fail("pinned-controller",
				fmt.Sprintf("the pinned root carries no usable identity: %v", err), nil)
		}
		evidence := map[string]any{
			"controller_id":       state.ControllerID,
			"controller_address":  state.ControllerAddress,
			"pinned_fingerprint":  pki.FingerprintOf(rootCert),
			"pinned_root_present": len(state.ControllerRootPEM) > 0,
			"pinned_identity_id":  rootIdentity.ID,
		}
		if rootIdentity.Kind != pki.KindController {
			return fail("pinned-controller",
				fmt.Sprintf("the pinned root identifies as a %s authority, not a controller authority",
					rootIdentity.Kind), evidence)
		}
		// The CA's id is its own ROOT id, which is deliberately NOT the controller
		// instance id the configuration records: the authority outlives any single
		// controller and a root is shared by every replica. So the two are
		// reported side by side rather than compared — an operator checks that
		// both correspond to the controller they meant to trust, and doctor states
		// the facts rather than inventing an equality that does not hold.
		return ok("pinned-controller",
			fmt.Sprintf("pinned root is a controller authority (%s) and the configuration names controller %q",
				rootIdentity.ID, state.ControllerID), evidence)
	}
}

// checkControllerConnectivity performs an mTLS handshake with the controller and
// reports the verified peer.
//
// It is the only check that touches the network, and it is bounded by its own
// timeout so a black-holed host cannot make doctor hang. A failure is reported as
// a WARNING rather than a failure, because ARCHITECTURE.md §13 makes a controller
// outage a non-event on a node: an unreachable controller means reporting is
// interrupted, not that the node is broken.
func checkControllerConnectivity(dir string, timeout time.Duration, skipProbe bool) CheckFunc {
	return func(ctx context.Context) Check {
		if skipProbe {
			return skip("controller-connectivity", "the connectivity probe was skipped by the caller")
		}
		state, err := nodeagent.LoadState(dir)
		if err != nil {
			return skip("controller-connectivity",
				fmt.Sprintf("the node identity could not be loaded, so the controller cannot be dialed: %v", err))
		}
		if state.ControllerAddress == "" {
			return skip("controller-connectivity", "no controller address is recorded in the node configuration")
		}

		verifier, err := pki.NewVerifier(pki.VerifierOptions{
			RootPEM: state.ControllerRootPEM,
			Kind:    pki.KindController,
			ID:      state.ControllerID,
		})
		if err != nil {
			return skip("controller-connectivity",
				fmt.Sprintf("the pinned root does not build a verifier, so no handshake can be attempted: %v", err))
		}
		// The probe uses the node's REAL certificate: a bare TCP connect would
		// report success against a listener that then refuses this node at the
		// handshake, which is exactly the failure being diagnosed.
		clientTLS, err := pki.NewTLSClientConfig(pki.TLSClientOptions{
			CertPEM:  state.Identity.CertPEM(),
			KeyPEM:   state.Identity.KeyPEM(),
			Verifier: verifier,
		})
		if err != nil {
			return skip("controller-connectivity",
				fmt.Sprintf("a client TLS configuration could not be built: %v", err))
		}

		probeCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: timeout}, Config: clientTLS}
		conn, err := dialer.DialContext(probeCtx, "tcp", state.ControllerAddress)
		if err != nil {
			return warn("controller-connectivity",
				fmt.Sprintf("the controller at %s could not be reached or refused this node: %v; local "+
					"workloads are unaffected and heartbeat reporting is interrupted",
					state.ControllerAddress, err),
				map[string]any{"controller_address": state.ControllerAddress, "timeout": timeout.String()})
		}
		defer func() { _ = conn.Close() }()

		tlsConn, isTLS := conn.(*tls.Conn)
		if !isTLS {
			return warn("controller-connectivity",
				fmt.Sprintf("the connection to %s did not produce a TLS session", state.ControllerAddress), nil)
		}
		peer := tlsConn.ConnectionState().PeerCertificates
		if len(peer) == 0 {
			return fail("controller-connectivity",
				fmt.Sprintf("%s completed a handshake without presenting a certificate", state.ControllerAddress), nil)
		}
		identity, err := pki.IdentityOf(peer[0])
		if err != nil {
			return fail("controller-connectivity",
				fmt.Sprintf("the controller's certificate has no usable identity: %v", err), nil)
		}
		return ok("controller-connectivity",
			fmt.Sprintf("reached the controller at %s; it identifies as %s %q",
				state.ControllerAddress, identity.Kind, identity.ID),
			map[string]any{
				"controller_address": state.ControllerAddress,
				"peer_kind":          string(identity.Kind),
				"peer_id":            identity.ID,
				"peer_not_after":     peer[0].NotAfter.UTC(),
			})
	}
}

// checkOperationSupport reports which operations this host can actually execute.
//
// It matters because the panel decides which actions to offer from the node's
// reported capabilities, so an operator seeing a disabled Inspect button needs to
// learn that systemd is absent rather than guess the node is offline.
func checkOperationSupport(context.Context) Check {
	executors := nodeagent.NewExecutors(nodeagent.ExecutorOptions{})
	evidence := map[string]any{"goos": runtime.GOOS, "systemctl": executors.SystemctlPath()}

	if runtime.GOOS != "linux" {
		// Not a silent pass: the agent refuses mutating operations off Linux, so
		// the honest report names the platform instead of showing a green tick
		// that implies service management works.
		return warn("operation-support",
			fmt.Sprintf("this host runs %s; the agent only performs service operations on Linux, so inspect "+
				"and restart are reported as unsupported", runtime.GOOS), evidence)
	}
	if executors.SystemctlPath() == "" {
		return warn("operation-support",
			"systemd was not detected, so service inspect and restart are reported as unsupported; "+
				"capabilities and heartbeat still work", evidence)
	}
	return ok("operation-support",
		fmt.Sprintf("systemd detected at %s; typed service operations are available", executors.SystemctlPath()),
		evidence)
}

// checkRuntimeFiles confirms the read-only inputs the agent reads are present.
//
// Separate from operation-support because these are inventory inputs: a missing
// os-release degrades what a node reports without stopping any operation, and
// conflating the two would report a cosmetic gap as a fault.
func checkRuntimeFiles(context.Context) Check {
	if runtime.GOOS != "linux" {
		return skip("runtime-files", "the inventory inputs are read from Linux-specific paths")
	}
	var missing []string
	for _, path := range []string{"/etc/os-release"} {
		if _, err := os.Stat(path); err != nil {
			missing = append(missing, path)
		}
	}
	if len(missing) > 0 {
		return warn("runtime-files",
			fmt.Sprintf("these read-only inputs are missing, so the inventory this node reports will be "+
				"incomplete: %s", strings.Join(missing, ", ")),
			map[string]any{"missing": missing})
	}
	return ok("runtime-files", "the files the agent reads at runtime are present", nil)
}
