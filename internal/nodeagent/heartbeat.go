package nodeagent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
)

// The agent's outbound side: heartbeats to the controller.
//
// It is deliberately tiny, and deliberately incapable of affecting anything
// locally. ARCHITECTURE.md §13 requires that a controller outage change nothing
// about a node's workloads, so the outbound path can only do two things: report,
// and log a failure. There is no queue of undelivered work, because a queue would
// mean the agent holds instructions it has not yet applied — and applying them
// later, when the controller comes back, is indistinguishable from applying them
// now except that nobody is watching.
//
// The client pins the controller exactly as the server does: the pinned root AND
// the pinned identity. Heartbeats carry host resource readings, which is not
// secret, but a heartbeat is also the controller's evidence that a node is alive —
// so it must not be forgeable by anyone who can answer a TCP connection.

// DefaultHeartbeatInterval is how often the agent reports liveness.
const DefaultHeartbeatInterval = 30 * time.Second

// HeartbeatPath is the controller endpoint a heartbeat is posted to. The
// constant lives in nodewire beside the payload so the two ends cannot disagree
// about it; this alias keeps call sites in this package readable.
const HeartbeatPath = nodewire.HeartbeatPath

// HeartbeatPayload is what a heartbeat carries. It is the SHARED wire type, so
// the controller decodes exactly what the agent encoded.
type HeartbeatPayload = nodewire.HeartbeatPayload

// HeartbeatClient posts heartbeats over mutual TLS.
type HeartbeatClient struct {
	state      *State
	exec       *Executors
	logger     *slog.Logger
	httpClient *http.Client
	interval   time.Duration
}

// HeartbeatOptions configures the client.
type HeartbeatOptions struct {
	State   *State
	Exec    *Executors
	Logger  *slog.Logger
	Now     func() time.Time
	Timeout time.Duration
	// Interval overrides the default reporting period. Zero uses the default.
	Interval time.Duration
	// Transport overrides the HTTP transport, for tests. Nil builds the pinned
	// mutual-TLS transport.
	Transport http.RoundTripper
}

// NewHeartbeatClient builds the client.
//
// It fails on an unusable pinned root rather than deferring the failure to the
// first beat: an agent that starts and then cannot report is worse than one that
// refuses to start, because the controller sees a node that enrolled and then
// silently vanished.
func NewHeartbeatClient(opts HeartbeatOptions) (*HeartbeatClient, error) {
	if opts.State == nil || opts.Exec == nil || opts.Logger == nil {
		return nil, fmt.Errorf("nodeagent: heartbeat client needs state, executors and a logger")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = DefaultHeartbeatInterval
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	transport := opts.Transport
	if transport == nil {
		verifier, err := pki.NewVerifier(pki.VerifierOptions{
			RootPEM: opts.State.ControllerRootPEM,
			Kind:    pki.KindController,
			ID:      opts.State.ControllerID,
			Now:     now,
		})
		if err != nil {
			return nil, fmt.Errorf("nodeagent: pinned controller root is not usable: %w", err)
		}
		identity := opts.State.Identity
		if identity == nil || !identity.HasPrivateKey() {
			return nil, fmt.Errorf("nodeagent: the node has no usable identity; re-enrollment is required")
		}
		tlsConfig, err := pki.NewTLSClientConfig(pki.TLSClientOptions{
			CertPEM:  identity.CertPEM(),
			KeyPEM:   identity.KeyPEM(),
			Verifier: verifier,
		})
		if err != nil {
			return nil, err
		}
		transport = &http.Transport{
			TLSClientConfig: tlsConfig,
			// One idle connection per peer is all this client ever needs, and
			// bounding it stops an unreachable controller from accumulating
			// sockets across a long outage.
			MaxIdleConns:        1,
			MaxIdleConnsPerHost: 1,
			IdleConnTimeout:     90 * time.Second,
		}
	}

	return &HeartbeatClient{
		state:      opts.State,
		exec:       opts.Exec,
		logger:     opts.Logger,
		httpClient: &http.Client{Transport: transport, Timeout: timeout},
		interval:   interval,
	}, nil
}

// Beats returns the configured interval, for the run loop and tests.
func (c *HeartbeatClient) Beats() time.Duration { return c.interval }

// Beat sends one heartbeat.
//
// Every failure is returned and NONE of them changes local state. In particular a
// failed beat does not stop the agent, does not touch a hosted process, and does
// not queue anything: the caller logs it and tries again on the next tick.
func (c *HeartbeatClient) Beat(ctx context.Context) error {
	report, err := c.exec.Heartbeat(ctx)
	if err != nil {
		// A collector fault is not a transport fault, but both mean "no usable
		// reading", and sending a partially-read heartbeat would enter a
		// plausible-looking zero into the controller's time series. Report the
		// fault and skip this beat.
		return fmt.Errorf("nodeagent: collect heartbeat: %w", err)
	}

	body, err := json.Marshal(HeartbeatPayload{
		ServerID:     c.state.ServerID,
		Reported:     report,
		AgentVersion: c.exec.agentVersion,
	})
	if err != nil {
		return fmt.Errorf("nodeagent: encode heartbeat: %w", err)
	}

	url := heartbeatURL(c.state.ControllerAddress)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("nodeagent: build heartbeat request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(nodewire.VersionHeader, fmt.Sprint(nodewire.ProtocolVersion))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("nodeagent: heartbeat failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("nodeagent: heartbeat refused with HTTP %d", resp.StatusCode)
	}
	return nil
}

// Run beats until ctx is canceled.
//
// A failed beat is logged at warn and the loop CONTINUES. Stopping on a failure
// would turn a controller restart into a fleet that has to be restarted by hand,
// and the whole point of the outage requirement is that a node does not need the
// controller to keep serving.
func (c *HeartbeatClient) Run(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	// Beat once immediately so a node that just came up appears within seconds
	// rather than after a full interval.
	c.beatAndLog(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.beatAndLog(ctx)
		}
	}
}

func (c *HeartbeatClient) beatAndLog(ctx context.Context) {
	if err := c.Beat(ctx); err != nil {
		if ctx.Err() != nil {
			// Shutting down; no operator wants a warning about the shutdown
			// they asked for.
			return
		}
		c.logger.WarnContext(ctx, "heartbeat failed; local workloads are unaffected",
			"error", err, "server_id", c.state.ServerID)
	}
}

// heartbeatURL builds the heartbeat endpoint from the recorded controller
// address.
//
// https is hardcoded rather than taken from configuration: the pinned root only
// means something over TLS, and a plaintext heartbeat endpoint would let anyone
// who can answer the address report a node as alive.
func heartbeatURL(controllerAddress string) string {
	return "https://" + controllerAddress + HeartbeatPath
}
