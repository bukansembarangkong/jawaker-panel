package nodes

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
)

// The controller's node-facing mTLS listener.
//
// It is a SECOND listener, on its own port, separate from the public API, and
// that separation is deliberate:
//
//   - the public API authenticates browsers with session cookies and CSRF tokens;
//     a node presents a client certificate. Mixing the two on one listener would
//     mean one set of middleware has to reason about both, and a relaxation for
//     one would silently apply to the other;
//   - a listener that REQUIRES a client certificate cannot be reached by an
//     anonymous client at all. The agent's heartbeat and the controller's
//     dispatch both use it, so the trust decision is made by the TLS stack before
//     any handler runs.
//
// The verifier pins the Node CA and accepts any node id: which node is calling is
// established by the certificate, and the handler compares that identity against
// what the request claims. Pinning one id here would make one listener per node.

// NodeListenerOptions configures the listener.
type NodeListenerOptions struct {
	Handlers *Handlers
	Logger   *slog.Logger
	// Now supplies the clock. Nil means time.Now.
	Now func() time.Time
}

// NodeListener serves node-facing routes over mutual TLS.
type NodeListener struct {
	handlers *Handlers
	logger   *slog.Logger
	now      func() time.Time
}

// NewNodeListener builds the listener.
func NewNodeListener(opts NodeListenerOptions) (*NodeListener, error) {
	if opts.Handlers == nil {
		return nil, errors.New("nodes: handlers are required for the node listener")
	}
	if opts.Logger == nil {
		return nil, errors.New("nodes: logger is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &NodeListener{handlers: opts.Handlers, logger: opts.Logger, now: now}, nil
}

// TLSConfig builds the listener's TLS configuration.
//
// The controller presents its own leaf and requires a client certificate that
// chains to the pinned Node CA. A node certificate is the ONLY thing that gets
// past the handshake, so an authenticated session is a precondition for every
// handler on this listener rather than a check inside one.
func (l *NodeListener) TLSConfig() (*tls.Config, error) {
	authority := l.handlers.auth
	verifier, err := pki.NewVerifier(pki.VerifierOptions{
		RootPEM: authority.NodeCertPEM(),
		Kind:    pki.KindNode,
		Now:     l.now,
	})
	if err != nil {
		return nil, fmt.Errorf("nodes: node root is not usable as a trust anchor: %w", err)
	}
	leaf, err := authority.IssueControllerLeaf()
	if err != nil {
		return nil, err
	}
	return pki.NewTLSServerConfig(pki.TLSServerOptions{
		CertPEM:  leaf.CertPEM(),
		KeyPEM:   leaf.KeyPEM(),
		Verifier: verifier,
	})
}

// Handler is the node-facing route table.
//
// It is deliberately tiny, and nothing here is a user-facing route: this listener
// carries node traffic only, so mounting the fleet API on it would expose operator
// endpoints to a credential class that was never meant to reach them.
func (l *NodeListener) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST "+nodewire.HeartbeatPath, http.HandlerFunc(l.handlers.handleHeartbeat))
	return mux
}

// Serve runs on an existing listener until ctx is canceled.
//
// ln is a PLAIN listener: the TLS handshake is applied here rather than by the
// caller, and that matters. http.Server.Serve IGNORES its TLSConfig field — only
// ServeTLS consults it — so setting TLSConfig and calling Serve would serve
// PLAINTEXT and the required-client-certificate verifier would never run. Wrapping
// the listener with tls.NewListener is what makes the handshake, and therefore the
// mutual-TLS authentication, actually happen.
func (l *NodeListener) Serve(ctx context.Context, ln net.Listener) error {
	tlsConfig, err := l.TLSConfig()
	if err != nil {
		return err
	}
	tlsListener := tls.NewListener(ln, tlsConfig)

	server := &http.Server{
		Handler:           l.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		// No write timeout: a node's handler is a single bounded database write,
		// and a blanket write timeout would cut a slow-but-successful beat at an
		// arbitrary point while telling the node it failed.
		BaseContext: func(net.Listener) context.Context { return ctx },
	}

	errs := make(chan error, 1)
	go func() {
		err := server.Serve(tlsListener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errs <- err
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
	return <-errs
}

// ListenAndServe binds an address and serves.
func (l *NodeListener) ListenAndServe(ctx context.Context, address string) error {
	if address == "" {
		return errors.New("nodes: a node listener address is required")
	}
	// A listener bootstrap has no request context in scope; ListenConfig keeps
	// this the one place that says so explicitly rather than the one that trips
	// a linter for it.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", address)
	if err != nil {
		return fmt.Errorf("nodes: listen for nodes on %s: %w", address, err)
	}
	l.logger.Info("node listener started", "address", address)
	return l.Serve(ctx, ln)
}
