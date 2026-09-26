package nodeagent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
)

// The agent's mTLS listener: the ONLY way anything reaches this host's privileged
// operations.
//
// Three things make this a boundary rather than a port.
//
// FIRST, every connection presents a certificate that must chain to the PINNED
// controller root AND carry the pinned controller identity. A certificate that
// verifies against a public CA is refused; so is one signed by our own node CA.
// The verifier is built once at construction, so a listener cannot be started with
// weaker trust by omission.
//
// SECOND, the operation set is derived from what this build can actually do, and
// an operation outside it is refused BEFORE the payload is decoded and before any
// process is started. The closed registry in nodewire is what makes an arbitrary
// command unrepresentable; this is where that refusal happens.
//
// THIRD, concurrency is bounded. A controller that queues a thousand restarts
// must not produce a thousand children on one host: the agent refuses the excess
// with a retryable answer instead of either blocking forever or forking without
// limit.

// OperationPath is the single endpoint the agent serves.
//
// One path for all operations rather than one path per operation: the envelope
// already names the operation, and a per-operation URL would mean the routing
// table becomes a second registry that has to be kept in agreement with the
// first. Two definitions of "what can be called" is exactly how a closed registry
// stops being closed.
const OperationPath = "/api/v1/node/op"

// maxRequestBodyBytes bounds a request. The envelope itself is small; the input
// payload has its own limit in nodewire. This is the outer bound that stops a
// hostile peer from making the agent allocate by opening a connection and
// dribbling bytes.
const maxRequestBodyBytes = 128 * 1024

// maxConcurrentOperations bounds how many operations run at once on one host.
//
// Small on purpose. Every operation here either reads state or restarts a
// service; neither benefits from wide parallelism on one machine, and a restart
// storm is a self-inflicted outage.
const maxConcurrentOperations = 4

// Agent is a running node agent.
type Agent struct {
	state  *State
	exec   *Executors
	logger *slog.Logger
	now    func() time.Time
	// sem bounds concurrent operations. It is a buffered channel because that is
	// the smallest thing that expresses "at most N at once" without a mutex and a
	// counter that can disagree.
	sem chan struct{}
	// served is the operation set, decided once at construction.
	served map[nodewire.Operation]bool
}

// AgentOptions configures an Agent.
type AgentOptions struct {
	// State is the loaded identity and pinned trust. Required.
	State *State
	// Executors provide the operation implementations. Required.
	Executors *Executors
	// Logger receives operational messages. Required.
	Logger *slog.Logger
	// Now supplies the clock. Nil means time.Now.
	Now func() time.Time
	// MaxConcurrentOperations overrides the bound. Zero means the default.
	MaxConcurrentOperations int
}

// NewAgent builds an agent from loaded state.
//
// It fails rather than degrades on a missing identity or an unusable pinned root:
// an agent that starts without them would either refuse every connection with no
// explanation, or — far worse — accept some.
func NewAgent(opts AgentOptions) (*Agent, error) {
	if opts.State == nil {
		return nil, errors.New("nodeagent: state is required")
	}
	if opts.Executors == nil {
		return nil, errors.New("nodeagent: executors are required")
	}
	if opts.Logger == nil {
		return nil, errors.New("nodeagent: logger is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	limit := opts.MaxConcurrentOperations
	if limit <= 0 {
		limit = maxConcurrentOperations
	}
	return &Agent{
		state:  opts.State,
		exec:   opts.Executors,
		logger: opts.Logger,
		now:    now,
		sem:    make(chan struct{}, limit),
		served: servedOperations(opts.Executors),
	}, nil
}

// Served returns the operations this build implements.
//
// Derived from what was detected rather than from the registry: a node without
// systemd must not advertise service.restart, because the controller would offer
// an operator a button that always fails. Honest advertisement and honest
// refusal come from the same value.
func servedOperations(e *Executors) map[nodewire.Operation]bool {
	served := map[nodewire.Operation]bool{
		nodewire.OpNodeCapabilities: true,
		nodewire.OpNodeHeartbeat:    true,
	}
	// service.* requires BOTH systemd and a supported OS. The executors check the
	// same conditions independently; this list is what makes the capability report
	// and the refusal agree.
	if e.hasSystemd && supportedOS() {
		served[nodewire.OpServiceInspect] = true
		served[nodewire.OpServiceRestart] = true
	}
	// web.config.validate requires a detected web server AND the staging
	// directory it stages candidates in. Advertising it from the binary alone
	// would offer an operator a check that always fails, which is precisely what
	// the systemd gate above exists to avoid.
	if e.webServer.Available() && supportedOS() {
		served[nodewire.OpWebConfigValidate] = true
	}
	// site.logs.tail is available on any Linux node. It does NOT require nginx
	// to be installed or running: a node may have logs from a prior nginx
	// installation, and the operation reads a file — it does not talk to the
	// web server process. The gate is only the OS, matching the descriptor's
	// OSSupport declaration.
	if supportedOS() {
		served[nodewire.OpSiteLogsTail] = true
	}
	// web.config.apply WRITES the live configuration. The gate is the
	// intersection of everything the executor will refuse on its own: a
	// detected web server with a sites-enabled directory, systemd (the
	// reload must be supervised, or a failed config cannot be rolled back
	// into a running service), and a supported OS. Advertising apply from a
	// node that cannot reload would offer a button whose first use breaks
	// hosting.
	if e.webServer.CanApply() && e.hasSystemd && supportedOS() {
		served[nodewire.OpWebConfigApply] = true
	}
	// app.deploy WRITES a release directory, writes a systemd unit, and reloads
	// systemd. It requires systemd, git installed on the host, and Linux.
	if e.hasSystemd && e.gitAvailable && supportedOS() {
		served[nodewire.OpAppDeploy] = true
	}
	// database.* operations require a detected database engine and Linux.
	// Either PostgreSQL or MariaDB capability satisfies the gate; individual
	// executors re-verify the specific engine requested by each payload.
	if (e.pgAvailable || e.mariaAvailable) && supportedOS() {
		served[nodewire.OpDatabaseManage] = true
		served[nodewire.OpDatabaseDump] = true
		served[nodewire.OpDatabaseRestore] = true
		served[nodewire.OpDatabaseMetrics] = true
		served[nodewire.OpDatabaseUpgrade] = true
	}
	// node.metrics reads host-level counters. Gate is Linux only.
	if supportedOS() {
		served[nodewire.OpNodeMetrics] = true
	}
	// file.* operations require tar and Linux. Same honest-advertisement rule:
	// a node without tar must not offer a backup that always fails.
	if e.tarPath != "" && supportedOS() {
		served[nodewire.OpFileArchive] = true
		served[nodewire.OpFileRestore] = true
	}
	// container.* operations require docker and Linux. The capability report
	// and this gate read the same field so they cannot disagree.
	if e.dockerAvailable && supportedOS() {
		served[nodewire.OpContainerList] = true
		served[nodewire.OpContainerInspect] = true
		served[nodewire.OpContainerLogs] = true
		served[nodewire.OpContainerLifecycle] = true
	}
	// net.* operations require Linux. iptables-save and ss are detected at
	// dispatch time (not startup) because they may be installed after the
	// agent starts. All three are always offered on Linux; the executor
	// returns notAvailable if the binary is missing at dispatch time.
	if supportedOS() {
		served[nodewire.OpNetFirewallList] = true
		served[nodewire.OpNetPortInventory] = true
		served[nodewire.OpNetDiag] = true
		served[nodewire.OpSecHardeningScan] = true
		served[nodewire.OpSecSSHPosture] = true
		served[nodewire.OpSecBanList] = true
		served[nodewire.OpSecBanAdd] = true
		served[nodewire.OpSecBanRemove] = true
		served[nodewire.OpSecWAFApply] = true
		served[nodewire.OpUpdateNodeAgent] = true
	}
	// site.nodejs.* manages per-site Node.js systemd units. Requires systemd
	// and Linux, same gates as service.* — a node without systemd cannot
	// write a unit file and expect it to be picked up.
	if e.hasSystemd && supportedOS() {
		served[nodewire.OpSiteNodeJSManage] = true
		served[nodewire.OpSiteNodeJSStatus] = true
	}
	return served
}

// Served returns the operation set this agent implements.
func (a *Agent) Served() map[nodewire.Operation]bool { return a.served }

// TLSConfig builds the listener's TLS configuration.
//
// The verifier pins the controller root AND the controller identity, which is the
// pair that makes "a valid certificate from a different installation" a refusal
// rather than an acceptance.
func (a *Agent) TLSConfig() (*tls.Config, error) {
	verifier, err := pki.NewVerifier(pki.VerifierOptions{
		RootPEM: a.state.ControllerRootPEM,
		Kind:    pki.KindController,
		ID:      a.state.ControllerID,
		Now:     a.now,
	})
	if err != nil {
		return nil, fmt.Errorf("nodeagent: pinned controller root is not usable: %w", err)
	}
	identity := a.state.Identity
	if identity == nil {
		return nil, errors.New("nodeagent: the node has no identity; re-enrollment is required")
	}
	if !identity.HasPrivateKey() {
		return nil, errors.New("nodeagent: the stored identity has no private key; re-enrollment is required")
	}
	return pki.NewTLSServerConfig(pki.TLSServerOptions{
		CertPEM:  identity.CertPEM(),
		KeyPEM:   identity.KeyPEM(),
		Verifier: verifier,
	})
}

// Serve runs the listener until ctx is canceled.
//
// ln is a PLAIN listener. The TLS handshake is applied here because
// http.Server.Serve IGNORES its TLSConfig field — only ServeTLS consults it — so
// setting TLSConfig and calling Serve would serve PLAINTEXT and the verifier that
// pins the controller would never run. The agent's tests did not catch this
// because they handed Serve a listener that tls.Listen had already wrapped, which
// is exactly the arrangement production does not have.
func (a *Agent) Serve(ctx context.Context, ln net.Listener) error {
	tlsConfig, err := a.TLSConfig()
	if err != nil {
		return err
	}
	tlsListener := tls.NewListener(ln, tlsConfig)

	server := &http.Server{
		Handler:           a.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// No write timeout: an operation's own deadline governs it, and a
		// blanket write timeout would cut a legitimate long restart at an
		// arbitrary point while still reporting success to nobody.
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

// ListenAndServe binds the configured address and serves.
//
// The listener is created here rather than passed in so the address the agent
// reported at enrollment is the address it actually binds; a mismatch between the
// two is why a controller cannot reach a node that looks enrolled.
func (a *Agent) ListenAndServe(ctx context.Context, address string) error {
	if address == "" {
		return errors.New("nodeagent: a listen address is required")
	}
	// A listener bootstrap has no request context in scope; ListenConfig keeps
	// this the one place that says so explicitly rather than the one that trips
	// a linter for it.
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", address)
	if err != nil {
		return fmt.Errorf("nodeagent: listen on %s: %w", address, err)
	}
	a.logger.Info("node agent listening", "address", address, "server_id", a.state.ServerID)
	return a.Serve(ctx, ln)
}

// Handler is the agent's HTTP surface. Exposed so tests can drive it over a real
// TLS listener without the address bookkeeping.
func (a *Agent) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+OperationPath, a.handleOperation)
	return mux
}

// handleOperation decodes one request envelope, dispatches it, and replies.
//
// The HTTP status carries only transport-level facts. An operation that ran and
// failed is still a 200 with ok=false: the envelope is the answer, and encoding
// operation failures as HTTP errors would mean the controller reads the status
// line to decide whether the panel is broken or the unit is down.
func (a *Agent) handleOperation(w http.ResponseWriter, r *http.Request) {
	// Reject a peer whose protocol version is not ours before reading a body we
	// may not understand.
	if raw := r.Header.Get(nodewire.VersionHeader); raw != "" {
		if v, err := strconv.Atoi(raw); err != nil || v != nodewire.ProtocolVersion {
			a.writeRefusal(w, "", "", nodewire.CodeProtocolMismatch,
				"this agent speaks a different protocol version", false, http.StatusBadRequest)
			return
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		// A body too large is a 413 rather than a 400 so a controller that
		// legitimately hit a limit can tell the difference and not retry.
		var maxErr *http.MaxBytesError
		status := http.StatusBadRequest
		if errors.As(err, &maxErr) {
			status = http.StatusRequestEntityTooLarge
		}
		a.writeRefusal(w, "", "", nodewire.CodeInvalidInput,
			"the request body could not be read", false, status)
		return
	}

	// THE CLOSED REGISTRY. DecodeRequest refuses an operation with no descriptor
	// and one this build does not serve, before the payload is decoded and before
	// anything is started.
	req, desc, err := nodewire.DecodeRequest(body, a.served)
	if err != nil {
		code := nodewire.CodeInvalidInput
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, nodewire.ErrUnknownOperation):
			code = nodewire.CodeUnsupportedOperation
		case errors.Is(err, nodewire.ErrProtocolMismatch):
			code = nodewire.CodeProtocolMismatch
		case errors.Is(err, nodewire.ErrScopeViolation):
			code = nodewire.CodeScopeViolation
		}
		a.logger.Warn("operation refused",
			"reason", err.Error(), "request_id", r.Header.Get("X-Request-Id"))
		a.writeRefusal(w, "", "", code, err.Error(), false, status)
		return
	}

	// Bound concurrency. Refusing with a retryable answer is better than either
	// queueing without limit or forking without limit.
	select {
	case a.sem <- struct{}{}:
		defer func() { <-a.sem }()
	default:
		w.Header().Set("Retry-After", "5")
		a.writeRefusal(w, req.Operation, req.RequestID, nodewire.CodeDeadlineExceeded,
			"this agent is already running the maximum number of concurrent operations", true,
			http.StatusTooManyRequests)
		return
	}

	opCtx, cancel := a.operationContext(r.Context(), req, desc)
	defer cancel()

	// An expired deadline is refused here rather than delegated to the executor.
	// operationContext maps it to an already-canceled context, but an executor
	// that reads /proc without consulting ctx would still run the work — nobody
	// is waiting for the answer, and the controller would see success for a
	// request it had already given up on.
	if err := opCtx.Err(); err != nil {
		a.logger.Warn("refusing an operation whose deadline has already passed",
			"operation", req.Operation, "request_id", req.RequestID)
		a.writeRefusal(w, req.Operation, req.RequestID, nodewire.CodeDeadlineExceeded,
			"the deadline for this operation had already passed", false, http.StatusGatewayTimeout)
		return
	}

	result, opErr := a.dispatch(opCtx, req)
	a.writeResponse(w, req, result, opErr)
}

// operationContext derives the per-operation deadline from the request.
//
// The request carries an ABSOLUTE instant rather than a duration, because a
// duration means different things to two machines whose clocks differ. It is
// capped by the descriptor's own timeout: a controller that asks for a ten-hour
// restart must not get one, and the descriptor is the reviewed statement of how
// long this operation may take.
func (a *Agent) operationContext(parent context.Context, req nodewire.Request, desc nodewire.Descriptor) (context.Context, context.CancelFunc) {
	timeout := desc.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	remaining := req.Deadline.Sub(a.now())
	if remaining > timeout {
		// The controller asked for longer than this operation may run. The
		// descriptor is the reviewed statement of that bound, so it wins.
		remaining = timeout
	}
	if remaining <= 0 {
		// The deadline has already passed. WithTimeout(parent, 0) produces an
		// already-canceled context, so the executor fails immediately with a
		// deadline error rather than doing work nobody is waiting for.
		remaining = 0
	}
	return context.WithTimeout(parent, remaining)
}

// dispatch runs one operation.
//
// This is a switch on a closed enum rather than a map of function values: a
// reviewer can see every operation the agent will perform by reading this
// function, and there is no registration point where a new one could appear.
func (a *Agent) dispatch(ctx context.Context, req nodewire.Request) (json.RawMessage, error) {
	switch req.Operation {
	case nodewire.OpNodeCapabilities:
		result, err := a.exec.Capabilities()
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpNodeHeartbeat:
		result, err := a.exec.Heartbeat(ctx)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpNodeMetrics:
		in, err := nodewire.DecodeInput[nodewire.NodeMetricsInput](req)
		if err != nil {
			return nil, err
		}
		result, err := a.exec.HostMetrics(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpServiceInspect:
		in, err := nodewire.DecodeInput[nodewire.ServiceInspectInput](req)
		if err != nil {
			return nil, err
		}
		if err = nodewire.ValidateInspectInput(in, req.Target); err != nil {
			return nil, err
		}
		result, err := a.exec.InspectService(ctx, in.Unit)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpServiceRestart:
		in, err := nodewire.DecodeInput[nodewire.ServiceRestartInput](req)
		if err != nil {
			return nil, err
		}
		if err = nodewire.ValidateRestartInput(in, req.Target); err != nil {
			return nil, err
		}
		result, err := a.exec.RestartService(ctx, in.Unit)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpWebConfigValidate:
		in, err := nodewire.DecodeInput[nodewire.WebConfigValidateInput](req)
		if err != nil {
			return nil, err
		}
		// Validate is called by the executor as well. Doing it here too is not
		// belt-and-braces for its own sake: DecodeInput is generic and cannot
		// know a payload's rules, and the dispatch switch is where a reviewer
		// looks to see what an operation does before it runs.
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{
				Code:    nodewire.CodeInvalidInput,
				Message: err.Error(),
			}
		}
		result, err := a.exec.ValidateWebConfig(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpSiteLogsTail:
		in, err := nodewire.DecodeInput[nodewire.SiteLogsTailInput](req)
		if err != nil {
			return nil, err
		}
		// Validate early so a malformed slug is refused with CodeInvalidInput
		// before the executor opens a file path derived from it.
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{
				Code:    nodewire.CodeInvalidInput,
				Message: err.Error(),
			}
		}
		result, err := a.exec.SiteLogs(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpWebConfigApply:
		in, err := nodewire.DecodeInput[nodewire.WebConfigApplyInput](req)
		if err != nil {
			return nil, err
		}
		// Validate early: the executor also validates, but the dispatch switch
		// is where a reviewer sees what an operation does before it runs.
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{
				Code:    nodewire.CodeInvalidInput,
				Message: err.Error(),
			}
		}
		result, err := a.exec.ApplyWebConfig(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpAppDeploy:
		in, err := nodewire.DecodeInput[nodewire.AppDeployInput](req)
		if err != nil {
			return nil, err
		}
		// Validate early so a malformed slug or program name is refused with
		// CodeInvalidInput before any directory is created or process spawned.
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{
				Code:    nodewire.CodeInvalidInput,
				Message: err.Error(),
			}
		}
		result, err := a.exec.DeployApp(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpDatabaseManage:
		in, err := nodewire.DecodeInput[nodewire.DatabaseManageInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.ManageDatabase(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpDatabaseDump:
		in, err := nodewire.DecodeInput[nodewire.DatabaseDumpInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.DumpDatabase(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpDatabaseRestore:
		in, err := nodewire.DecodeInput[nodewire.DatabaseRestoreInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.RestoreDatabase(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpDatabaseMetrics:
		in, err := nodewire.DecodeInput[nodewire.DatabaseMetricsInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.GetDatabaseMetrics(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpDatabaseUpgrade:
		in, err := nodewire.DecodeInput[nodewire.DatabaseUpgradeInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.UpgradeDatabase(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpFileArchive:
		in, err := nodewire.DecodeInput[nodewire.FileArchiveInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.ArchiveFiles(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpFileRestore:
		in, err := nodewire.DecodeInput[nodewire.FileRestoreInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.RestoreFiles(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpContainerList:
		in, err := nodewire.DecodeInput[nodewire.ContainerListInput](req)
		if err != nil {
			return nil, err
		}
		result, err := a.exec.ListContainers(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpContainerInspect:
		in, err := nodewire.DecodeInput[nodewire.ContainerInspectInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.InspectContainer(ctx, in.Name)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpContainerLogs:
		in, err := nodewire.DecodeInput[nodewire.ContainerLogsInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.ContainerLogs(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpContainerLifecycle:
		in, err := nodewire.DecodeInput[nodewire.ContainerLifecycleInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.LifecycleContainer(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpNetFirewallList:
		in, err := nodewire.DecodeInput[nodewire.NetFirewallListInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.NetFirewallList(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpNetPortInventory:
		in, err := nodewire.DecodeInput[nodewire.NetPortInventoryInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.NetPortInventory(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpNetDiag:
		in, err := nodewire.DecodeInput[nodewire.NetDiagInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.NetDiag(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpSecHardeningScan:
		in, err := nodewire.DecodeInput[nodewire.SecHardeningScanInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.SecHardeningScan(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpSecSSHPosture:
		in, err := nodewire.DecodeInput[nodewire.SecSSHPostureInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.SecSSHPosture(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpSecBanList:
		in, err := nodewire.DecodeInput[nodewire.SecBanListInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.SecBanList(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpSecBanAdd:
		in, err := nodewire.DecodeInput[nodewire.SecBanAddInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.SecBanAdd(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpSecBanRemove:
		in, err := nodewire.DecodeInput[nodewire.SecBanRemoveInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.SecBanRemove(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpSecWAFApply:
		in, err := nodewire.DecodeInput[nodewire.SecWAFApplyInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.SecWAFApply(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpUpdateNodeAgent:
		in, err := nodewire.DecodeInput[nodewire.UpdateNodeAgentInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.UpdateNodeAgent(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpSiteNodeJSManage:
		in, err := nodewire.DecodeInput[nodewire.SiteNodeJSManageInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.ManageSiteNodeJS(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	case nodewire.OpSiteNodeJSStatus:
		in, err := nodewire.DecodeInput[nodewire.SiteNodeJSStatusInput](req)
		if err != nil {
			return nil, err
		}
		if err = in.Validate(); err != nil {
			return nil, &nodewire.Error{Code: nodewire.CodeInvalidInput, Message: err.Error()}
		}
		result, err := a.exec.StatusSiteNodeJS(ctx, in)
		if err != nil {
			return nil, err
		}
		return nodewire.EncodeResult(result)

	default:
		// Unreachable: DecodeRequest already refused anything not in served, and
		// served only ever contains operations this switch handles. Reaching
		// here means the two lists drifted, which must be loud rather than
		// silent. The check that they have not is TestDispatchHandlesEveryServed
		// Operation, which compares the switch's cases against the served set.
		return nil, &nodewire.Error{
			Code:    nodewire.CodeUnsupportedOperation,
			Message: fmt.Sprintf("operation %q reached dispatch without being served", req.Operation),
		}
	}
}

// writeResponse emits the reply envelope.
//
// An executor error that is already a nodewire.Error is passed through unchanged,
// so the codes the controller branches on survive. Anything else becomes an
// execution failure with a message that does not leak host detail: the full cause
// goes to the agent's own log, where the operator can read it, rather than onto
// the wire.
func (a *Agent) writeResponse(w http.ResponseWriter, req nodewire.Request, result json.RawMessage, opErr error) {
	resp := nodewire.Response{
		Operation: req.Operation,
		RequestID: req.RequestID,
		OK:        opErr == nil,
		Result:    result,
	}
	if opErr != nil {
		resp.Error = toWireError(opErr)
		a.logger.Warn("operation failed",
			"operation", req.Operation, "request_id", req.RequestID,
			"code", resp.Error.Code, "error", opErr)
	}
	a.encodeAndWrite(w, resp, http.StatusOK)
}

// writeRefusal emits a refusal for a request that could not be dispatched.
func (a *Agent) writeRefusal(w http.ResponseWriter,
	op nodewire.Operation, requestID, code, message string, retryable bool, status int) {
	resp := nodewire.Response{
		Operation: op,
		RequestID: requestID,
		Error:     nodewire.NewError(code, message, retryable, nil),
	}
	a.encodeAndWrite(w, resp, status)
}

// toWireError coerces an executor error onto the wire vocabulary.
func toWireError(err error) *nodewire.Error {
	var wireErr *nodewire.Error
	if errors.As(err, &wireErr) {
		return wireErr
	}
	if errors.Is(err, ErrOutputLimit) {
		return &nodewire.Error{
			Code:    nodewire.CodeExecutionFailed,
			Message: "the operation produced more output than the agent will read",
		}
	}
	// Deliberately generic. The cause may contain a host path or a command line,
	// and the wire is the wrong place for either; it is in the agent's log.
	return &nodewire.Error{
		Code:      nodewire.CodeExecutionFailed,
		Message:   "the operation could not be completed",
		Retryable: false,
	}
}

func (a *Agent) encodeAndWrite(w http.ResponseWriter, resp nodewire.Response, status int) {
	body, err := nodewire.EncodeResponse(resp, a.now())
	if err != nil {
		// Nothing useful can be said over a channel whose envelope will not
		// encode; the log is the only honest record.
		a.logger.Error("could not encode response envelope", "error", err)
		http.Error(w, "could not encode response", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set(nodewire.VersionHeader, strconv.Itoa(nodewire.ProtocolVersion))
	w.WriteHeader(status)
	_, _ = w.Write(body)
}
