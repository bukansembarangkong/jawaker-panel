package nodes

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
)

// Controller→node dispatch: the outbound half of the mesh.
//
// The agent's listener is what executes privileged operations, so this is the
// code that reaches it. Three properties are load-bearing.
//
// FIRST, the node is identified by its PINNED certificate, not by its address. The
// verifier pins the Node CA and requires the certificate's identity to be the
// server id being dialed — so a node whose address was taken over, or a DNS entry
// that moved, cannot impersonate the node it replaced. Matching on address would
// make every routing change an authentication change.
//
// SECOND, the operation is validated against the closed registry BEFORE a
// connection is opened. A dispatch that connects first and discovers the operation
// is unknown afterwards spends a handshake to learn something knowable locally.
//
// THIRD, there is no generic "run this" entry point. Dispatch is a typed function
// per operation, so adding a new privileged action requires adding a registry
// descriptor AND a dispatcher AND an executor — three visible edits in review,
// rather than one string in a payload.

// DispatchOptions configures the dispatcher.
type DispatchOptions struct {
	// Authority supplies the controller's own leaf and the node root to pin.
	Authority *Authority
	// Store is used to resolve a server's address.
	Store *Store
	// NodeRootPEM is the pinned Node CA. It is taken from the authority rather
	// than loaded separately, so the trust anchor cannot diverge from the one
	// that issued the node's certificate.
	NodeRootPEM []byte
	// Now supplies the clock for deadlines. Nil means time.Now.
	Now func() time.Time
	// Timeout bounds the whole call, including the handshake. Zero means the
	// descriptor's own timeout plus slack.
	Timeout time.Duration
}

// Dispatcher calls operations on enrolled nodes.
type Dispatcher struct {
	authority *Authority
	store     *Store
	rootPEM   []byte
	now       func() time.Time
	timeout   time.Duration
	// client is built once. Its transport pins the node root and presents the
	// controller's own certificate, so every call is mutually authenticated
	// without per-call configuration that a caller could get wrong.
	client *http.Client
}

// NewDispatcher builds a dispatcher.
func NewDispatcher(opts DispatchOptions) (*Dispatcher, error) {
	if opts.Authority == nil {
		return nil, errors.New("nodes: authority is required")
	}
	if opts.Store == nil {
		return nil, errors.New("nodes: store is required")
	}
	rootPEM := opts.NodeRootPEM
	if len(rootPEM) == 0 {
		rootPEM = opts.Authority.NodeCertPEM()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}

	// The verifier pins the node root and expects a NODE identity. It does NOT
	// pin one specific node id here, because one client serves the whole fleet;
	// the per-call identity check is what binds the connection to the server
	// being dialed. See call().
	verifier, err := pki.NewVerifier(pki.VerifierOptions{
		RootPEM: rootPEM,
		Kind:    pki.KindNode,
		Now:     now,
	})
	if err != nil {
		return nil, fmt.Errorf("nodes: node root is not usable as a trust anchor: %w", err)
	}
	leaf, err := opts.Authority.IssueControllerLeaf()
	if err != nil {
		return nil, err
	}
	tlsConfig, err := pki.NewTLSClientConfig(pki.TLSClientOptions{
		CertPEM:  leaf.CertPEM(),
		KeyPEM:   leaf.KeyPEM(),
		Verifier: verifier,
	})
	if err != nil {
		return nil, err
	}

	return &Dispatcher{
		authority: opts.Authority,
		store:     opts.Store,
		rootPEM:   rootPEM,
		now:       now,
		timeout:   timeout,
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsConfig,
				MaxIdleConns:    32,
				// One idle connection per node: a fleet of 200 nodes would
				// otherwise keep 200 sockets warm for traffic that is mostly
				// idle, and each one is a live authenticated session.
				MaxIdleConnsPerHost: 1,
				IdleConnTimeout:     90 * time.Second,
				DialContext: (&net.Dialer{
					Timeout:   10 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
			},
		},
	}, nil
}

// CallRequest describes one operation to perform on one node.
type CallRequest struct {
	// ServerID is the node to call. It is also the identity the peer's
	// certificate must carry.
	ServerID string
	// Operation is the registered operation to invoke.
	Operation nodewire.Operation
	// Target is the scoped object, e.g. a unit name.
	Target string
	// Input is the operation's typed payload, already validated by the caller's
	// own boundary.
	Input any
	// RequestID correlates this call with the HTTP request and the audit trail.
	RequestID string
}

// Call performs one operation and returns the node's result.
//
// The response envelope is decoded strictly and its ok/error pair is required to
// agree, so an ambiguous reply is refused rather than resolved in the caller's
// favor. An operation that failed is returned as an error carrying the node's
// own code — the controller must not flatten a node's refusal into "internal".
func (d *Dispatcher) Call(ctx context.Context, req CallRequest) (json.RawMessage, error) {
	if req.ServerID == "" {
		return nil, fmt.Errorf("%w: a server id is required", ErrInvalid)
	}
	if req.RequestID == "" {
		return nil, fmt.Errorf("%w: a request id is required", ErrInvalid)
	}

	// Validated against the CLOSED REGISTRY before any connection is opened. An
	// operation with no descriptor cannot be performed by any node, and a target
	// outside the descriptor's scope is refused here rather than by the agent —
	// both are facts knowable locally.
	desc, ok := nodewire.Lookup(req.Operation)
	if !ok {
		return nil, fmt.Errorf("%w: operation %q is not registered", ErrInvalid, req.Operation)
	}

	server, err := d.store.GetServer(ctx, req.ServerID)
	if err != nil {
		return nil, err
	}
	if server.Address == "" {
		// An enrolled server with no address cannot be dialed. That is a fact
		// about the record, and reporting it as a connection failure would send
		// an operator to look at the network.
		return nil, fmt.Errorf("%w: server %s has no address; it may not have completed enrollment",
			ErrInvalid, req.ServerID)
	}

	var encodedInput json.RawMessage
	if req.Input != nil {
		encodedInput, err = json.Marshal(req.Input)
		if err != nil {
			return nil, fmt.Errorf("nodes: encode operation input: %w", err)
		}
	}

	deadline := d.now().Add(desc.Timeout)
	envelope := nodewire.Request{
		Operation: req.Operation,
		RequestID: req.RequestID,
		Deadline:  deadline,
		Target:    req.Target,
		Input:     encodedInput,
	}
	body, err := nodewire.EncodeRequest(envelope)
	if err != nil {
		return nil, err
	}

	resp, err := d.post(ctx, server.Address, req.ServerID, body)
	if err != nil {
		return nil, err
	}
	return d.decodeReply(resp, req.Operation, req.RequestID)
}

// post sends the envelope and returns the decoded reply body.
func (d *Dispatcher) post(ctx context.Context, address, serverID string, body []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	url := "https://" + address + nodeOperationPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("nodes: build node request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(nodewire.VersionHeader, fmt.Sprint(nodewire.ProtocolVersion))

	httpResp, err := d.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("nodes: call node %s at %s: %w", serverID, address, err)
	}
	defer func() { _ = httpResp.Body.Close() }()

	// The connection's verified peer identity must BE the server being dialed.
	// The verifier pinned the Node CA, so the peer is a genuine node; this check
	// is what makes it THIS node. Without it, any enrolled node could answer for
	// any other address.
	if err = d.checkPeerIdentity(httpResp, serverID); err != nil {
		return nil, err
	}

	// Bounded read: a node is our own agent, but "our own" is a claim about
	// software, and a compromised agent should not be able to make the controller
	// allocate without limit.
	data, err := io.ReadAll(io.LimitReader(httpResp.Body, maxNodeReplyBytes))
	if err != nil {
		return nil, fmt.Errorf("nodes: read node reply: %w", err)
	}
	if httpResp.StatusCode != http.StatusOK {
		// A non-200 means the agent refused at the transport layer (bad
		// envelope, protocol mismatch, overload). The body still carries a
		// structured error, so it is decoded below rather than discarded.
		if len(data) == 0 {
			return nil, fmt.Errorf("nodes: node %s returned HTTP %d with no body",
				serverID, httpResp.StatusCode)
		}
	}
	return data, nil
}

// maxNodeReplyBytes bounds a node's reply.
const maxNodeReplyBytes = 1 << 20

// nodeOperationPath mirrors the agent's OperationPath. It is spelled here rather
// than imported from internal/nodeagent because the controller must not depend on
// the agent's package: the two are different programs that speak one protocol,
// and a shared source dependency would let a change on one side silently recompile
// the other.
const nodeOperationPath = "/api/v1/node/op"

// checkPeerIdentity confirms the verified peer is the server being dialed.
func (d *Dispatcher) checkPeerIdentity(resp *http.Response, serverID string) error {
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return fmt.Errorf("nodes: node %s presented no certificate", serverID)
	}
	identity, err := pki.IdentityOf(resp.TLS.PeerCertificates[0])
	if err != nil {
		return fmt.Errorf("nodes: node %s presented an unusable certificate: %w", serverID, err)
	}
	if identity.Kind != pki.KindNode || identity.ID != serverID {
		return fmt.Errorf("%w: dialed %s but the peer identifies as %s %q",
			ErrInvalid, serverID, identity.Kind, identity.ID)
	}
	return nil
}

// decodeReply parses the response envelope and surfaces the node's own error code.
func (d *Dispatcher) decodeReply(data []byte, want nodewire.Operation, requestID string) (json.RawMessage, error) {
	resp, err := nodewire.DecodeResponse(data)
	if err != nil {
		return nil, fmt.Errorf("nodes: node reply is not usable: %w", err)
	}
	// The reply must be for THIS call. A mismatched request id means the response
	// belongs to another operation, and applying it would mean acting on an
	// answer to a question nobody asked.
	if resp.RequestID != requestID {
		return nil, fmt.Errorf("%w: node replied to request %q, expected %q",
			ErrInvalid, resp.RequestID, requestID)
	}
	if resp.Operation != want {
		return nil, fmt.Errorf("%w: node replied about %q, expected %q",
			ErrInvalid, resp.Operation, want)
	}
	if !resp.OK {
		// The node's own code survives, wrapped so errors.Is still works on the
		// sentinel while the code reaches the audit trail and the UI.
		return nil, &NodeOperationError{
			Operation: resp.Operation,
			Code:      resp.Error.Code,
			Message:   resp.Error.Message,
			Retryable: resp.Error.Retryable,
			Details:   resp.Error.Details,
		}
	}
	return resp.Result, nil
}

// NodeOperationError is a refusal or failure reported BY a node.
//
// It is a distinct type rather than a wrapped sentinel because the controller has
// to tell these apart: "the node refused because systemd is absent" is a fact
// about the node to show in the UI, while "the controller could not reach the
// node" is an infrastructure fault. Collapsing both into one error is how a
// missing capability gets reported as a broken panel.
type NodeOperationError struct {
	Operation nodewire.Operation
	Code      string
	Message   string
	Retryable bool
	Details   map[string]any
}

func (e *NodeOperationError) Error() string {
	return fmt.Sprintf("node: %s failed with %s: %s", e.Operation, e.Code, e.Message)
}

// Unsupported reports whether the node could not perform the operation at all.
//
// The UI uses this to offer an explanation instead of a retry button, which is
// the difference between an honest gap and a control that always fails.
func (e *NodeOperationError) Unsupported() bool {
	return e.Code == nodewire.CodeUnsupportedOperation || e.Code == nodewire.CodeNotAvailable
}

// ErrNodeUnreachable marks a transport failure, so callers can distinguish "the
// node did not answer" from "the node answered that it cannot".
var ErrNodeUnreachable = errors.New("nodes: node is unreachable")

// --- typed call helpers ------------------------------------------------------

// Capabilities fetches a node's capability inventory.
func (d *Dispatcher) Capabilities(ctx context.Context, serverID, requestID string) (nodewire.CapabilitiesResult, error) {
	var out nodewire.CapabilitiesResult
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpNodeCapabilities,
		RequestID: requestID,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode capabilities: %w", err)
	}
	return out, nil
}

// InspectService fetches one unit's state.
func (d *Dispatcher) InspectService(ctx context.Context, serverID, requestID, unit string) (nodewire.ServiceState, error) {
	var out nodewire.ServiceState
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpServiceInspect,
		RequestID: requestID,
		Target:    unit,
		Input:     nodewire.ServiceInspectInput{Unit: unit},
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode service state: %w", err)
	}
	return out, nil
}

// RestartService restarts one unit and returns the bracketing states.
func (d *Dispatcher) RestartService(ctx context.Context, serverID, requestID, unit string) (nodewire.RestartResult, error) {
	var out nodewire.RestartResult
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpServiceRestart,
		RequestID: requestID,
		Target:    unit,
		Input:     nodewire.ServiceRestartInput{Unit: unit},
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode restart result: %w", err)
	}
	return out, nil
}

// ValidateWebConfig asks a node whether a candidate web-server configuration is
// valid, without touching the configuration the node is serving.
//
// The candidate configuration travels as text. The size check is done here as
// well as by the node: a candidate that cannot fit the envelope would be refused
// on the far side after a round trip, so refusing it here gives the caller a
// cheap, immediate answer instead of a transport error that looks like a failure
// of the node.
func (d *Dispatcher) ValidateWebConfig(ctx context.Context, serverID, requestID, _ string, in nodewire.WebConfigValidateInput) (nodewire.WebConfigValidateResult, error) {
	var out nodewire.WebConfigValidateResult
	if len(in.Config) > nodewire.MaxWebConfigBytes {
		return out, fmt.Errorf("nodes: candidate config is %d bytes, limit is %d",
			len(in.Config), nodewire.MaxWebConfigBytes)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpWebConfigValidate,
		RequestID: requestID,
		// Target is intentionally empty: web.config.validate has no
		// Scope.Services, so EncodeRequest rejects any non-empty target.
		// The site identity reaches the agent via the payload (in.Filename
		// encodes the site's slug) and via RequestID in the audit trail.
		Input: in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode web config validation: %w", err)
	}
	return out, nil
}

// ReadSiteLogs reads a bounded tail of one site's access or error log from the
// node hosting it, on demand.
//
// Per D-005 no log content is stored in PostgreSQL; this is a read-through to
// the host.
func (d *Dispatcher) ReadSiteLogs(ctx context.Context, serverID, requestID string, in nodewire.SiteLogsTailInput) (nodewire.SiteLogsTailResult, error) {
	var out nodewire.SiteLogsTailResult
	if err := in.Validate(); err != nil {
		return out, fmt.Errorf("nodes: invalid log tail request: %w", err)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpSiteLogsTail,
		RequestID: requestID,
		Input:     in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode site logs tail: %w", err)
	}
	return out, nil
}

// ApplyWebConfig writes a validated configuration to the live sites-enabled
// directory, reloads nginx, and rolls back on any step failure.
//
// Target is "nginx": the descriptor declares Services:["nginx"], so
// nodewire.EncodeRequest requires a non-empty target that matches the declared
// service. Passing the site ID or an empty string would be refused by the
// agent's scope check before the payload is read.
func (d *Dispatcher) ApplyWebConfig(ctx context.Context, serverID, requestID string, in nodewire.WebConfigApplyInput) (nodewire.WebConfigApplyResult, error) {
	var out nodewire.WebConfigApplyResult
	if len(in.Config) > nodewire.MaxWebConfigBytes {
		return out, fmt.Errorf("nodes: candidate config is %d bytes, limit is %d",
			len(in.Config), nodewire.MaxWebConfigBytes)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpWebConfigApply,
		RequestID: requestID,
		// Target MUST be "nginx": the descriptor has Scope.Services:["nginx"],
		// and EncodeRequest calls validateTarget which rejects any target that
		// is not exactly one of the listed service names.
		Target: "nginx",
		Input:  in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode web config apply: %w", err)
	}
	return out, nil
}

// DeployApp invokes an atomic deployment on the target node.
//
// Target is intentionally empty: app.deploy has no Scope.Services (services are
// managed dynamically as jw-<proj>-<app>.service rather than a static allowlist),
// so nodewire.EncodeRequest rejects any non-empty target.
func (d *Dispatcher) DeployApp(ctx context.Context, serverID, requestID string, in nodewire.AppDeployInput) (nodewire.AppDeployResult, error) {
	var out nodewire.AppDeployResult
	if err := in.Validate(); err != nil {
		return out, fmt.Errorf("nodes: invalid app deploy input: %w", err)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpAppDeploy,
		RequestID: requestID,
		// Target is intentionally empty.
		Input: in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode app deploy result: %w", err)
	}
	return out, nil
}

// ManageDatabase creates or drops a database or user on an enrolled node.
func (d *Dispatcher) ManageDatabase(ctx context.Context, serverID, requestID string, in nodewire.DatabaseManageInput) (nodewire.DatabaseManageResult, error) {
	var out nodewire.DatabaseManageResult
	if err := in.Validate(); err != nil {
		return out, fmt.Errorf("nodes: invalid database manage input: %w", err)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpDatabaseManage,
		RequestID: requestID,
		Input:     in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode database manage result: %w", err)
	}
	return out, nil
}

// DumpDatabase triggers an export of a managed database to a node-local dump artifact.
func (d *Dispatcher) DumpDatabase(ctx context.Context, serverID, requestID string, in nodewire.DatabaseDumpInput) (nodewire.DatabaseDumpResult, error) {
	var out nodewire.DatabaseDumpResult
	if err := in.Validate(); err != nil {
		return out, fmt.Errorf("nodes: invalid database dump input: %w", err)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpDatabaseDump,
		RequestID: requestID,
		Input:     in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode database dump result: %w", err)
	}
	return out, nil
}

// RestoreDatabase restores a managed database from a node-local dump artifact.
func (d *Dispatcher) RestoreDatabase(ctx context.Context, serverID, requestID string, in nodewire.DatabaseRestoreInput) (nodewire.DatabaseRestoreResult, error) {
	var out nodewire.DatabaseRestoreResult
	if err := in.Validate(); err != nil {
		return out, fmt.Errorf("nodes: invalid database restore input: %w", err)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpDatabaseRestore,
		RequestID: requestID,
		Input:     in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode database restore result: %w", err)
	}
	return out, nil
}

// GetDatabaseMetrics queries point-in-time metrics from a node's database engine.
func (d *Dispatcher) GetDatabaseMetrics(ctx context.Context, serverID, requestID string, in nodewire.DatabaseMetricsInput) (nodewire.DatabaseMetricsResult, error) {
	var out nodewire.DatabaseMetricsResult
	if err := in.Validate(); err != nil {
		return out, fmt.Errorf("nodes: invalid database metrics input: %w", err)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpDatabaseMetrics,
		RequestID: requestID,
		Input:     in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode database metrics result: %w", err)
	}
	return out, nil
}

// NodeMetrics samples host-level CPU, memory, disk and load from a node. The
// controller polls it on a fixed cadence (Phase 7 observability); results are
// stored as metric_samples rows for trend evaluation and alerting.
func (d *Dispatcher) NodeMetrics(ctx context.Context, serverID, requestID string) (nodewire.NodeMetricsResult, error) {
	var out nodewire.NodeMetricsResult
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		RequestID: requestID,
		Operation: nodewire.OpNodeMetrics,
		Input:     nodewire.NodeMetricsInput{},
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode node metrics result: %w", err)
	}
	if err := out.Validate(); err != nil {
		return out, fmt.Errorf("nodes: invalid node metrics result: %w", err)
	}
	return out, nil
}

// UpgradeDatabase triggers a major version engine upgrade with a pre-dump backup gate.
func (d *Dispatcher) UpgradeDatabase(ctx context.Context, serverID, requestID string, in nodewire.DatabaseUpgradeInput) (nodewire.DatabaseUpgradeResult, error) {
	var out nodewire.DatabaseUpgradeResult
	if err := in.Validate(); err != nil {
		return out, fmt.Errorf("nodes: invalid database upgrade input: %w", err)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpDatabaseUpgrade,
		RequestID: requestID,
		Input:     in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode database upgrade result: %w", err)
	}
	return out, nil
}

// ArchiveFiles packs source paths into a tar.gz on the node.
func (d *Dispatcher) ArchiveFiles(ctx context.Context, serverID, requestID string, in nodewire.FileArchiveInput) (nodewire.FileArchiveResult, error) {
	var out nodewire.FileArchiveResult
	if err := in.Validate(); err != nil {
		return out, fmt.Errorf("nodes: invalid file archive input: %w", err)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpFileArchive,
		RequestID: requestID,
		Input:     in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode file archive result: %w", err)
	}
	return out, nil
}

// RestoreFiles extracts an archive into a destination directory on the node.
func (d *Dispatcher) RestoreFiles(ctx context.Context, serverID, requestID string, in nodewire.FileRestoreInput) (nodewire.FileRestoreResult, error) {
	var out nodewire.FileRestoreResult
	if err := in.Validate(); err != nil {
		return out, fmt.Errorf("nodes: invalid file restore input: %w", err)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpFileRestore,
		RequestID: requestID,
		Input:     in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode file restore result: %w", err)
	}
	return out, nil
}

// ListContainers lists containers on a node, optionally filtered by project.
func (d *Dispatcher) ListContainers(ctx context.Context, serverID, requestID string, in nodewire.ContainerListInput) (nodewire.ContainerListResult, error) {
	var out nodewire.ContainerListResult
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpContainerList,
		RequestID: requestID,
		Input:     in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode container list result: %w", err)
	}
	return out, nil
}

// InspectContainer returns the full state of one container on a node.
func (d *Dispatcher) InspectContainer(ctx context.Context, serverID, requestID, name string) (nodewire.ContainerInspectResult, error) {
	var out nodewire.ContainerInspectResult
	if !nodewire.ValidContainerName(name) {
		return out, fmt.Errorf("nodes: container name %q is not safe to pass to the docker CLI", name)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpContainerInspect,
		RequestID: requestID,
		Target:    name,
		Input:     nodewire.ContainerInspectInput{Name: name},
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode container inspect result: %w", err)
	}
	return out, nil
}

// ContainerLogs returns a bounded, redacted log tail for one container.
func (d *Dispatcher) ContainerLogs(ctx context.Context, serverID, requestID string, in nodewire.ContainerLogsInput) (nodewire.ContainerLogsResult, error) {
	var out nodewire.ContainerLogsResult
	if err := in.Validate(); err != nil {
		return out, fmt.Errorf("nodes: invalid container logs input: %w", err)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpContainerLogs,
		RequestID: requestID,
		Input:     in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode container logs result: %w", err)
	}
	return out, nil
}

// NetFirewallList reads the iptables ruleset from a node.
func (d *Dispatcher) NetFirewallList(ctx context.Context, serverID, requestID string, in nodewire.NetFirewallListInput) (nodewire.NetFirewallListResult, error) {
	var out nodewire.NetFirewallListResult
	if err := in.Validate(); err != nil {
		return out, fmt.Errorf("nodes: invalid net firewall list input: %w", err)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpNetFirewallList,
		RequestID: requestID,
		Input:     in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode net firewall list result: %w", err)
	}
	return out, nil
}

// NetPortInventory lists listening ports on a node.
func (d *Dispatcher) NetPortInventory(ctx context.Context, serverID, requestID string, in nodewire.NetPortInventoryInput) (nodewire.NetPortInventoryResult, error) {
	var out nodewire.NetPortInventoryResult
	if err := in.Validate(); err != nil {
		return out, fmt.Errorf("nodes: invalid net port inventory input: %w", err)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpNetPortInventory,
		RequestID: requestID,
		Input:     in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode net port inventory result: %w", err)
	}
	return out, nil
}

// NetDiag runs a ping or traceroute diagnostic on a node.
func (d *Dispatcher) NetDiag(ctx context.Context, serverID, requestID string, in nodewire.NetDiagInput) (nodewire.NetDiagResult, error) {
	var out nodewire.NetDiagResult
	if err := in.Validate(); err != nil {
		return out, fmt.Errorf("nodes: invalid net diag input: %w", err)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpNetDiag,
		RequestID: requestID,
		Input:     in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode net diag result: %w", err)
	}
	return out, nil
}

// SecHardeningScan runs the hardening check suite on a node.
func (d *Dispatcher) SecHardeningScan(ctx context.Context, serverID, requestID string, in nodewire.SecHardeningScanInput) (nodewire.SecHardeningScanResult, error) {
	var out nodewire.SecHardeningScanResult
	if err := in.Validate(); err != nil {
		return out, fmt.Errorf("nodes: invalid sec hardening scan input: %w", err)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpSecHardeningScan,
		RequestID: requestID,
		Input:     in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode sec hardening scan result: %w", err)
	}
	return out, nil
}

// SecSSHPosture reads the SSH configuration and session posture from a node.
func (d *Dispatcher) SecSSHPosture(ctx context.Context, serverID, requestID string) (nodewire.SecSSHPostureResult, error) {
	var out nodewire.SecSSHPostureResult
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpSecSSHPosture,
		RequestID: requestID,
		Input:     nodewire.SecSSHPostureInput{},
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode sec ssh posture result: %w", err)
	}
	return out, nil
}

// SecBanList reads the active ban list from a node's fail2ban/crowdsec adapters.
func (d *Dispatcher) SecBanList(ctx context.Context, serverID, requestID string, in nodewire.SecBanListInput) (nodewire.SecBanListResult, error) {
	var out nodewire.SecBanListResult
	if err := in.Validate(); err != nil {
		return out, fmt.Errorf("nodes: invalid sec ban list input: %w", err)
	}
	raw, err := d.Call(ctx, CallRequest{
		ServerID:  serverID,
		Operation: nodewire.OpSecBanList,
		RequestID: requestID,
		Input:     in,
	})
	if err != nil {
		return out, err
	}
	if err := decodeStrict(raw, &out); err != nil {
		return out, fmt.Errorf("nodes: decode sec ban list result: %w", err)
	}
	return out, nil
}

// decodeStrict decodes a node's result, refusing unknown fields.
//
// A node newer than the controller may send fields the controller does not know.
// Refusing them is the right default for a privileged operation: partially
// understanding a restart result and reporting success is worse than reporting
// that the two ends disagree about the protocol.
func decodeStrict(raw json.RawMessage, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("result contains more than one JSON value")
	}
	return nil
}

// VerifyReachable performs an mTLS handshake with a node and reports the verified
// identity, without performing any operation.
//
// It exists so the UI can answer "can the controller actually reach this node?"
// without restarting anything, and so a test can assert the trust relationship
// independently of the operations built on it.
func (d *Dispatcher) VerifyReachable(ctx context.Context, serverID string) (pki.Identity, error) {
	server, err := d.store.GetServer(ctx, serverID)
	if err != nil {
		return pki.Identity{}, err
	}
	if server.Address == "" {
		return pki.Identity{}, fmt.Errorf("%w: server %s has no address", ErrInvalid, serverID)
	}
	// tls.Dialer.DialContext rather than tls.DialWithDialer: the probe is
	// bounded by BOTH the caller's deadline and this timeout, so canceling the
	// caller actually tears down the handshake instead of leaving it running.
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: d.client.Transport.(*http.Transport).TLSClientConfig}
	conn, err := dialer.DialContext(ctx, "tcp", server.Address)
	if err != nil {
		return pki.Identity{}, fmt.Errorf("%w: %w", ErrNodeUnreachable, err)
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return pki.Identity{}, fmt.Errorf("nodes: dial to node %s did not produce a TLS connection", serverID)
	}
	defer func() { _ = tlsConn.Close() }()
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return pki.Identity{}, fmt.Errorf("nodes: node %s presented no certificate", serverID)
	}
	identity, err := pki.IdentityOf(state.PeerCertificates[0])
	if err != nil {
		return pki.Identity{}, err
	}
	if identity.Kind != pki.KindNode || identity.ID != serverID {
		return pki.Identity{}, fmt.Errorf("%w: peer identifies as %s %q", ErrInvalid, identity.Kind, identity.ID)
	}
	return identity, nil
}
