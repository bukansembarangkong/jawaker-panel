package controller

import (
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/auth"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/network"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodes"
	"github.com/bukansembarangkong/jawaker-panel/internal/nodewire"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NetworkHandlerOptions configures the networking HTTP surface.
type NetworkHandlerOptions struct {
	Network    *network.Store
	Pool       *pgxpool.Pool
	Dispatcher *nodes.Dispatcher
	Logger     *slog.Logger
	Audit      audit.Execer
	Now        func() time.Time
}

// NetworkHandlers holds the networking HTTP handlers.
type NetworkHandlers struct {
	network     *network.Store
	pool        *pgxpool.Pool
	dispatcher  *nodes.Dispatcher
	logger      *slog.Logger
	auditExecer audit.Execer
	now         func() time.Time
}

// NewNetworkHandlers builds the networking handlers.
func NewNetworkHandlers(opts NetworkHandlerOptions) (*NetworkHandlers, error) {
	if opts.Network == nil {
		return nil, errors.New("controller: network store is required")
	}
	if opts.Pool == nil {
		return nil, errors.New("controller: pool is required")
	}
	if opts.Logger == nil {
		return nil, errors.New("controller: logger is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &NetworkHandlers{
		network:     opts.Network,
		pool:        opts.Pool,
		dispatcher:  opts.Dispatcher,
		logger:      opts.Logger,
		auditExecer: opts.Audit,
		now:         now,
	}, nil
}

// Routes registers the networking endpoints on the mux.
//
// All routes are server-scoped. Permissions follow the RBAC seed:
//   - firewall.read  / firewall.manage for firewall rules + apply
//   - network.read   / network.manage  for zones, forwards, wireguard, diag
func (h *NetworkHandlers) Routes(mux *http.ServeMux) {
	// Firewall rules (candidate state until apply)
	mux.HandleFunc("GET /api/v1/servers/{server_id}/firewall/rules", h.handleListRules)
	mux.HandleFunc("POST /api/v1/servers/{server_id}/firewall/rules", h.handleCreateRule)
	mux.HandleFunc("DELETE /api/v1/servers/{server_id}/firewall/rules/{id}", h.handleDeleteRule)
	// Safe Network Apply — activates candidate rules; requires step-up
	mux.HandleFunc("POST /api/v1/servers/{server_id}/firewall/apply", h.handleApplyFirewall)
	// Live iptables read from node
	mux.HandleFunc("GET /api/v1/servers/{server_id}/firewall/live", h.handleLiveFirewall)

	// Port forwards
	mux.HandleFunc("GET /api/v1/servers/{server_id}/port-forwards", h.handleListForwards)
	mux.HandleFunc("POST /api/v1/servers/{server_id}/port-forwards", h.handleCreateForward)
	mux.HandleFunc("DELETE /api/v1/servers/{server_id}/port-forwards/{id}", h.handleDeleteForward)

	// Network zones
	mux.HandleFunc("GET /api/v1/servers/{server_id}/network/zones", h.handleListZones)
	mux.HandleFunc("POST /api/v1/servers/{server_id}/network/zones", h.handleCreateZone)
	mux.HandleFunc("DELETE /api/v1/servers/{server_id}/network/zones/{id}", h.handleDeleteZone)

	// Live port inventory from node
	mux.HandleFunc("GET /api/v1/servers/{server_id}/network/ports", h.handlePortInventory)

	// WireGuard peers (management overlay)
	mux.HandleFunc("GET /api/v1/servers/{server_id}/wireguard/peers", h.handleListPeers)
	mux.HandleFunc("POST /api/v1/servers/{server_id}/wireguard/peers", h.handleCreatePeer)
	mux.HandleFunc("DELETE /api/v1/servers/{server_id}/wireguard/peers/{id}", h.handleDeletePeer)

	// Network diagnostics (ping/traceroute via node)
	mux.HandleFunc("POST /api/v1/servers/{server_id}/network/diag", h.handleNetDiag)

	// Apply log — audit trail for Safe Network Apply attempts
	mux.HandleFunc("GET /api/v1/servers/{server_id}/network/apply-log", h.handleListApplyLog)
}

// ── Firewall rules ─────────────────────────────────────────────────────────────

func (h *NetworkHandlers) handleListRules(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	authsession.RequirePermission(h.now, "firewall.read", rbac.ServerScope(serverID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rules, err := h.network.ListRules(r.Context(), serverID)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"rules":      rules,
				"total":      len(rules),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createFirewallRuleRequest struct {
	Chain       string `json:"chain"`
	Priority    int    `json:"priority"`
	Protocol    string `json:"protocol"`
	SourceCIDR  string `json:"source_cidr"`
	DestCIDR    string `json:"dest_cidr"`
	DestPortMin int    `json:"dest_port_min"`
	DestPortMax int    `json:"dest_port_max"`
	Action      string `json:"action"`
	Enabled     bool   `json:"enabled"`
	Description string `json:"description"`
}

func (h *NetworkHandlers) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	// firewall.manage is step-up: applying network rules is a privileged mutating action.
	authsession.RequirePermission(h.now, "firewall.manage", rbac.ServerScope(serverID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createFirewallRuleRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			if req.Chain == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("chain is required", nil))
				return
			}
			rule, err := h.network.CreateRule(r.Context(), network.CreateRuleParams{
				ServerID:    serverID,
				Chain:       req.Chain,
				Priority:    req.Priority,
				Protocol:    req.Protocol,
				SourceCIDR:  req.SourceCIDR,
				DestCIDR:    req.DestCIDR,
				DestPortMin: req.DestPortMin,
				DestPortMax: req.DestPortMax,
				Action:      req.Action,
				Enabled:     req.Enabled,
				Description: req.Description,
				State:       network.StateCandidate,
			})
			if err != nil {
				if errors.Is(err, network.ErrInvalid) {
					httpserver.WriteError(w, r, apierr.InvalidRequest(err.Error(), nil))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordNetAudit(r, audit.Event{
				Action:     "firewall.rule.created",
				ResourceID: rule.ID,
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"rule":       rule,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *NetworkHandlers) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "firewall.manage", rbac.ServerScope(serverID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := h.network.DeleteRule(r.Context(), id); err != nil {
				if errors.Is(err, network.ErrNotFound) {
					httpserver.WriteError(w, r, apierr.NotFound("Firewall rule not found."))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordNetAudit(r, audit.Event{
				Action:     "firewall.rule.deleted",
				ResourceID: id,
			})
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(w, r)
}

// handleApplyFirewall is the Safe Network Apply endpoint.
// Gate: activates all candidate rules atomically. On failure, no rules change
// state (ActivateRules updates only candidate rows, no rollback of active rules).
// Recorded in apply log regardless of outcome.
func (h *NetworkHandlers) handleApplyFirewall(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	// Step-up required: applying firewall changes is a privileged action
	// (RBAC seed: firewall.manage step_up=true).
	authsession.RequirePermission(h.now, "firewall.manage", rbac.ServerScope(serverID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			principal, ok := auth.PrincipalFrom(r.Context())
			appliedBy := "unknown"
			if ok {
				appliedBy = principal.UserID
			}
			if err := h.network.ActivateRules(r.Context(), serverID); err != nil {
				_, _ = h.network.RecordApply(r.Context(), serverID, appliedBy, network.OutcomeFailed,
					err.Error(), nil, nil)
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			log, _ := h.network.RecordApply(r.Context(), serverID, appliedBy,
				network.OutcomeApplied, "", []byte(`{"operation":"activate_rules"}`), nil)
			h.recordNetAudit(r, audit.Event{
				Action:     "firewall.apply",
				ResourceID: log.ID,
			})
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"log":        log,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// handleLiveFirewall reads the live iptables ruleset from the node via nodewire.
func (h *NetworkHandlers) handleLiveFirewall(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	authsession.RequirePermission(h.now, "firewall.read", rbac.ServerScope(serverID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.dispatcher == nil {
				httpserver.WriteError(w, r, apierr.ServiceUnavailable("Node dispatcher is not available on this controller."))
				return
			}
			table := r.URL.Query().Get("table")
			reqID := httpserver.RequestIDFromRequest(r)
			result, err := h.dispatcher.NetFirewallList(r.Context(), serverID, reqID,
				nodewire.NetFirewallListInput{Table: table})
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"chains":      result.Chains,
				"observed_at": result.ObservedAt,
				"request_id":  reqID,
			})
		})).ServeHTTP(w, r)
}

// ── Port forwards ──────────────────────────────────────────────────────────────

func (h *NetworkHandlers) handleListForwards(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	authsession.RequirePermission(h.now, "network.read", rbac.ServerScope(serverID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fwds, err := h.network.ListForwards(r.Context(), serverID)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"forwards":   fwds,
				"total":      len(fwds),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createPortForwardRequest struct {
	Protocol      string `json:"protocol"`
	ListenAddress string `json:"listen_address"`
	ListenPort    int    `json:"listen_port"`
	DestAddress   string `json:"dest_address"`
	DestPort      int    `json:"dest_port"`
	Enabled       bool   `json:"enabled"`
	Description   string `json:"description"`
}

func (h *NetworkHandlers) handleCreateForward(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	authsession.RequirePermission(h.now, "network.manage", rbac.ServerScope(serverID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createPortForwardRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			fwd, err := h.network.CreateForward(r.Context(), network.CreateForwardParams{
				ServerID:      serverID,
				Protocol:      req.Protocol,
				ListenAddress: req.ListenAddress,
				ListenPort:    req.ListenPort,
				DestAddress:   req.DestAddress,
				DestPort:      req.DestPort,
				Enabled:       req.Enabled,
				Description:   req.Description,
			})
			if err != nil {
				if errors.Is(err, network.ErrConflict) {
					httpserver.WriteError(w, r, apierr.Conflict("That port is already forwarded on this server.", nil))
					return
				}
				if errors.Is(err, network.ErrInvalid) {
					httpserver.WriteError(w, r, apierr.InvalidRequest(err.Error(), nil))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordNetAudit(r, audit.Event{
				Action:     "network.forward.created",
				ResourceID: fwd.ID,
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"forward":    fwd,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *NetworkHandlers) handleDeleteForward(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "network.manage", rbac.ServerScope(serverID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := h.network.DeleteForward(r.Context(), id); err != nil {
				if errors.Is(err, network.ErrNotFound) {
					httpserver.WriteError(w, r, apierr.NotFound("Port forward not found."))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordNetAudit(r, audit.Event{
				Action:     "network.forward.deleted",
				ResourceID: id,
			})
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(w, r)
}

// ── Network zones ──────────────────────────────────────────────────────────────

func (h *NetworkHandlers) handleListZones(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	authsession.RequirePermission(h.now, "network.read", rbac.ServerScope(serverID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			zones, err := h.network.ListZones(r.Context(), serverID)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"zones":      zones,
				"total":      len(zones),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createNetworkZoneRequest struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Interfaces string `json:"interfaces"`
}

func (h *NetworkHandlers) handleCreateZone(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	authsession.RequirePermission(h.now, "network.manage", rbac.ServerScope(serverID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createNetworkZoneRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			zone, err := h.network.CreateZone(r.Context(), network.CreateZoneParams{
				ServerID:   serverID,
				Name:       req.Name,
				Kind:       req.Kind,
				Interfaces: req.Interfaces,
			})
			if err != nil {
				if errors.Is(err, network.ErrInvalid) {
					httpserver.WriteError(w, r, apierr.InvalidRequest(err.Error(), nil))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"zone":       zone,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *NetworkHandlers) handleDeleteZone(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "network.manage", rbac.ServerScope(serverID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := h.network.DeleteZone(r.Context(), id); err != nil {
				if errors.Is(err, network.ErrNotFound) {
					httpserver.WriteError(w, r, apierr.NotFound("Network zone not found."))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(w, r)
}

// ── Port inventory from node ───────────────────────────────────────────────────

func (h *NetworkHandlers) handlePortInventory(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	authsession.RequirePermission(h.now, "network.read", rbac.ServerScope(serverID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.dispatcher == nil {
				httpserver.WriteError(w, r, apierr.ServiceUnavailable("Node dispatcher is not available on this controller."))
				return
			}
			proto := r.URL.Query().Get("protocol")
			reqID := httpserver.RequestIDFromRequest(r)
			result, err := h.dispatcher.NetPortInventory(r.Context(), serverID, reqID,
				nodewire.NetPortInventoryInput{Protocol: proto})
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"ports":       result.Ports,
				"total":       len(result.Ports),
				"observed_at": result.ObservedAt,
				"request_id":  reqID,
			})
		})).ServeHTTP(w, r)
}

// ── WireGuard peers ────────────────────────────────────────────────────────────

func (h *NetworkHandlers) handleListPeers(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	authsession.RequirePermission(h.now, "network.read", rbac.ServerScope(serverID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peers, err := h.network.ListPeers(r.Context(), serverID)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"peers":      peers,
				"total":      len(peers),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createWireGuardPeerRequest struct {
	PublicKey           string `json:"public_key"`
	Label               string `json:"label"`
	AllowedIPs          string `json:"allowed_ips"`
	Endpoint            string `json:"endpoint"`
	PersistentKeepalive int    `json:"persistent_keepalive"`
	Enabled             bool   `json:"enabled"`
}

func (h *NetworkHandlers) handleCreatePeer(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	authsession.RequirePermission(h.now, "network.manage", rbac.ServerScope(serverID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createWireGuardPeerRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			peer, err := h.network.CreatePeer(r.Context(), network.CreatePeerParams{
				ServerID:            serverID,
				PublicKey:           req.PublicKey,
				Label:               req.Label,
				AllowedIPs:          req.AllowedIPs,
				Endpoint:            req.Endpoint,
				PersistentKeepalive: req.PersistentKeepalive,
				Enabled:             req.Enabled,
			})
			if err != nil {
				if errors.Is(err, network.ErrInvalid) {
					httpserver.WriteError(w, r, apierr.InvalidRequest(err.Error(), nil))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordNetAudit(r, audit.Event{
				Action:     "network.peer.created",
				ResourceID: peer.ID,
			})
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"peer":       peer,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *NetworkHandlers) handleDeletePeer(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "network.manage", rbac.ServerScope(serverID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := h.network.DeletePeer(r.Context(), id); err != nil {
				if errors.Is(err, network.ErrNotFound) {
					httpserver.WriteError(w, r, apierr.NotFound("WireGuard peer not found."))
					return
				}
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			h.recordNetAudit(r, audit.Event{
				Action:     "network.peer.deleted",
				ResourceID: id,
			})
			w.WriteHeader(http.StatusNoContent)
		})).ServeHTTP(w, r)
}

// ── Network diagnostics ────────────────────────────────────────────────────────

type netDiagRequest struct {
	Target string `json:"target"`
	Mode   string `json:"mode"`
}

func (h *NetworkHandlers) handleNetDiag(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	authsession.RequirePermission(h.now, "network.read", rbac.ServerScope(serverID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.dispatcher == nil {
				httpserver.WriteError(w, r, apierr.ServiceUnavailable("Node dispatcher is not available on this controller."))
				return
			}
			var req netDiagRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			reqID := httpserver.RequestIDFromRequest(r)
			result, err := h.dispatcher.NetDiag(r.Context(), serverID, reqID,
				nodewire.NetDiagInput{Target: req.Target, Mode: req.Mode})
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"result":     result,
				"request_id": reqID,
			})
		})).ServeHTTP(w, r)
}

// ── Apply log ──────────────────────────────────────────────────────────────────

func (h *NetworkHandlers) handleListApplyLog(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	authsession.RequirePermission(h.now, "network.read", rbac.ServerScope(serverID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logs, err := h.network.ListApplyLog(r.Context(), serverID, 20)
			if err != nil {
				httpserver.WriteError(w, r, apierr.Internal(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"logs":       logs,
				"total":      len(logs),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Audit helper ───────────────────────────────────────────────────────────────

func (h *NetworkHandlers) recordNetAudit(r *http.Request, e audit.Event) {
	if h.auditExecer == nil {
		return
	}
	e.RequestID = httpserver.RequestIDFromRequest(r)
	e.SourceIP = r.RemoteAddr
	e.UserAgent = r.UserAgent()
	if e.ActorType == "" {
		e.ActorType = audit.ActorUser
	}
	if err := audit.Record(r.Context(), h.auditExecer, e); err != nil {
		h.logger.ErrorContext(r.Context(), "audit write failed",
			"error", err, "action", e.Action, "request_id", e.RequestID)
	}
}
