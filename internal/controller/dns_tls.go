package controller

// dns_tls.go — Phase 8 DNS and TLS control plane HTTP surface.
//
// DNS routes (project-scoped, permission dns.read / dns.write):
//
//	GET    /api/v1/projects/{project_id}/dns-providers
//	POST   /api/v1/projects/{project_id}/dns-providers
//	GET    /api/v1/projects/{project_id}/dns-providers/{id}
//	DELETE /api/v1/projects/{project_id}/dns-providers/{id}
//	GET    /api/v1/projects/{project_id}/dns-zones
//	POST   /api/v1/projects/{project_id}/dns-zones
//	GET    /api/v1/projects/{project_id}/dns-zones/{zone_id}
//	DELETE /api/v1/projects/{project_id}/dns-zones/{zone_id}
//	GET    /api/v1/projects/{project_id}/dns-zones/{zone_id}/records
//	POST   /api/v1/projects/{project_id}/dns-zones/{zone_id}/records
//	PATCH  /api/v1/projects/{project_id}/dns-zones/{zone_id}/records/{id}
//	DELETE /api/v1/projects/{project_id}/dns-zones/{zone_id}/records/{id}
//
// TLS routes (project-scoped, permission tls.read / tls.write):
//
//	GET    /api/v1/projects/{project_id}/certificates
//	GET    /api/v1/projects/{project_id}/certificates/{id}
//	POST   /api/v1/projects/{project_id}/certificates/import
//	POST   /api/v1/projects/{project_id}/certificates/{id}/revoke
//	GET    /api/v1/projects/{project_id}/cert-orders
//	POST   /api/v1/projects/{project_id}/cert-orders
//	GET    /api/v1/projects/{project_id}/cert-orders/{order_id}
//	POST   /api/v1/projects/{project_id}/cert-orders/{order_id}/cancel
//
// Security invariants:
//   - dns_providers.secret_ref is NEVER returned in responses; the raw token
//     field in the create request is sealed into the secret subsystem before
//     the provider row is inserted (SECURITY.md §8).
//   - certificate private key is NEVER returned by inventory endpoints; it is
//     sealed in certs.Store and only retrievable via an explicit OpenKey call
//     that is not exposed over HTTP.
//   - bad certificate/key pairs are rejected by crypto/x509 parsing before
//     touching the database (Gate: "bad certificate/key pair rejected").
//   - previous valid certificate remains bound during a failed renewal: the
//     certs.Store Bind() call uses a transaction-level deactivate+activate, so
//     rollback always has a row to revert to (Gate 4).

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/certs"
	"github.com/bukansembarangkong/jawaker-panel/internal/dns"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
	"github.com/bukansembarangkong/jawaker-panel/internal/secret"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DNSTLSHandlerOptions configures the DNS and TLS HTTP surface.
type DNSTLSHandlerOptions struct {
	DNS     *dns.Store
	Certs   *certs.Store
	Secrets *secret.Store
	Pool    *pgxpool.Pool
	Logger  *slog.Logger
	Audit   audit.Execer
	Now     func() time.Time
}

// DNSTLSHandlers holds the DNS and TLS HTTP handlers.
type DNSTLSHandlers struct {
	dns     *dns.Store
	certs   *certs.Store
	secrets *secret.Store
	pool    *pgxpool.Pool
	logger  *slog.Logger
	audit   audit.Execer
	now     func() time.Time
}

// NewDNSTLSHandlers builds the DNS+TLS handlers.
func NewDNSTLSHandlers(opts DNSTLSHandlerOptions) (*DNSTLSHandlers, error) {
	if opts.DNS == nil {
		return nil, errors.New("controller: dns store is required")
	}
	if opts.Logger == nil {
		return nil, errors.New("controller: logger is required")
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &DNSTLSHandlers{
		dns:     opts.DNS,
		certs:   opts.Certs,
		secrets: opts.Secrets,
		pool:    opts.Pool,
		logger:  opts.Logger,
		audit:   opts.Audit,
		now:     now,
	}, nil
}

// Routes registers all DNS and TLS endpoints.
func (h *DNSTLSHandlers) Routes(mux *http.ServeMux) {
	// DNS providers.
	mux.HandleFunc("GET /api/v1/projects/{project_id}/dns-providers", h.handleListProviders)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/dns-providers", h.handleCreateProvider)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/dns-providers/{id}", h.handleGetProvider)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/dns-providers/{id}", h.handleDeleteProvider)
	// DNS zones.
	mux.HandleFunc("GET /api/v1/projects/{project_id}/dns-zones", h.handleListZones)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/dns-zones", h.handleCreateZone)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/dns-zones/{zone_id}", h.handleGetZone)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/dns-zones/{zone_id}", h.handleDeleteZone)
	// DNS records.
	mux.HandleFunc("GET /api/v1/projects/{project_id}/dns-zones/{zone_id}/records", h.handleListRecords)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/dns-zones/{zone_id}/records", h.handleCreateRecord)
	mux.HandleFunc("PATCH /api/v1/projects/{project_id}/dns-zones/{zone_id}/records/{id}", h.handleUpdateRecord)
	mux.HandleFunc("DELETE /api/v1/projects/{project_id}/dns-zones/{zone_id}/records/{id}", h.handleDeleteRecord)
	// Certificates.
	mux.HandleFunc("GET /api/v1/projects/{project_id}/certificates", h.handleListCerts)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/certificates/{id}", h.handleGetCert)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/certificates/import", h.handleImportCert)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/certificates/{id}/revoke", h.handleRevokeCert)
	// ACME orders.
	mux.HandleFunc("GET /api/v1/projects/{project_id}/cert-orders", h.handleListOrders)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/cert-orders", h.handleCreateOrder)
	mux.HandleFunc("GET /api/v1/projects/{project_id}/cert-orders/{order_id}", h.handleGetOrder)
	mux.HandleFunc("POST /api/v1/projects/{project_id}/cert-orders/{order_id}/cancel", h.handleCancelOrder)
}

// ── DNS Providers ─────────────────────────────────────────────────────────────

func (h *DNSTLSHandlers) handleListProviders(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "dns.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			list, err := h.dns.ListProviders(r.Context(), projectID)
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"providers":  providerResponses(list),
				"total":      len(list),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createProviderRequest struct {
	Name     string `json:"name"`
	Provider string `json:"provider"`
	// Token is sealed into the secret subsystem; NEVER stored or returned plaintext.
	Token string `json:"token"`
}

func (h *DNSTLSHandlers) handleCreateProvider(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "dns.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createProviderRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			if strings.TrimSpace(req.Token) == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("token is required", nil))
				return
			}
			if h.secrets == nil {
				httpserver.WriteError(w, r, apierr.ServiceUnavailable("secret subsystem unavailable"))
				return
			}

			// Seal the token before touching the database.
			// ref format: secret://dns-providers/{project_id}/{name}/token
			ref := fmt.Sprintf("secret://dns-providers/%s/%s/token", projectID, req.Name)
			if err := h.secrets.Create(r.Context(), ref, req.Token,
				fmt.Sprintf("DNS provider token for %s/%s", projectID, req.Name)); err != nil {
				h.logger.Error("seal dns provider token", "error", err)
				httpserver.WriteError(w, r, apierr.Internal(errors.New("failed to seal provider credentials")))
				return
			}

			prov, err := h.dns.CreateProvider(r.Context(), dns.CreateProviderParams{
				ProjectID: projectID,
				Name:      req.Name,
				Provider:  req.Provider,
				SecretRef: ref,
				CreatedBy: principalUserID(r),
			})
			if err != nil {
				// Clean up the sealed secret on store failure.
				_ = h.secrets.Delete(r.Context(), ref)
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"provider":   providerResponse(prov),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *DNSTLSHandlers) handleGetProvider(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "dns.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			prov, err := h.dns.GetProvider(r.Context(), id)
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			if prov.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("not found"))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"provider":   providerResponse(prov),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *DNSTLSHandlers) handleDeleteProvider(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "dns.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Load first so we can cross-check project ownership.
			prov, err := h.dns.GetProvider(r.Context(), id)
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			if prov.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("not found"))
				return
			}
			if err := h.dns.DeleteProvider(r.Context(), id); err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			// Best-effort: remove the sealed token.
			if h.secrets != nil {
				_ = h.secrets.Delete(r.Context(), prov.SecretRef)
			}
			writeJSONResponse(w, http.StatusNoContent, nil)
		})).ServeHTTP(w, r)
}

// ── DNS Zones ──────────────────────────────────────────────────────────────────

func (h *DNSTLSHandlers) handleListZones(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "dns.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			list, err := h.dns.ListZones(r.Context(), projectID)
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"zones":      zoneResponses(list),
				"total":      len(list),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createZoneRequest struct {
	ProviderID string `json:"provider_id"`
	Apex       string `json:"apex"`
	ExternalID string `json:"external_id,omitempty"`
}

func (h *DNSTLSHandlers) handleCreateZone(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "dns.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createZoneRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			zone, err := h.dns.CreateZone(r.Context(), dns.CreateZoneParams{
				ProjectID:  projectID,
				ProviderID: req.ProviderID,
				Apex:       req.Apex,
				ExternalID: req.ExternalID,
				CreatedBy:  principalUserID(r),
			})
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"zone":       zoneResponse(zone),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *DNSTLSHandlers) handleGetZone(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	zoneID := r.PathValue("zone_id")
	authsession.RequirePermission(h.now, "dns.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			zone, err := h.dns.GetZone(r.Context(), zoneID)
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			if zone.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("not found"))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"zone":       zoneResponse(zone),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *DNSTLSHandlers) handleDeleteZone(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	zoneID := r.PathValue("zone_id")
	authsession.RequirePermission(h.now, "dns.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			zone, err := h.dns.GetZone(r.Context(), zoneID)
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			if zone.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("not found"))
				return
			}
			if err := h.dns.DeleteZone(r.Context(), zoneID); err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			writeJSONResponse(w, http.StatusNoContent, nil)
		})).ServeHTTP(w, r)
}

// ── DNS Records ───────────────────────────────────────────────────────────────

func (h *DNSTLSHandlers) handleListRecords(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	zoneID := r.PathValue("zone_id")
	authsession.RequirePermission(h.now, "dns.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify zone belongs to project.
			zone, err := h.dns.GetZone(r.Context(), zoneID)
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			if zone.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("not found"))
				return
			}
			list, err := h.dns.ListRecords(r.Context(), zoneID)
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"records":    recordResponses(list),
				"total":      len(list),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createRecordRequest struct {
	RType    string `json:"rtype"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	TTL      int    `json:"ttl,omitempty"`
	Priority *int   `json:"priority,omitempty"`
}

func (h *DNSTLSHandlers) handleCreateRecord(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	zoneID := r.PathValue("zone_id")
	authsession.RequirePermission(h.now, "dns.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			zone, err := h.dns.GetZone(r.Context(), zoneID)
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			if zone.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("not found"))
				return
			}
			var req createRecordRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			rec, err := h.dns.CreateRecord(r.Context(), dns.CreateRecordParams{
				ZoneID:    zoneID,
				RType:     req.RType,
				Name:      req.Name,
				Value:     req.Value,
				TTL:       req.TTL,
				Priority:  req.Priority,
				Managed:   true,
				CreatedBy: principalUserID(r),
			})
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"record":     recordResponse(rec),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type updateRecordRequest struct {
	Value    string `json:"value"`
	TTL      int    `json:"ttl,omitempty"`
	Priority *int   `json:"priority,omitempty"`
}

func (h *DNSTLSHandlers) handleUpdateRecord(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	zoneID := r.PathValue("zone_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "dns.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			zone, err := h.dns.GetZone(r.Context(), zoneID)
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			if zone.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("not found"))
				return
			}
			var req updateRecordRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			rec, err := h.dns.UpdateRecord(r.Context(), id, dns.UpdateRecordParams{
				Value:    req.Value,
				TTL:      req.TTL,
				Priority: req.Priority,
			})
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"record":     recordResponse(rec),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *DNSTLSHandlers) handleDeleteRecord(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	zoneID := r.PathValue("zone_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "dns.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			zone, err := h.dns.GetZone(r.Context(), zoneID)
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			if zone.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("not found"))
				return
			}
			if err := h.dns.DeleteRecord(r.Context(), id); err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			writeJSONResponse(w, http.StatusNoContent, nil)
		})).ServeHTTP(w, r)
}

// ── Certificates ──────────────────────────────────────────────────────────────

func (h *DNSTLSHandlers) handleListCerts(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ssl.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.certs == nil {
				httpserver.WriteError(w, r, apierr.ServiceUnavailable("cert store unavailable"))
				return
			}
			window := certs.DefaultRenewalWindow
			list, err := h.certs.ListExpiring(r.Context(), window*100) // large window = all
			if err != nil {
				httpserver.WriteError(w, r, tlsErr(err))
				return
			}
			// Filter by project.
			var filtered []certs.Certificate
			for _, c := range list {
				if c.ProjectID == projectID {
					filtered = append(filtered, c)
				}
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"certificates": certResponses(filtered),
				"total":        len(filtered),
				"request_id":   httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *DNSTLSHandlers) handleGetCert(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "ssl.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.certs == nil {
				httpserver.WriteError(w, r, apierr.ServiceUnavailable("cert store unavailable"))
				return
			}
			cert, err := h.certs.Get(r.Context(), id)
			if err != nil {
				httpserver.WriteError(w, r, tlsErr(err))
				return
			}
			if cert.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("not found"))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"certificate": certResponse(cert),
				"request_id":  httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// importCertRequest is the payload for POST …/certificates/import.
// Gate: "bad certificate/key pair rejected" — both PEM blocks are parsed
// before any database write.
type importCertRequest struct {
	// ChainPEM is the PEM-encoded certificate chain (leaf + intermediates).
	ChainPEM string `json:"chain_pem"`
	// PrivateKeyPEM is the PEM-encoded private key. Sealed into the secret
	// subsystem; NEVER stored plaintext.
	PrivateKeyPEM string `json:"private_key_pem"`
}

func (h *DNSTLSHandlers) handleImportCert(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ssl.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.certs == nil || h.secrets == nil {
				httpserver.WriteError(w, r, apierr.ServiceUnavailable("cert or secret store unavailable"))
				return
			}
			var req importCertRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}

			// ── Gate: reject bad certificate/key pair ─────────────────────────
			leafCert, issuedAt, notAfter, identifiers, issuer, serialHex, err := parseCertChain(req.ChainPEM)
			if err != nil {
				httpserver.WriteError(w, r, apierr.InvalidRequest("invalid chain_pem: "+err.Error(), nil))
				return
			}
			if keyErr := validateKeyMatchesCert(req.PrivateKeyPEM, leafCert); keyErr != nil {
				httpserver.WriteError(w, r, apierr.InvalidRequest("key/certificate mismatch: "+keyErr.Error(), nil))
				return
			}

			cert, err := h.certs.Record(r.Context(), certs.RecordParams{
				ProjectID:     projectID,
				IssuedAt:      issuedAt,
				NotAfter:      notAfter,
				Identifiers:   identifiers,
				Issuer:        issuer,
				DirectoryURL:  "imported",
				SerialHex:     serialHex,
				PrivateKeyPEM: req.PrivateKeyPEM,
				ChainPEM:      req.ChainPEM,
			})
			if err != nil {
				httpserver.WriteError(w, r, tlsErr(err))
				return
			}
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"certificate": certResponse(cert),
				"request_id":  httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type revokeCertRequest struct {
	Reason string `json:"reason,omitempty"`
}

func (h *DNSTLSHandlers) handleRevokeCert(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	id := r.PathValue("id")
	authsession.RequirePermission(h.now, "ssl.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if h.certs == nil {
				httpserver.WriteError(w, r, apierr.ServiceUnavailable("cert store unavailable"))
				return
			}
			cert, err := h.certs.Get(r.Context(), id)
			if err != nil {
				httpserver.WriteError(w, r, tlsErr(err))
				return
			}
			if cert.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("not found"))
				return
			}
			var req revokeCertRequest
			_ = decodeJSONStrict(r, &req) // optional body
			revoked, err := h.certs.Revoke(r.Context(), id, req.Reason)
			if err != nil {
				httpserver.WriteError(w, r, tlsErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"certificate": certResponse(revoked),
				"request_id":  httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── ACME Orders ───────────────────────────────────────────────────────────────

func (h *DNSTLSHandlers) handleListOrders(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ssl.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			list, err := h.dns.ListOrders(r.Context(), projectID)
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"orders":     orderResponses(list),
				"total":      len(list),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

type createOrderRequest struct {
	ProviderID   string   `json:"provider_id,omitempty"`
	Identifiers  []string `json:"identifiers"`
	DirectoryURL string   `json:"directory_url,omitempty"`
}

func (h *DNSTLSHandlers) handleCreateOrder(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	authsession.RequirePermission(h.now, "ssl.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req createOrderRequest
			if apiErr := decodeJSONStrict(r, &req); apiErr != nil {
				httpserver.WriteError(w, r, apiErr)
				return
			}
			order, err := h.dns.CreateOrder(r.Context(), dns.CreateOrderParams{
				ProjectID:    projectID,
				ProviderID:   req.ProviderID,
				Identifiers:  req.Identifiers,
				DirectoryURL: req.DirectoryURL,
				CreatedBy:    principalUserID(r),
			})
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			writeJSONResponse(w, http.StatusCreated, map[string]any{
				"order":      orderResponse(order),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *DNSTLSHandlers) handleGetOrder(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	orderID := r.PathValue("order_id")
	authsession.RequirePermission(h.now, "ssl.read", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order, err := h.dns.GetOrder(r.Context(), orderID)
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			if order.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("not found"))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"order":      orderResponse(order),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

func (h *DNSTLSHandlers) handleCancelOrder(w http.ResponseWriter, r *http.Request) {
	projectID := r.PathValue("project_id")
	orderID := r.PathValue("order_id")
	authsession.RequirePermission(h.now, "ssl.manage", rbac.ProjectScope(projectID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			order, err := h.dns.GetOrder(r.Context(), orderID)
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			if order.ProjectID != projectID {
				httpserver.WriteError(w, r, apierr.NotFound("not found"))
				return
			}
			updated, err := h.dns.AdvanceOrderState(r.Context(), orderID, dns.OrderCanceled)
			if err != nil {
				httpserver.WriteError(w, r, dnsErr(err))
				return
			}
			writeJSONResponse(w, http.StatusOK, map[string]any{
				"order":      orderResponse(updated),
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// ── Response shapes ────────────────────────────────────────────────────────────

// providerResponse omits the secret_ref (credential redaction gate).
func providerResponse(p dns.Provider) map[string]any {
	return map[string]any{
		"id":         p.ID,
		"project_id": p.ProjectID,
		"name":       p.Name,
		"provider":   p.Provider,
		// secret_ref intentionally omitted — SECURITY.md §8: credentials redacted.
		"enabled":    p.Enabled,
		"created_at": p.CreatedAt,
		"updated_at": p.UpdatedAt,
	}
}

func providerResponses(ps []dns.Provider) []map[string]any {
	out := make([]map[string]any, len(ps))
	for i, p := range ps {
		out[i] = providerResponse(p)
	}
	return out
}

func zoneResponse(z dns.Zone) map[string]any {
	return map[string]any{
		"id":             z.ID,
		"project_id":     z.ProjectID,
		"provider_id":    z.ProviderID,
		"apex":           z.Apex,
		"external_id":    z.ExternalID,
		"state":          z.State,
		"last_synced_at": z.LastSyncedAt,
		"last_error":     z.LastError,
		"created_at":     z.CreatedAt,
		"updated_at":     z.UpdatedAt,
	}
}

func zoneResponses(zs []dns.Zone) []map[string]any {
	out := make([]map[string]any, len(zs))
	for i, z := range zs {
		out[i] = zoneResponse(z)
	}
	return out
}

func recordResponse(rec dns.Record) map[string]any {
	return map[string]any{
		"id":          rec.ID,
		"zone_id":     rec.ZoneID,
		"rtype":       rec.RType,
		"name":        rec.Name,
		"value":       rec.Value,
		"ttl":         rec.TTL,
		"priority":    rec.Priority,
		"external_id": rec.ExternalID,
		"sync_state":  rec.SyncState,
		"managed":     rec.Managed,
		"created_at":  rec.CreatedAt,
		"updated_at":  rec.UpdatedAt,
	}
}

func recordResponses(rs []dns.Record) []map[string]any {
	out := make([]map[string]any, len(rs))
	for i, r := range rs {
		out[i] = recordResponse(r)
	}
	return out
}

// certResponse never includes the private key or secret_ref.
func certResponse(c certs.Certificate) map[string]any {
	return map[string]any{
		"id":            c.ID,
		"project_id":    c.ProjectID,
		"issued_at":     c.IssuedAt,
		"not_after":     c.NotAfter,
		"identifiers":   c.Identifiers,
		"issuer":        c.Issuer,
		"serial_hex":    c.SerialHex,
		"state":         c.State,
		"replaces_id":   c.ReplacesID,
		"revoked_at":    c.RevokedAt,
		"revoke_reason": c.RevokeReason,
		"created_at":    c.CreatedAt,
		// chain_pem is public material — safe to return.
		"chain_pem": c.ChainPEM,
		// secret_ref and private_key intentionally omitted.
	}
}

func certResponses(cs []certs.Certificate) []map[string]any {
	out := make([]map[string]any, len(cs))
	for i, c := range cs {
		out[i] = certResponse(c)
	}
	return out
}

func orderResponse(o dns.Order) map[string]any {
	return map[string]any{
		"id":                  o.ID,
		"certificate_id":      o.CertificateID,
		"project_id":          o.ProjectID,
		"provider_id":         o.ProviderID,
		"identifiers":         o.Identifiers,
		"directory_url":       o.DirectoryURL,
		"state":               o.State,
		"order_url":           o.OrderURL,
		"challenge_placed_at": o.ChallengePlacedAt,
		"challenge_record_id": o.ChallengeRecordID,
		"error_message":       o.ErrorMessage,
		"expires_at":          o.ExpiresAt,
		"completed_at":        o.CompletedAt,
		"created_at":          o.CreatedAt,
		"updated_at":          o.UpdatedAt,
		// challenge_token and challenge_key_auth intentionally omitted from
		// API responses — the node agent receives them via event publishing.
	}
}

func orderResponses(os []dns.Order) []map[string]any {
	out := make([]map[string]any, len(os))
	for i, o := range os {
		out[i] = orderResponse(o)
	}
	return out
}

// ── Error mapping ──────────────────────────────────────────────────────────────

func dnsErr(err error) *apierr.Error {
	if errors.Is(err, dns.ErrNotFound) {
		return apierr.NotFound("not found")
	}
	if errors.Is(err, dns.ErrInvalid) {
		return apierr.InvalidRequest(err.Error(), nil)
	}
	if errors.Is(err, dns.ErrState) {
		return apierr.Conflict(err.Error(), nil)
	}
	if errors.Is(err, dns.ErrProviderUnavailable) {
		return apierr.ServiceUnavailable("DNS provider unavailable")
	}
	return apierr.Internal(err)
}

func tlsErr(err error) *apierr.Error {
	if errors.Is(err, certs.ErrNotFound) {
		return apierr.NotFound("not found")
	}
	if errors.Is(err, certs.ErrInvalid) {
		return apierr.InvalidRequest(err.Error(), nil)
	}
	if errors.Is(err, certs.ErrState) {
		return apierr.Conflict(err.Error(), nil)
	}
	return apierr.Internal(err)
}

// ── Crypto helpers ─────────────────────────────────────────────────────────────

// parseCertChain parses a PEM chain and returns the leaf certificate metadata.
// Gate: called before any DB write so a bad PEM never reaches the store.
func parseCertChain(chainPEM string) (leaf *x509.Certificate, issuedAt, notAfter time.Time, identifiers []string, issuer, serialHex string, err error) {
	rest := []byte(chainPEM)
	var leafBlock *pem.Block
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if leafBlock == nil {
			leafBlock = block
		}
	}
	if leafBlock == nil {
		return nil, time.Time{}, time.Time{}, nil, "", "", errors.New("no CERTIFICATE block found")
	}
	leaf, err = x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		return nil, time.Time{}, time.Time{}, nil, "", "", fmt.Errorf("parse certificate: %w", err)
	}

	identifiers = append(identifiers, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		identifiers = append(identifiers, ip.String())
	}

	// Ensure subject CN is present when no SANs exist.
	if len(identifiers) == 0 && leaf.Subject.CommonName != "" {
		identifiers = []string{leaf.Subject.CommonName}
	}

	return leaf,
		leaf.NotBefore,
		leaf.NotAfter,
		identifiers,
		leaf.Issuer.CommonName,
		leaf.SerialNumber.Text(16),
		nil
}

// validateKeyMatchesCert ensures the PEM private key matches the leaf certificate.
// Gate: "bad certificate/key pair rejected".
func validateKeyMatchesCert(privateKeyPEM string, leaf *x509.Certificate) error {
	block, _ := pem.Decode([]byte(privateKeyPEM))
	if block == nil {
		return errors.New("no PEM block found in private key")
	}
	// leaf.Raw is DER; X509KeyPair requires PEM.
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	if _, err := tls.X509KeyPair(leafPEM, []byte(privateKeyPEM)); err != nil {
		return fmt.Errorf("key does not match certificate: %w", err)
	}
	return nil
}

// ── _ unused import guard ─────────────────────────────────────────────────────
// (pool kept for future direct queries)
var _ = (*pgxpool.Pool)(nil)
