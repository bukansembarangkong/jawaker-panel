//go:build integration

package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"testing"
	"time"
)

// generateTestCertAndKey creates a minimal valid self-signed cert and key in PEM.
func generateTestCertAndKey(t *testing.T, domain string) (certPEM, keyPEM string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1001),
		Subject: pkix.Name{
			CommonName: domain,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{domain},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	keyBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}))
	return certPEM, keyPEM
}

func TestDNSTLSUnauthenticated(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	var projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('dns-unauth', 'DNS Unauth', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	routes := []struct{ method, path string }{
		{"GET", fmt.Sprintf("/api/v1/projects/%s/dns-providers", projectID)},
		{"GET", fmt.Sprintf("/api/v1/projects/%s/dns-zones", projectID)},
		{"GET", fmt.Sprintf("/api/v1/projects/%s/certificates", projectID)},
		{"GET", fmt.Sprintf("/api/v1/projects/%s/cert-orders", projectID)},
	}
	for _, tc := range routes {
		resp := h.doRaw(tc.method, tc.path, "", nil)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s unauthenticated = %d, want 401", tc.method, tc.path, resp.StatusCode)
		}
	}
}

func TestDNSProviderLifecycleAndTokenRedaction(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('dns-prov', 'DNS Prov', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	body := `{"name":"cloudflare-main","provider":"cloudflare","token":"secret-cf-token-value-12345"}`
	resp := h.post(t, fmt.Sprintf("/api/v1/projects/%s/dns-providers", projectID), body)
	if resp.StatusCode != http.StatusCreated {
		var errBody map[string]any
		decodeBody(t, resp, &errBody)
		t.Fatalf("create provider = %d, body: %v", resp.StatusCode, errBody)
	}

	var created struct {
		Provider map[string]any `json:"provider"`
	}
	decodeBody(t, resp, &created)
	provID, _ := created.Provider["id"].(string)
	if provID == "" {
		t.Fatal("expected provider ID")
	}

	// Gate: sensitive credentials redacted — secret_ref and token must NOT be returned.
	if _, present := created.Provider["secret_ref"]; present {
		t.Error("secret_ref leaked in create response")
	}
	if _, present := created.Provider["token"]; present {
		t.Error("token leaked in create response")
	}

	// Verify GET also redacts.
	getResp := h.do("GET", fmt.Sprintf("/api/v1/projects/%s/dns-providers/%s", projectID, provID), "", nil)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get provider = %d, want 200", getResp.StatusCode)
	}
	var got struct {
		Provider map[string]any `json:"provider"`
	}
	decodeBody(t, getResp, &got)
	if _, present := got.Provider["secret_ref"]; present {
		t.Error("secret_ref leaked in get response")
	}

	// Verify DELETE removes provider.
	delResp := h.csrfDo(t, http.MethodDelete, fmt.Sprintf("/api/v1/projects/%s/dns-providers/%s", projectID, provID), "")
	if delResp.StatusCode != http.StatusNoContent {
		t.Errorf("delete provider = %d, want 204", delResp.StatusCode)
	}
}

func TestCertificateImportValidation(t *testing.T) {
	h := newHarness(t, nil)
	h.bootstrapOwner(t)
	ctx := context.Background()

	var projectID string
	if err := h.pool.QueryRow(ctx,
		`INSERT INTO projects (slug, name, state) VALUES ('tls-cert', 'TLS Cert', 'active') RETURNING id`,
	).Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}

	certPEM, keyPEM := generateTestCertAndKey(t, "example.com")
	_, otherKeyPEM := generateTestCertAndKey(t, "other.com")

	importURL := fmt.Sprintf("/api/v1/projects/%s/certificates/import", projectID)

	// Gate 2: Bad PEM chain rejected before database write.
	badChainPayload, _ := json.Marshal(map[string]string{
		"chain_pem":       "NOT A REAL PEM",
		"private_key_pem": keyPEM,
	})
	resp := h.post(t, importURL, string(badChainPayload))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("import bad chain = %d, want 400", resp.StatusCode)
	}

	// Gate 2: Mismatched key/certificate pair rejected.
	mismatchedPayload, _ := json.Marshal(map[string]string{
		"chain_pem":       certPEM,
		"private_key_pem": otherKeyPEM,
	})
	resp = h.post(t, importURL, string(mismatchedPayload))
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("import mismatched key = %d, want 400", resp.StatusCode)
	}

	// Valid certificate imported successfully.
	validPayload, _ := json.Marshal(map[string]string{
		"chain_pem":       certPEM,
		"private_key_pem": keyPEM,
	})
	resp = h.post(t, importURL, string(validPayload))
	if resp.StatusCode != http.StatusCreated {
		var errBody map[string]any
		decodeBody(t, resp, &errBody)
		t.Fatalf("import valid cert = %d, body: %v", resp.StatusCode, errBody)
	}

	var imported struct {
		Certificate map[string]any `json:"certificate"`
	}
	decodeBody(t, resp, &imported)
	certID, _ := imported.Certificate["id"].(string)
	if certID == "" {
		t.Fatal("expected cert ID in imported response")
	}

	// Gate: private_key is NEVER returned in response.
	if _, present := imported.Certificate["private_key"]; present {
		t.Error("private_key leaked in imported cert response")
	}
	if _, present := imported.Certificate["private_key_pem"]; present {
		t.Error("private_key_pem leaked in imported cert response")
	}
}
