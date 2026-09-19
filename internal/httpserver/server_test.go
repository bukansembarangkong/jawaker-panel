package httpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
)

func newTestHandler(t *testing.T) (http.Handler, *bytes.Buffer) {
	t.Helper()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, nil))
	h, err := New(Options{
		Logger:         logger,
		MaxBodyBytes:   1024,
		RequestTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h, &logBuf
}

func TestNewRequiresOptions(t *testing.T) {
	if _, err := New(Options{MaxBodyBytes: 1, RequestTimeout: time.Second}); err == nil {
		t.Error("expected error when Logger is nil")
	}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	if _, err := New(Options{Logger: logger, MaxBodyBytes: 0, RequestTimeout: time.Second}); err == nil {
		t.Error("expected error when MaxBodyBytes <= 0")
	}
	if _, err := New(Options{Logger: logger, MaxBodyBytes: 1, RequestTimeout: 0}); err == nil {
		t.Error("expected error when RequestTimeout <= 0")
	}
}

func TestHealthz(t *testing.T) {
	h, _ := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q, want ok", body["status"])
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
}

func TestVersionEndpoint(t *testing.T) {
	h, _ := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/version", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body not JSON: %v", err)
	}
	for _, field := range []string{"version", "commit", "build_time"} {
		if _, ok := body[field]; !ok {
			t.Errorf("version response missing %q: %v", field, body)
		}
	}
}

func TestRequestIDGeneratedWhenAbsent(t *testing.T) {
	h, _ := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))

	id := rec.Header().Get(HeaderRequestID)
	if !strings.HasPrefix(id, "req_") {
		t.Errorf("generated request id = %q, want req_ prefix", id)
	}
}

func TestRequestIDEchoedWhenSafe(t *testing.T) {
	h, _ := newTestHandler(t)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
	req.Header.Set(HeaderRequestID, "req_client-123_abc")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get(HeaderRequestID); got != "req_client-123_abc" {
		t.Errorf("request id = %q, want echoed client id", got)
	}
}

func TestRequestIDRejectedWhenUnsafe(t *testing.T) {
	h, _ := newTestHandler(t)
	for _, bad := range []string{
		"req_<script>alert(1)</script>",               // charset violation
		"req_" + strings.Repeat("a", maxRequestIDLen), // too long
		"req_ünïcödé",                                 // non-ASCII
		"req id",                                      // space
	} {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
		req.Header.Set(HeaderRequestID, bad)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		got := rec.Header().Get(HeaderRequestID)
		if got == bad {
			t.Errorf("unsafe request id was echoed verbatim: %q", bad)
		}
		if !strings.HasPrefix(got, "req_") {
			t.Errorf("replacement id = %q, want req_ prefix", got)
		}
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	h, _ := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil))

	want := map[string]string{
		"X-Content-Type-Options":     "nosniff",
		"X-Frame-Options":            "DENY",
		"Referrer-Policy":            "no-referrer",
		"Cross-Origin-Opener-Policy": "same-origin",
	}
	for header, expected := range want {
		if got := rec.Header().Get(header); got != expected {
			t.Errorf("%s = %q, want %q", header, got, expected)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP = %q, want restrictive default-src", csp)
	}
}

func TestBodyLimitEnforced(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /echo", func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			WriteError(w, r, apierr.PayloadTooLarge(""))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	h := withRequestID(withBodyLimit(mux, 16))

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/echo", strings.NewReader(strings.Repeat("x", 64)))
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
	var env struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
		RequestID string `json:"request_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("body not JSON envelope: %v", err)
	}
	if env.Error.Code != apierr.CodePayloadTooLarge {
		t.Errorf("error code = %q, want %q", env.Error.Code, apierr.CodePayloadTooLarge)
	}
	if !strings.HasPrefix(env.RequestID, "req_") {
		t.Errorf("error envelope missing request id: %q", env.RequestID)
	}
}

func TestTimeoutReturnsCanonicalEnvelope(t *testing.T) {
	slow := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate a handler that ignores cancellation and keeps working.
		time.Sleep(300 * time.Millisecond)
		writeJSON(w, http.StatusOK, map[string]string{"late": "true"})
	})
	h := withRequestID(withTimeout(slow, 20*time.Millisecond))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/slow", nil))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	var env struct {
		Error struct {
			Code      string `json:"code"`
			Retryable bool   `json:"retryable"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
		t.Fatalf("body not JSON envelope: %v", err)
	}
	if env.Error.Code != apierr.CodeServiceUnavailable || !env.Error.Retryable {
		t.Errorf("envelope = %+v, want retryable service_unavailable", env.Error)
	}
	if strings.Contains(rec.Body.String(), "late") {
		t.Error("timed-out handler output must not reach the client")
	}
}

func TestPanicRecoveryReturnsInternalEnvelope(t *testing.T) {
	h, logBuf := newTestHandler(t)

	crashy := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("synthetic test panic")
	})
	// Re-wrap: reuse the production chain with a crashing terminal handler.
	wrapped := withRequestID(withRecovery(crashy, slog.New(slog.NewJSONHandler(logBuf, nil))))

	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/crash", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "synthetic test panic") {
		t.Error("panic detail must not leak to the client")
	}
	if !strings.Contains(logBuf.String(), "panic recovered") {
		t.Error("panic must be logged server-side")
	}
	// The outer handler built by New also has recovery; ensure it exists.
	if h == nil {
		t.Fatal("handler is nil")
	}
}

func TestLoggingEmitsCorrelatedRecord(t *testing.T) {
	h, logBuf := newTestHandler(t)
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
	req.Header.Set(HeaderRequestID, "req_logcheck")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(logBuf.Bytes()), &record); err != nil {
		t.Fatalf("log output not JSON: %v (raw=%q)", err, logBuf.String())
	}
	if record["request_id"] != "req_logcheck" {
		t.Errorf("log request_id = %v, want req_logcheck", record["request_id"])
	}
	if record["method"] != "GET" || record["path"] != "/healthz" {
		t.Errorf("log record missing method/path: %v", record)
	}
	if record["status"] != float64(200) {
		t.Errorf("log status = %v, want 200", record["status"])
	}
}

func TestNotFoundUsesStdlibMuxBehavior(t *testing.T) {
	h, _ := newTestHandler(t)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/does-not-exist", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
}

func TestWriteErrorStampsRequestID(t *testing.T) {
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/x", nil)
	req = req.WithContext(context.WithValue(req.Context(), requestIDKey{}, "req_stamp"))
	rec := httptest.NewRecorder()
	WriteError(rec, req, apierr.Forbidden("denied"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "req_stamp") {
		t.Errorf("envelope missing request id: %s", rec.Body.String())
	}
}

func TestIsSafeRequestID(t *testing.T) {
	valid := []string{"req_abc", "a", strings.Repeat("a", maxRequestIDLen), "ABC-123_x"}
	for _, id := range valid {
		if !isSafeRequestID(id) {
			t.Errorf("isSafeRequestID(%q) = false, want true", id)
		}
	}
	invalid := []string{"", strings.Repeat("a", maxRequestIDLen+1), "a b", "a\nb", "héllo"}
	for _, id := range invalid {
		if isSafeRequestID(id) {
			t.Errorf("isSafeRequestID(%q) = true, want false", id)
		}
	}
}

func TestNewRequestIDUniqueness(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		id := newRequestID()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate request id generated: %q", id)
		}
		seen[id] = struct{}{}
	}
}
