// Package httpserver builds the controller HTTP surface.
//
// Phase 0 scope: health, version, hardened middleware chain, and the shared
// response/error helpers every later handler will use. Stdlib net/http only
// (Go 1.22+ patterns); no router dependency.
package httpserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/logging"
	"github.com/bukansembarangkong/jawaker-panel/internal/version"
)

// HeaderRequestID is the correlation header exchanged with clients (API.md §6).
const HeaderRequestID = "X-Request-ID"

// maxRequestIDLen bounds client-supplied request IDs (header hygiene).
const maxRequestIDLen = 128

// Options configures New.
type Options struct {
	// Logger receives request-scoped logs; required.
	Logger *slog.Logger
	// MaxBodyBytes bounds request bodies; required, > 0.
	MaxBodyBytes int64
	// RequestTimeout bounds handler execution; required, > 0.
	RequestTimeout time.Duration
	// RegisterRoutes lets callers mount feature routes on the SAME mux, so they
	// share the middleware chain below. It is optional.
	//
	// The indirection exists because feature packages import this one (for
	// WriteError and the request-ID helpers), so this package cannot import
	// them back.
	RegisterRoutes func(mux *http.ServeMux)
}

// New returns the fully wired controller handler (routes + middleware).
func New(opts Options) (http.Handler, error) {
	if opts.Logger == nil {
		return nil, errors.New("httpserver: Logger is required")
	}
	if opts.MaxBodyBytes <= 0 {
		return nil, errors.New("httpserver: MaxBodyBytes must be positive")
	}
	if opts.RequestTimeout <= 0 {
		return nil, errors.New("httpserver: RequestTimeout must be positive")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handleHealthz())
	mux.HandleFunc("GET /api/v1/version", handleVersion())
	if opts.RegisterRoutes != nil {
		opts.RegisterRoutes(mux)
	}

	var handler http.Handler = mux
	// Order matters: withRequestID runs OUTSIDE withLogging so every log
	// record already carries the correlation ID.
	handler = withLogging(handler, opts.Logger)
	handler = withRequestID(handler)
	handler = withSecurityHeaders(handler)
	handler = withBodyLimit(handler, opts.MaxBodyBytes)
	handler = withTimeout(handler, opts.RequestTimeout)
	// Recovery outermost: a panicking handler must never kill the process,
	// and the client still receives the canonical error envelope.
	handler = withRecovery(handler, opts.Logger)
	return handler, nil
}

func handleHealthz() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	}
}

func handleVersion() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, version.Get())
	}
}

// writeJSON serializes v with the canonical content type.
func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		// Only possible for unsupported types — a programming error.
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// WriteError renders the canonical error envelope (API.md §8), stamping the
// request correlation ID when present in the request context.
func WriteError(w http.ResponseWriter, r *http.Request, apiErr *apierr.Error) {
	if requestID := RequestIDFromRequest(r); requestID != "" {
		apiErr = apiErr.WithRequestID(requestID)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(apiErr.Status)
	_ = json.NewEncoder(w).Encode(apiErr)
}

// --- Middleware --------------------------------------------------------------

type requestIDKey struct{}

// withRequestID assigns or echoes a correlation ID and exposes it via
// context + response header. Client-supplied IDs are length-bounded and
// restricted to a safe charset to keep logs clean.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(HeaderRequestID)
		if !isSafeRequestID(id) {
			id = newRequestID()
		}
		w.Header().Set(HeaderRequestID, id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id)))
	})
}

// RequestIDFromRequest extracts the correlation ID from a request context.
func RequestIDFromRequest(r *http.Request) string {
	if id, ok := r.Context().Value(requestIDKey{}).(string); ok {
		return id
	}
	return ""
}

func isSafeRequestID(id string) bool {
	if id == "" || len(id) > maxRequestIDLen {
		return false
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_':
		default:
			return false
		}
	}
	return true
}

// newRequestID generates a 16-byte random hex ID with the req_ prefix.
// crypto/rand failure means a broken environment; fall back to a
// timestamp-based ID rather than dropping correlation entirely.
func newRequestID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "req_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	return "req_" + hex.EncodeToString(buf)
}

// withLogging emits one structured record per request with method, path,
// status, duration, and the correlation ID.
func withLogging(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)

		level := slog.LevelInfo
		switch {
		case rec.status >= 500:
			level = slog.LevelError
		case rec.status >= 400:
			level = slog.LevelWarn
		}
		logger.Log(r.Context(), level, "http request",
			logging.AttrRequestID, RequestIDFromRequest(r),
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"bytes", rec.bytesWritten,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", clientAddr(r),
		)
	})
}

// clientAddr extracts the host from RemoteAddr without trusting proxy headers
// (SECURITY.md §10: do not trust arbitrary forwarded headers; trusted-proxy
// handling arrives with the network phase).
func clientAddr(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

type statusRecorder struct {
	http.ResponseWriter
	status       int
	bytesWritten int
	wroteHeader  bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
		s.ResponseWriter.WriteHeader(code)
	}
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.WriteHeader(http.StatusOK)
	n, err := s.ResponseWriter.Write(b)
	s.bytesWritten += n
	return n, err
}

// withSecurityHeaders applies baseline hardening headers to every response.
func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		// HSTS only matters over TLS; harmless on plain HTTP during dev.
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// withBodyLimit enforces the global request body bound (API.md §18).
func withBodyLimit(next http.Handler, maxBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// withTimeout bounds handler execution (AGENTS.md §6: every operation needs
// timeout/cancellation).
//
// The downstream handler writes into an in-memory buffer; only after it
// returns is the buffer flushed to the real ResponseWriter. If the deadline
// fires first, the canonical 503 envelope is written instead and the buffered
// output is discarded. This keeps a single writer on the live response and
// avoids data races with a slow handler (same model as http.TimeoutHandler).
// Phase 0 responses are small JSON payloads; streaming routes (SSE, logs)
// will opt out of this middleware when they arrive in Phase 1.
func withTimeout(next http.Handler, timeout time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		buf := &bufferedResponse{header: make(http.Header), status: http.StatusOK}
		done := make(chan struct{})
		go func() {
			defer close(done)
			next.ServeHTTP(buf, r.WithContext(ctx))
		}()

		select {
		case <-done:
			buf.flush(w)
		case <-ctx.Done():
			if ctx.Err() == context.DeadlineExceeded {
				WriteError(w, r.WithContext(ctx), apierr.ServiceUnavailable("The request timed out."))
			}
			// Do not wait for the handler: its context is canceled, so it
			// should stop promptly; its buffered output is discarded.
		}
	})
}

// bufferedResponse captures a handler's output for the timeout middleware.
type bufferedResponse struct {
	header      http.Header
	body        bytes.Buffer
	status      int
	wroteHeader bool
}

func (b *bufferedResponse) Header() http.Header { return b.header }

func (b *bufferedResponse) WriteHeader(code int) {
	if !b.wroteHeader {
		b.status = code
		b.wroteHeader = true
	}
}

func (b *bufferedResponse) Write(p []byte) (int, error) {
	b.WriteHeader(http.StatusOK)
	return b.body.Write(p)
}

// flush copies the buffered response to the real writer.
func (b *bufferedResponse) flush(w http.ResponseWriter) {
	dst := w.Header()
	for k, vs := range b.header {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
	w.WriteHeader(b.status)
	_, _ = w.Write(b.body.Bytes())
}

// withRecovery converts panics into logged 500 envelopes.
func withRecovery(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				logger.Error("panic recovered",
					logging.AttrRequestID, RequestIDFromRequest(r),
					"panic", v,
					"method", r.Method,
					"path", r.URL.Path,
				)
				WriteError(w, r, apierr.Internal(errors.New("panic")))
			}
		}()
		next.ServeHTTP(w, r)
	})
}
