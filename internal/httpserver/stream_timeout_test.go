package httpserver

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The buffering timeout delivers a response only after the handler returns. For a
// streaming route that means the client sees nothing until it disconnects, which
// is the exact failure StreamPathPrefixes exists to prevent. This test proves the
// opt-out is real: a stream under a streaming prefix keeps emitting, and the same
// handler under a normal prefix is buffered and cut off by the deadline.
func TestStreamPathPrefixBypassesBufferingTimeout(t *testing.T) {
	// Three frames, one per 30ms, then stop. Under a 50ms buffering timeout a
	// non-streaming route cannot finish in time; a streaming prefix is handed
	// the real writer and streams all three.
	streamHandler := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for i := 0; i < 3; i++ {
			_, _ = io.WriteString(w, "data: frame\n\n")
			if flusher != nil {
				flusher.Flush()
			}
			time.Sleep(30 * time.Millisecond)
		}
	}

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	handler, err := New(Options{
		Logger:         logger,
		MaxBodyBytes:   1 << 20,
		RequestTimeout: 50 * time.Millisecond,
		RegisterRoutes: func(mux *http.ServeMux) {
			mux.HandleFunc("GET /stream/x", streamHandler)
			mux.HandleFunc("GET /buffered/x", streamHandler)
		},
		StreamPathPrefixes: []string{"/stream/"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// A real server, so flushing and streaming behave as in production.
	srv := httptest.NewServer(handler)
	defer srv.Close()

	client := srv.Client()
	// get performs the request and fully drains/closes the body, returning the
	// status and bytes. The response itself never escapes the helper so there is
	// no body left for a caller to leak.
	get := func(t *testing.T, path string) (int, []byte) {
		t.Helper()
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
		if err != nil {
			t.Fatalf("new request %s: %v", path, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		if err := resp.Body.Close(); err != nil {
			t.Errorf("close body %s: %v", path, err)
		}
		return resp.StatusCode, body
	}

	// Streaming prefix: all three frames arrive despite exceeding the timeout.
	status, body := get(t, "/stream/x")
	if status != http.StatusOK {
		t.Errorf("stream status = %d, want 200", status)
	}
	if got := strings.Count(string(body), "data: frame"); got != 3 {
		t.Errorf("stream delivered %d frames, want 3 (the timeout must not buffer a streaming route)", got)
	}

	// Non-streaming prefix: buffered, so the deadline fires first and the client
	// gets the canonical 503 rather than a partial body.
	status2, body2 := get(t, "/buffered/x")
	if status2 != http.StatusServiceUnavailable {
		t.Errorf("buffered status = %d, want 503 (the deadline should have fired)", status2)
	}
	if strings.Contains(string(body2), "data: frame") {
		t.Errorf("a timed-out buffered route leaked its partial body: %q", body2)
	}
}

// With no streaming prefixes configured, every route keeps the buffering
// timeout. This guards against the opt-out accidentally disabling it for
// everything.
func TestNoStreamPrefixesKeepsTimeoutForAll(t *testing.T) {
	slow := func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(120 * time.Millisecond)
		_, _ = io.WriteString(w, "late")
	}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	handler, err := New(Options{
		Logger:         logger,
		MaxBodyBytes:   1 << 20,
		RequestTimeout: 30 * time.Millisecond,
		RegisterRoutes: func(mux *http.ServeMux) {
			mux.HandleFunc("GET /slow", slow)
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/slow", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "late") {
		t.Error("timed-out output reached the client")
	}
}

// A prefix matches literally, so a route cannot opt out of the timeout by
// shaping a path that merely contains a streaming route's name.
func TestStreamPrefixMatchesLiterally(t *testing.T) {
	reached := false
	slow := func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		time.Sleep(80 * time.Millisecond)
		_, _ = io.WriteString(w, "late")
	}
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	handler, err := New(Options{
		Logger:         logger,
		MaxBodyBytes:   1 << 20,
		RequestTimeout: 20 * time.Millisecond,
		RegisterRoutes: func(mux *http.ServeMux) {
			// Note the different path: it is not under /api/v1/events/.
			mux.HandleFunc("GET /api/v1/fake-events/x", slow)
		},
		StreamPathPrefixes: []string{"/api/v1/events/"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/fake-events/x", nil))
	if !reached {
		t.Fatal("handler was not invoked")
	}
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503: a non-matching path must keep the timeout", rec.Code)
	}
}
