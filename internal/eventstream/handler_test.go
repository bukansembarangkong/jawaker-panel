package eventstream

import (
	"bufio"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// NewHandler refuses to build without an authorize function: an unguarded stream
// is how one user's events reach another user's browser, and that must be a
// construction-time failure rather than a runtime oversight.
func TestNewHandlerRequiresBrokerAndAuthorize(t *testing.T) {
	b := New(Options{})
	defer b.Close()

	if _, err := NewHandler(HandlerOptions{Authorize: func(*http.Request, string) bool { return true }}); err == nil {
		t.Error("NewHandler without a broker succeeded")
	}
	if _, err := NewHandler(HandlerOptions{Broker: b}); err == nil {
		t.Error("NewHandler without Authorize succeeded; an unguarded stream would leak events")
	}
}

// A denied subscription must be a 403 BEFORE any stream header is written. Once
// 200 text/event-stream is on the wire a client library treats the connection as
// established and reconnects, turning an authorization failure into a loop.
func TestHandlerDeniesUnauthorizedBeforeStreaming(t *testing.T) {
	b := New(Options{})
	defer b.Close()

	h, err := NewHandler(HandlerOptions{
		Broker:    b,
		Authorize: func(*http.Request, string) bool { return false },
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/user:abc", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); strings.Contains(ct, "text/event-stream") {
		t.Errorf("a denied request set the stream content type %q", ct)
	}
}

func TestHandlerRejectsBadTopic(t *testing.T) {
	b := New(Options{})
	defer b.Close()

	h, err := NewHandler(HandlerOptions{Broker: b, Authorize: allowAll})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	cases := map[string]string{
		"empty":   "/api/v1/events/",
		"invalid": "/api/v1/events/bad%20topic",
	}
	for label, path := range cases {
		t.Run(label, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", rec.Code)
			}
		})
	}
}

func TestHandlerRejectsBadLastEventID(t *testing.T) {
	b := New(Options{})
	defer b.Close()

	h, err := NewHandler(HandlerOptions{Broker: b, Authorize: allowAll})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/jobs", nil)
	req.Header.Set("Last-Event-ID", "not-a-number")
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// The happy path: the stream connects, emits the connected comment, then the
// published event, all flushed. Driven through a real httptest server so the
// Flusher interface is present, exactly as it is under a real server.
func TestHandlerStreamsPublishedEvent(t *testing.T) {
	b := New(Options{Heartbeat: time.Hour})
	defer b.Close()

	h, err := NewHandler(HandlerOptions{Broker: b, Authorize: allowAll})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/events/jobs", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET stream: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Errorf("content-type = %q, want text/event-stream", ct)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("cache-control = %q, want no-store", resp.Header.Get("Cache-Control"))
	}

	reader := bufio.NewReader(resp.Body)
	// The connected comment arrives first, so a client's onopen fires without
	// waiting for real data.
	if line := readLine(t, reader); !strings.HasPrefix(line, ": connected") {
		t.Errorf("first line = %q, want the connected comment", line)
	}
	// Consume the blank line ending the comment frame.
	readLine(t, reader)

	// Publish and expect the frame to arrive on the open stream.
	if _, err := b.PublishJSON(ctx, "jobs", "job.progress", map[string]any{"step": 1}); err != nil {
		t.Fatalf("PublishJSON: %v", err)
	}
	frame := readFrame(t, reader)
	if !strings.Contains(frame, "event: job.progress") {
		t.Errorf("frame = %q, want event: job.progress", frame)
	}
	if !strings.Contains(frame, `"step":1`) {
		t.Errorf("frame = %q, want the payload", frame)
	}
}

// A client that sends Last-Event-ID resumes: the stream replays the gap before
// any new event, proving the reconnect path is wired to the replay buffer.
func TestHandlerResumesFromLastEventID(t *testing.T) {
	b := New(Options{ReplayBuffer: 10, Heartbeat: time.Hour})
	defer b.Close()

	// Publish before any subscriber exists.
	for i := 0; i < 3; i++ {
		if _, err := b.Publish("jobs", "job.progress", []byte("{}")); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}

	h, err := NewHandler(HandlerOptions{Broker: b, Authorize: allowAll})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+"/api/v1/events/jobs", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Last-Event-ID", "1") // seen id 1, expect 2 and 3 replayed
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET stream: %v", err)
	}
	defer resp.Body.Close()

	reader := bufio.NewReader(resp.Body)
	readLine(t, reader) // ": connected"
	readLine(t, reader) // blank

	seen := map[uint64]bool{}
	for i := 0; i < 2; i++ {
		frame := readFrame(t, reader)
		for _, id := range []uint64{2, 3} {
			if strings.Contains(frame, "id: "+strconv.FormatUint(id, 10)) {
				seen[id] = true
			}
		}
	}
	if !seen[2] || !seen[3] {
		t.Errorf("resumed stream did not replay ids 2 and 3 (seen %v)", seen)
	}
}

// The authorize callback receives the resolved topic, because per-user topics can
// only be checked by someone who knows which user asked and which topic it is.
func TestAuthorizeReceivesTopic(t *testing.T) {
	b := New(Options{})
	defer b.Close()

	var mu sync.Mutex
	var gotTopics []string
	h, err := NewHandler(HandlerOptions{
		Broker: b,
		Authorize: func(_ *http.Request, topic string) bool {
			mu.Lock()
			gotTopics = append(gotTopics, topic)
			mu.Unlock()
			return false // deny fast so the handler returns immediately
		},
	})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	for _, topic := range []string{"user:abc", "jobs"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/"+topic, nil)
		h.ServeHTTP(rec, req)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(gotTopics) != 2 || gotTopics[0] != "user:abc" || gotTopics[1] != "jobs" {
		t.Errorf("authorize saw topics %v, want [user:abc jobs]", gotTopics)
	}
}

func TestLastEventIDParsing(t *testing.T) {
	cases := []struct {
		header, query string
		want          uint64
		wantErr       bool
	}{
		{"", "", 0, false},
		{"5", "", 5, false},
		{"", "9", 9, false},
		{"7", "3", 7, false}, // header wins: the browser sets it on reconnect
		{"x", "", 0, true},
		{"", "y", 0, true},
		{"-1", "", 0, true}, // not a valid uint
	}
	for _, tc := range cases {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/api/v1/events/jobs", nil)
		if tc.header != "" {
			req.Header.Set("Last-Event-ID", tc.header)
		}
		if tc.query != "" {
			q := req.URL.Query()
			q.Set("last_event_id", tc.query)
			req.URL.RawQuery = q.Encode()
		}
		got, err := lastEventID(req)
		if tc.wantErr {
			if err == nil {
				t.Errorf("lastEventID(%q,%q) = %d, want an error", tc.header, tc.query, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("lastEventID(%q,%q) errored: %v", tc.header, tc.query, err)
			continue
		}
		if got != tc.want {
			t.Errorf("lastEventID(%q,%q) = %d, want %d", tc.header, tc.query, got, tc.want)
		}
	}
}

func allowAll(*http.Request, string) bool { return true }

// readLine reads one line, failing the test on timeout rather than hanging.
func readLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	type lineResult struct {
		line string
		err  error
	}
	ch := make(chan lineResult, 1)
	go func() {
		line, err := r.ReadString('\n')
		ch <- lineResult{line, err}
	}()
	select {
	case res := <-ch:
		if res.err != nil && !errors.Is(res.err, context.Canceled) {
			t.Fatalf("read line: %v", res.err)
		}
		return strings.TrimRight(res.line, "\r\n")
	case <-time.After(3 * time.Second):
		t.Fatal("timed out reading a stream line")
		return ""
	}
}

// readFrame consumes lines until the blank line that terminates an SSE event,
// returning the joined frame.
func readFrame(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	var sb strings.Builder
	for {
		line := readLine(t, r)
		if line == "" {
			return sb.String()
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}
}
