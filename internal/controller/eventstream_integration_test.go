//go:build integration

package controller

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// bootstrapOwner creates the platform owner and returns its user id.
func bootstrapOwner(t *testing.T, h *harness) string {
	t.Helper()
	token, _ := h.csrf()
	resp := h.csrfPost("/api/v1/auth/bootstrap",
		`{"email":"owner@example.test","display_name":"Owner","password":"correct horse battery staple"}`, token)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("bootstrap status = %d", resp.StatusCode)
	}
	var id string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT id::text FROM users WHERE is_owner`).Scan(&id); err != nil {
		t.Fatalf("read owner id: %v", err)
	}
	return id
}

// login logs the owner in on the harness client, leaving its cookie jar
// authenticated.
func loginOwner(t *testing.T, h *harness) {
	t.Helper()
	token, _ := h.csrf()
	resp := h.csrfPost("/api/v1/auth/login",
		`{"email":"owner@example.test","password":"correct horse battery staple"}`, token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", resp.StatusCode)
	}
}

// openStream starts an SSE request and returns the reader plus the response. The
// caller closes the body. A context with a deadline is attached so a test that
// never finishes cannot hang the suite.
func openStream(t *testing.T, h *harness, path string) (*bufio.Reader, *http.Response) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, h.server.URL+path, nil)
	if err != nil {
		t.Fatalf("new stream request: %v", err)
	}
	// The client carries the authenticated cookie jar.
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return bufio.NewReader(resp.Body), resp
}

func readStreamLine(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := r.ReadString('\n')
		ch <- result{line, err}
	}()
	select {
	case res := <-ch:
		// io.EOF is a normal end-of-stream, and the final line may still carry
		// data (the 403 JSON envelope has no trailing newline). Any other error
		// is a real failure.
		if res.err != nil && !errors.Is(res.err, io.EOF) {
			t.Fatalf("read stream line: %v", res.err)
		}
		return strings.TrimRight(res.line, "\r\n")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out reading a stream line")
		return ""
	}
}

func readStreamFrame(t *testing.T, r *bufio.Reader) string {
	t.Helper()
	var sb strings.Builder
	for {
		line := readStreamLine(t, r)
		if line == "" {
			return sb.String()
		}
		sb.WriteString(line)
		sb.WriteString("\n")
	}
}

// The Phase 1 promise, end to end: an authenticated session opens a live stream,
// a publisher emits an event on that topic, and the event arrives on the open
// connection. This is the wiring that unit tests cannot prove.
func TestEventStreamDeliversToAuthenticatedSession(t *testing.T) {
	h := newHarness(t, nil)
	bootstrapOwner(t, h)
	loginOwner(t, h)

	reader, resp := openStream(t, h, "/api/v1/events/jobs")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/event-stream") {
		t.Fatalf("content-type = %q, want text/event-stream", ct)
	}
	// The connected comment proves the headers reached the client without
	// waiting for a real event.
	if line := readStreamLine(t, reader); !strings.HasPrefix(line, ": connected") {
		t.Fatalf("first line = %q, want the connected comment", line)
	}
	readStreamLine(t, reader) // blank line ending the comment frame

	// Publishing through the broker the CONTROLLER built — not a test broker —
	// is what proves the wired broker is the one serving the stream.
	if _, err := h.events.PublishJSON(context.Background(), "jobs", "job.progress",
		map[string]any{"job_id": "abc", "progress": 40}); err != nil {
		t.Fatalf("PublishJSON: %v", err)
	}

	frame := readStreamFrame(t, reader)
	if !strings.Contains(frame, "event: job.progress") {
		t.Errorf("frame = %q, want the job.progress event", frame)
	}
	if !strings.Contains(frame, `"progress":40`) {
		t.Errorf("frame = %q, want the payload", frame)
	}
}

// The stream must be exactly as protected as the API: no session, no stream.
func TestEventStreamRequiresAuthentication(t *testing.T) {
	h := newHarness(t, nil)
	bootstrapOwner(t, h)
	// Deliberately NOT logging in: the harness client has the CSRF cookie but no
	// session cookie.

	reader, resp := openStream(t, h, "/api/v1/events/jobs")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unauthenticated stream status = %d, want 403", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "text/event-stream") {
		t.Errorf("a denied stream set the stream content type %q; the client would keep reconnecting", ct)
	}
	// The error envelope arrives as JSON, not as an empty stream.
	frame := readStreamFrame(t, reader)
	if !strings.Contains(frame, "forbidden") {
		t.Errorf("denied stream body = %q, want the forbidden envelope", frame)
	}
}

// A user must not read another user's personal stream, even authenticated with a
// generous role: that is a cross-tenant read.
func TestEventStreamRejectsAnotherUsersPersonalTopic(t *testing.T) {
	h := newHarness(t, nil)
	bootstrapOwner(t, h)
	loginOwner(t, h)

	// The owner's own topic is allowed.
	_, resp := openStream(t, h, "/api/v1/events/user:"+otherUserID(t, h))
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("streaming another user's topic = %d, want 403", resp.StatusCode)
	}
}

// otherUserID finds an id that is NOT the owner's, so the cross-tenant test has
// a real target rather than a made-up uuid.
func otherUserID(t *testing.T, h *harness) string {
	t.Helper()
	var ownerID string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT id::text FROM users WHERE is_owner`).Scan(&ownerID); err != nil {
		t.Fatalf("read owner id: %v", err)
	}
	// Create a second user so the id is real and definitely not the session's.
	var otherID string
	if err := h.pool.QueryRow(context.Background(), `
		INSERT INTO users (email, display_name, account_type)
		VALUES ('other@example.test', 'Other', 'customer')
		RETURNING id::text`).Scan(&otherID); err != nil {
		t.Fatalf("seed second user: %v", err)
	}
	if otherID == ownerID {
		t.Fatal("seeded user has the owner's id")
	}
	return otherID
}

// The owner may subscribe to their own personal stream.
func TestEventStreamAllowsOwnerPersonalTopic(t *testing.T) {
	h := newHarness(t, nil)
	ownerID := bootstrapOwner(t, h)
	loginOwner(t, h)

	_, resp := openStream(t, h, "/api/v1/events/user:"+ownerID)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("owner's own stream status = %d, want 200", resp.StatusCode)
	}
}

// An unknown topic fails closed rather than streaming silence, because a stream
// that carries nothing is indistinguishable from a quiet system.
func TestEventStreamRejectsUnknownTopic(t *testing.T) {
	h := newHarness(t, nil)
	bootstrapOwner(t, h)
	loginOwner(t, h)

	_, resp := openStream(t, h, "/api/v1/events/not-a-real-topic")
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("unknown topic status = %d, want 403", resp.StatusCode)
	}
}
