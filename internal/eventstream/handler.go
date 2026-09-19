package eventstream

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
)

// HandlerOptions configures the SSE endpoint.
type HandlerOptions struct {
	// Broker is the fan-out. Required.
	Broker *Broker
	// Authorize decides whether this request may subscribe to this topic.
	//
	// It is a function rather than a permission constant because the answer is
	// per-topic: subscribing to "user:abc" is only legitimate for user abc, and
	// the check has to know which topic was asked for. Returning false yields a
	// 403, never an empty stream — a stream that silently carries nothing is the
	// failure mode that hides an authorization bug.
	Authorize func(r *http.Request, topic string) bool
}

// Handler serves the SSE endpoint.
type Handler struct {
	broker    *Broker
	authorize func(r *http.Request, topic string) bool
}

// NewHandler validates options and returns a Handler.
func NewHandler(opts HandlerOptions) (*Handler, error) {
	if opts.Broker == nil {
		return nil, errors.New("eventstream: broker is required")
	}
	if opts.Authorize == nil {
		return nil, errors.New("eventstream: Authorize is required; an unguarded stream leaks another user's events")
	}
	return &Handler{broker: opts.Broker, authorize: opts.Authorize}, nil
}

// ServeHTTP streams one topic.
//
// The route is GET /api/v1/events/{topic}; a topic key may contain a colon
// ("user:<id>"), so it is taken as the whole remainder of the path rather than a
// single segment.
//
// Authorization failure is a 403 before any stream header is written. That order
// matters: once 200 and text/event-stream are on the wire, a client library
// treats the connection as established and will reconnect, and the error becomes
// a retry loop instead of a message.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	topic := strings.TrimPrefix(r.URL.Path, "/api/v1/events/")
	if topic == "" {
		httpserver.WriteError(w, r, apierr.InvalidRequest("A topic is required.", nil))
		return
	}
	if !validTopic(topic) {
		httpserver.WriteError(w, r, apierr.InvalidRequest("The topic is not valid.", nil))
		return
	}
	if !h.authorize(r, topic) {
		// Denied, and deliberately without detail: naming what exists would let
		// an unauthorized caller enumerate other users' topics.
		httpserver.WriteError(w, r, apierr.Forbidden("You do not have access to this stream."))
		return
	}

	sinceID, err := lastEventID(r)
	if err != nil {
		httpserver.WriteError(w, r, apierr.InvalidRequest("Last-Event-ID is not valid.", nil))
		return
	}

	sub, err := h.broker.Subscribe(topic, sinceID)
	if err != nil {
		if errors.Is(err, ErrTooManySubscribers) {
			httpserver.WriteError(w, r, apierr.TooManyRequests(
				"Too many open streams. Close another tab or try again later.", 0))
			return
		}
		httpserver.WriteError(w, r, apierr.ServiceUnavailable("The event stream is unavailable."))
		return
	}
	defer sub.Close()

	flusher, ok := w.(http.Flusher)
	if !ok {
		// Without flushing, events accumulate in a buffer and a live stream is
		// not live. Every server this runs on supports it; a middleware that
		// does not is a deployment bug worth reporting rather than working
		// around silently.
		httpserver.WriteError(w, r, apierr.Internal(errors.New("response writer does not support flushing")))
		return
	}

	write := sseWriter(w, flusher)

	// A first comment establishes the connection immediately, so a client's
	// onopen fires without waiting for the first real event.
	if err := write(": connected\n\n"); err != nil {
		return
	}

	// The request context is the client's: when the browser closes the tab, it is
	// canceled and the subscription ends. No separate liveness check is needed.
	_ = sub.Run(r.Context(), write)
}

// sseWriter returns a frame writer that flushes each frame.
func sseWriter(w http.ResponseWriter, flusher http.Flusher) func(string) error {
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-store")
	h.Set("Connection", "keep-alive")
	// Proxies that buffer responses turn a live stream into a batch delivery at
	// disconnect. These headers ask them not to.
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	return func(frame string) error {
		if _, err := fmt.Fprint(w, frame); err != nil {
			return err
		}
		flusher.Flush()
		return nil
	}
}

// lastEventID reads the resume position. The browser sends it in the
// Last-Event-ID header on its own reconnect; a query parameter is also accepted
// because a client that controls its own reconnect (a fetch-based reader) has no
// header to set.
func lastEventID(r *http.Request) (uint64, error) {
	raw := r.Header.Get("Last-Event-ID")
	if raw == "" {
		raw = r.URL.Query().Get("last_event_id")
	}
	if raw == "" {
		return 0, nil
	}
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("eventstream: parse Last-Event-ID %q: %w", raw, err)
	}
	return id, nil
}

// validTopic bounds a topic key. The charset is restricted because the topic is
// echoed into authorization decisions and logs; a key containing control
// characters or newlines would be a log-injection vector.
func validTopic(topic string) bool {
	if topic == "" || len(topic) > 128 {
		return false
	}
	for _, c := range topic {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == ':' || c == '-' || c == '_' || c == '.':
		default:
			return false
		}
	}
	return true
}

// PublishJSON marshals v and publishes it. It exists so call sites cannot
// accidentally publish a non-JSON payload: the SSE data field is parsed as JSON
// by every client, and a handler that published a raw string would produce a
// stream the UI cannot read.
func (b *Broker) PublishJSON(ctx context.Context, topic, eventType string, v any) (Event, error) {
	if err := ctx.Err(); err != nil {
		return Event{}, err
	}
	if !validTopic(topic) {
		return Event{}, fmt.Errorf("eventstream: topic %q is not valid", topic)
	}
	data, err := json.Marshal(v)
	if err != nil {
		return Event{}, fmt.Errorf("eventstream: encode event payload: %w", err)
	}
	return b.Publish(topic, eventType, data)
}
