package eventstream

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// Subscription is one client's view of a topic.
//
// It is a buffered channel plus a lag flag. Both are needed: the channel carries
// events, and the flag carries the one fact a channel cannot — "you missed
// something". Without the flag a client that falls behind would resume as if
// nothing happened, which for job progress means a progress bar that stalls at
// 60% while the job finishes, and for a deployment means the UI never learns the
// outcome.
type Subscription struct {
	topic  string
	broker *Broker
	events chan Event
	done   chan struct{}
	once   sync.Once
	lagged atomic.Bool
}

// Events is the receive channel. It is closed when the subscription ends, so a
// range loop over it terminates correctly.
func (s *Subscription) Events() <-chan Event { return s.events }

// Done is closed when the subscription ends.
func (s *Subscription) Done() <-chan struct{} { return s.done }

// Topic returns the subscribed topic key.
func (s *Subscription) Topic() string { return s.topic }

// Lagged reports whether events were dropped for this subscriber. A client that
// sees this must re-read state over the API rather than assume its view is
// complete. The flag is sticky: once a gap exists, the client's view is
// incomplete until it refreshes, and clearing the flag on the next delivered
// event would hide that.
func (s *Subscription) Lagged() bool { return s.lagged.Load() }

// Close unsubscribes and releases resources. It is idempotent and safe to call
// concurrently with the broker delivering events.
func (s *Subscription) Close() {
	s.broker.unsubscribe(s)
}

// closeLocked ends the subscription. The caller holds the broker lock, so this
// must not re-enter it.
func (s *Subscription) closeLocked() {
	s.once.Do(func() {
		close(s.done)
		close(s.events)
	})
}

// Run drives a subscription for one request, forwarding events to write and
// emitting a heartbeat comment when the stream is idle.
//
// It owns the loop rather than the HTTP handler because the policy here is not
// HTTP-specific: a heartbeat interval, a bounded idle time, and the rule that a
// lagged subscriber is told so are decisions about the stream, and duplicating
// them in a handler would let the two drift.
//
// write is called for each frame. Returning an error from write (the client
// disconnected) ends Run; it is not retried, because the only writer that matters
// — the browser — is gone.
func (s *Subscription) Run(ctx context.Context, write func(frame string) error) error {
	heartbeat := time.NewTicker(s.broker.Heartbeat())
	defer heartbeat.Stop()

	var lastID uint64
	// On resume, announce the gap before anything else, so the client cannot
	// render three good events and only then discover it missed some.
	if s.Lagged() {
		if err := write(laggedFrame(lastID)); err != nil {
			return err
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.done:
			return nil
		case <-heartbeat.C:
			// A comment line keeps proxies and browsers from closing an idle
			// stream. It also carries the current position so a client that has
			// received nothing yet still learns where the stream is.
			if err := write(heartbeatFrame(lastID)); err != nil {
				return err
			}
		case ev, ok := <-s.events:
			if !ok {
				return nil
			}
			lastID = ev.ID
			if err := write(eventFrame(ev)); err != nil {
				return err
			}
			// A gap detected while delivering: report it as soon as it is known,
			// not at the next heartbeat.
			if s.Lagged() {
				if err := write(laggedFrame(lastID)); err != nil {
					return err
				}
			}
		}
	}
}

// frame builders. SSE's wire format is fixed, so these are the only place the
// syntax lives; a handler that formatted its own frames would be a second
// definition of the protocol.
func eventFrame(ev Event) string {
	name := ev.Type
	if name == "" {
		name = "message"
	}
	return "id: " + strconv.FormatUint(ev.ID, 10) + "\nevent: " + name + "\ndata: " + string(ev.Data) + "\n\n"
}

func heartbeatFrame(lastID uint64) string {
	return ": heartbeat " + strconv.FormatUint(lastID, 10) + "\n\n"
}

func laggedFrame(lastID uint64) string {
	return "id: " + strconv.FormatUint(lastID, 10) + "\nevent: lagged\ndata: {}\n\n"
}
