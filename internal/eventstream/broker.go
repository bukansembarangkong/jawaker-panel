// Package eventstream is the SSE fan-out used by the panel's live channels
// (API.md §13, ARCHITECTURE.md §13).
//
// It carries job progress, notifications, incident state, and deployment
// updates to browsers. The requirements there shape every decision here:
//
//   - authenticated: the HTTP handler in this package is wrapped by the caller's
//     session middleware; a subscription cannot exist without a principal.
//   - reconnection/resume: every event carries a monotonic id, and a client that
//     reconnects with Last-Event-ID is caught up from a bounded replay buffer.
//     Without this, a browser tab that briefly loses its connection silently
//     misses the deployment result it was waiting for.
//   - bounded buffers: a subscription has a fixed capacity. A slow consumer is
//     dropped with an explicit lagged signal rather than being allowed to grow
//     the server's memory or to block the publisher. Blocking a publisher on one
//     stalled browser would let a single tab freeze every other subscriber.
//   - no secret payloads: events are built from already-safe data. This package
//     cannot verify that, so it is stated here and enforced by convention at the
//     call sites that publish.
//   - heartbeat/timeout: an idle connection is kept alive by a periodic comment
//     line, because proxy and browser idle timeouts will otherwise silently drop
//     a stream that nothing has been sent on.
package eventstream

import (
	"errors"
	"sync"
	"time"
)

// Defaults. Every one of these is bounded on purpose: an unbounded buffer, an
// unbounded subscriber count, or an unbounded replay log is how a live-update
// feature becomes an outage.
const (
	// DefaultSubscriptionBuffer is how many events a subscriber may fall behind
	// before it is declared lagged.
	DefaultSubscriptionBuffer = 64
	// DefaultReplayBuffer is how many recent events per topic are kept for a
	// reconnecting client.
	DefaultReplayBuffer = 256
	// DefaultHeartbeat is the interval between keep-alive comments.
	DefaultHeartbeat = 20 * time.Second
	// DefaultMaxSubscribers bounds concurrent streams per topic, so a client
	// looping connections cannot exhaust server resources.
	DefaultMaxSubscribers = 128
)

// Errors.
var (
	// ErrTooManySubscribers means the topic is at its subscriber limit.
	ErrTooManySubscribers = errors.New("eventstream: too many subscribers")
	// ErrClosed means the broker is shut down.
	ErrClosed = errors.New("eventstream: broker closed")
)

// Event is one message on a topic.
type Event struct {
	// ID is assigned by the broker and is monotonic within a topic. A client
	// sends the last id it saw on reconnect, and the broker replays everything
	// after it.
	ID uint64
	// Type is the SSE event name, e.g. "job.progress". A client switches on it.
	Type string
	// Data is the JSON payload. Callers must not put secret material here.
	Data []byte
}

// Topic is a subscription channel key. Strings rather than an enum so new
// live-update sources do not require a change here.
const (
	// TopicUserPrefix scopes personal events. The full key is
	// "user:<id>", so one user's notifications never reach another's stream.
	TopicUserPrefix = "user:"
	// TopicJobs carries job progress.
	TopicJobs = "jobs"
	// TopicIncidents carries incident state changes.
	TopicIncidents = "incidents"
)

// UserTopic returns the per-user topic key.
func UserTopic(userID string) string { return TopicUserPrefix + userID }

// Broker fans events out to subscribers and remembers recent events per topic so
// a reconnecting client can resume.
//
// It is safe for concurrent use. There is no persistence: replay covers a brief
// network blip, and a client that has been away longer re-reads state over the
// API. Making the replay durable would be a second source of truth for job
// progress, which already lives in the database.
type Broker struct {
	mu          sync.Mutex
	topics      map[string]*topicState
	closed      bool
	heartbeat   time.Duration
	maxSubs     int
	subBuffer   int
	replayLimit int
}

type topicState struct {
	nextID   uint64
	replay   []Event
	subs     map[*Subscription]struct{}
	liveSubs int
}

// Options configures a Broker. Zero values use the package defaults; nil or
// non-positive values are replaced rather than accepted, because a
// zero-capacity buffer would silently drop every event.
type Options struct {
	// SubscriptionBuffer is the per-subscriber capacity.
	SubscriptionBuffer int
	// ReplayBuffer is how many events per topic are retained for resume.
	ReplayBuffer int
	// Heartbeat is the keep-alive interval.
	Heartbeat time.Duration
	// MaxSubscribers bounds concurrent subscribers per topic.
	MaxSubscribers int
}

// New returns a Broker.
func New(opts Options) *Broker {
	if opts.SubscriptionBuffer <= 0 {
		opts.SubscriptionBuffer = DefaultSubscriptionBuffer
	}
	if opts.ReplayBuffer <= 0 {
		opts.ReplayBuffer = DefaultReplayBuffer
	}
	if opts.Heartbeat <= 0 {
		opts.Heartbeat = DefaultHeartbeat
	}
	if opts.MaxSubscribers <= 0 {
		opts.MaxSubscribers = DefaultMaxSubscribers
	}
	return &Broker{
		topics:      make(map[string]*topicState),
		heartbeat:   opts.Heartbeat,
		maxSubs:     opts.MaxSubscribers,
		subBuffer:   opts.SubscriptionBuffer,
		replayLimit: opts.ReplayBuffer,
	}
}

// Heartbeat returns the configured keep-alive interval.
func (b *Broker) Heartbeat() time.Duration { return b.heartbeat }

// Subscribe registers a subscriber on a topic.
//
// sinceID is the client's last-seen event id (0 for a fresh connection). Events
// after it are replayed into the subscription's buffer before it is returned, so
// the caller cannot miss the gap between "I reconnected" and "I started reading".
//
// If the gap is larger than the replay buffer, the subscription is returned with
// Lagged set AND the reachable tail still delivered: the client is brought as
// close as the server can, but is told a gap exists so it re-reads state rather
// than silently resuming with a hole.
func (b *Broker) Subscribe(topic string, sinceID uint64) (*Subscription, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return nil, ErrClosed
	}
	ts := b.topicLocked(topic)
	if ts.liveSubs >= b.maxSubs {
		return nil, ErrTooManySubscribers
	}

	sub := &Subscription{
		topic:  topic,
		broker: b,
		events: make(chan Event, b.subBuffer),
		done:   make(chan struct{}),
	}
	ts.subs[sub] = struct{}{}
	ts.liveSubs++

	// Catch-up. Events are pushed oldest-first so a client processes them in the
	// order they happened.
	//
	// When the client is further behind than the log reaches, it is marked
	// lagged AND still given the reachable tail: that leaves it as up to date as
	// the server can make it while telling it a gap exists. Delivering nothing
	// would leave it both stale and unsure whether it was merely idle.
	if sinceID > 0 {
		if len(ts.replay) > 0 && sinceID+1 < ts.replay[0].ID {
			sub.lagged.Store(true)
		}
		for _, ev := range ts.replay {
			if ev.ID <= sinceID {
				continue
			}
			select {
			case sub.events <- ev:
			default:
				sub.lagged.Store(true)
			}
		}
	}
	return sub, nil
}

// Publish assigns an id and delivers an event to every subscriber of a topic.
//
// It never blocks on a subscriber: a subscription whose buffer is full is marked
// lagged and skipped. Blocking here would let one stalled browser tab freeze
// every publisher in the process.
func (b *Broker) Publish(topic string, eventType string, data []byte) (Event, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return Event{}, ErrClosed
	}
	ts := b.topicLocked(topic)
	ts.nextID++
	ev := Event{ID: ts.nextID, Type: eventType, Data: data}

	ts.replay = append(ts.replay, ev)
	if len(ts.replay) > b.replayLimit {
		// Drop the oldest: the replay window slides.
		ts.replay = ts.replay[len(ts.replay)-b.replayLimit:]
	}

	for sub := range ts.subs {
		select {
		case sub.events <- ev:
		default:
			// Buffer full: the consumer is too slow to keep up. Mark it so its
			// client is told to re-read state instead of quietly missing data.
			sub.lagged.Store(true)
		}
	}
	return ev, nil
}

// SubscriberCount returns the number of live subscribers on a topic. Used by
// tests and by the metrics surface.
func (b *Broker) SubscriberCount(topic string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	if ts, ok := b.topics[topic]; ok {
		return ts.liveSubs
	}
	return 0
}

// Close shuts the broker down and ends every subscription. It is idempotent.
func (b *Broker) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return
	}
	b.closed = true
	for _, ts := range b.topics {
		for sub := range ts.subs {
			sub.closeLocked()
		}
		ts.subs = map[*Subscription]struct{}{}
		ts.liveSubs = 0
	}
}

func (b *Broker) topicLocked(topic string) *topicState {
	ts, ok := b.topics[topic]
	if !ok {
		ts = &topicState{subs: make(map[*Subscription]struct{})}
		b.topics[topic] = ts
	}
	return ts
}

func (b *Broker) unsubscribe(sub *Subscription) {
	b.mu.Lock()
	defer b.mu.Unlock()
	ts, ok := b.topics[sub.topic]
	if !ok {
		return
	}
	if _, ok := ts.subs[sub]; ok {
		delete(ts.subs, sub)
		ts.liveSubs--
	}
	sub.closeLocked()
}
