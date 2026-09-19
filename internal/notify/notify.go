// Package notify is the notification event abstraction (ARCHITECTURE.md §13,
// PRD §19.5, DESIGN_SYSTEM.md §19).
//
// The unit of a notification is an EVENT, not a message. A module says "the
// backup failed for site X"; which humans learn about it, on which channels, and
// in what words is decided here. That separation is what lets a channel be added
// later (email, Telegram, webhook) without touching a single caller.
//
// Delivery is durable and retryable, so a channel outage never blocks the
// operation that produced the event. Publishing only writes rows; the Claim,
// MarkDelivered and MarkFailed functions advance them, and a delivery loop calls
// those. Nothing on the request path waits for a network call to a chat service.
//
// Two rules shape routing:
//
//   - severity is a filter, not a label. A user who only wants warnings must not
//     receive info digests, so the filter is applied when a delivery row is
//     created rather than when it is sent.
//   - an unresolved condition is notified once. DESIGN_SYSTEM.md §19 forbids
//     re-notifying the same unresolved condition, so a dedup key suppresses
//     repeats inside a window instead of spamming a channel every poll.
package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Sentinel errors.
var (
	// ErrNotFound means the referenced row does not exist.
	ErrNotFound = errors.New("notify: not found")
)

// Severities. Kept in sync with the notification_deliveries.severity CHECK
// constraint (migration 0006).
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// rank orders severities so a route's minimum can be compared. An unrecognized
// value ranks lowest rather than highest, so a typo cannot escalate itself past
// a filter.
func rank(severity string) int {
	switch severity {
	case SeverityCritical:
		return 3
	case SeverityWarning:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// AtLeast reports whether severity is at least as urgent as minimum. Both sides
// go through the same ranking, so a route asking for "warning" keeps warning and
// critical but drops info.
func AtLeast(severity, minimum string) bool {
	return rank(severity) >= rank(minimum)
}

// Channel types. Kept in sync with the notification_channels.type CHECK
// constraint.
const (
	ChannelInPanel  = "in_panel"
	ChannelEmail    = "email"
	ChannelTelegram = "telegram"
	ChannelWebhook  = "webhook"
	ChannelDiscord  = "discord"
	ChannelSlack    = "slack"
)

// Delivery states. Kept in sync with the notification_deliveries.state CHECK
// constraint.
const (
	StatePending    = "pending"
	StateSending    = "sending"
	StateFailed     = "failed"
	StateDelivered  = "delivered"
	StateSuppressed = "suppressed"
	StateDeadLetter = "dead_letter"
)

// DefaultDedupWindow is how long an unresolved condition stays quiet after it
// has been notified once.
const DefaultDedupWindow = 30 * time.Minute

// payload keys carry the rendered summary. The schema has no title/body columns
// because the wording is part of the event content, not delivery metadata, so it
// travels in the payload document. Storing it once, at publish time, is what
// makes every channel show the same words.
const (
	payloadKeyTitle = "title"
	payloadKeyBody  = "body"
	payloadKeyScope = "scope"
)

// Event is something worth telling someone about.
//
// Event is the required event key, e.g. "backup.failed" or "server.offline". It
// is the stable identifier an operator subscribes to, so it must not embed a
// resource id or a timestamp — those belong in the scope and payload.
type Event struct {
	Event    string
	Severity string
	// ResourceType, ResourceID, ServerID and ProjectID scope the event so a
	// notification can say what it is about and link to it.
	ResourceType string
	ResourceID   string
	ServerID     string
	ProjectID    string
	// Title and Body are the human-facing summary, rendered once at publish
	// time. Required: a notification with no wording cannot be delivered on any
	// channel.
	Title string
	Body  string
	// DedupKey identifies the CONDITION, not the occurrence: two events sharing
	// a key are the same unresolved problem reported twice. Empty disables
	// deduplication, which is correct for discrete events such as
	// "deployment.completed".
	DedupKey string
	// Payload is bounded structured detail for machine consumers (webhooks) and
	// for richer rendering later. Never secret material.
	Payload map[string]any
	// JobID and RequestID correlate the notification with the operation that
	// caused it.
	JobID     string
	RequestID string
}

func (e Event) validate() error {
	var errs []error
	if e.Event == "" {
		errs = append(errs, errors.New("notify: event key is required"))
	}
	if e.Title == "" {
		errs = append(errs, errors.New("notify: title is required"))
	}
	if rank(e.Severity) == 0 {
		errs = append(errs, fmt.Errorf("notify: severity %q is not valid", e.Severity))
	}
	if e.DedupKey != "" && e.ResourceType == "" {
		// A dedup key with no resource scope would silence the same condition
		// across unrelated resources, which is the kind of quiet failure nobody
		// notices until it matters.
		errs = append(errs, errors.New("notify: dedup_key requires a resource_type"))
	}
	return errors.Join(errs...)
}

// Result reports what publishing actually did, so a caller can log a dropped
// notification without treating it as a failure of the operation itself.
type Result struct {
	// DeliveryIDs are the rows created, in route order.
	DeliveryIDs []string
	// Enqueued and Suppressed split those rows by whether they will be sent.
	// Enqueued == 0 with no error is the normal "nobody subscribes" case, not a
	// failure.
	Enqueued   int
	Suppressed int
}

// Recipient is a resolved (user, channel) destination.
type Recipient struct {
	UserID    string
	ChannelID string
	Channel   string
}

// PublishOptions tunes publishing. Only the dedup window is configurable today;
// quiet hours and escalation (PRD §19.5) arrive with the delivery channels that
// need them.
type PublishOptions struct {
	// DedupWindow is how far back a matching dedup key suppresses a repeat.
	// Zero means DefaultDedupWindow.
	DedupWindow time.Duration
}

// Publish records an event for every recipient whose routing accepts its
// severity, applying the dedup window.
//
// Nothing is sent here. Publishing is a database write, which is what keeps a
// slow or dead channel from delaying the operation that produced the event.
//
// Dedup behavior: if a non-suppressed delivery for the same
// (dedup_key, recipient, channel) exists inside the window, the new row is
// recorded as SUPPRESSED rather than dropped. Keeping the row is deliberate —
// "we noticed this five more times and stayed quiet" is exactly the evidence
// needed to judge whether the window is too long.
func Publish(ctx context.Context, pool *pgxpool.Pool, event Event, opts PublishOptions) (Result, error) {
	if err := event.validate(); err != nil {
		return Result{}, err
	}
	if pool == nil {
		return Result{}, errors.New("notify: database is required")
	}
	window := opts.DedupWindow
	if window == 0 {
		window = DefaultDedupWindow
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("notify: begin publish: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	recipients, err := recipientsFor(ctx, tx, event.Severity)
	if err != nil {
		return Result{}, err
	}

	payload, err := json.Marshal(event.payloadDocument())
	if err != nil {
		return Result{}, fmt.Errorf("notify: encode payload: %w", err)
	}

	var result Result
	for _, recipient := range recipients {
		state := StatePending
		if event.DedupKey != "" {
			duplicate, dupErr := recentlyNotified(ctx, tx, event.DedupKey, recipient, window)
			if dupErr != nil {
				return Result{}, dupErr
			}
			if duplicate {
				state = StateSuppressed
			}
		}

		var id string
		if err := tx.QueryRow(ctx, `
			INSERT INTO notification_deliveries (
			    event, severity, channel_id, recipient_id, payload, dedup_key,
			    state, job_id, request_id
			) VALUES (
			    $1, $2, $3::uuid, $4::uuid, $5::jsonb, NULLIF($6, ''),
			    $7, NULLIF($8, '')::uuid, NULLIF($9, '')
			)
			RETURNING id`,
			event.Event, event.Severity, recipient.ChannelID, recipient.UserID,
			payload, event.DedupKey, state, event.JobID, event.RequestID).Scan(&id); err != nil {
			return Result{}, fmt.Errorf("notify: insert delivery: %w", err)
		}

		result.DeliveryIDs = append(result.DeliveryIDs, id)
		if state == StateSuppressed {
			result.Suppressed++
		} else {
			result.Enqueued++
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return Result{}, fmt.Errorf("notify: commit publish: %w", err)
	}
	return result, nil
}

// payloadDocument is the stored payload: the caller's detail plus the rendered
// summary and the scope. The summary is written at publish time so a later
// change to how titles are worded cannot retroactively alter what a user was
// told.
func (e Event) payloadDocument() map[string]any {
	doc := make(map[string]any, len(e.Payload)+3)
	for k, v := range e.Payload {
		doc[k] = v
	}
	doc[payloadKeyTitle] = e.Title
	doc[payloadKeyBody] = e.Body
	doc[payloadKeyScope] = map[string]string{
		"resource_type": e.ResourceType,
		"resource_id":   e.ResourceID,
		"server_id":     e.ServerID,
		"project_id":    e.ProjectID,
	}
	return doc
}

// severityRankSQL is the SQL form of rank(). It is inlined rather than created
// as a database function because exactly one query needs it; a migration would
// be more machinery than the problem.
const severityRankSQL = `CASE %s
	WHEN 'critical' THEN 3
	WHEN 'warning'  THEN 2
	WHEN 'info'     THEN 1
	ELSE 0
END`

// recipientsFor resolves every enabled route to an enabled channel whose minimum
// severity the event meets. The join is one statement, so the severity filter and
// the enabled checks cannot disagree with each other.
func recipientsFor(ctx context.Context, tx pgx.Tx, severity string) ([]Recipient, error) {
	query := fmt.Sprintf(`
		SELECT r.user_id::text, c.id::text, c.type
		FROM notification_routes r
		JOIN notification_channels c ON c.id = r.channel_id
		WHERE r.enabled AND c.enabled
		  AND %s <= %s
		ORDER BY r.user_id, c.id`,
		fmt.Sprintf(severityRankSQL, `r.min_severity`),
		fmt.Sprintf(severityRankSQL, `$1::text`))

	rows, err := tx.Query(ctx, query, severity)
	if err != nil {
		return nil, fmt.Errorf("notify: resolve recipients: %w", err)
	}
	defer rows.Close()

	var out []Recipient
	for rows.Next() {
		var r Recipient
		if err := rows.Scan(&r.UserID, &r.ChannelID, &r.Channel); err != nil {
			return nil, fmt.Errorf("notify: scan recipient: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notify: iterate recipients: %w", err)
	}
	return out, nil
}

// recentlyNotified reports whether this condition was already sent to this
// recipient within the window. Suppressed rows do not count: otherwise the
// window would re-arm on every repeat and a long-running condition would be
// notified once per window forever.
func recentlyNotified(ctx context.Context, tx pgx.Tx, dedupKey string, recipient Recipient, window time.Duration) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `
		SELECT EXISTS (
		    SELECT 1 FROM notification_deliveries
		    WHERE dedup_key = $1
		      AND channel_id = $2::uuid
		      AND recipient_id = $3::uuid
		      AND state <> 'suppressed'
		      AND created_at > now() - make_interval(secs => $4)
		)`, dedupKey, recipient.ChannelID, recipient.UserID, window.Seconds()).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("notify: dedup check: %w", err)
	}
	return exists, nil
}

// Delivery is one recorded notification.
type Delivery struct {
	ID          string
	Event       string
	Severity    string
	ChannelID   string
	Channel     string
	RecipientID string
	Title       string
	Body        string
	Payload     map[string]any
	DedupKey    string
	State       string
	Attempts    int
	MaxAttempts int
	LastError   string
	JobID       string
	RequestID   string
	CreatedAt   time.Time
	DeliveredAt *time.Time
	ReadAt      *time.Time
}

// Inbox returns a user's delivered notifications, newest first, with read state.
// This is the in-panel channel's read path.
//
// Suppressed rows are excluded: they exist as evidence for an operator auditing
// the dedup window, not as things a user was told about. The query matches the
// notification_deliveries_inbox_idx partial index.
func Inbox(ctx context.Context, pool *pgxpool.Pool, userID string, limit int) ([]Delivery, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := pool.Query(ctx, selectDelivery+`
		WHERE d.recipient_id = $1::uuid AND d.state = 'delivered'
		ORDER BY d.created_at DESC
		LIMIT $2`, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("notify: inbox: %w", err)
	}
	defer rows.Close()

	var out []Delivery
	for rows.Next() {
		d, err := scanDelivery(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("notify: iterate inbox: %w", err)
	}
	return out, nil
}

// GetDelivery loads one delivery.
func GetDelivery(ctx context.Context, pool *pgxpool.Pool, id string) (Delivery, error) {
	return scanDelivery(pool.QueryRow(ctx, selectDelivery+` WHERE d.id = $1`, id))
}

const selectDelivery = `
	SELECT d.id::text, d.event, d.severity, d.channel_id::text, c.type,
	       COALESCE(d.recipient_id::text, ''), d.payload, COALESCE(d.dedup_key, ''),
	       d.state, d.attempt_count, d.max_attempts, COALESCE(d.last_error, ''),
	       COALESCE(d.job_id::text, ''), COALESCE(d.request_id, ''),
	       d.created_at, d.delivered_at, r.read_at
	FROM notification_deliveries d
	JOIN notification_channels c ON c.id = d.channel_id
	LEFT JOIN notification_reads r ON r.delivery_id = d.id`

type rowScanner interface {
	Scan(dest ...any) error
}

func scanDelivery(row rowScanner) (Delivery, error) {
	var d Delivery
	var payload []byte
	err := row.Scan(&d.ID, &d.Event, &d.Severity, &d.ChannelID, &d.Channel,
		&d.RecipientID, &payload, &d.DedupKey,
		&d.State, &d.Attempts, &d.MaxAttempts, &d.LastError,
		&d.JobID, &d.RequestID,
		&d.CreatedAt, &d.DeliveredAt, &d.ReadAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Delivery{}, ErrNotFound
	}
	if err != nil {
		return Delivery{}, fmt.Errorf("notify: scan delivery: %w", err)
	}
	if len(payload) > 0 {
		if err := json.Unmarshal(payload, &d.Payload); err != nil {
			return Delivery{}, fmt.Errorf("notify: decode delivery payload: %w", err)
		}
	}
	d.Title = stringField(d.Payload, payloadKeyTitle)
	d.Body = stringField(d.Payload, payloadKeyBody)
	return d, nil
}

// MarkRead records that a user has seen a notification. It is idempotent, so a
// double click is not an error; an unknown id is.
func MarkRead(ctx context.Context, pool *pgxpool.Pool, deliveryID string) error {
	if pool == nil {
		return errors.New("notify: database is required")
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO notification_reads (delivery_id) VALUES ($1::uuid)
		ON CONFLICT (delivery_id) DO NOTHING`, deliveryID); err != nil {
		// The only expected failure is a foreign-key violation, which means the
		// delivery does not exist. Reporting it as not-found keeps the caller
		// from turning a typo into a 500.
		if isForeignKeyViolation(err) {
			return fmt.Errorf("%w: delivery %s", ErrNotFound, deliveryID)
		}
		return fmt.Errorf("notify: mark read: %w", err)
	}
	return nil
}

// UnreadCount returns how many delivered notifications a user has not read. The
// in-panel badge reads this, so it is a single aggregate rather than a list the
// UI counts.
func UnreadCount(ctx context.Context, pool *pgxpool.Pool, userID string) (int, error) {
	var count int
	err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM notification_deliveries d
		LEFT JOIN notification_reads r ON r.delivery_id = d.id
		WHERE d.recipient_id = $1::uuid
		  AND d.state = 'delivered'
		  AND r.delivery_id IS NULL`, userID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("notify: unread count: %w", err)
	}
	return count, nil
}

func stringField(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// isForeignKeyViolation reports the PostgreSQL foreign-key-violation code.
func isForeignKeyViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23503"
}
