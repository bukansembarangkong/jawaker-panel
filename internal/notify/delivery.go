package notify

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Delivery tuning. Mirrors the job engine's lease/backoff shape so an operator
// reading one understands the other.
const (
	// DefaultLeaseTTL is how long a delivery is held before another loop may
	// retry it. A sender that hangs on a dead SMTP server must not hold the row
	// forever.
	DefaultLeaseTTL = 2 * time.Minute
	// retryBaseDelay and retryMaxDelay bound exponential backoff, so a channel
	// that is down for an hour is retried a handful of times rather than
	// hammered every second.
	retryBaseDelay = 10 * time.Second
	retryMaxDelay  = 10 * time.Minute
	// maxErrorLength bounds what a chatty client library can write into
	// last_error. A 4KB HTML error page in a notification row helps nobody.
	maxErrorLength = 500
)

// BackoffDelay returns the delay before retrying a delivery that has already
// failed `attempt` times.
func BackoffDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return retryBaseDelay
	}
	if attempt > 30 {
		return retryMaxDelay
	}
	d := time.Duration(math.Pow(2, float64(attempt-1))) * retryBaseDelay
	if d <= 0 || d > retryMaxDelay {
		return retryMaxDelay
	}
	return d
}

// Sender delivers one notification through one channel type.
//
// A Sender must be safe for concurrent use and must not touch the notification
// tables — recording success, failure, and retry state is the loop's job, and a
// sender that wrote its own state would race the lease.
//
// Returning an error means "not delivered, try again". There is deliberately no
// permanent-failure signal: a sender cannot know that an address is
// permanently bad, and guessing wrong either loses a notification or retries
// forever. The attempt bound decides.
type Sender func(ctx context.Context, d Delivery) error

// ClaimOptions selects which deliveries a loop may take.
type ClaimOptions struct {
	// LeaseTTL bounds how long a claimed delivery is held. Zero means
	// DefaultLeaseTTL.
	LeaseTTL time.Duration
	// ChannelTypes restricts the claim, so an email loop and a Telegram loop can
	// run independently without stealing each other's work. Empty means any.
	ChannelTypes []string
	// Limit bounds how many deliveries one claim pass takes. Zero means 25.
	Limit int
}

// DeliverOnce drains a batch of due deliveries.
//
// It claims rows whose next_attempt_at has arrived, dispatches each to the
// sender registered for its channel type, and records the outcome: delivered,
// retried with backoff, or dead-lettered once attempts are exhausted.
//
// A channel type with no registered sender is left PENDING rather than failed.
// That is a deliberate asymmetry: an unconfigured channel is a deployment state,
// not a delivery error, and burning its attempt budget on a missing
// configuration would dead-letter notifications the operator can still deliver by
// enabling the channel.
//
// It returns how many deliveries it attempted, so a caller can decide whether to
// loop again immediately or wait.
func DeliverOnce(ctx context.Context, pool *pgxpool.Pool, senders map[string]Sender, opts ClaimOptions) (int, error) {
	if pool == nil {
		return 0, errors.New("notify: database is required")
	}
	lease := opts.LeaseTTL
	if lease == 0 {
		lease = DefaultLeaseTTL
	}
	if lease < time.Second {
		return 0, errors.New("notify: lease TTL must be at least 1s")
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 25
	}
	if limit > 500 {
		limit = 500
	}

	// Claim by moving due rows into 'sending' with a lease. The lease is the
	// next_attempt_at column pushed into the future: a row being sent is not
	// claimable by anyone else until the lease lapses, and if this loop dies the
	// row becomes due again on its own. No separate reaper is needed.
	claimed, err := claimBatch(ctx, pool, lease, opts.ChannelTypes, limit)
	if err != nil {
		return 0, err
	}

	attempted := 0
	for _, d := range claimed {
		if ctx.Err() != nil {
			return attempted, ctx.Err()
		}
		sender, ok := senders[d.Channel]
		if !ok {
			// Unconfigured channel: return it to pending without consuming an
			// attempt.
			if err := releasePending(ctx, pool, d.ID); err != nil {
				return attempted, err
			}
			continue
		}
		attempted++

		sendErr := runSender(ctx, sender, d)
		if sendErr == nil {
			if err := markDelivered(ctx, pool, d.ID); err != nil {
				return attempted, err
			}
			continue
		}
		if err := markFailed(ctx, pool, d, sendErr); err != nil {
			return attempted, err
		}
	}
	return attempted, nil
}

// runSender invokes a sender and converts a panic into an error. A buggy
// channel implementation must not take down the loop that serves every other
// channel.
func runSender(ctx context.Context, sender Sender, d Delivery) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("sender panic: %v", r)
		}
	}()
	return sender(ctx, d)
}

func claimBatch(ctx context.Context, pool *pgxpool.Pool, lease time.Duration, channelTypes []string, limit int) ([]Delivery, error) {
	types := channelTypes
	if types == nil {
		types = []string{}
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("notify: begin claim: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// SKIP LOCKED so two delivery loops never take the same row and never block
	// each other waiting for it.
	rows, err := tx.Query(ctx, `
		UPDATE notification_deliveries
		SET state = 'sending',
		    attempt_count = attempt_count + 1,
		    next_attempt_at = now() + make_interval(secs => $1)
		WHERE id IN (
		    SELECT id FROM notification_deliveries
		    WHERE state = 'pending'
		      AND next_attempt_at <= now()
		      AND (cardinality(COALESCE($2::text[], '{}')) = 0
		           OR channel_id IN (SELECT id FROM notification_channels
		                             WHERE type = ANY($2::text[])))
		    ORDER BY CASE severity
		                 WHEN 'critical' THEN 0
		                 WHEN 'warning'  THEN 1
		                 ELSE 2
		             END,
		             next_attempt_at ASC, created_at ASC
		    FOR UPDATE SKIP LOCKED
		    LIMIT $3
		)
		RETURNING id`, lease.Seconds(), types, limit)
	if err != nil {
		return nil, fmt.Errorf("notify: claim deliveries: %w", err)
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, fmt.Errorf("notify: scan claimed id: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("notify: iterate claimed ids: %w", err)
	}
	rows.Close()

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("notify: commit claim: %w", err)
	}
	if len(ids) == 0 {
		return nil, nil
	}

	// Re-read the claimed rows outside the transaction. The claim already
	// committed, so this is a plain read of rows this loop owns.
	out := make([]Delivery, 0, len(ids))
	for _, id := range ids {
		d, err := GetDelivery(ctx, pool, id)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func markDelivered(ctx context.Context, pool *pgxpool.Pool, id string) error {
	if _, err := pool.Exec(ctx, `
		UPDATE notification_deliveries
		SET state = 'delivered', delivered_at = now(), last_error = NULL
		WHERE id = $1`, id); err != nil {
		return fmt.Errorf("notify: mark delivered: %w", err)
	}
	return nil
}

func markFailed(ctx context.Context, pool *pgxpool.Pool, d Delivery, sendErr error) error {
	summary := truncate(sendErr.Error(), maxErrorLength)

	// attempt_count was already incremented by the claim, so d.Attempts is the
	// number of tries that have now happened.
	if d.Attempts >= d.MaxAttempts {
		if _, err := pool.Exec(ctx, `
			UPDATE notification_deliveries
			SET state = 'dead_letter', last_error = $2
			WHERE id = $1`, d.ID, summary); err != nil {
			return fmt.Errorf("notify: dead-letter delivery: %w", err)
		}
		return nil
	}

	if _, err := pool.Exec(ctx, `
		UPDATE notification_deliveries
		SET state = 'pending', last_error = $2,
		    next_attempt_at = now() + make_interval(secs => $3)
		WHERE id = $1`, d.ID, summary, BackoffDelay(d.Attempts).Seconds()); err != nil {
		return fmt.Errorf("notify: schedule delivery retry: %w", err)
	}
	return nil
}

// releasePending returns a delivery to the pending queue without consuming an
// attempt or recording an error: nothing was tried.
func releasePending(ctx context.Context, pool *pgxpool.Pool, id string) error {
	if _, err := pool.Exec(ctx, `
		UPDATE notification_deliveries
		SET state = 'pending', attempt_count = GREATEST(attempt_count - 1, 0),
		    next_attempt_at = now() + interval '1 minute'
		WHERE id = $1`, id); err != nil {
		return fmt.Errorf("notify: release delivery: %w", err)
	}
	return nil
}

// DeadLetters returns deliveries that exhausted their attempts, oldest first.
// An operator needs this list to answer "what did we fail to tell people".
func DeadLetters(ctx context.Context, pool *pgxpool.Pool, limit int) ([]Delivery, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := pool.Query(ctx, selectDelivery+`
		WHERE d.state = 'dead_letter'
		ORDER BY d.created_at ASC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("notify: list dead letters: %w", err)
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
		return nil, fmt.Errorf("notify: iterate dead letters: %w", err)
	}
	return out, nil
}

// Redeliver puts a dead-lettered delivery back in the queue with a fresh attempt
// budget. Retrying without resetting the budget would dead-letter it again on
// the next failure, which makes the button a no-op that looks like it worked.
func Redeliver(ctx context.Context, pool *pgxpool.Pool, id string) error {
	if pool == nil {
		return errors.New("notify: database is required")
	}
	tag, err := pool.Exec(ctx, `
		UPDATE notification_deliveries
		SET state = 'pending', attempt_count = 0, next_attempt_at = now(),
		    last_error = NULL
		WHERE id = $1 AND state = 'dead_letter'`, id)
	if err != nil {
		return fmt.Errorf("notify: redeliver: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Either it does not exist or it is not dead-lettered. Both are the
		// caller's mistake, and conflating them would make the 404/409 choice
		// arbitrary, so distinguish.
		var state string
		if err := pool.QueryRow(ctx,
			`SELECT state FROM notification_deliveries WHERE id = $1`, id).Scan(&state); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return fmt.Errorf("notify: read delivery state: %w", err)
		}
		return fmt.Errorf("notify: cannot redeliver a %s delivery", state)
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
