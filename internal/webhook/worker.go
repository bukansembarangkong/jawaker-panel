// Package webhook provides the outbound webhook delivery worker (PRD §26.4).
//
// It drains the outbound_webhook_deliveries table: claims pending rows, sends
// the payload to the target URL with an HMAC-SHA256 signature, and records the
// result. A delivery failure is retried with exponential backoff; after
// max_attempts the row is dead-lettered and never retried again.
//
// The worker is a plain ticker loop — no separate job engine needed because
// webhooks are short-lived fire-and-forget requests.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	// deliveryTimeout is the per-request HTTP deadline. A slow receiver must
	// not hold the delivery goroutine forever.
	deliveryTimeout = 15 * time.Second
	// batchSize is how many deliveries the loop claims per tick.
	batchSize = 25
	// tickInterval controls how often the delivery loop wakes.
	tickInterval = 15 * time.Second
	// maxErrorLength bounds what an error message may store in the DB.
	maxErrorLength = 500
)

// Run is a blocking delivery loop that processes pending webhook deliveries
// until ctx is cancelled. Errors are logged but do not stop the loop.
func Run(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, client *http.Client) {
	if client == nil {
		client = &http.Client{Timeout: deliveryTimeout}
	}
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := drainOnce(ctx, pool, client, logger); err != nil {
				logger.Warn("webhook delivery loop error", "error", err)
			}
		}
	}
}

func drainOnce(ctx context.Context, pool *pgxpool.Pool, client *http.Client, logger *slog.Logger) error {
	type pendingRow struct {
		id          string
		webhookID   string
		event       string
		payload     []byte
		targetURL   string
		secretToken string
		attempt     int
		maxAttempts int
	}

	rows, err := pool.Query(ctx, `
		UPDATE outbound_webhook_deliveries d
		SET status = 'pending',
		    attempt_count = attempt_count + 1,
		    next_attempt_at = now() + make_interval(secs => $1)
		WHERE d.id IN (
		    SELECT d2.id FROM outbound_webhook_deliveries d2
		    JOIN outbound_webhooks w ON w.id = d2.webhook_id
		    WHERE d2.status = 'pending'
		      AND d2.next_attempt_at <= now()
		      AND w.enabled = true
		    ORDER BY d2.next_attempt_at ASC
		    FOR UPDATE OF d2 SKIP LOCKED
		    LIMIT $2
		)
		RETURNING d.id, d.webhook_id, d.event, d.payload,
		          (SELECT target_url FROM outbound_webhooks WHERE id = d.webhook_id),
		          (SELECT secret_token FROM outbound_webhooks WHERE id = d.webhook_id),
		          d.attempt_count, d.max_attempts`,
		deliveryTimeout.Seconds(), batchSize)
	if err != nil {
		return fmt.Errorf("webhook: claim batch: %w", err)
	}
	defer rows.Close()

	var pending []pendingRow
	for rows.Next() {
		var p pendingRow
		if err := rows.Scan(&p.id, &p.webhookID, &p.event, &p.payload,
			&p.targetURL, &p.secretToken, &p.attempt, &p.maxAttempts); err != nil {
			return fmt.Errorf("webhook: scan row: %w", err)
		}
		pending = append(pending, p)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("webhook: iterate rows: %w", err)
	}

	for _, p := range pending {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		statusCode, sendErr := sendDelivery(ctx, client, p.targetURL, p.secretToken, p.event, p.payload)
		if sendErr == nil {
			_, _ = pool.Exec(ctx, `
				UPDATE outbound_webhook_deliveries
				SET status = 'delivered', delivered_at = now(), status_code = $2, error_message = NULL
				WHERE id = $1`, p.id, statusCode)
			continue
		}

		errMsg := truncate(sendErr.Error(), maxErrorLength)
		if p.attempt >= p.maxAttempts {
			_, _ = pool.Exec(ctx, `
				UPDATE outbound_webhook_deliveries
				SET status = 'dead_letter', error_message = $2, status_code = $3
				WHERE id = $1`, p.id, errMsg, statusCode)
			logger.Warn("webhook delivery dead-lettered", "id", p.id, "url", p.targetURL, "err", sendErr)
			continue
		}

		// Schedule retry with exponential backoff.
		delay := backoffDelay(p.attempt)
		_, _ = pool.Exec(ctx, `
			UPDATE outbound_webhook_deliveries
			SET status = 'pending', error_message = $2, status_code = $3,
			    next_attempt_at = now() + make_interval(secs => $4)
			WHERE id = $1`, p.id, errMsg, statusCode, delay.Seconds())
	}
	return nil
}

func sendDelivery(ctx context.Context, client *http.Client, targetURL, secret, event string, payload []byte) (statusCode int, err error) {
	// Ensure valid JSON in body.
	if !json.Valid(payload) {
		payload, _ = json.Marshal(map[string]any{"event": event})
	}

	sig := computeHMAC(payload, secret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(payload))
	if err != nil {
		return 0, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Jawaker-Event", event)
	req.Header.Set("X-Jawaker-Signature", "sha256="+sig)

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return resp.StatusCode, fmt.Errorf("target returned HTTP %d", resp.StatusCode)
	}
	return resp.StatusCode, nil
}

func computeHMAC(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func backoffDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return 10 * time.Second
	}
	d := time.Duration(math.Pow(2, float64(attempt-1))) * 10 * time.Second
	if d > 10*time.Minute {
		return 10 * time.Minute
	}
	return d
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
