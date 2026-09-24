package certs

import (
	"context"
	"fmt"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/notify"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WorkerConfig configures the certificate renewal monitor.
type WorkerConfig struct {
	Pool     *pgxpool.Pool
	Certs    *Store
	Interval time.Duration
	Window   time.Duration
}

// Worker runs a background loop that detects expiring certificates and emits
// notifications, and provides the safe renewal candidate validation gate.
type Worker struct {
	pool     *pgxpool.Pool
	certs    *Store
	interval time.Duration
	window   time.Duration
}

// NewWorker builds a certificate renewal worker.
func NewWorker(cfg WorkerConfig) *Worker {
	interval := cfg.Interval
	if interval <= 0 {
		interval = 1 * time.Hour
	}
	window := cfg.Window
	if window <= 0 {
		window = DefaultRenewalWindow
	}
	return &Worker{
		pool:     cfg.Pool,
		certs:    cfg.Certs,
		interval: interval,
		window:   window,
	}
}

// Run starts the background ticker loop. It blocks until the context is cancelled.
func (w *Worker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = w.Sweep(ctx)
		}
	}
}

// Sweep finds expiring certificates, transitions them to 'expiring' if they are
// still 'active', and publishes a 'cert.expiring' notification.
func (w *Worker) Sweep(ctx context.Context) error {
	expiring, err := w.certs.ListExpiring(ctx, w.window)
	if err != nil {
		return fmt.Errorf("certs worker: list expiring: %w", err)
	}

	for _, c := range expiring {
		if c.State == StateActive {
			_, _ = w.certs.MarkExpiring(ctx, c.ID)
		}

		event := notify.Event{
			Event:        "cert.expiring",
			Severity:     notify.SeverityWarning,
			ResourceType: "certificate",
			ResourceID:   c.ID,
			ProjectID:    c.ProjectID,
			Title:        "Certificate expiring soon",
			Body:         fmt.Sprintf("Certificate %s expires at %s", c.ID, c.NotAfter.Format(time.RFC3339)),
			DedupKey:     fmt.Sprintf("cert.expiring:%s", c.ID),
			Payload: map[string]any{
				"not_after":   c.NotAfter.Format(time.RFC3339),
				"identifiers": c.Identifiers,
			},
		}
		_, _ = notify.Publish(ctx, w.pool, event, notify.PublishOptions{})
	}
	return nil
}

// SafeRenewCandidate validates a candidate certificate before binding it to a domain.
// Gate: "previous valid certificate remains available during failed renewal".
// If validateFunc returns an error, the current active binding is untouched.
func (w *Worker) SafeRenewCandidate(ctx context.Context, domainID, newCertID string, validateFunc func(c Certificate) error) error {
	candidate, err := w.certs.Get(ctx, newCertID)
	if err != nil {
		return err
	}

	if err := validateFunc(candidate); err != nil {
		return fmt.Errorf("candidate validation failed: %w", err)
	}

	return w.certs.Bind(ctx, domainID, newCertID)
}
