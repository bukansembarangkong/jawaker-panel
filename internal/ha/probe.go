// Package ha: health-probe background worker for HA pools (PRD §23).
//
// Every tick, the worker probes reachability of each server assigned to an
// active server pool. If a server stops responding, its member state transitions
// to 'failed' and an immutable failover event is recorded. If healthy member count
// drops below min_healthy, the pool transitions to 'degraded' or 'failed'.
package ha

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/pki"
)

// ReachabilityProber tests whether a node is reachable via mTLS.
type ReachabilityProber interface {
	VerifyReachable(ctx context.Context, serverID string) (pki.Identity, error)
}

// ProbeWorker monitors member health and triggers state transitions.
type ProbeWorker struct {
	store    *Store
	prober   ReachabilityProber
	logger   *slog.Logger
	interval time.Duration
}

// NewProbeWorker builds a new HA health-probe worker.
func NewProbeWorker(store *Store, prober ReachabilityProber, logger *slog.Logger, interval time.Duration) *ProbeWorker {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &ProbeWorker{
		store:    store,
		prober:   prober,
		logger:   logger,
		interval: interval,
	}
}

// Run executes the probe loop until ctx is cancelled.
func (w *ProbeWorker) Run(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.probeAll(ctx); err != nil {
				w.logger.Warn("ha: probe pass error", "error", err)
			}
		}
	}
}

func (w *ProbeWorker) probeAll(ctx context.Context) error {
	pools, err := w.listAllPools(ctx)
	if err != nil {
		return fmt.Errorf("list pools: %w", err)
	}

	for _, p := range pools {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := w.probePool(ctx, p); err != nil {
			w.logger.Warn("ha: probe pool error", "pool_id", p.ID, "error", err)
		}
	}
	return nil
}

func (w *ProbeWorker) probePool(ctx context.Context, p ServerPool) error {
	members, err := w.store.ListMembers(ctx, p.ID)
	if err != nil {
		return err
	}

	healthyCount := 0
	for _, m := range members {
		if m.State == "drained" || m.State == "draining" {
			continue // skip explicitly drained nodes
		}

		reachable := true
		if w.prober != nil {
			probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_, probeErr := w.prober.VerifyReachable(probeCtx, m.ServerID)
			cancel()
			if probeErr != nil {
				reachable = false
			}
		}

		newState := "active"
		if !reachable {
			newState = "failed"
		}

		if newState != m.State {
			_ = w.store.UpdateMemberState(ctx, m.ID, newState)
			_, _ = w.store.RecordFailoverEvent(ctx, p.ID, "node_status_change", m.ServerID, "ha_health_probe", map[string]any{
				"from": newState,
				"to":   m.State,
			})
		}

		if reachable {
			healthyCount++
		}
	}

	// Update pool state based on healthy count vs min_healthy.
	var newPoolState string
	switch {
	case healthyCount == 0 && len(members) > 0:
		newPoolState = "failed"
	case healthyCount < p.MinHealthy:
		newPoolState = "degraded"
	default:
		newPoolState = "healthy"
	}

	if newPoolState != p.State {
		_ = w.store.UpdatePoolState(ctx, p.ID, newPoolState)
		_, _ = w.store.RecordFailoverEvent(ctx, p.ID, "pool_state_change", "", "ha_health_probe", map[string]any{
			"from":          p.State,
			"to":            newPoolState,
			"healthy_count": healthyCount,
			"min_healthy":   p.MinHealthy,
		})
	}

	return nil
}

func (w *ProbeWorker) listAllPools(ctx context.Context) ([]ServerPool, error) {
	rows, err := w.store.pool.Query(ctx, `
		SELECT id, project_id, name, description, mode, state, min_healthy, created_at, updated_at
		FROM server_pools
		WHERE state != 'draining'
		ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ServerPool
	for rows.Next() {
		var p ServerPool
		if err := rows.Scan(&p.ID, &p.ProjectID, &p.Name, &p.Description, &p.Mode, &p.State,
			&p.MinHealthy, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
