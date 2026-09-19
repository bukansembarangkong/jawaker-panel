// Package db provides the control-plane PostgreSQL connection pool.
//
// Bounded pool settings follow AGENTS.md §12 (bound queues/concurrency).
// All operations take a context so cancellation propagates (AGENTS.md §6).
package db

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolConfig carries bounded pool settings with conservative defaults.
type PoolConfig struct {
	// MaxConns caps total connections the panel may hold. Small installs
	// share PostgreSQL with managed workloads; stay polite.
	MaxConns int32
	// MinConns keeps a small warm set; 0 keeps idle footprint minimal.
	MinConns int32
	// MaxConnLifetime rotates connections defensively.
	MaxConnLifetime time.Duration
	// ConnTimeout bounds establishing a connection.
	ConnTimeout time.Duration
}

// DefaultPoolConfig returns conservative production defaults.
func DefaultPoolConfig() PoolConfig {
	return PoolConfig{
		MaxConns:        8,
		MinConns:        0,
		MaxConnLifetime: time.Hour,
		ConnTimeout:     10 * time.Second,
	}
}

// Connect builds a pgx pool from a DSN and verifies reachability with a ping.
// The caller owns Close (usually via defer in main).
func Connect(ctx context.Context, dsn string, cfg PoolConfig) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("db: parse DSN: %w", err)
	}
	if cfg.MaxConns > 0 {
		poolCfg.MaxConns = cfg.MaxConns
	}
	if cfg.MinConns >= 0 {
		poolCfg.MinConns = cfg.MinConns
	}
	if cfg.MaxConnLifetime > 0 {
		poolCfg.MaxConnLifetime = cfg.MaxConnLifetime
	}
	if cfg.ConnTimeout > 0 {
		poolCfg.ConnConfig.ConnectTimeout = cfg.ConnTimeout
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("db: create pool: %w", err)
	}

	pingTimeout := cfg.ConnTimeout
	if pingTimeout <= 0 {
		pingTimeout = 10 * time.Second
	}
	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db: ping: %w", err)
	}
	return pool, nil
}
