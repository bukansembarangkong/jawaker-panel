// Package logging builds the process-wide structured logger.
//
// All JAWAKER services log through slog with a shared attribute vocabulary so
// request/job/revision correlation IDs are greppable across components
// (AGENTS.md §6: structured logging with correlation IDs).
package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

// Standard attribute keys. Use these instead of ad-hoc strings so log queries
// stay stable across services.
const (
	AttrRequestID  = "request_id"
	AttrJobID      = "job_id"
	AttrActorID    = "actor_id"
	AttrResourceID = "resource_id"
	AttrComponent  = "component"
)

type ctxKey struct{ name string }

var requestIDKey = ctxKey{"request_id"}

// Options configures logger construction.
type Options struct {
	// Level is one of debug, info, warn, error. Invalid values are an error.
	Level string
	// Format is json or text. Invalid values are an error.
	Format string
	// Component tags every record emitted by this logger (e.g. "controller").
	Component string
	// Out defaults to os.Stdout when nil.
	Out io.Writer
}

// New builds a slog logger from validated options.
func New(opts Options) (*slog.Logger, error) {
	level, err := parseLevel(opts.Level)
	if err != nil {
		return nil, err
	}

	out := opts.Out
	if out == nil {
		out = os.Stdout
	}

	handlerOpts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	switch strings.ToLower(opts.Format) {
	case "", "json":
		handler = slog.NewJSONHandler(out, handlerOpts)
	case "text":
		handler = slog.NewTextHandler(out, handlerOpts)
	default:
		return nil, fmt.Errorf("logging: unsupported format %q (want json or text)", opts.Format)
	}

	logger := slog.New(handler)
	if opts.Component != "" {
		logger = logger.With(AttrComponent, opts.Component)
	}
	return logger, nil
}

// WithRequestID returns a context carrying the request correlation ID and a
// logger bound to it.
func WithRequestID(ctx context.Context, logger *slog.Logger, requestID string) (context.Context, *slog.Logger) {
	return context.WithValue(ctx, requestIDKey, requestID), logger.With(AttrRequestID, requestID)
}

// RequestIDFromContext extracts the correlation ID, or "" when absent.
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

func parseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("logging: unsupported level %q (want debug|info|warn|error)", s)
	}
}
