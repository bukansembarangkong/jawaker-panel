// Package config loads typed runtime configuration from the environment.
//
// Design rules:
//   - Environment is the only configuration source (no config files to drift).
//   - Every value is validated once at startup; failures are actionable errors
//     naming the offending variable, never silent defaults over bad input.
//   - Secrets are kept out of String()/log output (see RedactedDSN).
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Defaults are deliberately conservative: loopback binding and strict limits.
const (
	defaultListenAddr   = "127.0.0.1:8443"
	defaultLogLevel     = "info"
	defaultLogFormat    = "json"
	defaultMaxBodyBytes = 1 << 20 // 1 MiB request body limit (API.md §18)
	defaultMaxHeaderKB  = 64
)

// Config is the validated controller configuration.
type Config struct {
	// ListenAddr is the host:port the controller HTTP server binds to.
	ListenAddr string
	// DatabaseURL is the PostgreSQL DSN. Empty disables database features;
	// the controller still serves health/version (graceful degradation).
	DatabaseURL string
	// RunMigrations applies pending migrations at startup when true.
	RunMigrations bool
	// LogLevel is one of debug, info, warn, error.
	LogLevel string
	// LogFormat is json or text.
	LogFormat string
	// MaxBodyBytes bounds request bodies.
	MaxBodyBytes int64
	// MaxHeaderBytes bounds request headers.
	MaxHeaderBytes int
	// RequestTimeoutSeconds bounds handler execution time.
	RequestTimeoutSeconds int
}

// Load reads configuration from the process environment and validates it.
// Unknown variables are ignored; malformed known variables are hard errors.
func Load() (*Config, error) {
	cfg := &Config{
		ListenAddr:            envOr("JAWAKER_LISTEN_ADDR", defaultListenAddr),
		DatabaseURL:           strings.TrimSpace(os.Getenv("JAWAKER_DATABASE_URL")),
		LogLevel:              strings.ToLower(envOr("JAWAKER_LOG_LEVEL", defaultLogLevel)),
		LogFormat:             strings.ToLower(envOr("JAWAKER_LOG_FORMAT", defaultLogFormat)),
		MaxBodyBytes:          defaultMaxBodyBytes,
		MaxHeaderBytes:        defaultMaxHeaderKB * 1024,
		RequestTimeoutSeconds: 30,
	}

	var errs []error

	if host, port, err := net.SplitHostPort(cfg.ListenAddr); err != nil {
		errs = append(errs, fmt.Errorf("JAWAKER_LISTEN_ADDR %q is not host:port: %w", cfg.ListenAddr, err))
	} else {
		if n, convErr := strconv.Atoi(port); convErr != nil || n < 1 || n > 65535 {
			errs = append(errs, fmt.Errorf("JAWAKER_LISTEN_ADDR %q has invalid port", cfg.ListenAddr))
		}
		_ = host // any host string is acceptable; binding decides reachability
	}

	if cfg.DatabaseURL != "" {
		if _, err := url.Parse(cfg.DatabaseURL); err != nil {
			errs = append(errs, fmt.Errorf("JAWAKER_DATABASE_URL is not a valid URL: %w", err))
		} else if !strings.HasPrefix(cfg.DatabaseURL, "postgres://") && !strings.HasPrefix(cfg.DatabaseURL, "postgresql://") {
			errs = append(errs, fmt.Errorf("JAWAKER_DATABASE_URL must use the postgres:// or postgresql:// scheme"))
		}
	}

	switch cfg.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("JAWAKER_LOG_LEVEL %q must be one of debug|info|warn|error", cfg.LogLevel))
	}

	switch cfg.LogFormat {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("JAWAKER_LOG_FORMAT %q must be json or text", cfg.LogFormat))
	}

	if v := os.Getenv("JAWAKER_RUN_MIGRATIONS"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("JAWAKER_RUN_MIGRATIONS %q is not a boolean: %w", v, err))
		} else {
			cfg.RunMigrations = b
		}
	} else {
		cfg.RunMigrations = true
	}

	if v := os.Getenv("JAWAKER_MAX_BODY_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			errs = append(errs, fmt.Errorf("JAWAKER_MAX_BODY_BYTES %q must be a positive integer", v))
		} else {
			cfg.MaxBodyBytes = n
		}
	}

	if v := os.Getenv("JAWAKER_REQUEST_TIMEOUT_SECONDS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			errs = append(errs, fmt.Errorf("JAWAKER_REQUEST_TIMEOUT_SECONDS %q must be a positive integer", v))
		} else {
			cfg.RequestTimeoutSeconds = n
		}
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid configuration: %w", joinErrors(errs))
	}
	return cfg, nil
}

// RedactedDSN returns the database URL with any password replaced, suitable
// for logs and diagnostics. Empty URL stays empty. The mask is substituted
// textually so it is never percent-encoded.
func (c *Config) RedactedDSN() string {
	if c.DatabaseURL == "" {
		return ""
	}
	u, err := url.Parse(c.DatabaseURL)
	if err != nil {
		return "<unparseable-dsn>"
	}
	if _, hasPassword := u.User.Password(); !hasPassword {
		return c.DatabaseURL
	}
	// Replace only the password segment between "//user:" and "@host".
	at := strings.LastIndex(c.DatabaseURL, "@")
	colon := strings.Index(c.DatabaseURL, "://")
	if at < 0 || colon < 0 {
		return "<unparseable-dsn>"
	}
	userinfo := c.DatabaseURL[colon+3 : at]
	pwColon := strings.Index(userinfo, ":")
	if pwColon < 0 {
		return c.DatabaseURL
	}
	return c.DatabaseURL[:colon+3] + userinfo[:pwColon+1] + "********" + c.DatabaseURL[at:]
}

// String renders a safe summary of the configuration for startup logs.
// It never includes credentials.
func (c *Config) String() string {
	return fmt.Sprintf("listen=%s database=%q migrations=%t log=%s/%s",
		c.ListenAddr, c.RedactedDSN(), c.RunMigrations, c.LogFormat, c.LogLevel)
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

type multiError struct{ errs []error }

func (m *multiError) Error() string {
	parts := make([]string, 0, len(m.errs))
	for _, err := range m.errs {
		parts = append(parts, err.Error())
	}
	return strings.Join(parts, "; ")
}

func joinErrors(errs []error) error { return &multiError{errs: errs} }
