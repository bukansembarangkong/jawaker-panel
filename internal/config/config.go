// Package config loads typed runtime configuration from the environment.
//
// Design rules:
//   - Environment is the only configuration source (no config files to drift).
//   - Every value is validated once at startup; failures are actionable errors
//     naming the offending variable, never silent defaults over bad input.
//   - Secrets are kept out of String()/log output (see RedactedDSN).
package config

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"regexp"
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

	// Login attempts are limited per client address per minute. 10 is generous
	// for a human who mistyped and useless for guessing: combined with the
	// per-account lockout it caps online guessing to a few hundred attempts a
	// day against one account.
	defaultLoginAttemptsPerMinute = 10
	// Bootstrap is a one-time operation, so the limit can be tight.
	defaultBootstrapAttemptsPerMinute = 5
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

	// SecretKeys maps key version -> base64 AES-256 key for the secret
	// subsystem. One env var per version lets a rotation run with the old and
	// the new key both present. Empty disables secret-backed features (TOTP).
	SecretKeys map[int]string
	// CookieSecure marks session cookies Secure. Defaults to true.
	CookieSecure bool
	// CookieAllowInsecure is the deliberate opt-out for local HTTP development.
	CookieAllowInsecure bool
	// TrustedOrigins are extra origins accepted for state-changing requests, for
	// a split front end. Empty means same-origin only.
	TrustedOrigins []string
	// LoginAttemptsPerMinute bounds login attempts per client address.
	LoginAttemptsPerMinute int
	// BootstrapAttemptsPerMinute bounds bootstrap attempts per client address.
	BootstrapAttemptsPerMinute int

	// GitOpsGitHubToken is the GitHub personal access token for GitOps push (PRD §24).
	// Set via JAWAKER_GITOPS_GITHUB_TOKEN. Empty disables real git push (rule-based fallback).
	GitOpsGitHubToken string
	// GitOpsRepoURL is the target GitHub repository, e.g. "owner/repo" or full https URL.
	// Set via JAWAKER_GITOPS_REPO_URL.
	GitOpsRepoURL string
	// GitOpsBranch is the branch to commit revisions to (default: "main").
	// Set via JAWAKER_GITOPS_BRANCH.
	GitOpsBranch string
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
		GitOpsGitHubToken:     strings.TrimSpace(os.Getenv("JAWAKER_GITOPS_GITHUB_TOKEN")),
		GitOpsRepoURL:         strings.TrimSpace(os.Getenv("JAWAKER_GITOPS_REPO_URL")),
		GitOpsBranch:          envOr("JAWAKER_GITOPS_BRANCH", "main"),
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

	cfg.SecretKeys = loadSecretKeys(&errs)

	// Secure cookies are the default. The insecure opt-out must be explicit so a
	// typo cannot silently downgrade session cookies to plain HTTP — a malformed
	// value is a startup error, consistent with every other known variable.
	if v := os.Getenv("JAWAKER_COOKIE_ALLOW_INSECURE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Errorf("JAWAKER_COOKIE_ALLOW_INSECURE %q is not a boolean: %w", v, err))
		} else {
			cfg.CookieAllowInsecure = b
		}
	}
	cfg.CookieSecure = !cfg.CookieAllowInsecure
	if cfg.CookieAllowInsecure && cfg.ListenAddr != "" && !isLoopbackHost(cfg.ListenAddr) {
		errs = append(errs, fmt.Errorf(
			"JAWAKER_COOKIE_ALLOW_INSECURE is set but JAWAKER_LISTEN_ADDR %q is not loopback; "+
				"session cookies must not travel over plain HTTP on a reachable interface", cfg.ListenAddr))
	}

	if v := os.Getenv("JAWAKER_TRUSTED_ORIGINS"); v != "" {
		for _, origin := range strings.Split(v, ",") {
			if origin = strings.TrimSpace(origin); origin != "" {
				cfg.TrustedOrigins = append(cfg.TrustedOrigins, origin)
			}
		}
	}

	cfg.LoginAttemptsPerMinute = defaultLoginAttemptsPerMinute
	if v := os.Getenv("JAWAKER_LOGIN_ATTEMPTS_PER_MINUTE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			errs = append(errs, fmt.Errorf("JAWAKER_LOGIN_ATTEMPTS_PER_MINUTE %q must be a positive integer", v))
		} else {
			cfg.LoginAttemptsPerMinute = n
		}
	}

	cfg.BootstrapAttemptsPerMinute = defaultBootstrapAttemptsPerMinute
	if v := os.Getenv("JAWAKER_BOOTSTRAP_ATTEMPTS_PER_MINUTE"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			errs = append(errs, fmt.Errorf("JAWAKER_BOOTSTRAP_ATTEMPTS_PER_MINUTE %q must be a positive integer", v))
		} else {
			cfg.BootstrapAttemptsPerMinute = n
		}
	}

	if len(errs) > 0 {
		return nil, fmt.Errorf("invalid configuration: %w", joinErrors(errs))
	}
	return cfg, nil
}

// Secret key environment variables, one per version:
//
//	JAWAKER_SECRET_KEY_V1, JAWAKER_SECRET_KEY_V2, ...
//
// Reading the version from the variable name lets a rotation run with the old
// key still present for reads while new writes use the higher version.
var secretKeyEnvPattern = regexp.MustCompile(`^JAWAKER_SECRET_KEY_V([0-9]+)$`)

// loadSecretKeys collects the configured master keys and validates each one by
// decoding it, so a malformed key is a startup error rather than a login
// failure later.
func loadSecretKeys(errs *[]error) map[int]string {
	keys := make(map[int]string)
	for _, entry := range os.Environ() {
		name, value, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		match := secretKeyEnvPattern.FindStringSubmatch(name)
		if match == nil {
			continue
		}
		version, err := strconv.Atoi(match[1])
		if err != nil || version <= 0 {
			*errs = append(*errs, fmt.Errorf("%s has an invalid key version", name))
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(value))
		if err != nil {
			// Also accept unpadded base64, which is what a generated key often
			// looks like when copied out of a config file.
			decoded, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(value))
		}
		if err != nil {
			*errs = append(*errs, fmt.Errorf("%s is not valid base64", name))
			continue
		}
		if len(decoded) != 32 {
			*errs = append(*errs, fmt.Errorf(
				"%s must decode to 32 bytes for AES-256, got %d", name, len(decoded)))
			continue
		}
		keys[version] = strings.TrimSpace(value)
	}
	return keys
}

// HasSecretKeys reports whether the secret subsystem can be enabled.
func (c *Config) HasSecretKeys() bool { return len(c.SecretKeys) > 0 }

// isLoopbackHost reports whether a listen address is bound to a loopback
// interface, which is the only place an insecure cookie override is tolerable.
func isLoopbackHost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return ip.IsLoopback()
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
	return fmt.Sprintf("listen=%s database=%q migrations=%t log=%s/%s secure_cookies=%t secret_keys=%d",
		c.ListenAddr, c.RedactedDSN(), c.RunMigrations, c.LogFormat, c.LogLevel,
		c.CookieSecure, len(c.SecretKeys))
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
