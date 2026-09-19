package config

import (
	"strings"
	"testing"
)

func setEnv(t *testing.T, kv map[string]string) {
	t.Helper()
	for k, v := range kv {
		t.Setenv(k, v)
	}
}

func TestLoadDefaults(t *testing.T) {
	// Ensure a clean environment: unset every recognized variable.
	for _, k := range []string{
		"JAWAKER_LISTEN_ADDR", "JAWAKER_DATABASE_URL", "JAWAKER_RUN_MIGRATIONS",
		"JAWAKER_LOG_LEVEL", "JAWAKER_LOG_FORMAT", "JAWAKER_MAX_BODY_BYTES",
		"JAWAKER_REQUEST_TIMEOUT_SECONDS",
	} {
		t.Setenv(k, "")
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() with defaults: unexpected error: %v", err)
	}
	if cfg.ListenAddr != defaultListenAddr {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, defaultListenAddr)
	}
	if cfg.DatabaseURL != "" {
		t.Errorf("DatabaseURL = %q, want empty", cfg.DatabaseURL)
	}
	if !cfg.RunMigrations {
		t.Error("RunMigrations should default to true")
	}
	if cfg.LogLevel != "info" || cfg.LogFormat != "json" {
		t.Errorf("log defaults = %s/%s, want json/info", cfg.LogFormat, cfg.LogLevel)
	}
	if cfg.MaxBodyBytes != defaultMaxBodyBytes {
		t.Errorf("MaxBodyBytes = %d, want %d", cfg.MaxBodyBytes, defaultMaxBodyBytes)
	}
}

func TestLoadInvalidListenAddr(t *testing.T) {
	setEnv(t, map[string]string{"JAWAKER_LISTEN_ADDR": "not-a-host-port"})
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid JAWAKER_LISTEN_ADDR")
	}
	if !strings.Contains(err.Error(), "JAWAKER_LISTEN_ADDR") {
		t.Errorf("error %q should name the offending variable", err)
	}
}

func TestLoadInvalidPort(t *testing.T) {
	setEnv(t, map[string]string{"JAWAKER_LISTEN_ADDR": "127.0.0.1:99999"})
	if _, err := Load(); err == nil {
		t.Fatal("expected error for out-of-range port")
	}
}

func TestLoadRejectsBadDSNScheme(t *testing.T) {
	setEnv(t, map[string]string{"JAWAKER_DATABASE_URL": "mysql://user:pass@localhost/db"})
	_, err := Load()
	if err == nil {
		t.Fatal("expected error for non-postgres DSN scheme")
	}
	if !strings.Contains(err.Error(), "postgres") {
		t.Errorf("error %q should mention the postgres scheme requirement", err)
	}
}

func TestLoadAcceptsPostgresDSN(t *testing.T) {
	setEnv(t, map[string]string{
		"JAWAKER_DATABASE_URL": "postgres://u:p@127.0.0.1:5432/jawaker?sslmode=disable",
	})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DatabaseURL == "" {
		t.Error("DatabaseURL should be populated")
	}
}

func TestLoadRejectsBadLogLevel(t *testing.T) {
	setEnv(t, map[string]string{"JAWAKER_LOG_LEVEL": "trace"})
	if _, err := Load(); err == nil {
		t.Fatal("expected error for unsupported log level")
	}
}

func TestLoadRejectsBadLogFormat(t *testing.T) {
	setEnv(t, map[string]string{"JAWAKER_LOG_FORMAT": "yaml"})
	if _, err := Load(); err == nil {
		t.Fatal("expected error for unsupported log format")
	}
}

func TestLoadRejectsBadBooleansAndInts(t *testing.T) {
	setEnv(t, map[string]string{"JAWAKER_RUN_MIGRATIONS": "maybe"})
	if _, err := Load(); err == nil {
		t.Fatal("expected error for non-boolean JAWAKER_RUN_MIGRATIONS")
	}

	setEnv(t, map[string]string{"JAWAKER_RUN_MIGRATIONS": "", "JAWAKER_MAX_BODY_BYTES": "-5"})
	if _, err := Load(); err == nil {
		t.Fatal("expected error for non-positive JAWAKER_MAX_BODY_BYTES")
	}
}

func TestRunMigrationsFalse(t *testing.T) {
	setEnv(t, map[string]string{"JAWAKER_RUN_MIGRATIONS": "false"})
	cfg, err := Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.RunMigrations {
		t.Error("RunMigrations should be false when JAWAKER_RUN_MIGRATIONS=false")
	}
}

func TestRedactedDSNHidesPassword(t *testing.T) {
	cfg := &Config{DatabaseURL: "postgres://admin:supersecret@db:5432/jawaker?sslmode=require"}
	redacted := cfg.RedactedDSN()
	if strings.Contains(redacted, "supersecret") {
		t.Errorf("RedactedDSN leaked the password: %q", redacted)
	}
	if !strings.Contains(redacted, "********") {
		t.Errorf("RedactedDSN should mask the password: %q", redacted)
	}
	if !strings.Contains(redacted, "admin") {
		t.Errorf("RedactedDSN should keep the username: %q", redacted)
	}
}

func TestRedactedDSNEmpty(t *testing.T) {
	cfg := &Config{}
	if got := cfg.RedactedDSN(); got != "" {
		t.Errorf("RedactedDSN for empty URL = %q, want empty", got)
	}
}

func TestStringOmitsSecrets(t *testing.T) {
	cfg := &Config{
		ListenAddr:  "127.0.0.1:8443",
		DatabaseURL: "postgres://admin:supersecret@db:5432/jawaker",
		LogLevel:    "info",
		LogFormat:   "json",
	}
	s := cfg.String()
	if strings.Contains(s, "supersecret") {
		t.Errorf("String() leaked the password: %q", s)
	}
}
