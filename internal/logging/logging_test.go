package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestNewRejectsUnknownFormat(t *testing.T) {
	if _, err := New(Options{Level: "info", Format: "yaml"}); err == nil {
		t.Fatal("expected error for unsupported format")
	}
}

func TestNewRejectsUnknownLevel(t *testing.T) {
	if _, err := New(Options{Level: "trace", Format: "json"}); err == nil {
		t.Fatal("expected error for unsupported level")
	}
}

func TestJSONOutputShape(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(Options{Level: "info", Format: "json", Component: "controller", Out: &buf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.Info("started", "listen", "127.0.0.1:8443")

	var record map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &record); err != nil {
		t.Fatalf("output is not valid JSON: %v (raw=%q)", err, buf.String())
	}
	if record["msg"] != "started" {
		t.Errorf("msg = %v, want started", record["msg"])
	}
	if record[AttrComponent] != "controller" {
		t.Errorf("component = %v, want controller", record[AttrComponent])
	}
	if record["level"] != "INFO" {
		t.Errorf("level = %v, want INFO", record["level"])
	}
}

func TestLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(Options{Level: "warn", Format: "json", Out: &buf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.Debug("noisy")
	logger.Info("also noisy")
	logger.Warn("keep me")

	if strings.Contains(buf.String(), "noisy") {
		t.Errorf("debug/info records should be filtered at warn level: %q", buf.String())
	}
	if !strings.Contains(buf.String(), "keep me") {
		t.Errorf("warn record should be emitted: %q", buf.String())
	}
}

func TestRequestIDRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(Options{Level: "info", Format: "json", Out: &buf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, bound := WithRequestID(context.Background(), logger, "req_abc123")
	bound.Info("handled")

	if got := RequestIDFromContext(ctx); got != "req_abc123" {
		t.Errorf("RequestIDFromContext = %q, want req_abc123", got)
	}
	if !strings.Contains(buf.String(), "req_abc123") {
		t.Errorf("log record should carry the request id: %q", buf.String())
	}
}

func TestRequestIDFromEmptyContext(t *testing.T) {
	if got := RequestIDFromContext(context.Background()); got != "" {
		t.Errorf("RequestIDFromContext on empty ctx = %q, want empty", got)
	}
}

func TestTextFormat(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(Options{Level: "info", Format: "text", Out: &buf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.Info("plain", slog.String("k", "v"))
	out := buf.String()
	if !strings.Contains(out, "msg=plain") || !strings.Contains(out, "k=v") {
		t.Errorf("unexpected text output: %q", out)
	}
}
