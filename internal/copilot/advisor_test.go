package copilot

import (
	"testing"
)

func TestExecuteTool_AnalyzeLogs(t *testing.T) {
	input := map[string]any{
		"resource": "web-01",
		"logs":     "2026-01-01 ERROR: out of memory\n2026-01-01 WARN: connection refused to db:5432",
	}
	result, err := ExecuteTool("analyze.logs", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RiskLevel != "high" {
		t.Errorf("expected high risk for OOM, got %q", result.RiskLevel)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings for OOM + connection refused")
	}
}

func TestExecuteTool_GeneratePlan(t *testing.T) {
	input := map[string]any{
		"intent":   "restart web server",
		"resource": "nginx-prod",
	}
	result, err := ExecuteTool("plan.generate", input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.RiskLevel != "high" {
		t.Errorf("restart plan should be high risk, got %q", result.RiskLevel)
	}
	if len(result.Steps) == 0 {
		t.Error("expected plan steps")
	}
}

func TestExecuteTool_UnknownTool(t *testing.T) {
	_, err := ExecuteTool("shell.run", map[string]any{})
	if err == nil {
		t.Fatal("expected error for unknown tool")
	}
}

func TestExecuteTool_AllAllowedTools(t *testing.T) {
	for name := range AllowedTools {
		_, err := ExecuteTool(name, map[string]any{
			"logs":          "normal operation",
			"cpu_pct":       50.0,
			"resource_type": "site",
			"title":         "disk full incident",
			"alert_name":    "cpu_high",
			"intent":        "deploy app",
			"resource":      "api-01",
		})
		if err != nil {
			t.Errorf("tool %q returned error: %v", name, err)
		}
	}
}
