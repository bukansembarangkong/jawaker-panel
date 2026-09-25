// Package copilot: rule-based advisor engine (PRD §28).
//
// ExecuteTool runs the deterministic, read-only analysis logic for each allowed tool.
// No external AI provider is required; results are computed from the provided inputs.
//
// When a real LLM provider is integrated, this engine serves as the fallback/override
// layer for structured outputs that must be deterministic.
package copilot

import (
	"fmt"
	"strings"
)

// ToolResult is the deterministic output of a tool invocation.
type ToolResult struct {
	Summary    string     `json:"summary"`
	Details    string     `json:"details,omitempty"`
	Findings   []string   `json:"findings,omitempty"`
	RiskLevel  string     `json:"risk_level,omitempty"`
	Steps      []PlanStep `json:"steps,omitempty"`
	Confidence string     `json:"confidence,omitempty"`
	Source     string     `json:"source"`
}

// PlanStep represents one step in a generated change plan.
type PlanStep struct {
	Order       int    `json:"order"`
	Description string `json:"description"`
	Reversible  bool   `json:"reversible"`
	Rollback    string `json:"rollback,omitempty"`
	RiskLevel   string `json:"risk_level"`
}

// ExecuteTool runs the allowed tool with the given input and returns a structured result.
// All tools are read-only analysis; mutations go through the revision + approval pipeline.
func ExecuteTool(name string, input map[string]any) (ToolResult, error) {
	switch name {
	case "analyze.logs":
		return analyzeLogs(input)
	case "analyze.metrics":
		return analyzeMetrics(input)
	case "analyze.config":
		return analyzeConfig(input)
	case "explain.incident":
		return explainIncident(input)
	case "explain.alert":
		return explainAlert(input)
	case "suggest.config":
		return suggestConfig(input)
	case "plan.generate":
		return generatePlan(input)
	case "config.propose":
		return proposeConfig(input)
	case "config.apply":
		return ToolResult{
			Summary: "Config apply must be initiated through the revision workflow.",
			Details: "Submit the revision ID from config.propose for validation and apply via POST /apply.",
			Source:  "advisor",
		}, nil
	default:
		return ToolResult{}, fmt.Errorf("tool %q not implemented", name)
	}
}

func strInput(input map[string]any, key string) string {
	if v, ok := input[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func analyzeLogs(input map[string]any) (ToolResult, error) {
	logs := strInput(input, "logs")
	resource := strInput(input, "resource")

	findings := []string{}
	var riskLevel = "low"

	lower := strings.ToLower(logs)
	if strings.Contains(lower, "out of memory") || strings.Contains(lower, "oom") {
		findings = append(findings, "OOM killer activity detected. Consider increasing container/process memory limit or profiling memory usage.")
		riskLevel = "high"
	}
	if strings.Contains(lower, "connection refused") || strings.Contains(lower, "no such host") {
		findings = append(findings, "Network connectivity errors detected. Check upstream service health and DNS resolution.")
		if riskLevel == "low" {
			riskLevel = "medium"
		}
	}
	if strings.Contains(lower, "502 bad gateway") || strings.Contains(lower, "upstream timed out") {
		findings = append(findings, "Upstream timeout/bad gateway detected. Check backend service health and response times.")
		if riskLevel == "low" {
			riskLevel = "medium"
		}
	}
	if strings.Contains(lower, "permission denied") || strings.Contains(lower, "access denied") {
		findings = append(findings, "Permission errors found. Audit filesystem permissions and service account grants.")
	}
	if strings.Contains(lower, "disk space") || strings.Contains(lower, "no space left") {
		findings = append(findings, "Disk space exhaustion detected. Clean up logs/temp files and check disk usage.")
		riskLevel = "high"
	}
	if strings.Contains(lower, "panic") || strings.Contains(lower, "fatal") {
		findings = append(findings, "Fatal error/panic in logs. Immediate investigation required.")
		riskLevel = "high"
	}
	if strings.Contains(lower, "too many open files") {
		findings = append(findings, "File descriptor exhaustion. Increase ulimits or review fd leak.")
		if riskLevel == "low" {
			riskLevel = "medium"
		}
	}

	summary := "Log analysis complete."
	if len(findings) == 0 {
		summary = "No critical patterns detected in the provided log sample."
		findings = []string{"Log sample appears healthy within analyzed window."}
	} else {
		summary = fmt.Sprintf("Found %d concern(s) in log sample.", len(findings))
	}
	if resource != "" {
		summary = resource + ": " + summary
	}

	return ToolResult{
		Summary:    summary,
		Findings:   findings,
		RiskLevel:  riskLevel,
		Confidence: "rule-based",
		Source:     "advisor",
	}, nil
}

func analyzeMetrics(input map[string]any) (ToolResult, error) {
	findings := []string{}
	riskLevel := "low"

	checkThreshold := func(key, label string, warnPct, critPct float64) {
		if v, ok := input[key]; ok {
			var pct float64
			switch val := v.(type) {
			case float64:
				pct = val
			case int:
				pct = float64(val)
			}
			if pct >= critPct {
				findings = append(findings, fmt.Sprintf("%s is critically high at %.1f%%.", label, pct))
				riskLevel = "high"
			} else if pct >= warnPct {
				findings = append(findings, fmt.Sprintf("%s is elevated at %.1f%% (above %.0f%% threshold).", label, pct, warnPct))
				if riskLevel == "low" {
					riskLevel = "medium"
				}
			}
		}
	}

	checkThreshold("cpu_pct", "CPU usage", 70, 90)
	checkThreshold("memory_pct", "Memory usage", 80, 95)
	checkThreshold("disk_pct", "Disk usage", 75, 90)
	checkThreshold("load_avg_1m", "Load average (1m)", 2.0, 5.0)

	summary := "Metrics analysis complete."
	if len(findings) == 0 {
		summary = "All resource metrics are within normal thresholds."
		findings = []string{"CPU, memory, and disk are within acceptable ranges."}
	} else {
		summary = fmt.Sprintf("Found %d resource pressure indicator(s).", len(findings))
	}

	return ToolResult{
		Summary:    summary,
		Findings:   findings,
		RiskLevel:  riskLevel,
		Confidence: "rule-based",
		Source:     "advisor",
	}, nil
}

func analyzeConfig(input map[string]any) (ToolResult, error) {
	cfg := strInput(input, "config")
	rtype := strInput(input, "resource_type")

	findings := []string{}
	lower := strings.ToLower(cfg)

	if strings.Contains(lower, "password") && !strings.Contains(lower, "password_ref") {
		findings = append(findings, "Potential plaintext password found in config. Replace with a secret reference (password_ref: secret://...).")
	}
	if strings.Contains(lower, "ssl_verify off") || strings.Contains(lower, "ssl verify off") {
		findings = append(findings, "SSL verification is disabled. Enable for production environments.")
	}
	if strings.Contains(lower, "allow all") || strings.Contains(lower, "0.0.0.0/0") {
		findings = append(findings, "Overly permissive access rule detected (allow all / 0.0.0.0/0). Restrict to known CIDRs.")
	}

	details := ""
	if rtype != "" {
		details = "Resource type: " + rtype
	}
	summary := "Config analysis complete."
	if len(findings) == 0 {
		summary = "No issues detected in the provided configuration."
		findings = []string{"Configuration appears compliant within the analyzed ruleset."}
	} else {
		summary = fmt.Sprintf("Found %d configuration concern(s).", len(findings))
	}

	return ToolResult{
		Summary:    summary,
		Details:    details,
		Findings:   findings,
		RiskLevel:  "medium",
		Confidence: "rule-based",
		Source:     "advisor",
	}, nil
}

func explainIncident(input map[string]any) (ToolResult, error) {
	title := strInput(input, "title")
	severity := strInput(input, "severity")

	details := ""
	steps := []PlanStep{}
	riskLevel := "medium"

	if severity == "critical" || severity == "high" {
		riskLevel = "high"
	}

	lower := strings.ToLower(title)
	switch {
	case strings.Contains(lower, "out of memory") || strings.Contains(lower, "oom"):
		details = "OOM incidents indicate a process is consuming more memory than allowed. Common causes: memory leak, traffic spike, under-provisioned limits."
		steps = []PlanStep{
			{Order: 1, Description: "Identify PID and memory usage pattern in process list", Reversible: true, RiskLevel: "low"},
			{Order: 2, Description: "Check memory growth trend in metrics (last 1h)", Reversible: true, RiskLevel: "low"},
			{Order: 3, Description: "Increase memory limit in resource profile if growth is expected", Reversible: true, Rollback: "Revert resource profile to previous values", RiskLevel: "medium"},
			{Order: 4, Description: "Enable memory profiling to locate leak if growth is unexpected", Reversible: true, RiskLevel: "low"},
		}
	case strings.Contains(lower, "disk") || strings.Contains(lower, "storage"):
		details = "Disk/storage incidents. Common causes: log accumulation, database growth, backup retention failure, runaway temp files."
		steps = []PlanStep{
			{Order: 1, Description: "Run df -h to identify full mount points", Reversible: true, RiskLevel: "low"},
			{Order: 2, Description: "Check /var/log size and last log rotation timestamp", Reversible: true, RiskLevel: "low"},
			{Order: 3, Description: "Review backup retention policy and remove expired backups", Reversible: false, Rollback: "Restore from backup catalog if needed", RiskLevel: "medium"},
		}
	case strings.Contains(lower, "database") || strings.Contains(lower, "db"):
		details = "Database incident. Common causes: connection pool exhaustion, slow query overload, corrupted index, replication lag."
		steps = []PlanStep{
			{Order: 1, Description: "Check active connections vs connection limit", Reversible: true, RiskLevel: "low"},
			{Order: 2, Description: "Identify top slow queries via pg_stat_statements or SLOW_QUERY_LOG", Reversible: true, RiskLevel: "low"},
			{Order: 3, Description: "Restart connection pooler if exhausted", Reversible: true, Rollback: "Restore previous connection pool config", RiskLevel: "medium"},
		}
	default:
		details = "Incident analysis requires reviewing logs and metrics for the affected resource. Use analyze.logs and analyze.metrics for deeper investigation."
		steps = []PlanStep{
			{Order: 1, Description: "Collect logs from the affected resource window", Reversible: true, RiskLevel: "low"},
			{Order: 2, Description: "Run analyze.logs on the collected sample", Reversible: true, RiskLevel: "low"},
			{Order: 3, Description: "Run analyze.metrics to identify resource pressure", Reversible: true, RiskLevel: "low"},
		}
	}

	return ToolResult{
		Summary:    "Incident explanation: " + title,
		Details:    details,
		Steps:      steps,
		RiskLevel:  riskLevel,
		Confidence: "rule-based",
		Source:     "advisor",
	}, nil
}

func explainAlert(input map[string]any) (ToolResult, error) {
	alertName := strInput(input, "alert_name")
	value := strInput(input, "value")

	details := fmt.Sprintf("Alert %q fired", alertName)
	if value != "" {
		details += " with value: " + value
	}

	return ToolResult{
		Summary:    "Alert explanation: " + alertName,
		Details:    details + ". Review the metric definition and threshold. Use analyze.metrics for resource context.",
		Findings:   []string{"Alert threshold breached.", "Verify trend duration before escalating.", "Check related alerts in the same time window."},
		RiskLevel:  "medium",
		Confidence: "rule-based",
		Source:     "advisor",
	}, nil
}

func suggestConfig(input map[string]any) (ToolResult, error) {
	rtype := strInput(input, "resource_type")
	concern := strInput(input, "concern")

	suggestions := []string{
		"Enable HTTP/2 on reverse proxy for latency improvement.",
		"Add health-check endpoints to all backend services.",
		"Enable gzip compression for static asset responses.",
		"Set explicit connection timeout values (avoid infinite waits).",
		"Configure rate limiting per IP at the edge layer.",
	}

	if strings.Contains(strings.ToLower(concern), "security") {
		suggestions = []string{
			"Enforce HSTS with max-age >= 31536000.",
			"Add Content-Security-Policy header.",
			"Set X-Frame-Options: DENY.",
			"Disable server_tokens / ServerSignature.",
			"Use TLS 1.2+ only with strong cipher suites.",
		}
	}

	return ToolResult{
		Summary:    "Configuration suggestions for " + rtype,
		Findings:   suggestions,
		RiskLevel:  "low",
		Confidence: "rule-based",
		Source:     "advisor",
	}, nil
}

func generatePlan(input map[string]any) (ToolResult, error) {
	intent := strInput(input, "intent")
	resource := strInput(input, "resource")

	lower := strings.ToLower(intent)
	steps := []PlanStep{}
	riskLevel := "medium"
	title := "Change plan: " + intent

	switch {
	case strings.Contains(lower, "restart") || strings.Contains(lower, "reboot"):
		riskLevel = "high"
		steps = []PlanStep{
			{Order: 1, Description: "Verify health of dependent services", Reversible: true, RiskLevel: "low"},
			{Order: 2, Description: "Drain traffic from " + resource + " if load-balanced", Reversible: true, Rollback: "Re-add to load balancer", RiskLevel: "medium"},
			{Order: 3, Description: "Restart " + resource, Reversible: false, Rollback: "Rollback to previous running state from snapshot", RiskLevel: "high"},
			{Order: 4, Description: "Verify service health post-restart", Reversible: true, RiskLevel: "low"},
			{Order: 5, Description: "Re-add to load balancer", Reversible: true, RiskLevel: "low"},
		}
	case strings.Contains(lower, "scale") || strings.Contains(lower, "resize"):
		riskLevel = "medium"
		steps = []PlanStep{
			{Order: 1, Description: "Check current resource utilization baseline", Reversible: true, RiskLevel: "low"},
			{Order: 2, Description: "Apply new resource profile to " + resource, Reversible: true, Rollback: "Revert resource profile to previous values", RiskLevel: "medium"},
			{Order: 3, Description: "Monitor resource usage for 5 minutes post-change", Reversible: true, RiskLevel: "low"},
		}
	case strings.Contains(lower, "deploy"):
		riskLevel = "medium"
		steps = []PlanStep{
			{Order: 1, Description: "Validate build artifacts for " + resource, Reversible: true, RiskLevel: "low"},
			{Order: 2, Description: "Create deployment job with idempotency key", Reversible: false, Rollback: "Rollback to previous release via release ID", RiskLevel: "medium"},
			{Order: 3, Description: "Monitor deployment health checks", Reversible: true, RiskLevel: "low"},
			{Order: 4, Description: "Verify application metrics post-deploy", Reversible: true, RiskLevel: "low"},
		}
	case strings.Contains(lower, "certificate") || strings.Contains(lower, "tls") || strings.Contains(lower, "ssl"):
		riskLevel = "medium"
		steps = []PlanStep{
			{Order: 1, Description: "Check certificate expiry date for " + resource, Reversible: true, RiskLevel: "low"},
			{Order: 2, Description: "Trigger renewal via ACME/Let's Encrypt", Reversible: true, RiskLevel: "low"},
			{Order: 3, Description: "Validate new certificate chain", Reversible: true, RiskLevel: "low"},
			{Order: 4, Description: "Reload nginx/web server with new certificate", Reversible: true, Rollback: "Restore previous certificate bundle", RiskLevel: "medium"},
		}
	default:
		steps = []PlanStep{
			{Order: 1, Description: "Assess current state of " + resource, Reversible: true, RiskLevel: "low"},
			{Order: 2, Description: "Prepare change: " + intent, Reversible: true, RiskLevel: "medium"},
			{Order: 3, Description: "Validate change in staging if available", Reversible: true, RiskLevel: "low"},
			{Order: 4, Description: "Apply change and monitor", Reversible: false, Rollback: "Revert via revision rollback", RiskLevel: "medium"},
		}
	}

	return ToolResult{
		Summary:    title,
		Details:    "Deterministic plan generated for: " + intent + " on " + resource,
		Steps:      steps,
		RiskLevel:  riskLevel,
		Confidence: "rule-based",
		Source:     "advisor",
	}, nil
}

func proposeConfig(input map[string]any) (ToolResult, error) {
	rtype := strInput(input, "resource_type")
	changes := strInput(input, "changes")

	return ToolResult{
		Summary: "Config proposal for " + rtype,
		Details: "Proposed changes: " + changes + ". Submit via POST /api/v1/projects/{id}/sites/{site_id}/apply after validation.",
		Findings: []string{
			"Run validate before apply to catch nginx/config syntax errors.",
			"The previous applied revision is stored as rollback reference.",
		},
		RiskLevel:  "medium",
		Confidence: "rule-based",
		Source:     "advisor",
	}, nil
}
