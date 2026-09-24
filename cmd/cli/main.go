// Command jawaker is the primary operator command-line interface for JAWAKER.
//
// Conforms to PRD §26.3 and §29.4:
// - jawaker server list
// - jawaker site create --domain <domain> --runtime <runtime>
// - jawaker deploy <app> --commit <commit>
// - jawaker backup run <target>
// - jawaker logs <target> [--follow]
// - jawaker doctor
// - jawaker repair
// - jawaker recovery
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/version"
)

type cliConfig struct {
	endpoint string
	token    string
	timeout  time.Duration
}

func loadConfig() cliConfig {
	ep := os.Getenv("JAWAKER_API_ENDPOINT")
	if ep == "" {
		ep = "http://127.0.0.1:8080"
	}
	ep = strings.TrimRight(ep, "/")

	token := os.Getenv("JAWAKER_API_TOKEN")
	return cliConfig{
		endpoint: ep,
		token:    token,
		timeout:  30 * time.Second,
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "server":
		err = handleServer(args)
	case "site":
		err = handleSite(args)
	case "deploy":
		err = handleDeploy(args)
	case "backup":
		err = handleBackup(args)
	case "logs":
		err = handleLogs(args)
	case "doctor":
		err = handleDoctor(args)
	case "repair":
		err = handleRepair(args)
	case "recovery":
		err = handleRecovery(args)
	case "version", "-version", "--version":
		fmt.Printf("jawaker version %s\n", version.String())
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\nRun 'jawaker help' for usage.\n", cmd)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`JAWAKER CLI - Unified Server & Platform Management

Usage:
  jawaker <command> [arguments]

Available Commands:
  server list                             List enrolled servers
  site create --domain <d> --runtime <r>  Create a new hosted site
  site list                               List hosted sites
  deploy <app> --commit <c>               Trigger application release deployment
  backup run <target>                     Trigger backup for site/database
  backup list                             List recent backup records
  logs <target> [--follow]                Tail recent logs for site or container
  doctor                                  Run local and remote health diagnostics
  repair                                  Run safe self-healing repair checks
  recovery                                Launch emergency recovery sub-system
  version                                 Display version information

Environment Variables:
  JAWAKER_API_ENDPOINT  Base controller API URL (default: http://127.0.0.1:8080)
  JAWAKER_API_TOKEN     Authentication bearer or personal access token`)
}

func apiRequest(ctx context.Context, cfg cliConfig, method, path string, body any) ([]byte, error) {
	var bodyReader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(raw)
	}

	url := fmt.Sprintf("%s%s", cfg.endpoint, path)
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cfg.token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.token)
	}

	client := &http.Client{Timeout: cfg.timeout}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API connection failed (%s): %w", url, err)
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, string(respData))
	}

	return respData, nil
}

// handleServer manages server list.
func handleServer(args []string) error {
	if len(args) == 0 || args[0] != "list" {
		return errors.New("usage: jawaker server list")
	}

	cfg := loadConfig()
	data, err := apiRequest(context.Background(), cfg, http.MethodGet, "/api/v1/servers", nil)
	if err != nil {
		return err
	}

	var payload struct {
		Servers []struct {
			ID       string `json:"id"`
			Hostname string `json:"hostname"`
			Address  string `json:"address"`
			Status   string `json:"status"`
			OS       string `json:"os"`
		} `json:"servers"`
	}

	if err := json.Unmarshal(data, &payload); err != nil {
		// Output raw JSON if structure doesn't match
		fmt.Println(string(data))
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "ID\tHOSTNAME\tADDRESS\tSTATUS\tOS")
	for _, s := range payload.Servers {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.ID, s.Hostname, s.Address, s.Status, s.OS)
	}
	return w.Flush()
}

// handleSite manages site creation and listing.
func handleSite(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: jawaker site [create|list]")
	}

	cfg := loadConfig()
	switch args[0] {
	case "list":
		data, err := apiRequest(context.Background(), cfg, http.MethodGet, "/api/v1/sites", nil)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil

	case "create":
		fs := flag.NewFlagSet("site create", flag.ContinueOnError)
		domain := fs.String("domain", "", "Primary domain name for the site")
		runtime := fs.String("runtime", "php", "Runtime mode (php, static, proxy)")
		projectID := fs.String("project", "default", "Target project ID")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *domain == "" {
			return errors.New("--domain is required")
		}

		body := map[string]any{
			"primary_domain": *domain,
			"mode":           *runtime,
		}
		path := fmt.Sprintf("/api/v1/projects/%s/sites", *projectID)
		res, err := apiRequest(context.Background(), cfg, http.MethodPost, path, body)
		if err != nil {
			return err
		}
		fmt.Printf("Site created successfully:\n%s\n", string(res))
		return nil

	default:
		return fmt.Errorf("unknown site subcommand: %s", args[0])
	}
}

// handleDeploy triggers an application deployment.
func handleDeploy(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: jawaker deploy <app_id> --commit <hash>")
	}
	appID := args[0]

	fs := flag.NewFlagSet("deploy", flag.ContinueOnError)
	commit := fs.String("commit", "HEAD", "Git commit hash or branch")
	projectID := fs.String("project", "default", "Target project ID")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	cfg := loadConfig()
	body := map[string]any{
		"commit_sha": *commit,
	}
	path := fmt.Sprintf("/api/v1/projects/%s/apps/%s/deployments", *projectID, appID)
	res, err := apiRequest(context.Background(), cfg, http.MethodPost, path, body)
	if err != nil {
		return err
	}

	fmt.Printf("Deployment triggered successfully for app '%s':\n%s\n", appID, string(res))
	return nil
}

// handleBackup handles triggering and viewing backups.
func handleBackup(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: jawaker backup [run|list]")
	}

	cfg := loadConfig()
	switch args[0] {
	case "list":
		data, err := apiRequest(context.Background(), cfg, http.MethodGet, "/api/v1/backups", nil)
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil

	case "run":
		if len(args) < 2 {
			return errors.New("usage: jawaker backup run <target_id>")
		}
		target := args[1]
		body := map[string]any{
			"target": target,
		}
		res, err := apiRequest(context.Background(), cfg, http.MethodPost, "/api/v1/backups/run", body)
		if err != nil {
			return err
		}
		fmt.Printf("Backup started for target '%s':\n%s\n", target, string(res))
		return nil

	default:
		return fmt.Errorf("unknown backup subcommand: %s", args[0])
	}
}

// handleLogs streams or tails logs for a given resource.
func handleLogs(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: jawaker logs <target_id> [--follow]")
	}
	target := args[0]
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	follow := fs.Bool("follow", false, "Follow log stream")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}

	cfg := loadConfig()
	path := fmt.Sprintf("/api/v1/logs/tail?source=%s&follow=%t", target, *follow)
	data, err := apiRequest(context.Background(), cfg, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	fmt.Print(string(data))
	return nil
}

// handleDoctor performs diagnostics.
func handleDoctor(args []string) error {
	fmt.Println("Running JAWAKER System Diagnostics...")
	cfg := loadConfig()

	// 1. Check API endpoint reachability
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	data, err := apiRequest(ctx, cfg, http.MethodGet, "/healthz", nil)
	if err != nil {
		fmt.Printf("[FAIL] Controller API reachability (%s): %v\n", cfg.endpoint, err)
	} else {
		fmt.Printf("[OK]   Controller API reachability: %s\n", string(bytes.TrimSpace(data)))
	}

	// 2. Query node/system doctor if endpoint available
	docData, err := apiRequest(context.Background(), cfg, http.MethodGet, "/api/v1/doctor", nil)
	if err == nil {
		fmt.Println("\nDiagnostic Report:")
		fmt.Println(string(docData))
	} else {
		fmt.Println("[WARN] Remote doctor diagnostics endpoint not accessible:", err)
	}
	return nil
}

// handleRepair implements repair preview and self-healing.
func handleRepair(args []string) error {
	fmt.Println("Analyzing system state for repairable issues...")
	cfg := loadConfig()

	data, err := apiRequest(context.Background(), cfg, http.MethodPost, "/api/v1/repair", map[string]any{"dry_run": true})
	if err != nil {
		fmt.Println("Repair preview result: No automated repairs required or repair service unreachable.")
		return nil
	}
	fmt.Println("Repair plan:")
	fmt.Println(string(data))
	return nil
}

// handleRecovery presents recovery options.
func handleRecovery(args []string) error {
	fmt.Println("=== JAWAKER EMERGENCY RECOVERY ===")
	fmt.Println("1. Restore last known-good configuration")
	fmt.Println("2. Disable misbehaving plugins/modules")
	fmt.Println("3. Rotate administrator credentials")
	fmt.Println("4. Export diagnostics bundle")
	fmt.Println("\nTo perform offline recovery, invoke 'jawaker-recovery' utility directly.")
	return nil
}
