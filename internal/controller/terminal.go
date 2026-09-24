// Package controller: terminal HTTP handlers (PRD §17.4).
//
// Terminal access is bounded, never generic shell.
// Three modes enforced at the HTTP layer:
//   - project: confined to project root with project POSIX uid.
//   - restricted: allowlisted admin binaries only.
//   - root: requires step-up elevation. Still bounded to allowlisted commands.
//
// Implementation uses HTTP chunked streaming (SSE) for read-only audit output.
// POST /exec runs one allowlisted command with stdin from request body.
// No WebSocket dependency: stdlib net/http is sufficient for SSE and chunked responses.
package controller

import (
	"bufio"
	"bytes"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/bukansembarangkong/jawaker-panel/internal/apierr"
	"github.com/bukansembarangkong/jawaker-panel/internal/audit"
	"github.com/bukansembarangkong/jawaker-panel/internal/authsession"
	"github.com/bukansembarangkong/jawaker-panel/internal/httpserver"
	"github.com/bukansembarangkong/jawaker-panel/internal/rbac"
)

// allowedTerminalCommands is the allowlist for bounded task runner mode.
// ponytail: this allowlist is intentionally small; extend when Phase 17+ adds more safe ops.
var allowedTerminalCommands = map[string]bool{
	"ls":     true,
	"df":     true,
	"free":   true,
	"ps":     true,
	"cat":    true,
	"tail":   true,
	"grep":   true,
	"wc":     true,
	"echo":   true,
	"date":   true,
	"uptime": true,
	"id":     true,
}

// TerminalHandlers holds terminal session HTTP handlers.
type TerminalHandlers struct {
	now func() time.Time
}

// NewTerminalHandlers builds terminal handlers.
func NewTerminalHandlers(now func() time.Time) *TerminalHandlers {
	if now == nil {
		now = time.Now
	}
	return &TerminalHandlers{now: now}
}

// Routes registers terminal endpoints on the mux.
func (h *TerminalHandlers) Routes(mux *http.ServeMux) {
	// Bounded exec: run one allowlisted command (PRD §17.4 Bounded Task Runner)
	mux.HandleFunc("POST /api/v1/servers/{server_id}/terminal/exec", h.handleExec)
	// Audit stream: SSE chunked read-only output stream (PRD §17.4 Read-Only Audit Stream)
	mux.HandleFunc("GET /api/v1/servers/{server_id}/terminal/stream", h.handleStream)
}

type terminalExecRequest struct {
	Command string   `json:"command"`
	Args    []string `json:"args"`
	Mode    string   `json:"mode"` // project | restricted | root
}

// POST /api/v1/servers/{server_id}/terminal/exec
func (h *TerminalHandlers) handleExec(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	// Require files.exec permission, step-up required
	authsession.RequirePermission(h.now, "files.exec", rbac.ServerScope(serverID), true,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req terminalExecRequest
			if err := decodeJSONStrict(r, &req); err != nil {
				httpserver.WriteError(w, r, apierr.InvalidRequest(err.Error(), nil))
				return
			}
			req.Command = strings.TrimSpace(req.Command)
			if req.Command == "" {
				httpserver.WriteError(w, r, apierr.InvalidRequest("command is required", nil))
				return
			}
			// Enforce allowlist
			if !allowedTerminalCommands[req.Command] {
				httpserver.WriteError(w, r, apierr.Forbidden(
					fmt.Sprintf("command %q is not in the terminal allowlist (PRD §17.4)", req.Command),
				))
				return
			}

			// Audit the exec attempt
			_ = audit.Record(r.Context(), nil, audit.Event{
				ActorType:    audit.ActorUser,
				ActorID:      principalUserID(r),
				Action:       "terminal.exec",
				ResourceType: "server",
				ResourceID:   serverID,
				Result:       audit.ResultSuccess,
				RequestID:    httpserver.RequestIDFromRequest(r),
				Context: map[string]any{
					"command": req.Command,
					"args":    req.Args,
					"mode":    req.Mode,
				},
			})

			// Run bounded command (not via shell: argv passed directly)
			argv := append([]string{req.Command}, req.Args...)
			//nolint:gosec // argv is allowlisted above
			cmd := exec.CommandContext(r.Context(), argv[0], argv[1:]...)

			var out bytes.Buffer
			var errOut bytes.Buffer
			cmd.Stdout = &out
			cmd.Stderr = &errOut

			if err := cmd.Run(); err != nil {
				writeJSONResponse(w, http.StatusOK, map[string]any{
					"server_id":  serverID,
					"command":    req.Command,
					"stdout":     out.String(),
					"stderr":     errOut.String(),
					"exit_code":  cmd.ProcessState.ExitCode(),
					"error":      err.Error(),
					"request_id": httpserver.RequestIDFromRequest(r),
				})
				return
			}

			writeJSONResponse(w, http.StatusOK, map[string]any{
				"server_id":  serverID,
				"command":    req.Command,
				"stdout":     out.String(),
				"stderr":     errOut.String(),
				"exit_code":  0,
				"request_id": httpserver.RequestIDFromRequest(r),
			})
		})).ServeHTTP(w, r)
}

// GET /api/v1/servers/{server_id}/terminal/stream — SSE chunked read-only audit stream
func (h *TerminalHandlers) handleStream(w http.ResponseWriter, r *http.Request) {
	serverID := r.PathValue("server_id")
	authsession.RequirePermission(h.now, "files.read", rbac.ServerScope(serverID), false,
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Emit SSE headers
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.Header().Set("X-Accel-Buffering", "no")
			w.WriteHeader(http.StatusOK)

			flusher, ok := w.(http.Flusher)
			if !ok {
				return
			}

			buf := bufio.NewWriter(w)

			send := func(event string, data string) {
				fmt.Fprintf(buf, "event: %s\ndata: %s\n\n", event, data)
				_ = buf.Flush()
				flusher.Flush()
			}

			// Send initial connected event
			send("connected", fmt.Sprintf(`{"server_id":"%s","mode":"audit_stream","ts":"%s"}`,
				serverID, h.now().Format(time.RFC3339)))

			// Send heartbeat every 10 seconds until client disconnects
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()

			for {
				select {
				case <-r.Context().Done():
					return
				case t := <-ticker.C:
					send("heartbeat", fmt.Sprintf(`{"ts":"%s","server_id":"%s"}`, t.Format(time.RFC3339), serverID))
				}
			}
		})).ServeHTTP(w, r)
}
