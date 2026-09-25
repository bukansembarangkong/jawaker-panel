# JAWAKER

Modern, modular, low-resource server control panel — standalone or centralized.

JAWAKER manages Linux servers: websites, runtimes, databases, containers, DNS, TLS,
backups, networking, security, observability and deployments from one coherent,
auditable control plane with explicit validation, revisions and recovery paths.

> **Status: Phase 0 — repository and engineering foundation.**
> This repository currently contains the engineering substrate only (build, CI,
> migrations framework, controller skeleton, UI shell). Product features start in
> Phase 1. Nothing here is marked complete that is not actually implemented.

## Stack

| Layer     | Technology                                              |
| --------- | ------------------------------------------------------- |
| Core      | Go (controller, node agent, CLI, installer, workers)    |
| Database  | PostgreSQL (control-plane system of record)             |
| UI        | React + TypeScript + Vite + Tailwind CSS                |
| Realtime  | SSE for events/progress, WebSocket for terminal only    |
| Jobs      | PostgreSQL durable jobs (no mandatory broker)           |

## Repository layout

```text
jawaker-panel/
├── apps/web/            React operations UI
├── cmd/                 Executables (controller, node-agent, cli, ...)
├── internal/            Core Go packages
├── migrations/          Control-plane SQL migrations (checksummed)
├── api/                 API contracts / OpenAPI
├── tests/               Cross-cutting system tests
├── packaging/           Distribution artifacts
├── scripts/             Developer and operational scripts
└── docs/                Public engineering documentation
```

## VPS Installation (one command)

Install JAWAKER on any fresh Debian/Ubuntu/RHEL/Rocky/Alma Linux VPS as root:

```bash
curl -sSL https://raw.githubusercontent.com/bukansembarangkong/jawaker-panel/main/install.sh | bash
```

The installer **asks interactively** for an optional custom domain, then:

1. Detects your OS (apt/dnf/yum)
2. Installs PostgreSQL, Go, Node.js
3. Creates `jawaker_panel` database with a generated password
4. Clones the repo, builds the frontend, compiles the binary (frontend embedded in binary)
5. Writes configuration to `/etc/jawaker/jawaker.env`
6. Installs and starts a systemd service (`jawaker-controller`)
7. **If a domain is provided:** installs Nginx + obtains a free Let's Encrypt SSL certificate, sets up auto-renewal
8. Prints the panel URL, admin email, and one-time password

### With custom domain + HTTPS (recommended)

Make sure your DNS `A` record points to the VPS first, then:

```bash
curl -sSL https://raw.githubusercontent.com/bukansembarangkong/jawaker-panel/main/install.sh | bash
# When prompted: enter your domain and email for Let's Encrypt
```

Panel accessible at `https://panel.example.com`.
SSL auto-renews via cron every 12 hours.

### Non-interactive / automated

```bash
JAWAKER_DOMAIN=panel.example.com \
JAWAKER_SSL_EMAIL=admin@example.com \
JAWAKER_ADMIN_EMAIL=admin@example.com \
  bash <(curl -sSL https://raw.githubusercontent.com/bukansembarangkong/jawaker-panel/main/install.sh)
```

### IP-only (no domain)

Leave the domain prompt empty — panel accessible at `http://<server-ip>:8443`.

### Post-install commands

```bash
# View logs
journalctl -u jawaker-controller -f

# Restart after config change
systemctl restart jawaker-controller

# Edit configuration
nano /etc/jawaker/jawaker.env

# Force SSL renewal
certbot renew --force-renewal && systemctl reload nginx
```

---


## Local Development Quickstart

Prerequisites: Go 1.26+, Node 24+, Docker (for the dev database), GNU Make optional.

```bash
# 1. Start the development database (PostgreSQL 17, localhost only)
docker compose up -d db

# 2. Run the migrations and the controller
export JAWAKER_DATABASE_URL='postgres://jawaker:jawaker_dev_password@127.0.0.1:5432/jawaker?sslmode=disable'
go run ./cmd/controller

# 3. Run the UI dev server (proxies /api to the controller)
cd apps/web && npm ci && npm run dev
```

Without `make` (Windows PowerShell), the raw commands are:

```powershell
go vet ./...
go test ./...
go build -o bin/controller.exe ./cmd/controller
cd apps/web; npm ci; npm run build; npm test -- --run
```

With `make`:

```bash
make db-up        # start dev PostgreSQL
make migrate-up   # apply control-plane migrations
make test         # Go unit tests
make test-integration   # Go integration tests (requires the dev database)
make web-test     # frontend tests
make lint         # Go + frontend linters
```

## Node agent

A managed server runs `jawaker-node-agent`. Enrollment is a one-time, operator-witnessed exchange; after it the agent runs forever on the identity it was given.

```bash
# 1. Build the agent (CI publishes linux/amd64 and linux/arm64 artifacts)
make build-node-agent

# 2. Enroll. -fingerprint is REQUIRED: without it, whoever answers the
#    controller address becomes this node's permanently trusted controller.
sudo ./bin/jawaker-node-agent enroll \
  -controller https://controller.example:8443 \
  -token "$ENROLLMENT_TOKEN" \
  -fingerprint <controller root fingerprint> \
  -node-address "$(hostname -I | awk '{print $1}'):9443"

# 3. Run. The controller starts the node listener with -node-listen.
sudo ./bin/jawaker-node-agent run -listen :9443
```

The state directory is `/var/lib/jawaker-node`, mode `0700`, holding the private key at `0600`. A directory or key that is group- or world-readable is **refused**, not silently repaired: by the time the agent notices, the key may already have been copied, and the only correct response is to re-enroll.

A controller outage is a non-event on a node: heartbeats fail and are logged, local workloads keep serving, and nothing is signaled, stopped or restarted except in response to an authenticated operation.

## Diagnostics

Both binaries have a read-only `doctor`. It prints one row per check with concrete evidence — a certificate's remaining lifetime, a migration count, the mode of a directory — rather than a single health score, and it never creates, repairs or binds anything it keeps.

```bash
jawaker-controller doctor              # text report
jawaker-controller doctor --json       # machine-readable
jawaker-node-agent doctor              # this node
jawaker-node-agent doctor --skip-connectivity   # local checks only
```

Exit status is non-zero only when a check **failed**. Warnings and skips exit zero: a warning is survivable by definition, and a skip means the check did not apply rather than that something is broken.

`doctor` is safe to run against an installation that is already broken. A check that panics is reported as a failed check naming the panic, so the rest of the report still arrives.

## Supported distributions

A distribution is supported because it was tested, not because the agent happens to start on it. [docs/distro-matrix.md](docs/distro-matrix.md) is the single source of truth: it names each test image by digest, its status, and exactly what the evidence covers.

```bash
./scripts/distro-matrix.sh              # raw equivalent of `make distro-matrix`
./scripts/distro-matrix.sh --arch arm64
```

The script builds the agent once as a static binary, runs it inside each pinned image, and asserts what it **claims** — that it names the distribution it is on, that its inventory inputs are present, and that it reports service operations as unsupported where systemd is absent. Asserting claims rather than merely exit codes is the point: a binary that runs and then reports an empty OS, or one that claims a capability it cannot deliver, would pass a smoke test and fail an operator.

> [!IMPORTANT]
> Containers do not run systemd as PID 1, so the matrix validates the **non-systemd** path only, and no row is marked **Certified** — that status additionally requires installation, upgrade and recovery to pass (TESTING.md §7, PRD.md §7.3). See the limits section of the matrix document rather than reading a pass here as a claim about service management.

## Configuration

All configuration is environment-based; there is no config file to drift.

| Variable                | Default                  | Purpose                              |
| ----------------------- | ------------------------ | ------------------------------------ |
| `JAWAKER_LISTEN_ADDR`   | `127.0.0.1:8443`         | Controller HTTP listen address       |
| `JAWAKER_DATABASE_URL`  | *(empty)*                | PostgreSQL DSN; empty disables DB    |
| `JAWAKER_LOG_LEVEL`     | `info`                   | `debug`/`info`/`warn`/`error`        |
| `JAWAKER_LOG_FORMAT`    | `json`                   | `json` or `text`                     |
| `JAWAKER_RUN_MIGRATIONS`| `true`                   | Apply migrations on startup          |
| `JAWAKER_SECRET_KEY_V<n>` | *(unset)*              | Base64 AES-256 key per version; unset disables second factors and node management |
| `JAWAKER_COOKIE_SECURE` | `true`                   | Mark session cookies `Secure`        |
| `JAWAKER_COOKIE_ALLOW_INSECURE` | `false`          | Development-only opt-out; `doctor` warns when set |

The controller also takes flags rather than variables for two things that are deployment-topology decisions, not secrets: `-node-listen HOST:PORT` starts the node-facing mutual-TLS listener (empty disables it, so nodes cannot report), and `-migrate-only` applies pending migrations and exits.

Several `JAWAKER_SECRET_KEY_V<n>` may be set at once. That is what a key rotation needs: the old version stays present to read existing ciphertext while the highest version seals new values.

Never commit credentials. `.env` files and key material are ignored by Git.

## Security baseline

- No secrets in Git, logs, or client-visible payloads.
- Secret scanning (`gitleaks`), dependency and Go vulnerability scanning run in CI.
- Deny-by-default is an architectural rule: authorization is enforced server-side.
- Privileged node actions are typed operations — never a generic remote shell RPC.

## Contributing

See [docs/contributing.md](docs/contributing.md) for branch, commit, review and
test expectations. Conventional commit scopes are used throughout:
`feat(api): ...`, `fix(agent): ...`, `test(backup): ...`.

## License

Proprietary. All rights reserved unless a LICENSE file is added.
