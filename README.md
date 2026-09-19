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

## Quickstart

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

## Configuration

All configuration is environment-based; there is no config file to drift.

| Variable                | Default                  | Purpose                              |
| ----------------------- | ------------------------ | ------------------------------------ |
| `JAWAKER_LISTEN_ADDR`   | `127.0.0.1:8443`         | Controller HTTP listen address       |
| `JAWAKER_DATABASE_URL`  | *(empty)*                | PostgreSQL DSN; empty disables DB    |
| `JAWAKER_LOG_LEVEL`     | `info`                   | `debug`/`info`/`warn`/`error`        |
| `JAWAKER_LOG_FORMAT`    | `json`                   | `json` or `text`                     |
| `JAWAKER_RUN_MIGRATIONS`| `true`                   | Apply migrations on startup          |

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
