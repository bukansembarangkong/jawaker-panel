# JAWAKER — developer Makefile.
# Every target here has a documented raw equivalent in README.md, so `make`
# stays optional (Windows developers are not forced to install it).

SHELL := /bin/sh
VERSION := $(shell cat VERSION)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w \
	-X github.com/bukansembarangkong/jawaker-panel/internal/version.Version=$(VERSION) \
	-X github.com/bukansembarangkong/jawaker-panel/internal/version.Commit=$(COMMIT) \
	-X github.com/bukansembarangkong/jawaker-panel/internal/version.BuildTime=$(BUILD_TIME)

BIN_DIR := bin
CONTROLLER := $(BIN_DIR)/jawaker-controller
NODE_AGENT := $(BIN_DIR)/jawaker-node-agent

.PHONY: help build build-controller build-node-agent test test-integration lint fmt vet vuln tidy \
	doctor doctor-node \
	web-install web-dev web-test web-lint web-typecheck web-build \
	db-up db-down migrate-up check clean

help: ## List available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

build: build-controller build-node-agent web-build ## Build both binaries and the web bundle

build-controller: ## Build the controller with injected version metadata
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(CONTROLLER) ./cmd/controller

build-node-agent: ## Build the node agent with injected version metadata
	@mkdir -p $(BIN_DIR)
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(NODE_AGENT) ./cmd/node-agent

doctor: ## Report the controller installation's condition
	go run ./cmd/controller doctor

doctor-node: ## Report this node agent's condition
	go run ./cmd/node-agent doctor

test: ## Run Go unit tests
	go test ./...

test-integration: ## Run Go integration tests (requires dev database)
	JAWAKER_TEST_DATABASE_URL="$${JAWAKER_TEST_DATABASE_URL:-postgres://jawaker:jawaker_dev_password@127.0.0.1:5432/jawaker_test?sslmode=disable}" \
		go test -tags integration ./...

fmt: ## Format Go sources
	gofmt -l -w .

vet: ## Run go vet
	go vet ./...

lint: ## Lint Go and frontend sources
	gofmt -l . | tee /dev/stderr | (! read)
	go vet ./...
	golangci-lint run
	$(MAKE) web-lint

vuln: ## Scan Go dependencies for known vulnerabilities
	govulncheck ./...

tidy: ## Tidy Go module files
	go mod tidy

web-install: ## Install frontend dependencies from the lockfile
	cd apps/web && npm ci

web-dev: ## Run the UI dev server
	cd apps/web && npm run dev

web-test: ## Run frontend tests
	cd apps/web && npm test -- --run

web-lint: ## Lint frontend sources
	cd apps/web && npm run lint

web-typecheck: ## Typecheck frontend sources
	cd apps/web && npm run typecheck

web-build: ## Build the production UI bundle
	cd apps/web && npm run build

db-up: ## Start the development PostgreSQL
	docker compose up -d db

db-down: ## Stop the development PostgreSQL
	docker compose down

migrate-up: ## Apply control-plane migrations and exit
	JAWAKER_RUN_MIGRATIONS=true \
	JAWAKER_DATABASE_URL="$${JAWAKER_DATABASE_URL:-postgres://jawaker:jawaker_dev_password@127.0.0.1:5432/jawaker?sslmode=disable}" \
		go run ./cmd/controller -migrate-only

check: lint test web-test ## Run the standard local verification set

clean: ## Remove build output
	rm -rf $(BIN_DIR) apps/web/dist
