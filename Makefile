.DEFAULT_GOAL := help

COMPOSE := docker compose

.PHONY: help up down logs generate test test-race test-integration lint run

help: ## Show available commands
	@awk 'BEGIN {FS = ":.*##"}; /^[a-zA-Z0-9_-]+:.*##/ {printf "%-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

up: ## Start the service in Docker; creates .env with random secrets on first run
	@test -f .env || { \
		printf 'API_KEY=%s\nPOSTGRES_PASSWORD=%s\n' "$$(openssl rand -hex 32)" "$$(openssl rand -hex 32)" > .env && \
		echo "Created .env with a random API_KEY and POSTGRES_PASSWORD"; }
	$(COMPOSE) up --build --detach --wait
	@echo ""
	@echo "Service is ready: http://localhost:8080"
	@echo "API key:          $$(grep '^API_KEY=' .env | cut -d= -f2)"

down: ## Stop the service and remove its containers, network, data volume and built image
	$(COMPOSE) down --volumes --remove-orphans --rmi local

logs: ## Follow service logs
	$(COMPOSE) logs --follow app

generate: ## Generate Go API types from OpenAPI
	go generate ./api/...

test: ## Run all tests (integration tests skip without Docker or INTEGRATION_DATABASE_URL)
	go test ./...

test-race: ## Run all tests with the race detector
	go test -race ./...

test-integration: ## Run integration tests verbosely so a skip is visible
	go test -count=1 -v ./tests/integration/...

lint: ## Run static checks
	go vet ./...

run: ## Run the HTTP server locally (requires DATABASE_URL and API_KEY)
	go run ./cmd/server
