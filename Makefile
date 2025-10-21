.DEFAULT_GOAL := help
.PHONY: build run test clean docker-build docker-run help lint verify-deps coverage check

# Variables
BINARY_NAME=inboundparse
DOCKER_IMAGE=inboundparse:latest
GOBIN := $(shell go env GOPATH)/bin

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "%-30s %s\n", $$1, $$2}'

build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME)

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	go mod tidy
	go mod download

run-dev: build ## Run with non-privileged port
	@echo "Starting inboundparse server on port 2525..."
	@echo "Webhook URL: $${WEBHOOK_URL:-http://localhost:8080/webhook}"
	./$(BINARY_NAME) -listen=:2525 

test: ## Run tests
	@echo "Running tests..."
	go test -v ./...


clean: ## Clean build artifacts
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	go clean

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE) .

up: ## Start the docker containers
	@echo "Starting the docker containers"
	@docker compose -f docker-compose.dev.yml up --build --detach

down: ## Stop the docker containers
	@echo "Stopping the docker containers"
	@docker compose -f docker-compose.dev.yml down

dev: down up ## Restart the docker containers

status: ## Show service status
	@echo "Checking service status..."
	@docker-compose ps 2>/dev/null || echo "Docker Compose not running"
	@ps aux | grep $(BINARY_NAME) | grep -v grep || echo "Binary not running" 

ci: ## Run CI workflow
	gh act push -W .github/workflows/ci.yml

format: ## Format the code
	@echo "Running golangci-lint..."
	@command -v $(GOBIN)/golangci-lint >/dev/null 2>&1 || go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	@$(GOBIN)/golangci-lint fmt

vet: ## Vet the code
	@echo "Vetting code..."
	go vet ./...

lint: ## Lint (golangci-lint) + vuln scan (govulncheck)
	@echo "Running golangci-lint..."
	@command -v $(GOBIN)/golangci-lint >/dev/null 2>&1 || go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	@$(GOBIN)/golangci-lint run --fix --timeout=5m
	@echo "Running govulncheck..."
	@command -v $(GOBIN)/govulncheck >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@latest
	@$(GOBIN)/govulncheck ./...

fl: format lint vet ## Format, lint, and vet the code

verify-deps: ## Verify and report dependency status
	@echo "Verifying dependencies..."
	go mod verify
	@echo "Outdated modules:"
	@go list -u -m all | grep -v "^inboundparse " | grep -E "\[[^\]]*\]$$" || true

coverage: ## Run tests with coverage and print summary
	@echo "Running tests with coverage..."
	go test -covermode=atomic -coverpkg=./... -coverprofile=cover.out ./...
	@go tool cover -func=cover.out | tail -n1

check: deps lint  ## Run deps, linters, vulncheck