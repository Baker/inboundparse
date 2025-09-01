.DEFAULT_GOAL := help
.PHONY: build run test clean docker-build docker-run help

# Variables
BINARY_NAME=inboundparse
DOCKER_IMAGE=inboundparse:latest
GOBIN := $(shell go env GOPATH)/bin

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "%-30s %s\n", $$1, $$2}'

build: ## Build the binary
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME) .

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	go mod tidy
	go mod download

run: build ## Run with default port
	@echo "Starting inboundparse server..."
	@echo "Webhook URL: $${WEBHOOK_URL:-http://localhost:8080/webhook}"
	@echo "SMTP listening on :25 (run as root or use port >1024)"
	./$(BINARY_NAME)

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

test-email: ## Test email sending
	@echo "Sending test email via telnet..."
	@echo "Connect with: telnet localhost 2525"
	@echo "Then use SMTP commands:"
	@echo "  HELO test.com"
	@echo "  MAIL FROM:<test@example.com>"
	@echo "  RCPT TO:<recipient@example.com>"
	@echo "  DATA"
	@echo "  Subject: Test Email"
	@echo "  From: test@example.com"
	@echo "  To: recipient@example.com"
	@echo "  "
	@echo "  This is a test email body."
	@echo "  ."
	@echo "  QUIT"


status: ## Show service status
	@echo "Checking service status..."
	@docker-compose ps 2>/dev/null || echo "Docker Compose not running"
	@ps aux | grep $(BINARY_NAME) | grep -v grep || echo "Binary not running" 

ci: ## Run CI workflow
	gh act push -W .github/workflows/ci.yml

.PHONY: lint verify-deps coverage check

lint: ## Lint (golangci-lint) + vuln scan (govulncheck)
	@echo "Running golangci-lint..."
	@command -v $(GOBIN)/golangci-lint >/dev/null 2>&1 || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@$(GOBIN)/golangci-lint run --fix --timeout=5m
	@echo "Running govulncheck..."
	@command -v $(GOBIN)/govulncheck >/dev/null 2>&1 || go install golang.org/x/vuln/cmd/govulncheck@latest
	@$(GOBIN)/govulncheck ./...

verify-deps: ## Verify and report dependency status
	@echo "Verifying dependencies..."
	go mod verify
	@echo "Outdated modules:"
	@go list -u -m all | grep -v "^inboundparse " | grep -E "\[[^\]]*\]$" || true

coverage: ## Run tests with coverage and print summary
	@echo "Running tests with coverage..."
	go test -covermode=atomic -coverpkg=./... -coverprofile=cover.out ./...
	@go tool cover -func=cover.out | tail -n1

check: deps lint  ## Run deps, linters, vulncheck