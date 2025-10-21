.PHONY: build run test clean docker-build docker-run help

# Variables
BINARY_NAME=inboundparse
DOCKER_IMAGE=inboundparse:latest

# Default target
help:
	@echo "Available commands:"
	@echo "  build        - Build the binary"
	@echo "  run          - Run the service with default webhook URL"
	@echo "  test         - Run tests"
	@echo "  clean        - Clean build artifacts"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run with Docker Compose"
	@echo "  docker-stop  - Stop Docker containers"
	@echo "  deps         - Download dependencies"

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME) .

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod tidy
	go mod download

# Run the service
run: build
	@echo "Starting inboundparse server..."
	@echo "Webhook URL: $${WEBHOOK_URL:-http://localhost:8080/webhook}"
	@echo "SMTP listening on :25 (run as root or use port >1024)"
	./$(BINARY_NAME)

# Run with non-privileged port
run-dev: build
	@echo "Starting inboundparse server on port 2525..."
	@echo "Webhook URL: $${WEBHOOK_URL:-http://localhost:8080/webhook}"
	./$(BINARY_NAME) -listen=:2525 

# Run tests
test:
    @echo "Running tests..."
    go test -v ./...


# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BINARY_NAME)
	go clean

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE) .

# Test email sending
test-email:
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

# Show service status
status:
	@echo "Checking service status..."
	@docker-compose ps 2>/dev/null || echo "Docker Compose not running"
	@ps aux | grep $(BINARY_NAME) | grep -v grep || echo "Binary not running" 