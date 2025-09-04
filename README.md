# InboundParse - Modern Email to Webhook Gateway

A production-ready SMTP server that receives emails from any domain without authentication and forwards them to webhooks with comprehensive email authentication validation, SSL/TLS support, and enterprise-grade observability.

## Features

### Core SMTP Functionality
- **No SMTP Auth Required**: Accepts emails from any domain without username/password
- **TLS Support**: Automatic SSL/TLS certificate management with Let's Encrypt
- **Multiple Ports**: Listens on 25 (SMTP) and 587 (Submission) with optional TLS
- **PROXY Protocol**: Accepts PROXY protocol connections (e.g., from load balancers)
- **Message Size Limits**: Configurable maximum message size (default: 10MB)

### Email Authentication
- **SPF Validation**: Validates Sender Policy Framework records
- **DKIM Validation**: Verifies DomainKeys Identified Mail signatures  
- **DMARC Validation**: Evaluates DMARC policy and alignment
- **Comprehensive Results**: Detailed authentication results in webhook payload

### Observability & Monitoring
- **Structured Logging**: JSON-formatted logs with configurable levels
- **Prometheus Metrics**: Comprehensive metrics collection and monitoring
- **Sentry Integration**: Error tracking and performance monitoring
- **Health Checks**: Built-in health endpoint for load balancers
- **Grafana Dashboards**: Pre-configured monitoring dashboards

### Deployment & Operations
- **Docker Support**: Multi-stage Docker builds with Alpine Linux
- **Docker Compose**: Complete development stack with monitoring
- **Fly.io Ready**: Pre-configured for Fly.io deployment
- **Automatic Certificates**: Let's Encrypt integration with DNS validation
- **Environment Configuration**: Flexible configuration via environment variables

### Webhook Integration
- **HTTP Basic Auth**: Secure webhook authentication
- **Rich Payload**: Complete email data including headers and attachments
- **Error Handling**: Robust webhook delivery with retry logic
- **Content Processing**: Parsed text and HTML content extraction

## Quick Start

### Using Make (Recommended)

```bash
# Install dependencies and build
make deps build

# Run on privileged port (requires root or sudo)
make run

# Run on non-privileged port for development
make run-dev

# Run with custom webhook URL
WEBHOOK_URL=https://your-app.com/webhook make run-dev
```

### Manual Build and Run

```bash
# Install dependencies
go mod tidy

# Build the binary
go build -o inboundparse ./cmd/inboundparse/

# Run with webhook URL
./inboundparse -webhook=http://localhost:8080/api/webhook
```

### Docker Development Stack

```bash
# Start complete development environment with monitoring
make up

# View logs
docker-compose -f docker-compose.dev.yml logs -f

# Stop services
make down

# Restart services
make dev
```

This starts:
- InboundParse SMTP server (ports 25, 587, 9090)
- Prometheus metrics collection (port 9091)
- Grafana dashboards (port 3000, admin/admin)

### Command Line Options

```bash
Usage of ./inboundparse:
  -listen string
        SMTP server listen address (default "0.0.0.0:25")
  -listen-tls string
        SMTP server listen address for TLS (default "0.0.0.0:587")
  -webhook string
        Webhook URL to send email data to (required)
  -webhook-user string
        Basic auth username for webhook
  -webhook-pass string
        Basic auth password for webhook
  -name string
        SMTP server name (default "mx.inboundparse.com")
  -max-size int
        Maximum message size in bytes (default 10485760)
  -read-timeout int
        Read timeout in seconds (default 30)
  -write-timeout int
        Write timeout in seconds (default 30)
  -enable-spf
        Enable SPF validation (default true)
  -enable-dkim
        Enable DKIM validation (default true)
  -enable-dmarc
        Enable DMARC validation (default true)
  -cert-file string
        TLS certificate file path (optional)
  -key-file string
        TLS private key file path (optional)
  -verbose
        Enable verbose logging (default false)
  -enable-metrics
        Enable Prometheus metrics collection (default false)
  -metrics-addr string
        Metrics server listen address (default "0.0.0.0:9090")
  -metrics-api-key string
        Metrics API key
  -metrics-username string
        Metrics username
  -metrics-password string
        Metrics password
  -enable-sentry
        Enable Sentry error tracking (default false)
  -sentry-dsn string
        Sentry DSN for error tracking
  -sentry-env string
        Sentry environment (default "production")
  -sentry-release string
        Sentry release version
```

### Environment Variables

You can configure InboundParse using environment variables or command line flags:

#### Core Configuration
- `WEBHOOK_URL` - Webhook URL (required)
- `WEBHOOK_USER` - Basic auth username for webhook
- `WEBHOOK_PASS` - Basic auth password for webhook
- `LISTEN_ADDR` - SMTP server listen address (default: "0.0.0.0:25")
- `LISTEN_ADDR_TLS` - TLS server listen address (default: "0.0.0.0:587")
- `SERVER_NAME` - SMTP server name (default: "mx.inboundparse.com")

#### TLS Configuration
- `CERT_FILE` - TLS certificate file path
- `KEY_FILE` - TLS private key file path

#### Feature Toggles
- `ENABLE_SPF` - Enable SPF validation (default: true)
- `ENABLE_DKIM` - Enable DKIM validation (default: true)
- `ENABLE_DMARC` - Enable DMARC validation (default: true)
- `VERBOSE` - Enable verbose logging (default: false)

#### Logging Configuration
- `LOG_LEVEL` - Log level (debug, info, warn, error) (default: "info")
- `LOG_FORMAT` - Log format (json, console) (default: "json")
- `LOG_OUTPUT` - Log output destination (default: "stdout")

#### Metrics Configuration
- `ENABLE_METRICS` - Enable Prometheus metrics collection (default: false)
- `METRICS_ADDR` - Metrics server listen address (default: "0.0.0.0:9090")
- `METRICS_API_KEY` - Metrics API key
- `METRICS_USERNAME` - Metrics username
- `METRICS_PASSWORD` - Metrics password

#### Sentry Configuration
- `ENABLE_SENTRY` - Enable Sentry error tracking (default: false)
- `SENTRY_DSN` - Sentry DSN for error tracking
- `SENTRY_ENV` - Sentry environment (default: "production")
- `SENTRY_RELEASE` - Sentry release version

#### Automatic Certificate Management
- `ACME_SH_EMAIL` - Email for Let's Encrypt account registration
- `MXDOMAIN` - Domain for SSL certificate (default: "mx.inboundparse.com")
- `DNS_API` - DNS API provider (default: "dns_cf")
- `CF_Token` - Cloudflare API token (required for dns_cf)
- `CF_Zone_ID` - Cloudflare Zone ID (required for dns_cf)

## Webhook Payload

The service sends a JSON payload to your webhook with comprehensive email data:

```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "from": [{ "address": "sender@example.com", "name": "Sender" }],
  "to":   [{ "address": "recipient@example.com", "name": "Recipient" }],
  "subject": "Email Subject",
  "body": "Plain text body content",
  "headers": {
    "From": "sender@example.com",
    "To": "recipient@example.com", 
    "Subject": "Email Subject",
    "Message-ID": "<unique-message-id@example.com>",
    "Date": "Mon, 01 Jan 2024 12:00:00 +0000"
  },
  "remote_ip": "192.168.1.100",
  "auth": {
    "spf": {
      "result": "pass",
      "error": null
    },
    "dkim": {
      "result": "pass", 
      "error": null
    },
    "dmarc": {
      "result": "pass",
      "policy": "reject",
      "error": null
    }
  }
}
```

### Payload Fields

- **timestamp**: ISO 8601 timestamp when the email was received
- **from**: Array of sender addresses with name and email
- **to**: Array of recipient addresses with name and email  
- **subject**: Email subject line
- **body**: Plain text body content
- **headers**: Key-value map of email headers
- **remote_ip**: IP address of the sending server
- **auth**: Authentication results (SPF, DKIM, DMARC)

## Authentication Results

### SPF (Sender Policy Framework)
- **result**: `pass`, `fail`, `softfail`, `neutral`, `none`, `temperror`, `permerror`
- **raw**: Human-readable description of the SPF check
- **mechanism**: The SPF mechanism that matched (if any)

### DKIM (DomainKeys Identified Mail)
- **valid**: Boolean indicating if all signatures are valid
- **signatures**: Array of signature validation results
- **raw**: Summary of DKIM verification
- **error**: Error message if verification failed

### DMARC (Domain-based Message Authentication, Reporting & Conformance)
- **result**: `pass`, `fail`, `none`
- **raw**: Human-readable description of DMARC check
- **error**: Error message if lookup failed

## Observability

InboundParse includes comprehensive observability features for monitoring and debugging:

### Prometheus Metrics

Enable metrics collection with `--enable-metrics` or `ENABLE_METRICS=true`:

```bash
# Enable metrics
./inboundparse --enable-metrics --webhook=http://localhost:8080/api/webhook

# Access metrics
curl http://localhost:9090/metrics
```

**Key Metrics:**
- SMTP connections and sessions
- Message processing rates and failures
- Webhook request duration and success rates
- Authentication check results (SPF, DKIM, DMARC)
- Server uptime and performance

### Sentry Error Tracking

Enable error tracking with `--enable-sentry` or `ENABLE_SENTRY=true`:

```bash
# Enable Sentry
./inboundparse \
  --enable-sentry \
  --sentry-dsn="https://your-dsn@sentry.io/project-id" \
  --sentry-env="production" \
  --webhook=http://localhost:8080/api/webhook
```

**Features:**
- Automatic error capture and reporting
- Performance monitoring for key operations
- Custom tags for service identification
- Release tracking for version-based analysis

### Health Checks

Built-in health endpoint for load balancers:

```bash
curl http://localhost:9090/health
```

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Complete Observability Stack

```bash
./inboundparse \
  --enable-metrics \
  --enable-sentry \
  --sentry-dsn="https://your-dsn@sentry.io/project-id" \
  --sentry-env="production" \
  --webhook=http://localhost:8080/api/webhook
```

See [OBSERVABILITY.md](OBSERVABILITY.md) for detailed configuration and monitoring setup.

## Deployment

### Docker Usage

#### Build Docker Image

```bash
docker build -t inboundparse .
```

#### Run with Docker (Basic)

```bash
docker run -p 25:25 -p 587:587 inboundparse \
  -webhook=http://your-webhook-url.com/api/webhook \
  -verbose=true
```

#### Run with Docker (TLS + Monitoring)

```bash
docker run -d \
  -p 25:25 -p 587:587 -p 9090:9090 \
  -e WEBHOOK_URL=https://your-webhook-url.com/api/webhook \
  -e ENABLE_METRICS=true \
  -e ENABLE_SENTRY=true \
  -e SENTRY_DSN=https://your-dsn@sentry.io/project-id \
  -e CF_Token=your-cloudflare-token \
  -e CF_Zone_ID=your-zone-id \
  -e MXDOMAIN=your-domain.com \
  inboundparse
```

### Fly.io Deployment

InboundParse is pre-configured for Fly.io deployment with automatic SSL certificate management:

```bash
# Deploy to Fly.io
fly deploy

# Set environment variables
fly secrets set WEBHOOK_URL=https://your-webhook-url.com/api/webhook
fly secrets set CF_Token=your-cloudflare-token
fly secrets set CF_Zone_ID=your-zone-id
fly secrets set MXDOMAIN=your-domain.com

# Enable monitoring
fly secrets set ENABLE_METRICS=true
fly secrets set ENABLE_SENTRY=true
fly secrets set SENTRY_DSN=https://your-dsn@sentry.io/project-id
```

The `fly.toml` configuration includes:
- PROXY protocol support for load balancers
- Automatic certificate management
- Health checks
- Resource allocation (1GB RAM, 1 CPU)

### Environment File (.env)

Create a `.env` file in your project directory (optional):

```bash
# Required
WEBHOOK_URL=https://your-webhook-url.com/api/webhook

# Optional overrides
LISTEN_ADDR=0.0.0.0:25
LISTEN_ADDR_TLS=0.0.0.0:587
ENABLE_SPF=true
ENABLE_DKIM=true
ENABLE_DMARC=true
VERBOSE=false

# TLS Configuration
CERT_FILE=/cert/cert.pem
KEY_FILE=/cert/key.pem

# Certificate Management
ACME_SH_EMAIL=admin@yourdomain.com
MXDOMAIN=your-domain.com
CF_Token=your-cloudflare-token
CF_Zone_ID=your-zone-id

# Monitoring
ENABLE_METRICS=true
ENABLE_SENTRY=true
SENTRY_DSN=https://your-dsn@sentry.io/project-id
```

## Testing

### Using Swaks (Recommended)

Swaks is a powerful SMTP testing tool. See [EXAMPLES.md](EXAMPLES.md) for comprehensive examples.

#### Basic Email Test

```bash
# Test with swaks
swaks --to user@example.com \
      --from me@example.com \
      --server 127.0.0.1:2525 \
      --header "Subject: Test Email" \
      --body "This is a test email body."
```

#### HTML Email with Attachments

```bash
swaks --to user@example.com \
      --from me@example.com \
      --server 127.0.0.1:2525 \
      --header "Subject: HTML Email Example" \
      --attach-type text/html \
      --attach-body '<html><body><h1>Hello!</h1><p>This is an <b>HTML</b> email.</p></body></html>'
```

### Send Test Email via Telnet

```bash
# Test port 25
telnet localhost 25
HELO test.com
MAIL FROM:<test@example.com>
RCPT TO:<recipient@example.com>
DATA
Subject: Test Email
From: test@example.com
To: recipient@example.com

This is a test email body.
.
QUIT
```

```bash
# Test port 587 (submission)
telnet localhost 587
EHLO test.com
MAIL FROM:<test@example.com>
RCPT TO:<recipient@example.com>
DATA
Subject: Test Email
From: test@example.com
To: recipient@example.com

This is a test email body.
.
QUIT
```

### Development Testing

```bash
# Start development environment
make up

# Send test email
make test-email

# View logs
docker-compose -f docker-compose.dev.yml logs -f inboundparse

# Check metrics
curl http://localhost:9090/metrics

# Check health
curl http://localhost:9090/health
```

## Development

### Available Make Commands

```bash
make help          # Show all available commands
make build         # Build the binary
make deps          # Download dependencies
make run           # Run on privileged port (25)
make run-dev       # Run on non-privileged port (2525)
make test          # Run tests
make test-email    # Show telnet test instructions
make clean         # Clean build artifacts
make docker-build  # Build Docker image
make up            # Start Docker Compose stack
make down          # Stop Docker Compose stack
make dev           # Restart Docker Compose stack
make lint          # Run linters and security checks
make coverage      # Run tests with coverage
make check         # Run deps, linters, and vulncheck
```

### Project Structure

```
inboundparse/
├── cmd/inboundparse/     # Main application
├── internal/
│   ├── config/          # Configuration management
│   ├── server/          # SMTP server implementation
│   └── service/         # Business logic services
├── pkg/                 # Public packages
├── _data/               # Monitoring configuration
│   ├── prometheus.yml   # Prometheus config
│   └── grafana/         # Grafana dashboards
├── docker-compose.dev.yml # Development stack
├── Dockerfile           # Multi-stage Docker build
├── fly.toml            # Fly.io deployment config
├── Makefile            # Build and development commands
└── start.sh            # Container startup script
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests: `make test`
5. Run linters: `make lint`
6. Submit a pull request

## License

This project is licensed under the MIT License. 
