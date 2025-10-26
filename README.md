# InboundParse - Modern Email to Webhook Gateway

A SMTP server that receives emails from any domain without authentication and forwards them to webhooks with comprehensive email authentication validation, automatic SSL/TLS support and more. 

> [!NOTE]
> This is my first major Golang product, so I may not do things the **golang way**, but I am open to feedback. I have used this application privately for the last 6 months, and have received well over **100,000** of pieces of mail (mostly spam, but thats for another day).


## Features

### Core SMTP Functionality

- ✉️ **No SMTP Auth Required**: Accepts emails from any domain without username/password
- 🔒 **TLS Support**: Automatic SSL/TLS certificate management with Let's Encrypt
- 🔌 **Multiple Ports**: Listens on 25 (SMTP) and 587 (Submission) with optional TLS
- 🛡️ **PROXY Protocol**: Accepts PROXY protocol connections (e.g., from load balancers)
- 📏 **Message Size Limits**: Configurable maximum message size (default: 10MB)

### Email Authentication (RFC Compliant)
- 🧐 **SPF Validation (RFC 7208)**: Validates Sender Policy Framework with HELO and envelope sender
- 🖊️ **DKIM Validation (RFC 6376)**: Verifies DomainKeys Identified Mail signatures with multi-signature support
- 🕵️‍♂️ **DMARC Validation (RFC 7489)**: Evaluates DMARC policy with hierarchical domain lookup and subdomain policy inheritance
- 📝 **Comprehensive Results**: Detailed authentication results with domain, mechanism, and alignment data
- 🔍 **Domain Hierarchy Tracking**: Tracks all attempted DMARC lookups with detailed per-domain results

### Observability & Monitoring
- 📋 **Structured Logging**: JSON-formatted logs with configurable levels
- 📊 **Prometheus Metrics**: Comprehensive metrics collection and monitoring
- 🛎️ **Sentry Integration**: Error tracking and performance monitoring
- ❤️ **Health Checks**: Built-in health endpoint for load balancers
- 📈 **Grafana Dashboards**: Pre-configured monitoring dashboards

### Deployment & Operations
- 🐳 **Docker Support**: Multi-stage Docker builds with Alpine Linux
- 🧩 **Docker Compose**: Complete development stack with monitoring
- 🚀 **Fly.io Ready**: Pre-configured for Fly.io deployment (more to come!)
- 🔑 **Automatic Certificates**: Let's Encrypt integration with DNS validation
- ⚙️ **Environment Configuration**: Flexible configuration via environment variables

### Webhook Integration
- 🔐 **HTTP Basic Auth**: Secure webhook authentication
- 📨 **Rich Payload**: Complete email data including headers and attachments
- 🔁 **Reliability Features**: Automatic retry with exponential backoff, rate limiting, and circuit breaker
- 🛡️ **Fault Tolerance**: Circuit breaker pattern prevents cascading failures
- ⚡ **Rate Limiting**: Configurable requests per second to protect downstream endpoints
- ✂️ **Content Processing**: Parsed text and HTML content extraction

## Quick Start

Welcome to **InboundParse**! Whether you're a developer, sysadmin, or open source enthusiast, getting started is easy. You can build and run the project with just a few commands. Contributions are welcome—see the bottom for how to get involved!

---

### 1. ⚡ Fastest Start with Make

Most development and deployment tasks are automated with `make` for simplicity.

```bash
# Download Go dependencies & build the project
make deps

# Development mode
make run-dev

# Copy the example environment file and customize your webhook target
cp .env.example .env
echo 'WEBHOOK_URL=https://your-app.com/webhook' >> .env # Recommend deleting the first WEBHOOK_URL to make it cleaner, but env should load last.
make run-dev
```

---

### 2. 👐 Manual Build & Run (for non-Make users)

```bash
# 1. Ensure Go ≥ 1.20 is installed
go mod tidy      # Download dependencies
go build -o inboundparse ./cmd/inboundparse/

# 2. Start the server with a custom webhook endpoint
./inboundparse -webhook=https://your-app.com/webhook
```

---

### 3. 🐳 Full Local Dev Stack (Docker Compose, Monitoring, Visual Dashboards)

Spin up the whole ecosystem: SMTP, metrics, dashboards, and log viewing, all with familiar tooling.

```bash
# Start SMTP server, Prometheus (metrics), and Grafana (dashboards)
make up

# View logs (all services)
docker-compose -f docker-compose.dev.yml logs -f

# Stop all services
make down

# Restart/dev workflow (down + up)
make dev
```

With the dev stack running, you'll have:
- **InboundParse SMTP server** (`:25`, `:587`, `:9090`)
- **Prometheus** for metrics (`:9091`)
- **Grafana** dashboards (`:3000`, login `admin`/`admin`)

---

### 4. 🛠️ Command Line Reference

You can configure nearly everything via CLI flags (or use environment variables). Use `./inboundparse -h` to see all options.

```bash
Usage of ./inboundparse:
  -listen string            SMTP server listen address (default "0.0.0.0:25")
  -listen-tls string        SMTP TLS listen address (default "0.0.0.0:587")
  -webhook string           Webhook URL for email payloads (required)
  -webhook-user string      Basic auth username for webhook (optional)
  -webhook-pass string      Basic auth password for webhook (optional)
  -webhook-max-retries int  Maximum webhook retry attempts (default 3)
  -webhook-retry-delay int  Initial webhook retry delay in seconds (default 1)
  -webhook-max-retry-delay int Maximum webhook retry delay in seconds (default 30)
  -webhook-retry-multiplier float Webhook retry delay multiplier (default 2.0)
  -webhook-rate-limit int   Webhook requests per second rate limit (default 10)
  -webhook-rate-burst int   Webhook rate limit burst capacity (default 20)
  -name string              SMTP server name (default "mx.inboundparse.com")
  -max-size int             Max message size bytes (default 10485760)
  -read-timeout int         Read timeout (seconds, default 30)
  -write-timeout int        Write timeout (seconds, default 30)
  -enable-spf               Enable SPF validation (default true)
  -enable-dkim              Enable DKIM validation (default true)
  -enable-dmarc             Enable DMARC validation (default true)
  -cert-file string         TLS cert file (optional)
  -key-file string          TLS private key (optional)
  -verbose                  Enable verbose logging (default false)
  -enable-metrics           Enable Prometheus metrics (default false)
  -metrics-addr string      Metrics server listen addr (default "0.0.0.0:9090")
  -metrics-api-key string   Metrics API key (optional)
  -metrics-username string  Metrics username (optional)
  -metrics-password string  Metrics password (optional)
  -enable-sentry            Enable Sentry error tracking (default false)
  -sentry-dsn string        Sentry DSN for errors (optional)
  -sentry-env string        Sentry env (default "production")
  -sentry-release string    Sentry release version (optional)
```



### 🔒 Environment Variables 

You can configure InboundParse using environment variables or command line flags:

#### Core Environment Variables

- `WEBHOOK_URL`           Webhook URL to receive email payloads (**required**)
- `WEBHOOK_USER`          Basic auth username for the webhook (optional)
- `WEBHOOK_PASS`          Basic auth password for the webhook (optional)

#### Webhook Reliability Configuration

- `WEBHOOK_MAX_RETRIES`      Maximum retry attempts (default: `3`)
- `WEBHOOK_RETRY_DELAY`      Initial retry delay in seconds (default: `1`)
- `WEBHOOK_MAX_RETRY_DELAY`  Maximum retry delay in seconds (default: `30`)
- `WEBHOOK_RETRY_MULTIPLIER` Exponential backoff multiplier (default: `2.0`)
- `WEBHOOK_RATE_LIMIT`       Requests per second rate limit (default: `10`)
- `WEBHOOK_RATE_BURST`       Rate limit burst capacity (default: `20`)
- `LISTEN_ADDR`           SMTP listen address (default: `0.0.0.0:25`)
- `LISTEN_ADDR_TLS`       TLS listen address (default: `0.0.0.0:587`)
- `SERVER_NAME`           SMTP service name for banner (default: `mx.inboundparse.com`)

#### TLS Settings

- `CERT_FILE`             Path to TLS certificate file (optional)
- `KEY_FILE`              Path to TLS private key file (optional)

#### Feature Flags

- `ENABLE_SPF`            Enable SPF checking (`true`/`false`, default: `true`)
- `ENABLE_DKIM`           Enable DKIM checking (`true`/`false`, default: `true`)
- `ENABLE_DMARC`          Enable DMARC checking (`true`/`false`, default: `true`)
- `VERBOSE`               Enable verbose (debug) logging (`true`/`false`, default: `false`)

#### Metrics (Prometheus)

- `ENABLE_METRICS`        Enable Prometheus metrics endpoint (`true`/`false`, default: `false`)
- `METRICS_ADDR`          Metrics endpoint listen address (default: `0.0.0.0:9090`)
- `METRICS_API_KEY`       Bearer token used for metrics endpoint authentication (optional)
- `METRICS_USERNAME`      Username for metrics endpoint basic auth (optional)
- `METRICS_PASSWORD`      Password for metrics endpoint basic auth (optional)

#### Sentry Error Tracking

- `ENABLE_SENTRY`         Enable Sentry error tracking (`true`/`false`, default: `false`)
- `SENTRY_DSN`            Sentry DSN (project key, required if Sentry enabled)
- `SENTRY_ENV`            Sentry environment name (default: `production`)
- `SENTRY_RELEASE`        Sentry release version (optional)

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
      "domain": "example.com",
      "mechanism": "ip4",
      "explanation": ""
    },
    "dkim": {
      "result": "pass",
      "signatures": [
        {
          "domain": "example.com",
          "result": "pass",
          "canonicalization": "signed headers: 8"
        }
      ],
      "body": "at least one signature passed verification"
    },
    "dmarc": {
      "result": "pass",
      "policy": "reject",
      "subdomain_policy": "quarantine",
      "percentage": 100,
      "spf_aligned": true,
      "dkim_aligned": true,
      "spf_domain": "example.com",
      "dkim_domain": "example.com",
      "details": [
        {
          "domain": "sub.example.com",
          "record_found": false,
          "error": "dmarc: no policy found for domain"
        },
        {
          "domain": "example.com",
          "record_found": true,
          "policy_used": "sp"
        }
      ],
      "spf_alignment": "relaxed",
      "dkim_alignment": "relaxed",
      "failure_options": "0",
      "report_uris": ["mailto:dmarc@example.com"],
      "failure_uris": ["mailto:dmarc-fail@example.com"]
    }
  }
}
```


## 🤝 Contributing

Contributions of all kinds are welcome! See [CONTRIBUTE.md](./docs/CONTRIBUTE.md) for guidelines, and don’t hesitate to open issues, fork, or create PRs.

---

> **Need help or want to suggest new features?**  
> Open an issue or start a discussion on GitHub!