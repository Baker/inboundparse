# InboundParse - Modern Email to Webhook Gateway

A SMTP server that receives emails from any domain without authentication and forwards them to webhooks with comprehensive email authentication validation, automatic SSL/TLS support and more. 

> [!NOTE]
> This is my first major Golang product, so I may not do things the **golang way**, but I am open to feedback. I have used this application privately for the last 6 months, and have received well over **100,000** of pieces of mail (mostly spam, but thats for another day).

## Features

### Core SMTP Functionality

- **No SMTP Auth Required**: Accepts emails from any domain without username/password
- **TLS Support**: Automatic SSL/TLS certificate management with Let's Encrypt
- **Multiple Ports**: Listens on 25 (SMTP) and 587 (Submission) with optional TLS
- **PROXY Protocol**: Accepts PROXY protocol connections (e.g., from load balancers)
- **Message Size Limits**: Configurable maximum message size (default: 10MB)

### Email Authentication (RFC Compliant)

- **SPF Validation (RFC 7208)**: Validates Sender Policy Framework with HELO and envelope sender
- **DKIM Validation (RFC 6376)**: Verifies DomainKeys Identified Mail signatures with multi-signature support
- **DKIM2 Verification (draft-ietf-dkim-dkim2-spec-09)**: Verifies DKIM2 signatures against the SMTP envelope and reports the result next to DKIM. It does not accept or reject mail, and it is not an input to DMARC
- **DMARC Validation (RFC 7489)**: Evaluates DMARC policy with hierarchical domain lookup and subdomain policy inheritance
- **Comprehensive Results**: Detailed authentication results with domain, mechanism, and alignment data
- **Domain Hierarchy Tracking**: Tracks all attempted DMARC lookups with detailed per-domain results

### Observability & Monitoring

- **Structured Logging**: JSON-formatted logs with configurable levels
- **Prometheus Metrics**: Comprehensive metrics collection and monitoring
- **Sentry Integration**: Error tracking and performance monitoring
- **Health Checks**: Built-in health endpoint for load balancers
- **Grafana Dashboards**: Pre-configured monitoring dashboards

### Deployment & Operations

- **Docker Support**: Multi-stage Docker builds with Alpine Linux
- **Docker Compose**: Complete development stack with monitoring
- **Fly.io Ready**: Pre-configured for Fly.io deployment (more to come!)
- **Automatic Certificates**: Let's Encrypt integration with DNS validation
- **Environment Configuration**: Flexible configuration via environment variables

### Webhook Integration

- **HTTP Basic Auth**: Secure webhook authentication
- **Rich Payload**: Complete email data including headers and attachments
- **Reliability Features**: Automatic retry with exponential backoff, rate limiting, and circuit breaker
- **Fault Tolerance**: Circuit breaker pattern prevents cascading failures
- **Rate Limiting**: Smooth per-second webhook rate cap (`WEBHOOK_RATE_LIMIT`)
- **Content Processing**: Parsed text and HTML content extraction

## Quick Start

Welcome to **InboundParse**! Whether you're a developer, sysadmin, or open source enthusiast, getting started is easy. You can build and run the project with just a few commands. Contributions are welcome—see the bottom for how to get involved!

---

### 1. Fastest start with Make

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

### 2. Manual build and run (for non-Make users)

```bash
# 1. Install a Go toolchain that matches go.mod (see the `go` directive there).
go mod tidy      # Download dependencies
go build -o inboundparse ./cmd/inboundparse/

# 2. Start the server (set WEBHOOK_URL or -webhook for real deliveries; omit for no-op / dev)
./inboundparse -webhook=https://your-app.com/webhook
```

---

### 3. Full local dev stack (Docker Compose, monitoring, dashboards)

Spin up the whole ecosystem: SMTP, metrics, dashboards, and log viewing, all with familiar tooling.

```bash
# Start SMTP server, Prometheus (metrics), and Grafana (dashboards)
make up

# View logs (all services)
docker compose -f docker-compose.dev.yml logs -f

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

### 4. Command line reference

You can configure nearly everything via CLI flags (or use environment variables). Use `./inboundparse -h` to see all options.

```bash
Usage of ./inboundparse:
  -listen string            SMTP server listen address (default "0.0.0.0:25")
  -listen-tls string        SMTP TLS listen address (default "0.0.0.0:587")
  -webhook string           Webhook URL for email payloads (optional; empty disables delivery)
  -webhook-user string      Basic auth username for webhook (optional)
  -webhook-pass string      Basic auth password for webhook (optional)
  -webhook-max-retries int  Maximum webhook retry attempts (default 3)
  -webhook-retry-delay int  Initial webhook retry delay in seconds (default 1)
  -webhook-max-retry-delay int Maximum webhook retry delay in seconds (default 30)
  -webhook-retry-multiplier float Webhook retry delay multiplier (default 2.0)
  -webhook-rate-limit int   Webhook requests per second (smooth limiter; default 10)
  -webhook-rate-burst int   Parsed for API compatibility; smooth limiter uses rate only (default 20)
  -name string              SMTP server name (default "mx.inboundparse.com")
  -max-size int             Max message size bytes (default 10485760)
  -read-timeout int         Read timeout (seconds, default 30)
  -write-timeout int        Write timeout (seconds, default 30)
  -message-processing-timeout int Per-message processing timeout in seconds, including auth and webhook (default 300)
  -enable-spf               Enable SPF validation (default true)
  -enable-dkim              Enable DKIM validation (default true)
  -enable-dkim2             Enable DKIM2 verification (default true)
  -enable-dmarc             Enable DMARC validation (default true)
  -cert-file string         TLS cert file (optional)
  -key-file string          TLS private key (optional)
  -verbose                  Enable verbose logging (default false)
  -enable-metrics           Enable Prometheus metrics (default false)
  -metrics-addr string      Metrics server listen addr (default "0.0.0.0:9090")
  -metrics-api-key string   Metrics API key (optional)
  -metrics-username string   Metrics username (optional)
  -metrics-password string   Metrics password (optional)
  -enable-sentry            Enable Sentry error tracking (default false)
  -sentry-dsn string        Sentry DSN for errors (optional)
  -sentry-env string        Sentry env (default "production")
  -sentry-release string    Sentry release version (optional)
```

### Environment variables

You can configure InboundParse using environment variables or command line flags:

#### Core Environment Variables

- `WEBHOOK_URL`           Webhook URL to receive email payloads (optional; if unset, messages are processed but not POSTed)
- `WEBHOOK_USER`          Basic auth username for the webhook (optional)
- `WEBHOOK_PASS`          Basic auth password for the webhook (optional)

#### Webhook Reliability Configuration

- `WEBHOOK_MAX_RETRIES`      Maximum retry attempts (default: `3`)
- `WEBHOOK_RETRY_DELAY`      Initial retry delay in seconds (default: `1`)
- `WEBHOOK_MAX_RETRY_DELAY`  Maximum retry delay cap in seconds (default: `30`)
- `WEBHOOK_RETRY_MULTIPLIER` Exponential backoff multiplier (default: `2.0`)
- `WEBHOOK_RATE_LIMIT`       Target average webhook requests per second for the smooth limiter (default: `10`)
- `WEBHOOK_RATE_BURST`       Parsed for compatibility; not used by the current smooth rate limiter (default: `20`)

#### Server & Processing

- `LISTEN_ADDR`           SMTP listen address (default: `0.0.0.0:25`)
- `LISTEN_ADDR_TLS`       TLS listen address (default: `0.0.0.0:587`)
- `SERVER_NAME`           SMTP service name for banner (default: `mx.inboundparse.com`)
- `MAX_SIZE`              Maximum message size in bytes (default: `10485760`)
- `READ_TIMEOUT`          Read timeout in seconds (default: `30`)
- `WRITE_TIMEOUT`         Write timeout in seconds (default: `30`)
- `MESSAGE_PROCESSING_TIMEOUT` Upper bound in seconds for processing one message (parse, auth, webhook; default: `300`)
- `TRUSTED_PROXY_CIDRS`   Comma-separated CIDRs trusted when interpreting PROXY protocol and client IP (optional)

#### TLS Settings

The image entrypoint requests a Let's Encrypt certificate on startup when DNS credentials are set, then starts SMTP. No extra script is required. If those credentials are unset, or issuance fails, SMTP still starts without STARTTLS. A volume mounted at `/cert` keeps the certificate across restarts.

- `CERT_FILE`             Path to TLS certificate file (optional; the entrypoint sets this when it has a certificate)
- `KEY_FILE`              Path to TLS private key file (optional)
- `MXDOMAIN`              Certificate domain (default: `SERVER_NAME`, then `mx.inboundparse.com`)
- `ACME_SH_EMAIL`         Let's Encrypt account email (default: `devnull@localhost`)
- `DNS_API`               acme.sh DNS provider (default: `dns_cf`)
- `CF_Token`              Cloudflare API token (required for `dns_cf`)
- `CF_Zone_ID`            Cloudflare zone id (required for `dns_cf`)

#### Feature Flags

- `ENABLE_SPF`            Enable SPF checking (`true`/`false`, default: `true`)
- `ENABLE_DKIM`           Enable DKIM checking (`true`/`false`, default: `true`)
- `ENABLE_DKIM2`          Enable DKIM2 verification (`true`/`false`, default: `true`)
- `ENABLE_DMARC`          Enable DMARC checking (`true`/`false`, default: `true`)
- `VERBOSE`               Enable verbose (debug) logging (`true`/`false`, default: `false`)

#### Metrics (Prometheus)

- `ENABLE_METRICS`        Enable Prometheus metrics endpoint (`true`/`false`, default: `false`)
- `METRICS_ADDR`          Metrics endpoint listen address (default: `0.0.0.0:9090`)
- `METRICS_API_KEY`       Bearer token used for metrics endpoint authentication (optional)
- `METRICS_USERNAME`      Username for metrics endpoint basic auth (optional; must be set together with `METRICS_PASSWORD`)
- `METRICS_PASSWORD`      Password for metrics endpoint basic auth (optional; must be set together with `METRICS_USERNAME`)

When metrics are enabled on a non-loopback address (`0.0.0.0`, public IP, etc.), you must configure either `METRICS_API_KEY` or both `METRICS_USERNAME` and `METRICS_PASSWORD`. Unauthenticated `/metrics` is only allowed when bound to loopback (for example `127.0.0.1:9090`).

#### Sentry Error Tracking

- `ENABLE_SENTRY`         Enable Sentry error tracking (`true`/`false`, default: `false`)
- `SENTRY_DSN`            Sentry DSN (project key, required if Sentry enabled)
- `SENTRY_ENV`            Sentry environment name (default: `production`)
- `SENTRY_RELEASE`        Sentry release version (optional)

## Webhook Payload

The webhook receives a JSON document shaped like `domain.WebhookPayload`: message metadata and `authentication_results` for SPF, DKIM, DKIM2, and DMARC. `from` and `to` are `net/mail.Address` values (JSON fields **`Name`** and **`Address`**). `timestamp` is taken from the parsed `Date` header when present. Attachments and inline parts use the structures from [`letters`](https://github.com/mnako/letters).

`authentication_results.dkim2` is the draft-09 verification state. `result` is `none` when the message has no DKIM2 fields, and otherwise `pass`, `fail`, `temperror`, or `permerror`. `reason` is the library reason code (`none` on pass, `missing_key`, `envelope_mismatch`, and the rest of that closed set). A canceled check is `temperror` with reason `unavailable`. The signing domain is not included. `signatures[].selector` is present only for a signature set that did not pass. DKIM2 is not used when evaluating DMARC.

```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "from": [{ "Name": "Sender", "Address": "sender@example.com" }],
  "to": [{ "Name": "", "Address": "recipient@example.com" }],
  "subject": "Email Subject",
  "message_id": "<unique-message-id@example.com>",
  "headers": {
    "X-Custom": ["value"]
  },
  "text_body": "Plain text body",
  "enriched_text_body": "",
  "html_body": "<p>HTML body</p>",
  "attachments": [],
  "inline_files": [],
  "authentication_results": {
    "spf": {
      "result": "pass",
      "raw": "v=spf1 ...",
      "mechanism": "include",
      "qualifier": "~",
      "explanation": "",
      "problem": "",
      "sender": "sender@example.com",
      "ip_address": "192.0.2.1"
    },
    "dkim": {
      "valid": true,
      "signatures": ["example.com"],
      "details": [
        {
          "domain": "example.com",
          "headers_signed": ["from", "to", "subject"],
          "timestamp": 1704110400,
          "expiration": 0,
          "valid": true,
          "error": ""
        }
      ],
      "raw": "",
      "error": ""
    },
    "dkim2": {
      "result": "pass",
      "reason": "none",
      "scope": "chain",
      "historical_content": "complete",
      "historical_signatures": "complete",
      "custody": "not_present",
      "sequence": 1,
      "instance": 1,
      "checks": [
        { "class": "body_hash", "reason": "none" },
        { "class": "domain_alignment", "reason": "none" },
        { "class": "envelope", "reason": "none" },
        { "class": "header_hash", "reason": "none" },
        { "class": "next_domain", "reason": "none" },
        { "class": "signature", "reason": "none" },
        { "class": "timestamp", "reason": "none" }
      ],
      "signatures": [
        {
          "algorithm": "ed25519-sha256",
          "status": "pass",
          "reason": "none"
        }
      ]
    },
    "dmarc": {
      "result": "pass",
      "raw": "v=DMARC1; p=reject; ...",
      "policy": "reject",
      "domain": "example.com",
      "percentage": 100,
      "subdomain_policy": "quarantine",
      "spf_aligned": true,
      "dkim_aligned": true,
      "spf_domain": "example.com",
      "dkim_domain": "example.com",
      "details": [
        {
          "domain": "example.com",
          "record_found": true,
          "policy_used": "p",
          "error": ""
        }
      ],
      "spf_alignment": "relaxed",
      "dkim_alignment": "relaxed",
      "failure_options": "",
      "report_uris": [],
      "failure_uris": []
    }
  }
}
```

Omitted optional fields are elided from the JSON (`omitempty`). If all auth checks are disabled, `authentication_results` may be empty.

## Contributing

Contributions of all kinds are welcome! See [CONTRIBUTE.md](./docs/CONTRIBUTE.md) for guidelines, and don’t hesitate to open issues, fork, or create PRs.

---

> **Need help or want to suggest new features?**  
> Open an issue or start a discussion on GitHub!
