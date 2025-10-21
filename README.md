# InboundParse - Email to Webhook Gateway

A modern SMTP server that receives emails from any domain without authentication and forwards them to webhooks with comprehensive email authentication validation and SSL/TLS support.

## Features

- **No SMTP Auth Required**: Accepts emails from any domain without username/password
- **TLS Support**: Optional TLS when `-cert-file` and `-key-file` are provided
- **SPF Validation**: Validates Sender Policy Framework records
- **DKIM Validation**: Verifies DomainKeys Identified Mail signatures
- **DMARC Validation**: Evaluates DMARC policy and alignment
- **Headers Included**: Forwards received headers along with parsed message data
- **Webhook Authentication**: Supports HTTP Basic Auth for webhook endpoints
- **Verbose Logging**: Enable extra logs with `-verbose`
- **Multiple Ports**: Listens on 25 by default; TLS listener on 587 when certs are provided
- **PROXY protocol**: Accepts PROXY protocol connections (e.g., from load balancers)

## Quick Start

### Build and Run

```bash
# Install dependencies
go mod tidy

# Build the binary
go build -o inboundparse

# Run with webhook URL
./inboundparse -webhook=http://localhost:8080/api/webhook
```

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
```

### Environment Variables

You can also configure using environment variables:

#### Core Configuration
- `WEBHOOK_URL` - Webhook URL (required)
- `WEBHOOK_USER` - Basic auth username for webhook
- `WEBHOOK_PASS` - Basic auth password for webhook
- `LISTEN_ADDR` - SMTP server listen address (overrides `-listen`)
- `LISTEN_ADDR_TLS` - TLS server listen address (overrides `-listen-tls`)

#### TLS Configuration
- `CERT_FILE` - TLS certificate file path
- `KEY_FILE` - TLS private key file path

#### Feature Toggles
- `ENABLE_SPF` - Enable SPF validation (default: true)
- `ENABLE_DKIM` - Enable DKIM validation (default: true)
- `ENABLE_DMARC` - Enable DMARC validation (default: true)
- `VERBOSE` - Enable verbose logging (default: false)

## Webhook Payload

The service sends a JSON payload to your webhook similar to:

```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "from": [{ "address": "sender@example.com", "name": "Sender" }],
  "to":   [{ "address": "recipient@example.com", "name": "Recipient" }],
  "subject": "Email Subject",
  "message_id": "<unique-message-id@example.com>",
  "headers": { "From": ["sender@example.com"], "Subject": ["Email Subject"] },
  "text_body": "Plain text body",
  "enriched_text_body": "...",
  "html_body": "<p>HTML body</p>",
  "attachments": [ /* array of files */ ],
  "inline_files": [ /* array of inline files */ ],
  "authentication_results": {
    "spf":   { "result": "pass", "raw": "...", "mechanism": "..." },
    "dkim":  { "valid": true, "signatures": ["Valid: example.com"], "raw": "..." },
    "dmarc": { "result": "pass", "raw": "...", "policy": "reject" }
  }
}
```

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
- **policy**: The DMARC policy (`none`, `quarantine`, `reject`)
- **error**: Error message if lookup failed

## Docker Usage

### Build Docker Image

```bash
docker build -t inboundparse .
```

### Run with Docker (Basic)

```bash
docker run -p 25:25 -p 587:587 inboundparse \
  -webhook=http://your-webhook-url.com/api/webhook \
  -verbose=true
```

### Run with Docker (TLS)

Provide your own certificate and key inside the container and set `CERT_FILE`/`KEY_FILE`.

### Environment File (.env)

Create a `.env` file in your project directory (optional):

```bash
WEBHOOK_URL=https://your-webhook-url.com/api/webhook

# Optional overrides
LISTEN_ADDR=0.0.0.0:25
LISTEN_ADDR_TLS=0.0.0.0:587
ENABLE_SPF=true
ENABLE_DKIM=true
ENABLE_DMARC=true
VERBOSE=false
CERT_FILE=/cert/cert.pem
KEY_FILE=/cert/key.pem
```

## Testing

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
