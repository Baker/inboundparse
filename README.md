# InboundParse - Enhanced Email to Webhook Gateway

A modern SMTP server that receives emails from any domain without authentication and forwards them to webhooks with comprehensive email authentication validation and SSL/TLS support.

## Features

- **No Authentication Required**: Accepts emails from any domain without username/password
- **SSL/TLS Support**: Automatic SSL certificate management via Let's Encrypt
- **SPF Validation**: Validates Sender Policy Framework records
- **DKIM Validation**: Verifies DomainKeys Identified Mail signatures  
- **DMARC Validation**: Checks Domain-based Message Authentication, Reporting & Conformance policies
- **Complete Headers**: Includes all email headers in the webhook payload
- **Webhook Authentication**: Supports HTTP Basic Auth for webhook endpoints
- **Comprehensive Logging**: Detailed logging with verbose mode option
- **Multiple Ports**: Supports both port 25 (SMTP) and 587 (submission)

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
        SMTP server listen address (default ":25")
  -webhook string
        Webhook URL to send email data to (required)
  -webhook-user string
        Basic auth username for webhook
  -webhook-pass string
        Basic auth password for webhook
  -name string
        SMTP server name (default "inboundparse")
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
        SSL certificate file path
  -key-file string
        SSL private key file path
  -verbose
        Enable verbose logging (default false)
```

### Environment Variables

You can also configure using environment variables:

#### Core Configuration
- `WEBHOOK_URL` - Webhook URL (required)
- `WEBHOOK_USER` - Basic auth username for webhook
- `WEBHOOK_PASS` - Basic auth password for webhook
- `LISTEN_ADDR` - SMTP server listen address
- `SERVER_NAME` - SMTP server name

#### SSL/TLS Configuration
- `MXDOMAIN` - Domain name for SSL certificates (required for SSL)
- `CERT_FILE` - SSL certificate file path (default: /cert/cert.pem)
- `KEY_FILE` - SSL private key file path (default: /cert/key.pem)

#### Let's Encrypt Configuration
- `CF_Token` - Cloudflare API token for DNS validation
- `CF_Zone_ID` - Cloudflare zone ID
- `DNS_API` - DNS API provider (default: dns_cf)
- `ACME_SH_EMAIL` - Email for Let's Encrypt account registration

#### Feature Toggles
- `ENABLE_SPF` - Enable SPF validation (default: true)
- `ENABLE_DKIM` - Enable DKIM validation (default: true)
- `ENABLE_DMARC` - Enable DMARC validation (default: true)
- `VERBOSE` - Enable verbose logging (default: false)

## Webhook Payload

The service sends a JSON payload to your webhook with the following structure:

```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "from": {
    "address": "sender@example.com",
    "name": "Sender Name"
  },
  "to": [
    {
      "address": "recipient1@example.com",
      "name": "Recipient 1"
    },
    {
      "address": "recipient2@example.com", 
      "name": "Recipient 2"
    }
  ],
  "subject": "Email Subject",
  "message_id": "<unique-message-id@example.com>",
  "headers": {
    "From": ["sender@example.com"],
    "To": ["recipient1@example.com", "recipient2@example.com"],
    "Subject": ["Email Subject"],
    "Date": ["Mon, 1 Jan 2024 12:00:00 +0000"],
    "Message-ID": ["<unique-message-id@example.com>"],
    "Content-Type": ["text/plain; charset=utf-8"]
  },
  "text_body": "Plain text email body content",
  "html_body": "HTML email body content",
  "authentication_results": {
    "spf": {
      "result": "pass",
      "raw": "SPF result: pass for domain example.com from IP 192.168.1.100",
      "mechanism": "include:_spf.example.com"
    },
    "dkim": {
      "valid": true,
      "signatures": ["Valid: example.com"],
      "raw": "DKIM verification found 1 signatures"
    },
    "dmarc": {
      "result": "pass",
      "raw": "DMARC record found for domain example.com",
      "policy": "quarantine"
    }
  },
  "raw": "Full raw email message including headers and body",
  "server_info": {
    "remote_addr": "192.168.1.100:54321",
    "local_addr": "0.0.0.0:25",
    "server_name": "inboundparse"
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

### Run with Docker (SSL/TLS)

```bash
docker run -p 25:25 -p 587:587 \
  -e WEBHOOK_URL=https://your-webhook-url.com/api/webhook \
  -e MXDOMAIN=mx.yourdomain.com \
  -e CF_Token=your-cloudflare-token \
  -e CF_Zone_ID=your-zone-id \
  -e ACME_SH_EMAIL=your-email@example.com \
  -e VERBOSE=true \
  inboundparse
```

### Environment File (.env)

Create a `.env` file in your project directory:

```bash
# Required
WEBHOOK_URL=https://your-webhook-url.com/api/webhook
MXDOMAIN=mx.yourdomain.com

# Cloudflare DNS API (required for SSL)
CF_Token=your-cloudflare-token
CF_Zone_ID=your-zone-id
DNS_API=dns_cf

# SSL Configuration
ACME_SH_EMAIL=your-email@example.com

# Feature Configuration
ENABLE_SPF=true
ENABLE_DKIM=true
ENABLE_DMARC=true
VERBOSE=true
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
