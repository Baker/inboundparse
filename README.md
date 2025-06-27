# SMTP2HTTP - Enhanced Email to Webhook Gateway

A modern SMTP server that receives emails from any domain without authentication and forwards them to webhooks with comprehensive email authentication validation.

## Features

- **No Authentication Required**: Accepts emails from any domain without username/password
- **SPF Validation**: Validates Sender Policy Framework records
- **DKIM Validation**: Verifies DomainKeys Identified Mail signatures  
- **DMARC Validation**: Checks Domain-based Message Authentication, Reporting & Conformance policies
- **Complete Headers**: Includes all email headers in the webhook payload
- **Webhook Authentication**: Supports HTTP Basic Auth for webhook endpoints
- **Comprehensive Logging**: Detailed logging with verbose mode option

## Quick Start

### Build and Run

```bash
# Install dependencies
go mod tidy

# Build the binary
go build -o smtp2http

# Run with webhook URL
./smtp2http -webhook=http://localhost:8080/api/webhook
```

### Command Line Options

```bash
Usage of ./smtp2http:
  -listen string
        SMTP server listen address (default ":25")
  -webhook string
        Webhook URL to send email data to (required)
  -webhook-user string
        Basic auth username for webhook
  -webhook-pass string
        Basic auth password for webhook
  -name string
        SMTP server name (default "smtp2http")
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
  -verbose
        Enable verbose logging (default false)
```

### Environment Variables

You can also configure using environment variables:

- `WEBHOOK_URL` - Webhook URL (required)
- `WEBHOOK_USER` - Basic auth username for webhook
- `WEBHOOK_PASS` - Basic auth password for webhook
- `LISTEN_ADDR` - SMTP server listen address
- `SERVER_NAME` - SMTP server name

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
    "server_name": "smtp2http"
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
docker build -t smtp2http .
```

### Run with Docker

```bash
docker run -p 25:25 smtp2http \
  -webhook=http://your-webhook-url.com/api/webhook \
  -verbose=true
```

### Docker Compose

```yaml
version: '3.8'
services:
  smtp2http:
    build: .
    ports:
      - "25:25"
    environment:
      - WEBHOOK_URL=http://your-webhook-url.com/api/webhook
      - WEBHOOK_USER=your-username
      - WEBHOOK_PASS=your-password
      - VERBOSE=true
    restart: unless-stopped
```

## Testing

### Send Test Email via Telnet

```bash
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

### Send Test Email via SMTP Client

```python
import smtplib
from email.mime.text import MIMEText

# Create message
msg = MIMEText("This is a test email")
msg['Subject'] = 'Test Email'
msg['From'] = 'test@example.com'
msg['To'] = 'recipient@example.com'

# Send email
server = smtplib.SMTP('localhost', 25)
server.send_message(msg)
server.quit()
```

## Security Considerations

- This service accepts emails from any source without authentication
- Run behind a firewall or reverse proxy for production use
- Consider rate limiting to prevent abuse
- Use HTTPS for webhook URLs in production
- Validate webhook payloads in your receiving application

## Dependencies

- [github.com/emersion/go-smtp](https://github.com/emersion/go-smtp) - SMTP server implementation
- [github.com/emersion/go-msgauth](https://github.com/emersion/go-msgauth) - DKIM and DMARC validation
- [github.com/zaccone/spf](https://github.com/zaccone/spf) - SPF validation
- [github.com/joho/godotenv](https://github.com/joho/godotenv) - Environment variable loading

## License

This project is based on the original [SMTP2HTTP](https://github.com/markterence/smtp2http) but completely rewritten to eliminate middleman dependencies and add comprehensive email authentication validation. 