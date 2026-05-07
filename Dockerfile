# Build stage
# Official images publish 1.26.2-alpine / 1.26.2-alpine3.22+ — not alpine3.21.
FROM golang:1.26.2-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o inboundparse ./cmd/inboundparse

# Final stage
FROM alpine:3.21

ARG ACME_SH_VERSION=3.0.7

# Install ca-certificates, openssl, socat, git, bash; pin acme.sh via git tag (no curl|sh)
RUN apk add --no-cache ca-certificates openssl socat git bash curl \
 && git clone --depth 1 --branch "${ACME_SH_VERSION}" https://github.com/acmesh-official/acme.sh.git /opt/acme.sh \
 && addgroup -S inboundparse \
 && adduser -S -G inboundparse -h /home/inboundparse inboundparse \
 && mkdir -p /cert /home/inboundparse \
 && chown -R inboundparse:inboundparse /cert /home/inboundparse /opt/acme.sh \
 && ln -sf /opt/acme.sh/acme.sh /usr/local/bin/acme.sh \
 && rm -rf /opt/acme.sh/.git

WORKDIR /home/inboundparse

COPY --from=builder /app/inboundparse /usr/local/bin/inboundparse
COPY start.sh /usr/local/bin/start.sh

RUN chmod +x /usr/local/bin/inboundparse /usr/local/bin/start.sh \
 && chown inboundparse:inboundparse /usr/local/bin/inboundparse /usr/local/bin/start.sh

USER inboundparse
ENV HOME=/home/inboundparse

# Environment variables for acme.sh and SMTP server
ENV CF_Token=""
ENV CF_Zone_ID=""
ENV DNS_API=""
ENV ACME_SH_EMAIL=""
ENV MXDOMAIN=""
ENV WEBHOOK_URL=""
ENV ENABLE_SPF="true"
ENV ENABLE_DKIM="true"
ENV ENABLE_DMARC="true"
ENV CERT_FILE="/cert/cert.pem"
ENV KEY_FILE="/cert/key.pem"
ENV VERBOSE="false"
ENV METRICS_ADDR="0.0.0.0:9090"
ENV ENABLE_METRICS="false"

# Expose SMTP ports
EXPOSE 25
EXPOSE 587
# Expose metrics port
EXPOSE 9090

# Run the startup script
ENTRYPOINT ["/usr/local/bin/start.sh"]
