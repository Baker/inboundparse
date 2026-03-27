# Build stage
FROM golang:1.26.1-alpine AS builder

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
FROM alpine:latest

# Install ca-certificates, openssl, and curl for HTTPS webhook calls and certificate management
RUN apk --no-cache add ca-certificates openssl curl socat

# Install acme.sh
RUN curl https://get.acme.sh | sh -s email=${ACME_SH_EMAIL:-dev@inboundparse.com}

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/inboundparse .

# Copy scripts
COPY start.sh ./start.sh

# Make scripts executable
RUN chmod +x ./start.sh

# Create cert directory
RUN mkdir -p /cert

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
ENTRYPOINT ["./start.sh"]