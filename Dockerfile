# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o smtp2http .

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS webhook calls
RUN apk --no-cache add ca-certificates

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/smtp2http .

# Expose SMTP port
EXPOSE 25

# Run the binary
ENTRYPOINT ["./smtp2http"] 