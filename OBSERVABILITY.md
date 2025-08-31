# Observability Guide for InboundParse

This document describes the observability features added to the InboundParse SMTP server, including metrics collection, monitoring, and alerting capabilities.

## Overview

The InboundParse server now includes comprehensive observability features:

- **Prometheus Metrics**: Detailed metrics exposed on `/metrics` endpoint
- **Optional Metrics**: Metrics collection can be enabled/disabled as needed
- **Health Checks**: Health endpoint at `/health` for load balancer health checks
- **Grafana Dashboards**: Pre-configured dashboards for visualization
- **Docker Compose**: Complete monitoring stack with Prometheus and Grafana

## Metrics Collected

### SMTP Server Metrics

- `smtp_connections_total`: Total number of SMTP connections
- `smtp_connections_active`: Number of active SMTP connections
- `smtp_connection_duration_seconds`: Duration of SMTP connections
- `smtp_active_sessions`: Number of active SMTP sessions

### Message Processing Metrics

- `smtp_messages_total`: Total number of SMTP messages received
- `smtp_message_size_bytes`: Size distribution of SMTP messages
- `smtp_messages_processed_total`: Total number of successfully processed messages
- `smtp_messages_failed_total`: Total number of failed message processing attempts
- `message_parsing_duration_seconds`: Duration of message parsing
- `message_parsing_failed_total`: Total number of failed message parsing attempts

### Webhook Metrics

- `webhook_requests_total`: Total number of webhook requests sent
- `webhook_request_duration_seconds`: Duration of webhook requests
- `webhook_requests_failed_total`: Total number of failed webhook requests

### Authentication Metrics

- `auth_checks_total`: Total number of authentication checks performed
- `auth_checks_spf_total`: Total number of SPF checks performed
- `auth_checks_dkim_total`: Total number of DKIM checks performed
- `auth_checks_dmarc_total`: Total number of DMARC checks performed
- `auth_checks_failed_total`: Total number of failed authentication checks

### System Metrics

- `server_uptime_seconds`: Server uptime in seconds

## Configuration

### Environment Variables

- `METRICS_ADDR`: Metrics server listen address (default: `0.0.0.0:9090`)
- `ENABLE_METRICS`: Enable Prometheus metrics collection (default: `false`)

### Command Line Flags

- `--metrics-addr`: Metrics server listen address
- `--enable-metrics`: Enable Prometheus metrics collection

## Running with Observability

### Using Docker Compose (Recommended)

The easiest way to run InboundParse with full observability is using the provided Docker Compose setup:

```bash
docker-compose up -d
```

This will start:
- InboundParse SMTP server with metrics
- Prometheus for metrics collection
- Grafana for visualization

- Test webhook endpoint

### Accessing the Services

- **SMTP Server**: `localhost:25` (plain), `localhost:587` (TLS)
- **Metrics Endpoint**: `http://localhost:9090/metrics`
- **Health Check**: `http://localhost:9090/health`
- **Prometheus**: `http://localhost:9091`
- **Grafana**: `http://localhost:3000` (admin/admin)
- **Test Webhook**: `http://localhost:8080`

### Grafana Dashboard

The Grafana dashboard includes:

1. **SMTP Traffic Rate**: Connection and message rates
2. **Active Connections & Sessions**: Current active connections
3. **SMTP Connection Duration**: Connection duration percentiles
4. **Message Size Distribution**: Message size percentiles
5. **Message Processing Rate**: Success/failure rates
6. **Webhook Request Duration**: Webhook performance
7. **Webhook Request Rate**: Webhook success/failure rates
8. **Authentication Check Rate**: SPF/DKIM/DMARC check rates
9. **Message Parsing Duration**: Parsing performance
10. **Server Uptime**: Server uptime tracking

## Prometheus Queries

### Key Queries for Monitoring

```promql
# Message processing success rate
rate(smtp_messages_processed_total[5m]) / rate(smtp_messages_total[5m])

# Webhook success rate
rate(webhook_requests_total[5m]) - rate(webhook_requests_failed_total[5m]) / rate(webhook_requests_total[5m])

# Average message size
rate(smtp_message_size_bytes_sum[5m]) / rate(smtp_message_size_bytes_count[5m])

# 95th percentile webhook response time
histogram_quantile(0.95, rate(webhook_request_duration_seconds_bucket[5m]))

# Authentication check failure rate
rate(auth_checks_failed_total[5m]) / rate(auth_checks_total[5m])
```

## Alerting Rules

You can set up Prometheus alerting rules for:

- High message processing failure rate
- High webhook failure rate
- Long webhook response times
- High authentication check failure rate
- Server downtime

Example alerting rule:

```yaml
groups:
  - name: inboundparse
    rules:
      - alert: HighMessageFailureRate
        expr: rate(smtp_messages_failed_total[5m]) / rate(smtp_messages_total[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High message processing failure rate"
          description: "Message processing failure rate is {{ $value | humanizePercentage }}"
```

## Metrics Configuration

Metrics are optional and disabled by default. To enable metrics:

```bash
# Using command line flag
docker run --enable-metrics inboundparse

# Using environment variable
docker run -e ENABLE_METRICS=true inboundparse
```

When metrics are disabled, the metrics server will not start and no metrics will be collected, reducing resource usage.

## Health Checks

The health endpoint at `/health` returns:

```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

This can be used by load balancers and orchestration systems for health checks.

## Troubleshooting

### Metrics Not Appearing

1. Check that the metrics server is running on the correct port
2. Verify Prometheus is scraping the correct endpoint
3. Check firewall settings for port 9090

### Grafana Dashboard Issues

1. Ensure Prometheus is configured as a data source
2. Check that the dashboard JSON is properly loaded
3. Verify metric names match between the application and dashboard

### Metrics Issues

1. Verify metrics are enabled with `--enable-metrics` flag or `ENABLE_METRICS=true`
2. Check that the metrics server is running on the correct port
3. Ensure Prometheus is configured to scrape the metrics endpoint

## Performance Considerations

- Metrics collection has minimal overhead
- Prometheus scraping interval can be adjusted based on needs
- Metrics collection has minimal overhead when enabled
- Consider using Prometheus remote storage for long-term retention

## Security Considerations

- Metrics endpoint is exposed on all interfaces by default
- Consider restricting access to the metrics port in production
- Health endpoint is safe to expose publicly
- Metrics endpoint is safe to expose internally

## Future Enhancements

Potential future observability enhancements:

- Distributed tracing with OpenTelemetry
- Custom business metrics (e.g., email volume by domain)
- Log aggregation and analysis
- Advanced alerting with PagerDuty/Slack integration
- Performance profiling and optimization insights