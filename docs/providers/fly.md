# Fly.io Deployment

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

