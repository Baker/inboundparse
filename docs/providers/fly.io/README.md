# Fly.io deployment

The sample Fly config in this directory is [`fly.toml`](./fly.toml). Adjust app name, region, and sizing for your project.

```bash
# From the directory that contains fly.toml
fly deploy

# The image entrypoint issues the certificate. No extra start script.
# ACME_SH_EMAIL defaults to devnull@localhost. SMTP still starts without
# STARTTLS when the DNS secrets are unset or issuance fails.
fly secrets set WEBHOOK_URL=https://your-webhook-url.com/api/webhook
fly secrets set CF_Token=your-cloudflare-token
fly secrets set CF_Zone_ID=your-zone-id
fly secrets set MXDOMAIN=your-domain.com
fly secrets set ACME_SH_EMAIL=you@your-domain.com

# Optional: error tracking
fly secrets set SENTRY_DSN=https://your-dsn@sentry.io/project-id
```

Typical elements in the sample `fly.toml`:

- TCP services on **25** and **587** with **PROXY protocol** handlers (load balancers / Fly proxies)
- **`[metrics]`** exposing `/metrics` on port **9090** for Fly’s Prometheus integration
- **`[mounts]`** volume for `/cert` so certificate material can persist
- **1 shared CPU / 1GB** VM sizing (adjust as needed)

For Prometheus metrics bound to non-loopback addresses, set `METRICS_API_KEY` or `METRICS_USERNAME` + `METRICS_PASSWORD` in secrets; the app requires credentials in that case.
