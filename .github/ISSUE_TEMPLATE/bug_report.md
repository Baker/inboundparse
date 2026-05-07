---
name: Bug report
about: Create a report to help us improve
title: "[BUG]"
labels: bug, pending-review
assignees: ''

---

**Worker compose with built-in 1..5 scale presets:** Root `**docker-compose.worker.yml**` defines `**backend-worker-1..5**` with profile gates so scaling is a single env var: default = 1 worker, `**COMPOSE_PROFILES=w3**` = 3 workers, `**COMPOSE_PROFILES=w5**` = 5 workers. Example: `**COMPOSE_PROFILES=w3 docker compose -f docker-compose.worker.yml up -d --build**` with `**DATABASE_*`**, `**REDIS_*`**, and `**STRIPE_SECRET_KEY**` set (see file header).

To run several workers on one host, duplicate the service with different `**WORKER_ID**` / `**RIVER_WORKER_METRICS_PORT**` (and optional `**ports:**` mappings for host access to metrics) or use `**docker compose up --scale**` without host port bindings.

Deploy workers on `**PROJECT_DOCKER_NETWORK` only** — same mesh as Postgres and Redis — with **no** public domains unless you intentionally expose metrics behind auth.
