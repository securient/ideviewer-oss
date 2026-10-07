---
title: Integrations
nav_order: 4
parent: Portal
---

# Integrations

The portal pushes security events to external systems over webhooks, and exposes operational metrics for scraping.

## Webhooks

Three subscription types are supported, managed under **Webhooks**:

| Type | Payload |
|------|---------|
| `generic` | JSON envelope, signed with HMAC |
| `slack` | Formatted Slack message blocks |
| `pagerduty` | PagerDuty Events API format |

Each subscription selects which events it receives. Wildcards are supported, so `extension.*` subscribes to every extension event.

### Events

| Event | Fires when |
|-------|-----------|
| `extension.installed` | A new extension appears on a host |
| `extension.removed` | An extension disappears |
| `extension.updated` | An extension's version changes |
| `extension.high_risk_detected` | A high or critical-risk extension is found |
| `extension.threat_matched` | An extension matches a threat-intel indicator |
| `secret.detected` | A new secret is found on a host |
| `anomaly.new_risky_extension` | A risky extension enters the fleet for the first time |
| `anomaly.rapid_propagation` | An extension spreads unusually fast across hosts |
| `soar.simulated` | A playbook in dry-run mode would have acted |
| `soar.notified` | A playbook sent a notification |

Extension install, remove and update events are diffed against the previous scan, so they describe genuine transitions rather than restating the inventory.

### Verifying delivery authenticity

Generic deliveries are signed with an HMAC secret in a Stripe-style scheme, so a receiver can confirm the payload came from your portal and was not replayed. The secret is shown when the subscription is created and can be rotated from the webhook's page without recreating the subscription.

### Retries and failure handling

Deliveries retry with backoff on failure. A subscription that keeps failing is auto-acknowledged after a threshold, so one dead endpoint does not generate unbounded retry load. Each delivery is recorded with its attempt count, response status and body (truncated), and an individual delivery can be replayed from the portal.

## Metrics

A Prometheus endpoint is exposed at `GET /metrics`:

| Metric | Meaning |
|--------|---------|
| `webhook_deliveries` | Delivery attempts by outcome |
| `policy_violations` | Policy violations recorded |
| `rq_jobs` | Background jobs by outcome |
| `extension_enrichments` | Marketplace metadata lookups |

### Access control

The endpoint follows the standard exporter pattern, with a secure default:

- Set `METRICS_TOKEN` and scraping requires `Authorization: Bearer <token>`
- With no token set, the endpoint is **denied in production** (`403`). Metrics are not open to the network by default.
- With no token set in development, it is open for convenience

```bash
curl -H "Authorization: Bearer $METRICS_TOKEN" https://portal.example.com/metrics
```

## Background jobs

Three workers run behind the portal when Redis is configured:

- **Worker** — processes queued jobs: OSV vulnerability correlation, marketplace enrichment, webhook delivery
- **Scheduler** — ticks recurring sweeps: extension metadata refresh (daily), host integrity (every 60s), fleet drift (every 5 minutes)

Without Redis the portal runs synchronously: jobs execute inline during the request instead of being queued. That works for a small deployment but puts vulnerability scanning on the daemon's report path.

## Daemon API

The `/api/*` endpoints serve the daemon, authenticated with a customer key and per-host token. They are not a general-purpose integration API — there is currently no endpoint for exporting findings, vulnerabilities or SBOMs in bulk to a SIEM. Webhooks are the supported push integration; a pull API is a known gap.
