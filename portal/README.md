# IDEViewer Portal

Web dashboard for centralized monitoring of IDE extensions, security risks, plaintext secrets, and software dependencies across your organization.

## Quick Start

### Development (SQLite)

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
FLASK_CONFIG=development flask run
```

Access at http://localhost:5000

### Docker Compose (PostgreSQL)

```bash
docker-compose up -d
```

Access at http://localhost:8080

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | Yes (prod) | dev key | Flask secret key for session signing |
| `DATABASE_URL` | Yes (prod) | SQLite | PostgreSQL connection string |
| `FLASK_CONFIG` | No | `development` | `development`, `production`, or `testing` |
| `PORTAL_URL` | No | `http://localhost:5000` | Public URL (used for OAuth redirects) |
| `GOOGLE_CLIENT_ID` | No | — | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | No | — | Google OAuth client secret |
| `GUNICORN_WORKERS` | No | `4` | Number of gunicorn worker processes |
| `GUNICORN_THREADS` | No | `2` | Threads per gunicorn worker |
| `GUNICORN_TIMEOUT` | No | `120` | Gunicorn worker timeout in seconds |
| `DB_POOL_SIZE` | No | `5` | SQLAlchemy connection pool size (prod only) |
| `DB_MAX_OVERFLOW` | No | `5` | SQLAlchemy pool overflow (prod only) |
| `DB_POOL_RECYCLE` | No | `1800` | Connection recycle interval, seconds |
| `REDIS_URL` | No | — | Redis connection URL (e.g. `redis://localhost:6379/0`). When set, vulnerability scans run async via RQ; when unset, they run inline. |

### Setting Environment Variables

**Linux / macOS** — set them before running the portal:

```bash
export SECRET_KEY="$(openssl rand -hex 32)"
export DATABASE_URL="postgresql://user:pass@localhost:5432/ideviewer"
export FLASK_CONFIG=production
flask run
```

**Docker Compose** — set them in `docker-compose.yml` under the `portal` service's `environment` section.

**Docker** — pass them with `-e`:

```bash
docker run -p 8080:8080 \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e DATABASE_URL="postgresql://user:pass@db:5432/ideviewer" \
  -e FLASK_CONFIG=production \
  ideviewer-oss-portal
```

### Google OAuth (Optional)

Google OAuth adds a "Sign in with Google" button alongside email/password login. To enable it:

1. Go to the [Google Cloud Console — Credentials](https://console.cloud.google.com/apis/credentials)
2. Create a project (or select an existing one)
3. Click **Create Credentials > OAuth 2.0 Client ID**
4. Select **Web application** as the application type
5. Under **Authorized redirect URIs**, add:
   - For local dev: `http://localhost:5000/login/google/callback`
   - For production: `https://your-domain.com/login/google/callback`
6. Copy the **Client ID** and **Client Secret**
7. Set the environment variables:

```bash
export GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
export GOOGLE_CLIENT_SECRET="your-client-secret"
```

The Google login button appears automatically when both variables are set. If they are not set, only email/password login is shown.

### Database Migrations

```bash
flask db init        # First time only
flask db migrate -m "Description"
flask db upgrade
```

## Job queue and worker

Vulnerability lookups against OSV.dev are dispatched to an RQ worker when `REDIS_URL` is set, so report ingestion stays fast under load. The worker runs as a separate process (`docker-compose.yml` includes a `worker` service; production uses a dedicated `portal-worker` ECS service in `deploy/terraform/`). When `REDIS_URL` is unset or Redis is unreachable, the portal falls back to running scans inline — useful for local development.

To run the worker manually: `rq worker default --url $REDIS_URL`.

## Host enrollment and tokens

The daemon authenticates to the portal in two stages:

1. **Enrollment** — On first run, the daemon sends its customer key (`X-Customer-Key`) to `POST /api/register-host`. The portal responds with a per-host token (`host_token`, 32-byte base64url) returned **once** in the JSON body. The daemon persists it to `~/.ideviewer/config.json` with mode `0600`.
2. **Steady state** — Every subsequent call uses `X-Host-Token`. The customer key is no longer needed for that host.

Admins can revoke a host's token from the host detail page in the portal UI. On the next call, the daemon detects the 401, re-enrolls via the customer key, persists a fresh token, and retries — no manual intervention required.

Daemons built before this change use the customer key indefinitely and continue working without modification.

## Outbound webhooks

The portal can push events to any HTTP endpoint as they happen. Manage subscriptions at `/webhooks`. Each subscription has a URL, an event filter (one or more of the event types below, or `*` for all), and an HMAC signing secret that's shown exactly once on creation.

### Event types

| Event | Fired when |
|---|---|
| `tamper_alert.created` | The daemon reports a tamper event (`/api/alert`) or a host deregisters (`/api/deregister-host`) |
| `extension.high_risk_detected` | A scan or realtime rescan surfaces an extension with `risk_level` of `high` or `critical` |
| `hook_bypass.detected` | A developer commits with `--no-verify` and the daemon reports it (`/api/hook-bypass`) |
| `policy.violation` | Reserved for the policy engine (T2.2) |

### Payload format

Every delivery is a `POST` with `Content-Type: application/json` and the body:

```json
{
  "id": "evt_5a3c…",
  "type": "tamper_alert.created",
  "created_at": "2026-05-29T18:42:01.123456Z",
  "data": { … event-specific fields … }
}
```

Headers:

| Header | Value |
|---|---|
| `X-IDEViewer-Signature` | `t=<unix-seconds>,v1=<hex>` — Stripe-style |
| `X-IDEViewer-Event-Type` | The event type (same as `type` in the body) |
| `X-IDEViewer-Event-Id` | The event id (same as `id` in the body) |
| `User-Agent` | `IDEViewer-Webhook/1.0` |

### Verifying signatures

The signed payload is `f"{t}.{raw_body}"` (literal `.` between the timestamp and the raw request body) HMAC-SHA256'd with the subscription's secret. Reject any request where the timestamp is more than five minutes off from your clock — that defeats replay.

Python receiver example:

```python
import hmac, hashlib, time
from flask import request, abort

SECRET = "whsec_…"  # the value shown once on creation

@app.post("/webhook")
def handle():
    sig = request.headers.get("X-IDEViewer-Signature", "")
    parts = dict(p.split("=", 1) for p in sig.split(",") if "=" in p)
    t, v1 = parts.get("t"), parts.get("v1")
    if not t or not v1 or abs(time.time() - int(t)) > 300:
        abort(401)
    expected = hmac.new(
        SECRET.encode(), f"{t}.{request.get_data(as_text=True)}".encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, v1):
        abort(401)
    # ... process request.json ...
    return "", 204
```

### Retries and health

Failed deliveries retry on a fixed schedule: 30 seconds, 2 minutes, 10 minutes, 1 hour, 6 hours (six attempts total, ~7.5h window). Each subscription's `consecutive_failures` counter increments per terminal failure and resets on the next success — at 25 consecutive failures the subscription auto-pauses to stop hammering a dead endpoint. You can replay any past delivery (succeeded or failed) from the subscription detail page.

### Async vs sync

When `REDIS_URL` is set, deliveries run on the RQ worker and benefit from the full retry schedule. When unset, the portal attempts a single inline POST and gives up if it fails — the same degradation pattern as the OSV.dev vuln scan.

## Extension policies

Manage rules at `/policies`. Each policy combines a set of match criteria with an action that fires when an extension matches. Policies are evaluated in **priority order** (lower number wins) and **first-match-wins** per extension — put a tight `allow` policy above a broad `block-alert` to whitelist specific extensions from a wider block.

### Match criteria

Every populated criterion is ANDed. A policy with zero criteria never matches.

| Field | Type | Notes |
|---|---|---|
| `match_publisher` | glob (fnmatch) | e.g., `evil-*` matches `evil-corp` but not `goodcorp` |
| `match_extension_id` | glob | e.g., `*.banned-*` |
| `match_permission_glob` | glob | matches any of the extension's permission names; e.g., `network*` |
| `match_risk_level` | minimum threshold | `low` < `medium` < `high` < `critical` |

### Actions

| Action | What fires |
|---|---|
| `allow` | Nothing. Acts as an explicit whitelist override — useful for exempting specific extensions from a broader block. |
| `warn` | Inserts a `PolicyViolation` row; fires `policy.violation` webhook with `action=warn`. |
| `block-alert` | Inserts a `PolicyViolation` row; inserts a `TamperAlert` at `critical` severity (same red surface as tamper alerts on the dashboard); fires `policy.violation` webhook with `action=block-alert`. The daemon does not currently enforce — this is detect-and-notify only. |

### Violations

`/violations` lists every active match across all your hosts. Each row is unique per `(host, policy, extension, extension_version)` — rescanning the same extension refreshes `last_seen_at` rather than inserting duplicates. Resolved violations stay in the table for audit; toggle the view to see them.

### Examples

```text
# Block all extensions from publisher "evil-corp"
match_publisher: evil-corp
action: block-alert

# Warn on anything that asks for network permissions and is high-risk
match_permission_glob: network*
match_risk_level: high
action: warn

# Whitelist one specific extension from being flagged
match_extension_id: trusted-publisher.essential-tool
action: allow
priority: 1                  # higher priority (lower number) than the broader block below
```

## Extension marketplace enrichment

On every scan, the portal enqueues a marketplace-metadata fetch for each `(marketplace, extension_id, version)` whose cache is missing or older than 24 hours. The worker stores publisher name, install count, average rating, marketplace `lastUpdated`, and — most importantly — `is_unpublished`. The whole point is to detect the moment an extension is removed from the marketplace while still installed on your hosts.

### What ships with it

- A new `extension_metadata` table — one row per `(marketplace, extension_id, version)`.
- A worker job `enrich_extension(marketplace, extension_id, version)` that calls the marketplace and upserts the cache row.
- A daily refresh job, run by an **rq-scheduler** container (`portal-scheduler` in compose / Terraform), that re-polls every cache row older than 24h. This is the safety net for hosts that stopped scanning.
- A new webhook event `extension.unpublished_detected` that fires **exactly once** per `(extension_id, version)` on the cache transition `is_unpublished: false → true`. The payload includes the list of affected hosts under your customer key.
- Two UI surfaces: a red banner on the extension detail page when the extension is unpublished, and an "Unpublished" stat card + table on the host detail page listing affected extensions.

### How "unpublished" is decided

The marketplace client tracks the HTTP status of the most recent fetch. A response of **404** or **410** is treated as definitively unpublished. Any other failure (network error, 5xx, JSON parse failure) is treated as transient — the cache row's `is_unpublished` state stays untouched, only `fetched_at` and `last_fetch_status` are refreshed. This prevents flapping caused by marketplace outages.

If an extension that was previously marked unpublished returns to the marketplace (200 with data), `is_unpublished` is cleared and `unpublished_detected_at` is reset — but no recovery event is fired.

### Operational notes

- The scheduler service must run as **a single replica** — multiple `rqscheduler` processes against the same Redis would double-schedule the recurring job. The Terraform module pins `desired_count = 1`.
- The first refresh tick fires 60 seconds after the scheduler starts; subsequent ticks every 24 hours.
- Without Redis (sync mode), scan-triggered enrichments run inline as best-effort single attempts and no daily refresh runs. This matches the existing degradation pattern for vuln scans and webhook deliveries.

## Production Deployment

### Google Cloud Run

```bash
# Build and push the container
docker build -t gcr.io/PROJECT_ID/ideviewer-oss-portal .
docker push gcr.io/PROJECT_ID/ideviewer-oss-portal

# Deploy to Cloud Run
gcloud run deploy ideviewer-oss-portal \
  --image gcr.io/PROJECT_ID/ideviewer-oss-portal \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars "SECRET_KEY=$(openssl rand -hex 32)" \
  --set-env-vars "DATABASE_URL=postgresql://user:pass@host:5432/ideviewer" \
  --set-env-vars "FLASK_CONFIG=production" \
  --set-env-vars "PORTAL_URL=https://your-service-url.run.app"
```

You'll need a PostgreSQL database accessible from Cloud Run (e.g., Cloud SQL with a private VPC connector or public IP with SSL).

### AWS ECS (Fargate)

**1. Create an ECR repository and push the image:**

```bash
# Authenticate Docker with ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com

# Create repository (first time only)
aws ecr create-repository --repository-name ideviewer-oss-portal

# Build, tag, and push
docker build -t ideviewer-oss-portal .
docker tag ideviewer-oss-portal:latest ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/ideviewer-oss-portal:latest
docker push ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/ideviewer-oss-portal:latest
```

**2. Create an ECS task definition** (`task-definition.json`):

```json
{
  "family": "ideviewer-oss-portal",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::ACCOUNT_ID:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "portal",
      "image": "ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/ideviewer-oss-portal:latest",
      "portMappings": [{ "containerPort": 8080 }],
      "environment": [
        { "name": "FLASK_CONFIG", "value": "production" },
        { "name": "PORTAL_URL", "value": "https://your-domain.com" }
      ],
      "secrets": [
        { "name": "SECRET_KEY", "valueFrom": "arn:aws:ssm:us-east-1:ACCOUNT_ID:parameter/ideviewer/secret-key" },
        { "name": "DATABASE_URL", "valueFrom": "arn:aws:ssm:us-east-1:ACCOUNT_ID:parameter/ideviewer/database-url" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/ideviewer-oss-portal",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
```

**3. Store secrets in SSM Parameter Store:**

```bash
aws ssm put-parameter --name "/ideviewer/secret-key" --type SecureString \
  --value "$(openssl rand -hex 32)"

aws ssm put-parameter --name "/ideviewer/database-url" --type SecureString \
  --value "postgresql://user:pass@your-rds-host:5432/ideviewer"
```

**4. Create the service:**

```bash
# Register the task definition
aws ecs register-task-definition --cli-input-json file://task-definition.json

# Create the service (assumes you have a cluster and VPC configured)
aws ecs create-service \
  --cluster your-cluster \
  --service-name ideviewer-oss-portal \
  --task-definition ideviewer-oss-portal \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=ENABLED}"
```

You'll need an RDS PostgreSQL instance in the same VPC, and optionally an ALB in front for HTTPS.

### Self-Hosted (Docker)

```bash
docker build -t ideviewer-oss-portal .

docker run -d --name ideviewer-oss-portal \
  -p 8080:8080 \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e DATABASE_URL="postgresql://user:pass@host:5432/ideviewer" \
  -e FLASK_CONFIG=production \
  -e PORTAL_URL="https://your-domain.com" \
  ideviewer-oss-portal
```

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | None | Health check |
| POST | `/api/validate-key` | Customer Key | Validate customer key |
| POST | `/api/register-host` | Customer Key | Register a host, issues a per-host token |
| POST | `/api/host-token/rotate` | Host Token | Rotate the host token proactively |
| POST | `/api/report` | Host Token or Customer Key | Submit scan report |
| GET | `/api/hosts` | Customer Key | List hosts for key |
| POST | `/api/heartbeat` | Host Token or Customer Key | Daemon heartbeat |
| POST | `/api/alert` | Host Token or Customer Key | Tamper/integrity alert |
| GET | `/api/scan-requests/pending` | Host Token or Customer Key | Check for on-demand scans |
| POST | `/api/scan-requests/<id>/update` | Host Token or Customer Key | Update scan progress |

Authenticated endpoints accept either `X-Host-Token` (preferred, issued during enrollment) or `X-Customer-Key` (UUID, used for enrollment and legacy daemons). When a request is authenticated by a host token, the body's `hostname` must match the host's enrolled hostname.

## License

Apache License 2.0 — Copyright 2024-2026 Securient
