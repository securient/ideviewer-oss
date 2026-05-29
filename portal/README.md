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
