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
| `FREE_TIER_HOST_LIMIT` | No | `5` | Max hosts per customer key |
| `GOOGLE_CLIENT_ID` | No | — | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | No | — | Google OAuth client secret |

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
  ideviewer-portal
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

## Production Deployment

### Google Cloud Run

```bash
# Build and push the container
docker build -t gcr.io/PROJECT_ID/ideviewer-portal .
docker push gcr.io/PROJECT_ID/ideviewer-portal

# Deploy to Cloud Run
gcloud run deploy ideviewer-portal \
  --image gcr.io/PROJECT_ID/ideviewer-portal \
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
aws ecr create-repository --repository-name ideviewer-portal

# Build, tag, and push
docker build -t ideviewer-portal .
docker tag ideviewer-portal:latest ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/ideviewer-portal:latest
docker push ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/ideviewer-portal:latest
```

**2. Create an ECS task definition** (`task-definition.json`):

```json
{
  "family": "ideviewer-portal",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::ACCOUNT_ID:role/ecsTaskExecutionRole",
  "containerDefinitions": [
    {
      "name": "portal",
      "image": "ACCOUNT_ID.dkr.ecr.us-east-1.amazonaws.com/ideviewer-portal:latest",
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
          "awslogs-group": "/ecs/ideviewer-portal",
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
  --service-name ideviewer-portal \
  --task-definition ideviewer-portal \
  --desired-count 1 \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx],securityGroups=[sg-xxx],assignPublicIp=ENABLED}"
```

You'll need an RDS PostgreSQL instance in the same VPC, and optionally an ALB in front for HTTPS.

### Self-Hosted (Docker)

```bash
docker build -t ideviewer-portal .

docker run -d --name ideviewer-portal \
  -p 8080:8080 \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e DATABASE_URL="postgresql://user:pass@host:5432/ideviewer" \
  -e FLASK_CONFIG=production \
  -e PORTAL_URL="https://your-domain.com" \
  ideviewer-portal
```

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | None | Health check |
| POST | `/api/validate-key` | Customer Key | Validate customer key |
| POST | `/api/register-host` | Customer Key | Register a host |
| POST | `/api/report` | Customer Key | Submit scan report |
| GET | `/api/hosts` | Customer Key | List hosts for key |
| POST | `/api/heartbeat` | Customer Key | Daemon heartbeat |
| POST | `/api/alert` | Customer Key | Tamper/integrity alert |
| GET | `/api/scan-requests/pending` | Customer Key | Check for on-demand scans |
| POST | `/api/scan-requests/<id>/update` | Customer Key | Update scan progress |

All authenticated endpoints require the `X-Customer-Key` header with a valid UUID key.

## License

Apache License 2.0 — Copyright 2024-2026 Securient
