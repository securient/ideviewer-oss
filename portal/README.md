# IDEViewer Portal

Web dashboard for centralized monitoring of IDE extensions, security risks, plaintext secrets, and software dependencies across your organization.

## Quick Start

### Development (SQLite)

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
flask run
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
| `SECRET_KEY` | Yes (prod) | dev key | Flask secret key |
| `DATABASE_URL` | Yes (prod) | SQLite | PostgreSQL connection string |
| `FLASK_CONFIG` | No | `development` | `development`, `production`, or `testing` |
| `PORTAL_URL` | No | `http://localhost:5000` | Public URL for OAuth redirects |
| `GOOGLE_CLIENT_ID` | No | — | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | No | — | Google OAuth secret |

### Google OAuth

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create an OAuth 2.0 Client ID (Web application)
3. Add redirect URI: `https://your-domain.com/login/google/callback`
4. Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` environment variables

The Google login button appears automatically when configured.

### Database Migrations

```bash
flask db init        # First time only
flask db migrate -m "Description"
flask db upgrade
```

## Production Deployment

### Google Cloud Run

```bash
docker build -t gcr.io/PROJECT/ideviewer-portal .
docker push gcr.io/PROJECT/ideviewer-portal

gcloud run deploy ideviewer-portal \
  --image gcr.io/PROJECT/ideviewer-portal \
  --set-env-vars "SECRET_KEY=$(openssl rand -hex 32)" \
  --set-env-vars "DATABASE_URL=postgresql://..."
```

### AWS ECS

```bash
docker build -t ideviewer-portal .
docker tag ideviewer-portal:latest ACCOUNT.dkr.ecr.REGION.amazonaws.com/ideviewer-portal:latest
docker push ACCOUNT.dkr.ecr.REGION.amazonaws.com/ideviewer-portal:latest
```

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/api/health` | None | Health check |
| POST | `/api/validate-key` | API Key | Validate customer key |
| POST | `/api/register-host` | API Key | Register a host |
| POST | `/api/report` | API Key | Submit scan report |
| GET | `/api/hosts` | API Key | List hosts for key |
| POST | `/api/heartbeat` | API Key | Daemon heartbeat |
| POST | `/api/alert` | API Key | Tamper/integrity alert |
| GET | `/api/scan-requests/pending` | API Key | Check for on-demand scans |
| POST | `/api/scan-requests/<id>/update` | API Key | Update scan progress |

## License

Apache License 2.0 — Copyright 2024-2026 Securient
