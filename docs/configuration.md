---
title: Configuration
nav_order: 2
---

# Configuration

## Portal Quick Start

The portal is a self-hosted web dashboard for monitoring multiple developer machines. It's optional -- the CLI works standalone.

```bash
./start.sh              # Local dev (SQLite, zero config)
./start.sh --docker     # Docker + PostgreSQL
./start.sh --aws        # Deploy to AWS (ECS + RDS + ALB)
```

Default login: `admin` / `ideviewer` (you will be prompted to change the password on first login).

## start.sh Options

| Option | Description | URL | Database |
|--------|-------------|-----|----------|
| `(none)` | Local development | `http://localhost:5000` | SQLite |
| `--docker` | Docker Compose | `http://localhost:8080` | PostgreSQL |
| `--aws` | AWS deployment wizard | Custom domain or ALB DNS | RDS PostgreSQL |
| `--help` | Show usage information | -- | -- |

The local mode automatically creates a Python virtual environment, installs dependencies, generates a `.env` file with a random `SECRET_KEY`, runs database migrations, and starts the Flask server.

## Environment Variables

Set these in `portal/.env` (local) or via your deployment platform:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | Yes (prod) | Auto-generated | Flask secret key for session signing |
| `DATABASE_URL` | Yes (prod) | SQLite | PostgreSQL connection string |
| `FLASK_CONFIG` | No | `development` | `development`, `production`, or `testing` |
| `PORTAL_URL` | No | `http://localhost:5000` | Public URL (used for OAuth redirects) |
| `FREE_TIER_HOST_LIMIT` | No | `5` | Maximum hosts per customer key |
| `GOOGLE_CLIENT_ID` | No | -- | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | No | -- | Google OAuth client secret |

### Setting Environment Variables

**Linux / macOS:**

```bash
export SECRET_KEY="$(openssl rand -hex 32)"
export DATABASE_URL="postgresql://user:pass@localhost:5432/ideviewer"
export FLASK_CONFIG=production
flask run
```

**Docker:**

```bash
docker run -p 8080:8080 \
  -e SECRET_KEY="$(openssl rand -hex 32)" \
  -e DATABASE_URL="postgresql://user:pass@db:5432/ideviewer" \
  -e FLASK_CONFIG=production \
  ghcr.io/securient/ideviewer-oss-portal:latest
```

## Google OAuth Setup

Google OAuth adds a "Sign in with Google" button alongside email/password login.

1. Go to the [Google Cloud Console -- Credentials](https://console.cloud.google.com/apis/credentials)
2. Create a project (or select an existing one)
3. Go to **APIs & Services > Credentials**
4. Click **Create Credentials > OAuth 2.0 Client ID**
5. Select **Web application** as the application type
6. Under **Authorized redirect URIs**, add:
   - Local dev: `http://localhost:5000/login/google/callback`
   - Production: `https://your-domain.com/login/google/callback`
7. Copy the **Client ID** and **Client Secret**
8. Set the environment variables:

```bash
export GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
export GOOGLE_CLIENT_SECRET="your-client-secret"
```

The Google login button appears automatically when both variables are set. If they are not set, only email/password login is shown.

## Host Limit Configuration

The `FREE_TIER_HOST_LIMIT` variable controls how many machines can register under a single customer key. The default is 5. Set to `0` for unlimited.

## Database Options

### SQLite (Development)

No configuration needed. The database file is created at `portal/instance/ideviewer.db` on first run.

### PostgreSQL (Production)

```bash
export DATABASE_URL="postgresql://user:password@host:5432/ideviewer"
```

Database migrations are managed with Alembic (Flask-Migrate):

```bash
flask db upgrade     # Apply pending migrations
flask db migrate -m "Description"   # Generate a new migration
```

## Default Credentials

| Username | Password |
|----------|----------|
| `admin` | `ideviewer` |

{: .warning }
Change the default password immediately after first login. The portal prompts you to do so.

## Daemon Configuration

When you run `ideviewer register`, the configuration is saved to `~/.ideviewer/config.json`:

```json
{
  "portal_url": "http://localhost:5000",
  "customer_key": "your-uuid-key",
  "scan_interval_minutes": 30
}
```

The daemon reads this configuration on startup. You can override values with CLI flags:

```bash
ideviewer daemon --foreground \
  --customer-key NEW-KEY \
  --portal-url https://portal.example.com \
  --interval 15
```
