---
title: Configuration
nav_order: 2
---

# Configuration

## Portal Quick Start

The portal is a self-hosted web dashboard for monitoring multiple developer machines. It's optional -- the CLI works standalone.

```bash
./start.sh              # Local dev (auto-provisions PostgreSQL)
./start.sh --docker     # Docker + PostgreSQL
./start.sh --aws        # Deploy to AWS (ECS + RDS + ALB)
```

Default login: `admin` / `ideviewer` (you will be prompted to change the password on first login).

## start.sh Options

| Option | Description | URL | Database |
|--------|-------------|-----|----------|
| `(none)` | Local development | `http://localhost:8090` | PostgreSQL (auto-provisioned) |
| `--docker` | Docker Compose | `http://localhost:8090` | PostgreSQL |
| `--aws` | AWS deployment wizard | Custom domain or ALB DNS | RDS PostgreSQL |
| `--help` | Show usage information | -- | -- |

The local mode automatically creates a Python virtual environment, installs dependencies, generates a `.env` file with a random `SECRET_KEY`, provisions PostgreSQL, runs database migrations, and starts the Flask server.

## Environment Variables

Set these in `portal/.env` (local) or via your deployment platform:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | Yes (prod) | Auto-generated | Flask secret key for session signing |
| `DATABASE_URL` | Yes | -- | PostgreSQL connection string. `./start.sh` sets this for you; there is no fallback if unset |
| `FLASK_CONFIG` | No | `development` | `development`, `production`, or `testing` |
| `PORTAL_PORT` | No | `8090` | Port the portal listens on (both local and Docker) |
| `PORTAL_URL` | No | `http://localhost:$PORTAL_PORT` | Public URL (used for OAuth redirects) |
| `GOOGLE_CLIENT_ID` | No | -- | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | No | -- | Google OAuth client secret |
| `GUNICORN_WORKERS` | No | `4` | Number of gunicorn worker processes |
| `GUNICORN_THREADS` | No | `2` | Threads per gunicorn worker |
| `GUNICORN_TIMEOUT` | No | `120` | Gunicorn worker timeout in seconds |
| `DB_POOL_SIZE` | No | `5` | SQLAlchemy connection pool size (prod only) |
| `DB_MAX_OVERFLOW` | No | `5` | SQLAlchemy pool overflow (prod only) |
| `DB_POOL_RECYCLE` | No | `1800` | Connection recycle interval, seconds |
| `REDIS_URL` | No | -- | Redis connection URL (e.g. `redis://localhost:6379/0`). When set, vulnerability scans run async via RQ; when unset, they run inline. |

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
   - Local dev: `http://localhost:8090/login/google/callback`
   - Production: `https://your-domain.com/login/google/callback`
7. Copy the **Client ID** and **Client Secret**
8. Set the environment variables:

```bash
export GOOGLE_CLIENT_ID="your-client-id.apps.googleusercontent.com"
export GOOGLE_CLIENT_SECRET="your-client-secret"
```

The Google login button appears automatically when both variables are set. If they are not set, only email/password login is shown.

## Database Options

The portal runs on PostgreSQL in every environment. There is deliberately no
SQLite fallback: running development on a different engine from production is
how schema problems go unnoticed, and SQLite silently ignores foreign-key
constraints entirely.

### Development

`./start.sh` reuses a PostgreSQL server already listening on `:5432`, or starts
a `postgres:15-alpine` container named `ideviewer-postgres` backed by a
persistent volume, then points the portal at it. Nothing to configure.

To use your own server instead, set `DATABASE_URL` in `portal/.env`:

```bash
DATABASE_URL=postgresql://ideviewer:password@localhost:5432/ideviewer
```

Connection settings for the provisioned container can be overridden with
`DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, and `DB_PASSWORD`.

### Production

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

`ideviewer register` writes an HMAC-signed configuration to the **user** path
for your platform:

```json
{
  "portal_url": "http://localhost:8090",
  "customer_key": "your-uuid-key",
  "scan_interval_minutes": 30
}
```

### Configuration file priority

The daemon loads the first of these that exists — a system-wide config
deliberately outranks a per-user one so an administrator can pin fleet
settings:

| Priority | Windows | macOS | Linux |
|---|---|---|---|
| 1 (system) | `C:\ProgramData\IDEViewer\config.json` | `/Library/Application Support/IDEViewer/config.json` | `/etc/ideviewer/config.json` |
| 2 (user) | `%LOCALAPPDATA%\IDEViewer\config.json` | `~/.ideviewer/config.json` | `~/.ideviewer/config.json` |
| 3 (legacy) | `%USERPROFILE%\.ideviewer\config.json` | *(same as 2)* | *(same as 2)* |

{: .warning }
Because `register` writes the user path, a leftover file at a higher-priority
path silently wins and the daemon keeps using the older portal URL, customer
key and host token. `register` warns when this happens; `ideviewer status`
marks the losers `[shadowed, ignored]`; `ideviewer reset --config` removes them
all. See [Troubleshooting](troubleshooting.md#reinstalling-didnt-give-me-a-clean-slate).

Run `ideviewer status` at any time to see which file is in force.

The daemon reads this configuration on startup. You can override values with CLI flags:

```bash
ideviewer daemon --foreground \
  --customer-key NEW-KEY \
  --portal-url https://portal.example.com \
  --interval 15
```
