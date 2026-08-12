---
title: Local Development
nav_order: 1
parent: Deployment
---

# Local Development

The simplest way to run the portal. Provisions PostgreSQL automatically via Docker, or reuses a server you already have on `:5432`.

## Prerequisites

- Python 3.10+
- Git
- Docker (only if you don't already have PostgreSQL on `:5432`)

## One-Command Start

```bash
./start.sh
```

This automatically:

1. Checks for Python 3.10+
2. Creates a virtual environment in `portal/venv`
3. Installs dependencies from `portal/requirements.txt`
4. Generates `portal/.env` with a random `SECRET_KEY`
5. Provisions PostgreSQL (reuses `:5432`, else starts the `ideviewer-postgres` container) and runs database migrations
6. Starts the Flask server on `http://localhost:5000`

The background job queue is auto-detected: if Redis is reachable (or Docker is available to start a local Redis instance), vulnerability scans run on an RQ worker. Otherwise, the portal runs scans synchronously inline — no configuration required.

## Manual Start

```bash
cd portal
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
FLASK_CONFIG=development flask run
```

## Default Credentials

| Username | Password |
|----------|----------|
| `admin` | `ideviewer` |

You will be prompted to change the password on first login.

## Connect a Daemon

```bash
ideviewer register \
  --customer-key YOUR-KEY \
  --portal-url http://localhost:5000
```

The customer key is a UUID created in the portal's admin interface. The daemon starts automatically after registration.

## Database

Local development uses PostgreSQL. When `./start.sh` provisions it, data
lives in the `ideviewer_pgdata` Docker volume and survives restarts — stopping
the portal with Ctrl+C leaves the database running.

```bash
docker stop ideviewer-postgres     # stop the database
```

To reset it completely:

```bash
docker rm -f ideviewer-postgres
docker volume rm ideviewer_pgdata
```

## When to Use

Local mode is suitable for:

- Individual developers monitoring their own machine
- Evaluating IDEViewer before a team deployment
- Development and testing of the portal itself

For team deployments, see [Docker](docker.md) or [AWS](aws.md).
