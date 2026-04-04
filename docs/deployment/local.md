---
title: Local Development
nav_order: 1
parent: Deployment
---

# Local Development

The simplest way to run the portal. Uses SQLite and requires no external services.

## Prerequisites

- Python 3.10+
- Git

## One-Command Start

```bash
./start.sh
```

This automatically:

1. Checks for Python 3.10+
2. Creates a virtual environment in `portal/venv`
3. Installs dependencies from `portal/requirements.txt`
4. Generates `portal/.env` with a random `SECRET_KEY`
5. Runs database migrations (creates SQLite database)
6. Starts the Flask server on `http://localhost:5000`

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

The SQLite database is stored at `portal/instance/ideviewer.db`. To reset:

```bash
rm portal/instance/ideviewer.db
flask db upgrade
```

## When to Use

Local mode is suitable for:

- Individual developers monitoring their own machine
- Evaluating IDEViewer before a team deployment
- Development and testing of the portal itself

For team deployments, see [Docker](docker.md) or [AWS](aws.md).
