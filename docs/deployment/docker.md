---
title: Docker
nav_order: 2
parent: Deployment
---

# Docker Deployment

Run the portal with Docker Compose using PostgreSQL as the database backend.

## Prerequisites

- [Docker](https://www.docker.com/products/docker-desktop/)
- Docker Compose

## Quick Start

```bash
./start.sh --docker
```

Or manually:

```bash
cd portal
docker-compose up -d
```

The portal is available at `http://localhost:8080`.

## Default Credentials

| Username | Password |
|----------|----------|
| `admin` | `ideviewer` |

## What Gets Created

The `docker-compose.yml` starts two containers:

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| `portal` | Built from `portal/Dockerfile` | 8080 | Flask web application |
| `db` | `postgres:15` | 5432 | PostgreSQL database |

## Container Image

You can also pull the pre-built container image:

```bash
docker pull ghcr.io/securient/ideviewer-oss-portal:latest

docker run -p 8080:8080 \
  -e SECRET_KEY=$(openssl rand -base64 32) \
  -e DATABASE_URL=postgresql://user:pass@host:5432/ideviewer \
  ghcr.io/securient/ideviewer-oss-portal:latest
```

## Configuration

Set environment variables in `docker-compose.yml` under the `portal` service's `environment` section, or pass them with `-e` flags to `docker run`.

See [Configuration](../configuration.md) for the full list of environment variables.

## Operations

```bash
# View logs
cd portal && docker-compose logs -f portal

# Stop
cd portal && docker-compose down

# Reset (removes database)
cd portal && docker-compose down -v

# Rebuild after code changes
cd portal && docker-compose up -d --build
```

## Connect a Daemon

```bash
ideviewer register \
  --customer-key YOUR-KEY \
  --portal-url http://localhost:8080
```
