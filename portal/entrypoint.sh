#!/bin/bash
set -e

echo "Running database migrations..."
flask db upgrade 2>&1 || echo "Migration warning (may be first run)"

# Signal to app factory that migrations are already done (skip _init_database)
export MIGRATIONS_DONE=1

echo "Starting IDEViewer Portal..."
exec gunicorn --bind "0.0.0.0:${PORT:-8080}" \
    --workers "${GUNICORN_WORKERS:-4}" \
    --threads "${GUNICORN_THREADS:-2}" \
    --timeout "${GUNICORN_TIMEOUT:-120}" \
    "run:app"
