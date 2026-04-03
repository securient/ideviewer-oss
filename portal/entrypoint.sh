#!/bin/bash
set -e

echo "Running database migrations..."
flask db upgrade 2>&1 || echo "Migration warning (may be first run)"

echo "Starting IDEViewer Portal..."
exec gunicorn --bind "0.0.0.0:${PORT:-8080}" --workers 4 --threads 2 --timeout 120 "run:app"
