"""Observability thin slice (T4.3): JSON logs + Prometheus /metrics.

Two surfaces:

1. ``init_json_logging(app)`` swaps the root logger formatter to a JSON
   formatter when ``FLASK_CONFIG=production``. Dev keeps human-readable
   output so local debugging stays readable.

2. ``metrics_bp`` exposes ``GET /metrics`` in Prometheus text format.
   Open by default (no auth) — operators control access via network
   policy / firewall / ingress, which is the standard exporter pattern.
   Set ``METRICS_TOKEN`` to require ``Authorization: Bearer <token>``.

The counters themselves are module-level Counters from prometheus_client
so callers can import them directly:

    from app.observability import (
        WEBHOOK_DELIVERIES, POLICY_VIOLATIONS,
        RQ_JOBS, EXTENSION_ENRICHMENTS,
    )
    WEBHOOK_DELIVERIES.labels(status='succeeded').inc()
"""
import logging
import os
import sys

from flask import Blueprint, Response, abort, request
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    generate_latest,
)


# ──────────────────────────────────────────────────────────────────────
# Counters
# ──────────────────────────────────────────────────────────────────────

WEBHOOK_DELIVERIES = Counter(
    'ideviewer_webhook_deliveries_total',
    'Outbound webhook delivery attempts by terminal status.',
    ['status'],  # succeeded | failed | retrying
)

POLICY_VIOLATIONS = Counter(
    'ideviewer_policy_violations_total',
    'Policy matches written to the violations table by action.',
    ['action'],  # warn | block-alert
)

RQ_JOBS = Counter(
    'ideviewer_rq_jobs_total',
    'Background job completions by name and outcome.',
    ['job', 'outcome'],  # outcome: success | failure
)

EXTENSION_ENRICHMENTS = Counter(
    'ideviewer_extension_enrichments_total',
    'Extension marketplace enrichment attempts by outcome.',
    ['outcome'],  # success | unpublished | error
)


# ──────────────────────────────────────────────────────────────────────
# JSON logging
# ──────────────────────────────────────────────────────────────────────

def init_json_logging(app) -> None:
    """Replace the root logger's handlers with one JSON handler to stdout.

    Idempotent on repeated calls (within the same process). Inspects
    ``FLASK_CONFIG`` lazily so the function is safe to call regardless
    of how it's invoked from create_app.
    """
    if (app.config.get('FLASK_CONFIG') or os.environ.get('FLASK_CONFIG')) != 'production':
        return

    try:
        from pythonjsonlogger import jsonlogger
    except ImportError:
        app.logger.warning("python-json-logger not installed; JSON logs disabled")
        return

    formatter = jsonlogger.JsonFormatter(
        fmt='%(asctime)s %(levelname)s %(name)s %(message)s',
        rename_fields={'asctime': 'timestamp', 'levelname': 'level'},
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    # Drop existing handlers we'd otherwise duplicate output through.
    for h in list(root.handlers):
        root.removeHandler(h)
    root.addHandler(handler)
    root.setLevel(logging.INFO)

    # Replace Flask's app.logger handlers too.
    for h in list(app.logger.handlers):
        app.logger.removeHandler(h)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)


# ──────────────────────────────────────────────────────────────────────
# /metrics endpoint
# ──────────────────────────────────────────────────────────────────────

metrics_bp = Blueprint('metrics', __name__)


@metrics_bp.route('/metrics')
def metrics():
    """Prometheus scrape endpoint.

    If ``METRICS_TOKEN`` is set, require ``Authorization: Bearer <token>``.
    If unset (default), open to anyone with network access.
    """
    expected = os.environ.get('METRICS_TOKEN')
    if expected:
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            abort(401)
        if auth[len('Bearer '):] != expected:
            abort(401)

    return Response(generate_latest(), mimetype=CONTENT_TYPE_LATEST)
