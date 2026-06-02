"""Daily extension metadata refresh job (T2.3).

Enumerates ExtensionMetadata rows whose ``fetched_at`` is older than
24 hours and enqueues an enrichment job for each. This is the safety
net that detects "extension got removed from marketplace" even for
hosts that are no longer submitting scans.

Scheduled by rq-scheduler from ``portal/run_scheduler.py``.
"""
import logging
import os
from datetime import datetime, timedelta

refresh_logger = logging.getLogger("ideviewer.extension_refresh")

REFRESH_THRESHOLD = timedelta(hours=24)


def refresh_stale_extension_metadata() -> dict:
    """Enqueue enrich_extension for every cache row older than the
    24-hour threshold. Returns a small dict for observability.
    """
    from flask import has_app_context

    if has_app_context():
        return _run()

    from app import create_app
    app = create_app(os.environ.get("FLASK_CONFIG", "production"))
    with app.app_context():
        return _run()


def _run() -> dict:
    from app.models import ExtensionMetadata
    from app.queue import enqueue
    from app.jobs.extension_enrich import enrich_extension

    cutoff = datetime.utcnow() - REFRESH_THRESHOLD
    stale = (
        ExtensionMetadata.query
        .filter(ExtensionMetadata.fetched_at < cutoff)
        .all()
    )

    enqueued = 0
    for row in stale:
        enqueue(enrich_extension, row.marketplace, row.extension_id, row.version, retry_max=2)
        enqueued += 1

    refresh_logger.info(
        "stale-refresh tick: %d stale rows, %d enqueued",
        len(stale), enqueued,
    )
    return {"stale_rows": len(stale), "enqueued": enqueued}
