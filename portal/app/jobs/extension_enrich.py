"""Marketplace metadata enrichment worker (T2.3).

Runs for one (marketplace, extension_id, version) per invocation.
Upserts the ExtensionMetadata cache row, and on the transition
``is_unpublished: False -> True`` fires
``extension.unpublished_detected`` to every webhook subscription on
every customer that has at least one host running this extension.

The transition fires exactly once per (extension_id, version) — once
``unpublished_detected_at`` is set, subsequent rechecks just refresh
``fetched_at`` (the event does not re-fire on each polling tick).

enqueue_pending_enrichments() is the public hook the scan ingestion
handlers call to schedule enrichments for extensions they just saw
where the cache is missing or stale.
"""
import logging
import os
from datetime import datetime, timedelta
from typing import Iterable, Optional, Set, Tuple

from app.events import emit_event
from app.marketplace import fetch_extension_with_status

enrich_logger = logging.getLogger("ideviewer.extension_enrich")

# HTTP status codes that we treat as "definitely unpublished" rather
# than a transient failure. 404 = not found; 410 = gone.
UNPUBLISHED_STATUSES = {404, 410}


def enrich_extension(marketplace: str, extension_id: str, version: str) -> dict:
    """Enrich one extension. Safe to retry; idempotent on the cache row.

    Returns a small dict describing what happened (for observability),
    not the marketplace payload itself.
    """
    from flask import has_app_context

    if has_app_context():
        return _run(marketplace, extension_id, version)

    from app import create_app
    app = create_app(os.environ.get("FLASK_CONFIG", "production"))
    with app.app_context():
        return _run(marketplace, extension_id, version)


def _run(marketplace: str, extension_id: str, version: str) -> dict:
    from app import db
    from app.models import ExtensionMetadata

    data, status_code = fetch_extension_with_status(extension_id, marketplace)

    row = (
        ExtensionMetadata.query
        .filter_by(marketplace=marketplace, extension_id=extension_id, version=version)
        .first()
    )
    is_new = row is None
    was_unpublished = row.is_unpublished if row else False

    if row is None:
        row = ExtensionMetadata(
            marketplace=marketplace,
            extension_id=extension_id,
            version=version,
        )
        db.session.add(row)

    row.fetched_at = datetime.utcnow()
    row.last_fetch_status = status_code

    just_unpublished = False
    if data:
        # Fresh data — extension still in marketplace.
        row.is_unpublished = False
        row.unpublished_detected_at = None
        row.publisher_display_name = data.get('publisher_display_name') or data.get('publisher')
        row.install_count = _coerce_int(data.get('installs') or data.get('install_count'))
        row.average_rating = _coerce_float(data.get('rating') or data.get('average_rating'))
        row.last_updated_at = _coerce_dt(data.get('last_updated'))
        row.raw_data = data
    elif status_code in UNPUBLISHED_STATUSES:
        # Definitely gone from marketplace.
        if not was_unpublished:
            row.is_unpublished = True
            row.unpublished_detected_at = datetime.utcnow()
            just_unpublished = True
    # else: transient failure — leave previous state intact, just refresh fetched_at.

    db.session.commit()

    if just_unpublished:
        _emit_unpublished_event(row)

    return {
        "marketplace": marketplace,
        "extension_id": extension_id,
        "version": version,
        "is_new": is_new,
        "status_code": status_code,
        "is_unpublished": row.is_unpublished,
        "just_unpublished": just_unpublished,
    }


def _emit_unpublished_event(row) -> None:
    """Fire extension.unpublished_detected to every customer that has at
    least one host running this extension+version.
    """
    from app import db
    from app.models import Host, ScanReport, CustomerKey

    # Find which customers have hosts running this extension at this
    # version. We use the latest ScanReport per host to determine "is
    # running today" rather than historical reports.
    affected_by_customer: dict = {}
    hosts = Host.query.filter_by(is_active=True).all()
    for host in hosts:
        latest = host.scan_reports.first()
        if not latest or not latest.scan_data:
            continue
        for ide in latest.scan_data.get('ides') or []:
            for ext in ide.get('extensions') or []:
                ext_id = ext.get('id') or ext.get('extension_id')
                ext_ver = ext.get('version')
                if ext_id == row.extension_id and ext_ver == row.version:
                    affected_by_customer.setdefault(host.customer_key_id, []).append({
                        'host_id': host.public_id,
                        'hostname': host.hostname,
                    })
                    break

    if not affected_by_customer:
        # No customer is affected — fire nothing. The transition still
        # stays recorded on the row for diagnostics.
        enrich_logger.info(
            "marketplace removed %s@%s — no active hosts affected",
            row.extension_id, row.version,
        )
        return

    for customer_key_id, hosts_list in affected_by_customer.items():
        emit_event(
            'extension.unpublished_detected',
            customer_key_id=customer_key_id,
            data={
                'extension_id': row.extension_id,
                'version': row.version,
                'marketplace': row.marketplace,
                'publisher_display_name': row.publisher_display_name,
                'install_count': row.install_count,
                'last_known_metadata': row.raw_data,
                'affected_hosts': hosts_list,
                'detected_at': row.unpublished_detected_at.isoformat() + 'Z' if row.unpublished_detected_at else None,
            },
        )


def _coerce_int(v) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _coerce_float(v) -> Optional[float]:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _coerce_dt(v) -> Optional[datetime]:
    """Parse common marketplace lastUpdated string formats; None on failure."""
    if not v:
        return None
    if isinstance(v, datetime):
        return v
    s = str(v).replace('Z', '+00:00')
    try:
        return datetime.fromisoformat(s).replace(tzinfo=None)
    except ValueError:
        return None


STALE_AFTER = timedelta(hours=24)


from app.queue import enqueue


def enqueue_pending_enrichments(scan_data: dict) -> int:
    """Schedule enrichment jobs for every (marketplace, extension_id,
    version) in ``scan_data`` whose cache row is missing or older than
    ``STALE_AFTER``. Called from /api/report and /api/realtime-event.

    Deduplicates within the request and within the existing cache, so
    repeated submissions from the same host don't fan-storm the queue.
    Returns the number of jobs enqueued (0 in sync mode is fine —
    the daily scheduler will pick them up).
    """
    from app.marketplace import detect_marketplace
    from app.models import ExtensionMetadata

    triples = _collect_triples(scan_data, detect_marketplace)
    if not triples:
        return 0

    # Fetch all existing cache rows in one query to decide which need work.
    existing = ExtensionMetadata.query.filter(
        db_tuple_in(
            (ExtensionMetadata.marketplace,
             ExtensionMetadata.extension_id,
             ExtensionMetadata.version),
            triples,
        )
    ).all()

    fresh_keys: Set[Tuple[str, str, str]] = set()
    threshold = datetime.utcnow() - STALE_AFTER
    for row in existing:
        if row.fetched_at and row.fetched_at >= threshold:
            fresh_keys.add((row.marketplace, row.extension_id, row.version))

    enqueued = 0
    for marketplace, ext_id, version in triples:
        if (marketplace, ext_id, version) in fresh_keys:
            continue
        # Returns None in sync mode — that's fine; the daily scheduler
        # will catch it on the next tick.
        enqueue(enrich_extension, marketplace, ext_id, version, retry_max=2)
        enqueued += 1
    return enqueued


def _collect_triples(scan_data: dict, detect_marketplace) -> Set[Tuple[str, str, str]]:
    out: Set[Tuple[str, str, str]] = set()
    if not scan_data:
        return out
    for ide in scan_data.get('ides') or []:
        ide_name = ide.get('name', '')
        ide_type = ide.get('type', '') or ide.get('ide_type', '')
        marketplace = detect_marketplace(ide_name=ide_name, ide_type=ide_type)
        for ext in ide.get('extensions') or []:
            ext_id = ext.get('id') or ext.get('extension_id')
            version = ext.get('version')
            if not ext_id or not version:
                continue
            out.add((marketplace, ext_id, version))
    return out


def db_tuple_in(columns, value_tuples):
    """Build a SQLAlchemy filter expression equivalent to
    ``WHERE (a, b, c) IN ((...), (...))``. Postgres supports tuple IN
    natively; falls back to chained OR for other dialects.
    """
    from sqlalchemy import and_, or_, tuple_

    if not value_tuples:
        # Empty filter that matches nothing.
        return columns[0].in_([])
    try:
        return tuple_(*columns).in_(value_tuples)
    except Exception:
        return or_(*[
            and_(*[c == v for c, v in zip(columns, vt)])
            for vt in value_tuples
        ])
