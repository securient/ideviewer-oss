"""Fleet drift / anomaly detection (Phase 1 B7).

Per-host events (install/remove/threat) can't see fleet-level patterns. This
sweep tracks, per tenant (customer key), how many hosts carry each extension and
compares it to the previous sweep, surfacing two deterministic signals:

  * anomaly.new_risky_extension — a high/critical-risk extension appears in the
    fleet for the first time (after a baseline sweep, so bootstrap doesn't flood)
  * anomaly.rapid_propagation   — an already-known extension's host count jumps
    by >= PROPAGATION_THRESHOLD between sweeps (worm-like spread)

No ML — every signal is a transparent count comparison, which keeps false
positives (and the resulting alert fatigue) low. Runs on rq-scheduler; a plain
function over the DB, so it is fully testable synchronously.
"""
import logging
import os
from datetime import datetime

logger = logging.getLogger("ideviewer.drift")

DEFAULT_PROPAGATION_THRESHOLD = 3


def _propagation_threshold() -> int:
    try:
        return int(os.environ.get("FLEET_PROPAGATION_THRESHOLD",
                                  DEFAULT_PROPAGATION_THRESHOLD))
    except (TypeError, ValueError):
        return DEFAULT_PROPAGATION_THRESHOLD


def detect_fleet_anomalies(customer_key_id=None, now=None) -> dict:
    """Recompute fleet prevalence and emit anomaly events. Returns a summary."""
    from flask import has_app_context

    if has_app_context():
        return _detect(customer_key_id, now)

    from app import create_app
    app = create_app(os.environ.get("FLASK_CONFIG", "production"))
    with app.app_context():
        return _detect(customer_key_id, now)


def _current_fleet(key):
    """Map extension_id -> (host_id_set, max_risk_level) from each host's latest scan."""
    from app.risk_rules import calculate_risk_level
    from app import threat_intel

    _RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    fleet = {}
    for host in key.hosts.filter_by(is_active=True):
        report = host.latest_report
        if not report or not report.scan_data:
            continue
        for ide in report.scan_data.get("ides", []) or []:
            for ext in ide.get("extensions") or []:
                ext_id = ext.get("id") or ext.get("extension_id")
                if not ext_id:
                    continue
                risk = calculate_risk_level(ext.get("permissions") or [])
                if threat_intel.evaluate_extension(ext_id, ext.get("publisher"), ext.get("name")):
                    risk = "critical"  # a threat match dominates
                hosts, cur = fleet.get(ext_id, (set(), "low"))
                hosts.add(host.id)
                if _RANK[risk] > _RANK[cur]:
                    cur = risk
                fleet[ext_id] = (hosts, cur)
    return fleet


def _detect(customer_key_id=None, now=None) -> dict:
    from app import db
    from app.models import CustomerKey, ExtensionPrevalence, TamperAlert
    from app.events import emit_event

    now = now or datetime.utcnow()
    threshold = _propagation_threshold()

    keys = ([CustomerKey.query.get(customer_key_id)] if customer_key_id
            else CustomerKey.query.all())
    new_risky = propagation = 0

    for key in keys:
        if key is None:
            continue
        # First sweep for a tenant establishes a baseline silently.
        is_baseline = ExtensionPrevalence.query.filter_by(customer_key_id=key.id).count() == 0
        fleet = _current_fleet(key)
        existing = {p.extension_id: p for p in
                    ExtensionPrevalence.query.filter_by(customer_key_id=key.id).all()}
        seen = set()

        for ext_id, (host_ids, max_risk) in fleet.items():
            seen.add(ext_id)
            count = len(host_ids)
            row = existing.get(ext_id)
            if row is None:
                row = ExtensionPrevalence(
                    customer_key_id=key.id, extension_id=ext_id,
                    host_count=count, prev_host_count=0, max_risk_level=max_risk,
                    first_seen_at=now, updated_at=now,
                )
                db.session.add(row)
                is_new = True
                prev = 0
            else:
                prev = row.host_count
                row.prev_host_count = prev
                row.host_count = count
                row.max_risk_level = max_risk
                row.updated_at = now
                is_new = False

            if is_baseline:
                continue

            rep_host_id = next(iter(host_ids), None)
            if is_new and max_risk in ("high", "critical"):
                new_risky += 1
                _raise(db, TamperAlert, emit_event, key, rep_host_id,
                       "anomaly.new_risky_extension", "high",
                       f"New {max_risk}-risk extension '{ext_id}' appeared in the fleet "
                       f"on {count} host(s).",
                       {"extension_id": ext_id, "host_count": count, "max_risk": max_risk})
            elif not is_new and (count - prev) >= threshold:
                propagation += 1
                _raise(db, TamperAlert, emit_event, key, rep_host_id,
                       "anomaly.rapid_propagation", "high",
                       f"Extension '{ext_id}' spread to {count - prev} new host(s) "
                       f"(now {count}, was {prev}) since the last sweep.",
                       {"extension_id": ext_id, "host_count": count,
                        "prev_host_count": prev, "max_risk": max_risk})

        # Extensions no longer present anywhere drop to zero (so a later
        # re-appearance is correctly treated as growth, not stale state).
        for ext_id, row in existing.items():
            if ext_id not in seen and row.host_count != 0:
                row.prev_host_count = row.host_count
                row.host_count = 0
                row.updated_at = now

        db.session.commit()

    if new_risky or propagation:
        logger.info("fleet drift sweep: %d new-risky, %d rapid-propagation",
                    new_risky, propagation)
    return {"new_risky": new_risky, "rapid_propagation": propagation}


def _raise(db, TamperAlert, emit_event, key, host_id, event_type, severity, details, extra):
    """Record a representative TamperAlert (for the bell) and fan out the event."""
    if host_id is not None:
        db.session.add(TamperAlert(
            host_id=host_id, alert_type=event_type, details=details, severity=severity))
        db.session.commit()
    data = {"severity": severity, "details": details, "customer_key": key.name}
    data.update(extra)
    emit_event(event_type, customer_key_id=key.id, data=data)
