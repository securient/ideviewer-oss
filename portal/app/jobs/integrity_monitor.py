"""Server-side integrity monitoring (Phase 1 B2).

The daemon already detects local tampering (file-hash checks) and reports it.
But a tampered or killed daemon stops reporting — silence is itself a signal the
endpoint cannot send. This sweep runs on the portal's vantage point: it flags
hosts whose heartbeats have stopped.

A host heartbeats every couple of minutes; if we haven't heard from it within
``HEARTBEAT_SILENCE_THRESHOLD_MINUTES`` (default 15) we mark it ``silent`` and
raise one ``host.silent`` TamperAlert. The alarm state on the Host row dedupes
the alert so a host that stays silent doesn't re-alert every sweep. When a
heartbeat returns, the heartbeat endpoint flips the state back to ``ok``.

Scheduled from ``run_scheduler.py`` (rq-scheduler) every 60s, but it is a plain
function operating on the DB so it is fully testable synchronously.
"""
import logging
import os
from datetime import datetime, timedelta

logger = logging.getLogger("ideviewer.integrity")

DEFAULT_SILENCE_THRESHOLD_MINUTES = 15

ALARM_OK = "ok"
ALARM_SILENT = "silent"


def _threshold_minutes() -> int:
    try:
        return int(os.environ.get("HEARTBEAT_SILENCE_THRESHOLD_MINUTES",
                                  DEFAULT_SILENCE_THRESHOLD_MINUTES))
    except (TypeError, ValueError):
        return DEFAULT_SILENCE_THRESHOLD_MINUTES


def _last_contact(host) -> datetime:
    """When did the daemon last actively report in?

    Heartbeats and real-time events update while the daemon runs, so they are
    the true liveness signals. ``last_seen_at``/``first_seen_at`` are set at
    enrollment and do not move on heartbeat, so we only fall back to them for a
    host that has *never* heartbeated (so a register-then-vanish host is still
    eventually flagged after the threshold).
    """
    active = [c for c in (host.last_heartbeat_at, host.last_realtime_event)
              if c is not None]
    if active:
        return max(active)
    return host.last_seen_at or host.first_seen_at


def sweep_host_integrity(now: datetime = None) -> dict:
    """Flag active hosts that have gone silent. Returns a small summary dict.

    Builds its own Flask app context when run as a worker job; reuses the
    current one when called from within a request/test.
    """
    from flask import has_app_context

    if has_app_context():
        return _sweep(now)

    from app import create_app
    app = create_app(os.environ.get("FLASK_CONFIG", "production"))
    with app.app_context():
        return _sweep(now)


def _sweep(now: datetime = None) -> dict:
    from app import db
    from app.models import Host, TamperAlert
    from app.events import emit_event

    now = now or datetime.utcnow()
    cutoff = now - timedelta(minutes=_threshold_minutes())

    newly_silent = 0
    hosts = Host.query.filter(Host.is_active.is_(True)).all()
    for host in hosts:
        if (host.heartbeat_alarm_state or ALARM_OK) == ALARM_SILENT:
            continue  # already alarmed; dedupe
        last = _last_contact(host)
        if last is None or last >= cutoff:
            continue  # never expected / still healthy

        host.heartbeat_alarm_state = ALARM_SILENT
        host.silent_since = now
        gap_min = int((now - last).total_seconds() // 60)
        alert = TamperAlert(
            host_id=host.id,
            alert_type="host.silent",
            details=(f"No heartbeat from {host.hostname} for ~{gap_min} minutes "
                     f"(last contact {last.isoformat()}Z). The daemon may have "
                     f"been stopped, uninstalled, or the host taken offline."),
            severity="high",
        )
        db.session.add(alert)
        db.session.commit()
        newly_silent += 1

        # Reuse the existing tamper-alert delivery path so this lights up
        # webhooks (Slack/PagerDuty) and the notifications bell with no new code.
        key = host.customer_key
        if key is not None:
            emit_event(
                "tamper_alert.created",
                customer_key_id=key.id,
                data={
                    "alert_id": alert.id,
                    "alert_type": alert.alert_type,
                    "severity": alert.severity,
                    "details": alert.details,
                    "host": {"id": host.public_id, "hostname": host.hostname},
                    "created_at": alert.created_at.isoformat() + "Z" if alert.created_at else None,
                },
            )

    if newly_silent:
        logger.info("integrity sweep flagged %d newly-silent host(s)", newly_silent)
    return {"checked": len(hosts), "newly_silent": newly_silent}


def clear_silent_state(host) -> bool:
    """Reset a recovered host's alarm state. Called from the heartbeat endpoint.

    Returns True if the host was previously silent (i.e. this is a recovery).
    """
    if (host.heartbeat_alarm_state or ALARM_OK) == ALARM_SILENT:
        host.heartbeat_alarm_state = ALARM_OK
        host.silent_since = None
        return True
    return False
