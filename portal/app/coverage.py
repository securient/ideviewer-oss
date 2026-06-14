"""Fleet coverage computation (Phase 1 B12).

Compares the authoritative roster (ExpectedHost) against hosts actually
reporting in, per customer key, so operators can see shadow IT (reporting but
not on the roster) and coverage gaps (on the roster but not reporting).

"Reporting" = an active host that has heartbeated within REPORTING_WINDOW_HOURS.
"""
import os
from datetime import datetime, timedelta

DEFAULT_REPORTING_WINDOW_HOURS = 24


def _window_hours() -> int:
    try:
        return int(os.environ.get("COVERAGE_REPORTING_WINDOW_HOURS",
                                  DEFAULT_REPORTING_WINDOW_HOURS))
    except (TypeError, ValueError):
        return DEFAULT_REPORTING_WINDOW_HOURS


def coverage_for_key(key, now=None) -> dict:
    """Coverage stats + gap lists for one customer key."""
    from app.models import Host, ExpectedHost

    now = now or datetime.utcnow()
    cutoff = now - timedelta(hours=_window_hours())

    expected = {e.hostname for e in
                ExpectedHost.query.filter_by(customer_key_id=key.id).all()}

    reporting = set()
    for h in key.hosts.filter_by(is_active=True):
        if h.last_heartbeat_at and h.last_heartbeat_at >= cutoff:
            reporting.add(h.hostname)

    covered = sorted(expected & reporting)
    missing = sorted(expected - reporting)      # on roster, not reporting
    unmanaged = sorted(reporting - expected)    # reporting, not on roster

    total_expected = len(expected)
    pct = int(round(100 * len(covered) / total_expected)) if total_expected else None

    return {
        "key_id": key.id,
        "key_name": key.name,
        "expected_count": total_expected,
        "reporting_count": len(reporting),
        "covered": covered,
        "missing": missing,
        "unmanaged": unmanaged,
        "coverage_pct": pct,
    }


def coverage_for_user(user, now=None) -> list:
    """Coverage stats for every customer key owned by the user."""
    return [coverage_for_key(k, now=now) for k in user.customer_keys]
