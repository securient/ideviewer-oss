"""SOAR remediation engine (Phase 1 B10).

Closes the detect->respond loop on top of primitives that already exist: the
enforcement command channel (B3), webhooks/events, and the audit log (B9). When
a trigger event fires, matching playbooks run — auto-quarantining the offending
extension or notifying — subject to three safety controls:

  * dry_run by default — a playbook simulates (logs/emits/audits) until an
    operator explicitly flips it to ``active``;
  * per-hour rate limit — bounds how many auto-quarantines a playbook can issue,
    so a bad trigger can't brick a fleet;
  * dedupe — never stacks a second quarantine on an extension already being
    quarantined.

Every decision (simulated, executed, rate-limited, deduped) is written to the
audit log, so automated actions are as attributable as manual ones.
"""
import logging
from datetime import datetime, timedelta

logger = logging.getLogger("ideviewer.soar")

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _meets_severity(severity, minimum) -> bool:
    return _SEVERITY_RANK.get((severity or "low").lower(), 0) >= \
        _SEVERITY_RANK.get((minimum or "high").lower(), 2)


def run_playbooks_for_event(event_type, customer_key_id, host, extension, severity) -> list:
    """Run any matching playbooks for one event. Returns a list of outcome dicts.

    ``extension`` is a dict with at least extension_id (and optionally name,
    version). Defensive: never raises into the caller (report ingestion).
    """
    try:
        return _run(event_type, customer_key_id, host, extension, severity)
    except Exception as e:  # automation must never break ingestion
        logger.exception("SOAR playbook run failed for %s: %s", event_type, e)
        try:
            from app import db
            db.session.rollback()
        except Exception:
            pass
        return []


def _open_quarantine_exists(host_id, extension_id):
    from app.models import EnforcementAction
    return EnforcementAction.query.filter(
        EnforcementAction.host_id == host_id,
        EnforcementAction.extension_id == extension_id,
        EnforcementAction.action == EnforcementAction.ACTION_QUARANTINE,
        EnforcementAction.status.in_([
            EnforcementAction.STATUS_PENDING,
            EnforcementAction.STATUS_DISPATCHED,
            EnforcementAction.STATUS_APPLIED,
        ]),
    ).first() is not None


def _recent_auto_quarantine_count(customer_key_id, since):
    """How many quarantines have been issued for this tenant's hosts recently."""
    from app.models import EnforcementAction, Host
    return (EnforcementAction.query.join(Host)
            .filter(Host.customer_key_id == customer_key_id,
                    EnforcementAction.action == EnforcementAction.ACTION_QUARANTINE,
                    EnforcementAction.created_at >= since)
            .count())


def _run(event_type, customer_key_id, host, extension, severity) -> list:
    from app import db
    from app.models import RemediationPlaybook, EnforcementAction
    from app.audit import record_audit
    from app.events import emit_event
    from app.policy.runner import emit_enforcement_created

    playbooks = RemediationPlaybook.query.filter_by(
        customer_key_id=customer_key_id, trigger_event=event_type, is_active=True).all()
    if not playbooks:
        return []

    ext_id = extension.get("extension_id") or extension.get("id")
    outcomes = []

    for pb in playbooks:
        if not _meets_severity(severity, pb.min_severity):
            continue

        base_detail = f'playbook "{pb.name}" on {ext_id} ({host.hostname})'

        if pb.action == RemediationPlaybook.ACTION_NOTIFY_ONLY:
            record_audit('soar.notify', target_type='host', target_id=host.public_id,
                         detail=f'SOAR notify — {base_detail}')
            emit_event('soar.notified', customer_key_id=customer_key_id,
                       data={'playbook': pb.name, 'host': {'id': host.public_id, 'hostname': host.hostname},
                             'extension': extension, 'severity': severity})
            outcomes.append({'playbook': pb.name, 'outcome': 'notified'})
            continue

        # auto_quarantine path
        if _open_quarantine_exists(host.id, ext_id):
            outcomes.append({'playbook': pb.name, 'outcome': 'deduped'})
            continue

        since = datetime.utcnow() - timedelta(hours=1)
        if _recent_auto_quarantine_count(customer_key_id, since) >= (pb.max_actions_per_hour or 5):
            record_audit('soar.rate_limited', target_type='host', target_id=host.public_id,
                         detail=f'SOAR rate limit hit — skipped {base_detail}')
            outcomes.append({'playbook': pb.name, 'outcome': 'rate_limited'})
            continue

        if pb.mode == RemediationPlaybook.MODE_DRY_RUN:
            record_audit('soar.dry_run', target_type='host', target_id=host.public_id,
                         detail=f'SOAR would auto-quarantine — {base_detail}')
            emit_event('soar.simulated', customer_key_id=customer_key_id,
                       data={'playbook': pb.name, 'action': 'auto_quarantine',
                             'host': {'id': host.public_id, 'hostname': host.hostname},
                             'extension': extension, 'severity': severity})
            outcomes.append({'playbook': pb.name, 'outcome': 'simulated'})
            continue

        action = EnforcementAction(
            host_id=host.id,
            action=EnforcementAction.ACTION_QUARANTINE,
            status=EnforcementAction.STATUS_PENDING,
            extension_id=ext_id,
            extension_name=extension.get("name"),
            extension_version=extension.get("version"),
            result_detail=f'auto-quarantine by SOAR playbook "{pb.name}"',
        )
        db.session.add(action)
        db.session.commit()
        record_audit('soar.auto_quarantine', target_type='host', target_id=host.public_id,
                     detail=f'SOAR auto-quarantined — {base_detail}')
        emit_enforcement_created(action, host, customer_key_id)
        outcomes.append({'playbook': pb.name, 'outcome': 'quarantined', 'action_id': action.id})

    return outcomes
