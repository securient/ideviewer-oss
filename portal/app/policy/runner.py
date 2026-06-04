"""Apply policies to a scan and persist the consequences.

Called from /api/report and /api/realtime-event after the scan data has
been committed. Loads the customer's active policies, runs the pure
evaluator, then for each warn/block-alert match: upserts a
PolicyViolation row, raises a critical TamperAlert (block-alert only),
and emits a policy.violation webhook event.

Allow matches are intentionally not persisted — the audit trail for
explicit whitelists lives in the policy table itself, not the violation
table.
"""
from datetime import datetime
from typing import Iterable, List

from app import db
from app.events import emit_event
from app.models import ExtensionPolicy, PolicyViolation, TamperAlert
from app.observability import POLICY_VIOLATIONS
from app.policy import evaluate


def evaluate_and_record(
    host,
    customer_key_id: int,
    extensions: Iterable[dict],
) -> List[int]:
    """Run policy evaluation for ``host`` and persist warn/block matches.

    Returns the list of PolicyViolation IDs that were inserted or
    refreshed. Safe to call from request handlers; never raises on
    individual extension issues.
    """
    extensions_list = list(extensions)
    if not extensions_list:
        return []

    policies = (
        ExtensionPolicy.query
        .filter_by(customer_key_id=customer_key_id, is_active=True)
        .all()
    )
    if not policies:
        return []

    matches = evaluate(extensions_list, policies)
    violation_ids: List[int] = []
    now = datetime.utcnow()

    for match in matches:
        if match.action == ExtensionPolicy.ACTION_ALLOW:
            continue  # explicit whitelist, no audit row

        existing = (
            PolicyViolation.query
            .filter_by(
                host_id=host.id,
                policy_id=match.policy.id,
                extension_id=(match.extension.get('extension_id') or match.extension.get('id') or ''),
                extension_version=match.extension.get('version'),
            )
            .first()
        )
        if existing:
            existing.last_seen_at = now
            existing.is_resolved = False
            existing.resolved_at = None
            existing.action_taken = match.action
            violation = existing
        else:
            violation = PolicyViolation(
                host_id=host.id,
                policy_id=match.policy.id,
                extension_id=(match.extension.get('extension_id') or match.extension.get('id') or ''),
                extension_name=match.extension.get('name'),
                extension_version=match.extension.get('version'),
                publisher=match.extension.get('publisher'),
                risk_level=match.extension.get('risk_level'),
                action_taken=match.action,
            )
            db.session.add(violation)
            db.session.flush()

        violation_ids.append(violation.id)
        POLICY_VIOLATIONS.labels(action=match.action).inc()

        if match.action == ExtensionPolicy.ACTION_BLOCK_ALERT:
            alert = TamperAlert(
                host_id=host.id,
                alert_type='policy_violation',
                details=(
                    f'Policy "{match.policy.name}" blocked extension '
                    f'{violation.extension_id}@{violation.extension_version or "?"}'
                ),
                severity='critical',
            )
            db.session.add(alert)

    db.session.commit()

    for vid in violation_ids:
        v = PolicyViolation.query.get(vid)
        if not v:
            continue
        emit_event(
            'policy.violation',
            customer_key_id=customer_key_id,
            data={
                'violation_id': v.id,
                'policy': {
                    'id': v.policy.public_id,
                    'name': v.policy.name,
                    'action': v.action_taken,
                },
                'host': {'id': host.public_id, 'hostname': host.hostname},
                'extension': {
                    'extension_id': v.extension_id,
                    'name': v.extension_name,
                    'version': v.extension_version,
                    'publisher': v.publisher,
                    'risk_level': v.risk_level,
                },
                'first_detected_at': v.first_detected_at.isoformat() + 'Z' if v.first_detected_at else None,
            },
        )

    return violation_ids


def build_extensions_from_scan(scan_data: dict, risk_calculator) -> List[dict]:
    """Flatten a scan_data ides[].extensions[] into the policy evaluator's
    extension-dict shape, computing risk_level via the supplied
    ``risk_calculator(permissions)`` callable.
    """
    out: List[dict] = []
    for ide in scan_data.get('ides', []) or []:
        for ext in (ide.get('extensions') or []):
            permissions = ext.get('permissions') or []
            out.append({
                'extension_id': ext.get('id') or ext.get('extension_id'),
                'name': ext.get('name'),
                'version': ext.get('version'),
                'publisher': ext.get('publisher'),
                'permissions': permissions,
                'risk_level': risk_calculator(permissions),
                'ide': ide.get('name'),
            })
    return out
