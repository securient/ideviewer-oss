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
from app.models import EnforcementAction, ExtensionPolicy, PolicyViolation, TamperAlert
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
    enforcement_action_ids: List[int] = []
    ide_by_vid: dict = {}  # violation id -> IDE info from the scan
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
        ide_by_vid[violation.id] = {
            'ide': match.extension.get('ide'),
            'ide_type': match.extension.get('ide_type'),
        }
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

        if match.action == ExtensionPolicy.ACTION_QUARANTINE:
            alert = TamperAlert(
                host_id=host.id,
                alert_type='policy_violation',
                details=(
                    f'Policy "{match.policy.name}" requested quarantine of extension '
                    f'{violation.extension_id}@{violation.extension_version or "?"}'
                ),
                severity='critical',
            )
            db.session.add(alert)
            aid = _ensure_quarantine_action(host, violation, match.extension)
            if aid is not None:
                enforcement_action_ids.append(aid)

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
                    'ide': (ide_by_vid.get(v.id) or {}).get('ide'),
                    'ide_type': (ide_by_vid.get(v.id) or {}).get('ide_type'),
                    'vulnerable_dependencies': _extension_dependency_risk(host.id, v.extension_id),
                },
                'first_detected_at': v.first_detected_at.isoformat() + 'Z' if v.first_detected_at else None,
            },
        )

    for aid in enforcement_action_ids:
        a = EnforcementAction.query.get(aid)
        if a is not None:
            emit_enforcement_created(a, host, customer_key_id)

    return violation_ids


def _extension_dependency_risk(host_id, extension_id) -> dict:
    """Summarise critical/high vulnerabilities in packages bundled by this
    extension (PackageInfo.source_extension == extension_id), correlated by the
    OSV vuln scan. Eventually-consistent: reflects the last completed vuln scan
    for the host (the current scan's vuln job may still be running).
    """
    result = {'critical': 0, 'high': 0, 'examples': []}
    if not extension_id:
        return result
    from app.models import Vulnerability, PackageInfo
    rows = (
        db.session.query(Vulnerability)
        .join(PackageInfo, Vulnerability.package_info_id == PackageInfo.id)
        .filter(
            Vulnerability.host_id == host_id,
            Vulnerability.is_resolved.is_(False),
            PackageInfo.source_extension == extension_id,
        )
        .all()
    )
    for v in rows:
        sev = (v.severity_label or '').lower()
        if sev == 'critical':
            result['critical'] += 1
        elif sev == 'high':
            result['high'] += 1
        if sev in ('critical', 'high') and len(result['examples']) < 5:
            result['examples'].append({
                'vuln_id': v.vuln_id,
                'package': f"{v.package_name}@{v.package_version}",
                'severity': sev,
            })
    return result


def _ensure_quarantine_action(host, violation, ext) -> int:
    """Create a pending quarantine EnforcementAction for this violation,
    unless one is already open (pending/dispatched/applied) for the same
    host + extension + version. Idempotent across rescans.

    Returns the new action id, or None if one already existed.
    """
    q = EnforcementAction.query.filter(
        EnforcementAction.host_id == host.id,
        EnforcementAction.extension_id == violation.extension_id,
        EnforcementAction.action == EnforcementAction.ACTION_QUARANTINE,
        EnforcementAction.status.in_(EnforcementAction.OPEN_STATUSES),
    )
    if violation.extension_version is None:
        q = q.filter(EnforcementAction.extension_version.is_(None))
    else:
        q = q.filter(EnforcementAction.extension_version == violation.extension_version)
    if q.first() is not None:
        return None

    action = EnforcementAction(
        host_id=host.id,
        violation_id=violation.id,
        action=EnforcementAction.ACTION_QUARANTINE,
        status=EnforcementAction.STATUS_PENDING,
        extension_id=violation.extension_id,
        extension_name=violation.extension_name,
        extension_version=violation.extension_version,
        ide_type=ext.get('ide_type'),
        created_by_user_id=None,  # policy-driven
    )
    db.session.add(action)
    db.session.flush()
    return action.id


def emit_enforcement_created(action, host, customer_key_id: int) -> None:
    """Emit the enforcement.action_created webhook event for one action."""
    emit_event(
        'enforcement.action_created',
        customer_key_id=customer_key_id,
        data={
            'action_id': action.id,
            'action': action.action,
            'status': action.status,
            'host': {'id': host.public_id, 'hostname': host.hostname},
            'extension': {
                'extension_id': action.extension_id,
                'name': action.extension_name,
                'version': action.extension_version,
                'ide_type': action.ide_type,
            },
            'created_at': action.created_at.isoformat() + 'Z' if action.created_at else None,
        },
    )


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
                'ide_type': ide.get('ide_type'),
            })
    return out
