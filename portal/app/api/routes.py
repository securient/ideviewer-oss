"""
API routes for daemon communication.

All API endpoints require a valid customer key in the X-Customer-Key header.
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
import hashlib
import os
import socket
import threading
import traceback

import logging

from app import db
from app.models import CustomerKey, Host, ScanReport, ExtensionInfo, SecretFinding, PackageInfo, ScanRequest, TamperAlert, Vulnerability, HookBypass, AIToolInfo, EnforcementAction
from app.main.routes import calculate_risk_level
from app.events import emit_event
from app.signing import sign_envelope, public_key_info
from app import threat_intel
from app.risk_score import score_host
from app.policy.runner import evaluate_and_record, build_extensions_from_scan
from app.jobs.extension_enrich import enqueue_pending_enrichments
from app.queue import is_async, enqueue
from app.jobs.vuln_scan import scan_host_vulnerabilities

vuln_logger = logging.getLogger('ideviewer.vuln_scan')

api_bp = Blueprint('api', __name__)


@api_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for load balancers and container orchestration."""
    try:
        # Simple database connectivity check
        db.session.execute(db.text('SELECT 1'))
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 503


import logging
api_logger = logging.getLogger(__name__)


@api_bp.errorhandler(Exception)
def handle_api_error(error):
    """Handle all API errors and return JSON response."""
    api_logger.error(f"API Error on {request.method} {request.path}: {type(error).__name__}: {error}")
    
    # Only include detailed error info in debug mode
    if current_app.debug:
        traceback.print_exc()
        return jsonify({
            'error': str(error),
            'type': type(error).__name__
        }), 500
    else:
        # Generic error message in production
        return jsonify({
            'error': 'Internal server error',
            'type': 'ServerError'
        }), 500


@api_bp.before_request
def log_request():
    """Log incoming API requests for debugging (with sensitive data redacted)."""
    # Redact sensitive headers
    safe_headers = {}
    sensitive_headers = {'x-customer-key', 'x-host-token', 'authorization', 'x-api-key', 'cookie'}
    
    for key, value in request.headers:
        if key.lower() in sensitive_headers:
            # Show only first 8 and last 4 characters
            if len(value) > 12:
                safe_headers[key] = f"{value[:8]}...{value[-4:]}"
            else:
                safe_headers[key] = "[REDACTED]"
        else:
            safe_headers[key] = value
    
    api_logger.debug(f"API Request: {request.method} {request.path} Headers: {safe_headers}")


def get_customer_key():
    """Extract and validate customer key from request."""

    key_value = request.headers.get('X-Customer-Key')

    if not key_value:
        return None, {'error': 'Missing X-Customer-Key header'}, 401

    key = CustomerKey.query.filter_by(key=key_value, is_active=True).first()

    if not key:
        return None, {'error': 'Invalid or inactive customer key'}, 401

    return key, None, None


def authenticate_request():
    """Resolve the requester's CustomerKey (and Host if token-auth).

    Returns ``(key, host, err, status)``. ``host`` is None for
    customer-key auth (enrollment / legacy daemons) and an active Host
    when a valid X-Host-Token header was presented.

    Resolution order:
      1. If X-Host-Token is set, look up Host by sha256(token).
         - Not found, revoked, or inactive -> 401.
         - Valid -> return (host.customer_key, host, None, None).
      2. Else fall back to X-Customer-Key.
    """
    token = request.headers.get('X-Host-Token')
    if token:
        h = hashlib.sha256(token.encode('ascii')).hexdigest()
        host = Host.query.filter_by(token_hash=h, is_active=True).first()
        if host is None or host.token_revoked_at is not None:
            return None, None, {'error': 'Invalid or revoked host token'}, 401
        host.customer_key.last_used_at = datetime.utcnow()
        return host.customer_key, host, None, None
    key, err, status = get_customer_key()
    if err:
        return None, None, err, status
    return key, None, None, None


def _enforce_hostname_binding(host, body_hostname):
    """If token-auth, body hostname must match host.hostname.

    Returns an error tuple (response_dict, status) on mismatch, else None.
    """
    if host is None:
        return None
    if body_hostname and body_hostname != host.hostname:
        return {'error': 'Hostname does not match token binding'}, 403
    return None


def _reject_customer_key_if_enrolled(key, host_from_token, hostname):
    """Refuse customer-key data writes once a host has been enrolled.

    After enrollment a host holds a per-host token and the daemon uses it
    (X-Host-Token). The shared customer key is then only valid for
    enrollment / token rotation. This stops a holder of the org-wide
    customer key from impersonating or overwriting an already-enrolled
    host's data via the legacy customer-key path.

    Returns an error tuple (response_dict, status) to reject, else None.
    Enrollment (register-host) and rotation intentionally do NOT call this.
    """
    if host_from_token is not None:
        return None  # already token-authenticated — fine
    existing = Host.query.filter_by(hostname=hostname, customer_key_id=key.id).first()
    if existing is not None and existing.token_is_valid():
        return {'error': 'Host is enrolled; X-Host-Token required'}, 401
    return None


@api_bp.route('/validate-key', methods=['POST'])
def validate_key():
    """
    Validate a customer key.
    
    Used by the daemon during installation/first run.
    
    Request:
        Headers:
            X-Customer-Key: <uuid>
        Body (optional):
            {
                "hostname": "machine-name",
                "platform": "Darwin 23.0"
            }
    
    Response:
        {
            "valid": true,
            "key_name": "My Key",
            "current_hosts": 3
        }
    """

    key, error, status = get_customer_key()
    if error:
        return jsonify({'valid': False, **error}), status

    # Update last used
    key.last_used_at = datetime.utcnow()
    db.session.commit()

    _pub = public_key_info()
    return jsonify({
        'valid': True,
        'key_name': key.name,
        'current_hosts': key.host_count,
        'portal_url': request.host_url.rstrip('/'),
        'command_public_key': _pub['public_key_b64'],
        'command_key_id': _pub['key_id'],
    })


@api_bp.route('/register-host', methods=['POST'])
def register_host():
    """
    Register a new host with a customer key.
    
    Request:
        Headers:
            X-Customer-Key: <uuid>
        Body:
            {
                "hostname": "machine-name",
                "platform": "Darwin 23.0",
                "ip_address": "192.168.1.100"  // optional, auto-detected if not provided
            }
    
    Response:
        {
            "success": true,
            "host_id": "<public_id>",
            "host_token": "<base64url, ~43 chars>",
            "message": "Host registered successfully"
        }
    """

    key, host_from_token, error, status = authenticate_request()
    if error:
        return jsonify(error), status

    data = request.get_json() or {}

    hostname = data.get('hostname')
    if not hostname:
        return jsonify({'error': 'hostname is required'}), 400

    # Token auth pins this request to a specific host — refuse hostname spoof.
    err = _enforce_hostname_binding(host_from_token, hostname)
    if err:
        return jsonify(err[0]), err[1]

    platform = data.get('platform', 'Unknown')
    ip_address = data.get('ip_address') or request.remote_addr

    # If we already authenticated by token, prefer that host record.
    host = host_from_token
    if host is None:
        host = Host.query.filter_by(
            hostname=hostname,
            customer_key_id=key.id
        ).first()

    if host:
        # Update existing host
        host.ip_address = ip_address
        host.platform = platform
        host.last_seen_at = datetime.utcnow()
        host.is_active = True
        message = 'Host updated successfully'
    else:
        # Create new host
        host = Host(
            hostname=hostname,
            ip_address=ip_address,
            platform=platform,
            customer_key_id=key.id
        )
        db.session.add(host)
        message = 'Host registered successfully'

    # Issue (or rotate) the per-host enrollment token. Plaintext is returned
    # exactly once — the daemon persists it to its 0600 config file.
    plaintext = host.issue_token()

    key.last_used_at = datetime.utcnow()
    db.session.commit()

    _pub = public_key_info()
    return jsonify({
        'success': True,
        'host_id': host.public_id,
        'host_token': plaintext,
        'message': message,
        'command_public_key': _pub['public_key_b64'],
        'command_key_id': _pub['key_id'],
    })


@api_bp.route('/host-token/rotate', methods=['POST'])
def rotate_host_token():
    """Rotate the current host token.

    Authenticated by X-Host-Token only; the old hash is replaced atomically
    so the previous plaintext stops working as soon as this returns.
    """
    key, host, error, status = authenticate_request()
    if error:
        return jsonify(error), status
    if host is None:
        return jsonify({'error': 'Token authentication required'}), 401
    plaintext = host.issue_token()
    db.session.commit()
    return jsonify({'success': True, 'host_token': plaintext}), 200


def _index_extensions(scan_data):
    """Index a scan's extensions by (ide_name, extension_id) for diffing."""
    idx = {}
    if not scan_data:
        return idx
    for ide in scan_data.get('ides', []) or []:
        ide_name = ide.get('name', 'Unknown')
        ide_type = ide.get('ide_type')
        for ext in (ide.get('extensions') or []):
            ext_id = ext.get('id') or ext.get('extension_id')
            if not ext_id:
                continue
            idx[(ide_name, ext_id)] = {
                'extension_id': ext_id,
                'name': ext.get('name'),
                'version': ext.get('version'),
                'publisher': ext.get('publisher'),
                'ide': ide_name,
                'ide_type': ide_type,
            }
    return idx


def _emit_extension_changes(host, customer_key_id, prev_scan_data, new_scan_data):
    """Emit extension.installed / removed / updated by diffing two scans.

    Only fires when a previous scan exists, so a host's first report doesn't
    flood the feed with one 'installed' per existing extension.
    """
    if not prev_scan_data:
        return
    prev = _index_extensions(prev_scan_data)
    new = _index_extensions(new_scan_data)

    def host_blk():
        return {'id': host.public_id, 'hostname': host.hostname}

    for key, ext in new.items():
        if key not in prev:
            emit_event('extension.installed', customer_key_id=customer_key_id,
                       data={'host': host_blk(), 'extension': ext})
        elif ext.get('version') != prev[key].get('version'):
            ext_u = dict(ext)
            ext_u['previous_version'] = prev[key].get('version')
            emit_event('extension.updated', customer_key_id=customer_key_id,
                       data={'host': host_blk(), 'extension': ext_u})
    for key, ext in prev.items():
        if key not in new:
            emit_event('extension.removed', customer_key_id=customer_key_id,
                       data={'host': host_blk(), 'extension': ext})


@api_bp.route('/report', methods=['POST'])
def submit_report():
    """
    Submit a scan report from a host.
    
    Request:
        Headers:
            X-Customer-Key: <uuid>
        Body:
            {
                "hostname": "machine-name",
                "platform": "Darwin 23.0",
                "ip_address": "192.168.1.100",
                "scan_data": {
                    "timestamp": "2024-01-15T10:30:00",
                    "platform": "Darwin 23.0",
                    "ides": [...],
                    "total_ides": 3,
                    "total_extensions": 50
                }
            }
    
    Response:
        {
            "success": true,
            "report_id": 1,
            "message": "Report submitted successfully"
        }
    """
    
    key, host_from_token, error, status = authenticate_request()
    if error:
        return jsonify(error), status

    data = request.get_json()

    if not data:
        return jsonify({'error': 'Request body is required'}), 400

    hostname = data.get('hostname')
    if not hostname:
        return jsonify({'error': 'hostname is required'}), 400

    err = _enforce_hostname_binding(host_from_token, hostname)
    if err:
        return jsonify(err[0]), err[1]

    enroll_err = _reject_customer_key_if_enrolled(key, host_from_token, hostname)
    if enroll_err:
        return jsonify(enroll_err[0]), enroll_err[1]

    scan_data = data.get('scan_data')
    if not scan_data:
        return jsonify({'error': 'scan_data is required'}), 400

    platform = data.get('platform', 'Unknown')
    ip_address = data.get('ip_address') or request.remote_addr

    # Token-auth pins the request to a specific host record.
    host = host_from_token
    if host is None:
        host = Host.query.filter_by(
            hostname=hostname,
            customer_key_id=key.id
        ).first()

    if not host:
        host = Host(
            hostname=hostname,
            ip_address=ip_address,
            platform=platform,
            customer_key_id=key.id
        )
        db.session.add(host)
        db.session.flush()  # Get host.id
    else:
        host.ip_address = ip_address
        host.platform = platform
        host.last_seen_at = datetime.utcnow()
    
    # Calculate statistics
    total_ides = scan_data.get('total_ides', 0)
    total_extensions = scan_data.get('total_extensions', 0)
    
    # Count dangerous extensions
    dangerous_count = 0
    high_risk_extensions = []
    threat_matched_extensions = []  # B5: known-bad / typosquat matches
    for ide in scan_data.get('ides', []):
        for ext in (ide.get('extensions') or []):
            permissions = (ext.get('permissions') or [])
            risk = calculate_risk_level(permissions)
            ext_id = ext.get('id') or ext.get('extension_id')
            if risk in ['high', 'critical']:
                dangerous_count += 1
                high_risk_extensions.append({
                    'extension_id': ext_id,
                    'name': ext.get('name'),
                    'version': ext.get('version'),
                    'publisher': ext.get('publisher'),
                    'ide': ide.get('name'),
                    'risk_level': risk,
                    'permissions': permissions,
                })
            # B5: evaluate against the threat-intel feed.
            for m in threat_intel.evaluate_extension(ext_id, ext.get('publisher'), ext.get('name')):
                threat_matched_extensions.append({
                    'extension_id': ext_id,
                    'name': ext.get('name'),
                    'version': ext.get('version'),
                    'publisher': ext.get('publisher'),
                    'ide': ide.get('name'),
                    'indicator_type': m['indicator_type'],
                    'indicator': m['indicator'],
                    'detail': m['detail'],
                    'severity': m['severity'],
                })

    # Capture the previous scan's extensions for install/remove/update
    # diffing (before this report becomes the host's latest). Also collect
    # newly-detected secrets to emit proactive events after commit.
    _prev_report = host.latest_report
    prev_scan_data = _prev_report.scan_data if _prev_report else None
    new_secret_events = []

    # Create scan report
    report = ScanReport(
        host_id=host.id,
        scan_data=scan_data,
        total_ides=total_ides,
        total_extensions=total_extensions,
        dangerous_extensions=dangerous_count
    )
    db.session.add(report)
    db.session.flush()  # Get report.id for foreign keys
    
    # Process secrets findings
    secrets_data = scan_data.get('secrets', {})
    secrets_count = 0
    critical_secrets = 0

    # Track which secrets are still present in this scan
    reported_secret_keys = set()

    if secrets_data and secrets_data.get('findings'):
        for finding in secrets_data['findings']:
            file_path = finding.get('file_path', '')
            variable_name = finding.get('variable_name')
            reported_secret_keys.add((file_path, variable_name))

            # Check if this finding already exists (by file_path and variable_name)
            existing = SecretFinding.query.filter_by(
                host_id=host.id,
                file_path=file_path,
                variable_name=variable_name,
                is_resolved=False
            ).first()

            if existing:
                # Update last seen time
                existing.last_seen_at = datetime.utcnow()
                existing.scan_report_id = report.id
            else:
                # Create new finding
                secret = SecretFinding(
                    host_id=host.id,
                    scan_report_id=report.id,
                    file_path=file_path,
                    secret_type=finding.get('secret_type', 'unknown'),
                    variable_name=variable_name,
                    line_number=finding.get('line_number'),
                    severity=finding.get('severity', 'critical'),
                    description=finding.get('description', ''),
                    recommendation=finding.get('recommendation', ''),
                    redacted_value=finding.get('redacted_value', ''),
                    source=finding.get('source', 'filesystem'),
                    commit_hash=finding.get('commit_hash'),
                    commit_author=finding.get('commit_author'),
                    commit_date=finding.get('commit_date'),
                    repo_path=finding.get('repo_path'),
                )
                db.session.add(secret)
                new_secret_events.append({
                    'secret_type': finding.get('secret_type', 'unknown'),
                    'file_path': file_path,
                    'variable_name': variable_name,
                    'severity': finding.get('severity', 'critical'),
                    'source': finding.get('source', 'filesystem'),
                })

            secrets_count += 1
            if finding.get('severity') == 'critical':
                critical_secrets += 1

    # Mark secrets that were NOT in this scan as resolved
    unresolved_secrets = SecretFinding.query.filter_by(
        host_id=host.id,
        is_resolved=False
    ).all()

    for secret in unresolved_secrets:
        if (secret.file_path, secret.variable_name) not in reported_secret_keys:
            secret.is_resolved = True
            secret.resolved_at = datetime.utcnow()
    
    # Process dependency data — upsert to preserve first_seen_at
    deps_data = scan_data.get('dependencies', {})
    packages_count = 0

    if deps_data and deps_data.get('packages'):
        # Build a set of current package keys for this scan
        current_pkg_keys = set()

        for pkg in deps_data['packages']:
            source_type = pkg.get('source_type') or pkg.get('install_type', 'project')
            name = pkg.get('name', 'unknown')
            version = pkg.get('version', 'unknown')
            manager = pkg.get('package_manager', 'unknown')

            pkg_key = f"{manager}:{name}:{version}:{source_type}"
            current_pkg_keys.add(pkg_key)

            # Try to find existing package
            existing = PackageInfo.query.filter_by(
                host_id=host.id,
                name=name,
                version=version,
                package_manager=manager,
                source_type=source_type,
            ).first()

            if existing:
                # Update — preserve first_seen_at
                existing.scan_report_id = report.id
                existing.last_seen_at = datetime.utcnow()
                existing.install_type = pkg.get('install_type', 'project')
                existing.project_path = pkg.get('project_path')
                existing.lifecycle_hooks = pkg.get('lifecycle_hooks')
                existing.source_extension = pkg.get('source_extension')
            else:
                # Insert new
                package = PackageInfo(
                    host_id=host.id,
                    scan_report_id=report.id,
                    name=name,
                    version=version,
                    package_manager=manager,
                    install_type=pkg.get('install_type', 'project'),
                    project_path=pkg.get('project_path'),
                    lifecycle_hooks=pkg.get('lifecycle_hooks'),
                    source_type=source_type,
                    source_extension=pkg.get('source_extension'),
                )
                db.session.add(package)

            packages_count += 1

        # Remove packages no longer present in this scan
        all_host_packages = PackageInfo.query.filter_by(host_id=host.id).all()
        for existing_pkg in all_host_packages:
            existing_key = f"{existing_pkg.package_manager}:{existing_pkg.name}:{existing_pkg.version}:{existing_pkg.source_type}"
            if existing_key not in current_pkg_keys:
                db.session.delete(existing_pkg)

    # Process AI tools data — upsert to preserve first_seen_at
    ai_data = scan_data.get('ai_tools', {})
    ai_tools_count = 0

    if ai_data and ai_data.get('ai_tools'):
        current_tool_names = set()

        for tool in ai_data['ai_tools']:
            tool_name = tool.get('name', 'Unknown')
            current_tool_names.add(tool_name)

            existing = AIToolInfo.query.filter_by(
                host_id=host.id,
                tool_name=tool_name,
            ).first()

            if existing:
                existing.scan_report_id = report.id
                existing.version = tool.get('version')
                existing.is_running = tool.get('is_running', False)
                existing.config_path = tool.get('config_path')
                existing.mcp_servers = tool.get('components')
                existing.open_ports = tool.get('open_ports')
                existing.redacted_secrets = tool.get('secrets')
                existing.last_seen_at = datetime.utcnow()
            else:
                ai_tool = AIToolInfo(
                    host_id=host.id,
                    scan_report_id=report.id,
                    tool_name=tool_name,
                    version=tool.get('version'),
                    is_running=tool.get('is_running', False),
                    config_path=tool.get('config_path'),
                    mcp_servers=tool.get('components'),
                    open_ports=tool.get('open_ports'),
                    redacted_secrets=tool.get('secrets'),
                )
                db.session.add(ai_tool)

            ai_tools_count += 1

        # Remove tools no longer detected
        for existing_tool in AIToolInfo.query.filter_by(host_id=host.id).all():
            if existing_tool.tool_name not in current_tool_names:
                db.session.delete(existing_tool)

    # Update key last used
    key.last_used_at = datetime.utcnow()

    # Commit everything first so the daemon gets a fast response
    db.session.commit()

    # Run vulnerability enrichment without blocking the daemon's response.
    #   * Async path (Redis present): enqueue an RQ job.
    #   * No queue: run in a background thread bound to the current app so
    #     the OSV.dev network round-trip can't stall (or time out) report
    #     ingestion. Set INLINE_VULN_SCAN=0 to skip it entirely.
    host_id_for_vuln = host.id
    job_id = None
    if is_async():
        job = enqueue(scan_host_vulnerabilities, host_id_for_vuln)
        if job is not None:
            job_id = job.id
    elif os.environ.get('INLINE_VULN_SCAN', '1').lower() in ('1', 'true', 'yes'):
        if current_app.config.get('TESTING'):
            # Under tests run synchronously: the suite uses an in-memory
            # SQLite DB (per-connection) and tears it down right after the
            # request, so a background thread would race the teardown.
            try:
                scan_host_vulnerabilities(host_id_for_vuln)
            except Exception as e:
                vuln_logger.error("inline vuln scan failed: %s", e)
        else:
            app_obj = current_app._get_current_object()

            def _bg_vuln_scan(hid, app_ref):
                with app_ref.app_context():
                    try:
                        scan_host_vulnerabilities(hid)
                    except Exception as e:
                        vuln_logger.error("background vuln scan failed: %s", e)

            threading.Thread(
                target=_bg_vuln_scan,
                args=(host_id_for_vuln, app_obj),
                daemon=True,
            ).start()

    for ext_data in high_risk_extensions:
        emit_event(
            'extension.high_risk_detected',
            customer_key_id=key.id,
            data={
                'host': {'id': host.public_id, 'hostname': host.hostname},
                'extension': ext_data,
                'scan_report_id': report.id,
            },
        )

    evaluate_and_record(
        host,
        customer_key_id=key.id,
        extensions=build_extensions_from_scan(scan_data, calculate_risk_level),
    )

    enqueue_pending_enrichments(scan_data)

    # Proactive events: extension installs/removals/updates (diffed against the
    # previous scan) and any newly-detected secrets.
    _emit_extension_changes(host, key.id, prev_scan_data, scan_data)
    for s in new_secret_events:
        emit_event('secret.detected', customer_key_id=key.id,
                   data={'host': {'id': host.public_id, 'hostname': host.hostname}, 'secret': s})

    # B5: surface threat-intel matches (known-bad / typosquat extensions).
    for tm in threat_matched_extensions:
        emit_event('extension.threat_matched', customer_key_id=key.id,
                   data={'host': {'id': host.public_id, 'hostname': host.hostname},
                         'extension': tm})

    # B8: recompute and persist the composite host risk score from current state.
    try:
        scored = score_host(host)
        host.risk_score = scored['score']
        host.risk_level_composite = scored['level']
        db.session.commit()
    except Exception as e:  # never fail ingestion on a scoring hiccup
        db.session.rollback()
        vuln_logger.error("composite risk scoring failed for host %s: %s", host.id, e)

    response_payload = {
        'success': True,
        'report_id': report.id,
        'message': 'Report submitted successfully',
        'stats': {
            'total_ides': total_ides,
            'total_extensions': total_extensions,
            'dangerous_extensions': dangerous_count,
            'secrets_found': secrets_count,
            'critical_secrets': critical_secrets,
            'packages_found': packages_count,
            'ai_tools_found': ai_tools_count,
        },
    }
    if job_id:
        response_payload['job_id'] = job_id
    return jsonify(response_payload)


@api_bp.route('/hosts', methods=['GET'])
def list_hosts():
    """
    List all hosts for a customer key.
    
    Request:
        Headers:
            X-Customer-Key: <uuid>
    
    Response:
        {
            "hosts": [
                {
                    "id": 1,
                    "hostname": "machine-name",
                    "ip_address": "192.168.1.100",
                    "platform": "Darwin 23.0",
                    "last_seen": "2024-01-15T10:30:00",
                    "total_extensions": 50,
                    "dangerous_extensions": 3
                }
            ]
        }
    """
    
    key, error, status = get_customer_key()
    if error:
        return jsonify(error), status
    
    hosts = []
    for host in key.hosts.filter_by(is_active=True):
        latest = host.latest_report
        hosts.append({
            'id': host.public_id,
            'hostname': host.hostname,
            'ip_address': host.ip_address,
            'platform': host.platform,
            'first_seen': host.first_seen_at.isoformat() if host.first_seen_at else None,
            'last_seen': host.last_seen_at.isoformat() if host.last_seen_at else None,
            'total_extensions': latest.total_extensions if latest else 0,
            'dangerous_extensions': latest.dangerous_extensions if latest else 0,
        })
    
    return jsonify({'hosts': hosts})


@api_bp.route('/scan-requests/pending', methods=['GET'])
def get_pending_scan_requests():
    """
    Get pending scan requests for hosts belonging to this customer key.
    Called by the daemon to check for on-demand scan requests.

    Accepts X-Host-Token (post-enrollment daemons) or X-Customer-Key
    (legacy daemons). With token auth the result is scoped to just
    the authenticated host.
    """
    key, host_from_token, error, status = authenticate_request()
    if error:
        return jsonify(error), status

    q = ScanRequest.query.join(Host).filter(
        Host.customer_key_id == key.id,
        ScanRequest.status == 'pending'
    )
    if host_from_token is not None:
        q = q.filter(Host.id == host_from_token.id)
    pending = q.all()

    return jsonify({
        'requests': [r.to_dict() for r in pending]
    })


@api_bp.route('/scan-requests/<int:request_id>/update', methods=['POST'])
def update_scan_request(request_id):
    """
    Update the status/progress of an on-demand scan request.
    Called by the daemon to report progress.

    Accepts X-Host-Token (post-enrollment daemons) or X-Customer-Key
    (legacy daemons). With token auth the request_id must belong to
    the authenticated host.
    """
    key, host_from_token, error, status = authenticate_request()
    if error:
        return jsonify(error), status

    scan_req = ScanRequest.query.get_or_404(request_id)

    # Verify the scan request belongs to this key's host
    host = Host.query.get(scan_req.host_id)
    if not host or host.customer_key_id != key.id:
        return jsonify({'error': 'Access denied'}), 403

    # Token auth pins the request to one host -- refuse cross-host updates.
    if host_from_token is not None and host.id != host_from_token.id:
        return jsonify({'error': 'Scan request does not belong to this host'}), 403
    
    # If scan was cancelled by user, tell the daemon to stop
    if scan_req.status == 'cancelled':
        return jsonify({'success': False, 'cancelled': True, 'request': scan_req.to_dict()})

    data = request.get_json() or {}

    VALID_SCAN_STATUSES = {
        'pending', 'connecting', 'scanning_ides', 'scanning_secrets',
        'scanning_packages', 'completed', 'failed', 'timeout'
    }
    new_status = data.get('status')
    if new_status and new_status in VALID_SCAN_STATUSES:
        scan_req.status = new_status
        if new_status not in ('pending',) and not scan_req.started_at:
            scan_req.started_at = datetime.utcnow()
        if new_status in ('completed', 'failed', 'timeout'):
            scan_req.completed_at = datetime.utcnow()
    
    log_message = data.get('log_message')
    log_level = data.get('log_level', 'info')
    if log_message:
        scan_req.add_log(log_message, log_level)
    
    error_message = data.get('error_message')
    if error_message:
        scan_req.error_message = error_message
    
    db.session.commit()

    return jsonify({'success': True, 'request': scan_req.to_dict()})


@api_bp.route('/enforcement-actions/pending', methods=['GET'])
def get_pending_enforcement_actions():
    """Return pending enforcement actions for the authenticated host.

    Called by the daemon (token auth). Hand-out flips each action to
    ``dispatched`` so the same action is not executed on every poll; the
    daemon reports the final status via the report endpoint. With customer-key
    auth the result spans the key's hosts; with token auth it is scoped to
    the one host.
    """
    key, host_from_token, error, status = authenticate_request()
    if error:
        return jsonify(error), status

    q = EnforcementAction.query.join(Host).filter(
        Host.customer_key_id == key.id,
        EnforcementAction.status == EnforcementAction.STATUS_PENDING,
    )
    if host_from_token is not None:
        q = q.filter(Host.id == host_from_token.id)
    pending = q.all()

    now = datetime.utcnow()
    for a in pending:
        a.status = EnforcementAction.STATUS_DISPATCHED
        a.dispatched_at = now
    db.session.commit()

    # Sign the command envelope. A daemon executes an action only if this
    # signature verifies against its pinned key — this is what lets enforcement
    # run default-ON instead of behind the old kill-switch. The top-level
    # "actions" key is preserved inside the envelope for pre-signing daemons.
    body = {'actions': [a.to_dict() for a in pending]}
    return jsonify(sign_envelope(body))


@api_bp.route('/signing-key', methods=['GET'])
def get_signing_key():
    """Return the portal's command-signing public key for the daemon to pin.

    Token- or customer-key-authenticated. Daemons fetch this at enrollment (the
    key is also embedded in the register/validate responses) and can re-fetch it
    to pick up a rotated key.
    """
    key, host_from_token, error, status = authenticate_request()
    if error:
        return jsonify(error), status
    return jsonify(public_key_info())


@api_bp.route('/enforcement-actions/<int:action_id>/report', methods=['POST'])
def report_enforcement_action(action_id):
    """Daemon reports the outcome of an enforcement action.

    Body: {status: applied|failed|reverted, result_detail, quarantine_path,
    original_path}. Token auth pins the action to the authenticated host.
    """
    key, host_from_token, error, status = authenticate_request()
    if error:
        return jsonify(error), status

    action = EnforcementAction.query.get_or_404(action_id)

    host = Host.query.get(action.host_id)
    if not host or host.customer_key_id != key.id:
        return jsonify({'error': 'Access denied'}), 403
    if host_from_token is not None and host.id != host_from_token.id:
        return jsonify({'error': 'Action does not belong to this host'}), 403

    data = request.get_json() or {}
    new_status = data.get('status')
    valid = {
        EnforcementAction.STATUS_APPLIED,
        EnforcementAction.STATUS_FAILED,
        EnforcementAction.STATUS_REVERTED,
    }
    if new_status not in valid:
        return jsonify({'error': 'invalid status'}), 400

    action.status = new_status
    if data.get('result_detail'):
        action.result_detail = str(data['result_detail'])[:2000]
    if data.get('quarantine_path'):
        action.quarantine_path = str(data['quarantine_path'])[:1000]
    if data.get('original_path'):
        action.original_path = str(data['original_path'])[:1000]
    action.completed_at = datetime.utcnow()
    key.last_used_at = datetime.utcnow()
    db.session.commit()

    emit_event(
        'enforcement.completed',
        customer_key_id=key.id,
        data={
            'action_id': action.id,
            'action': action.action,
            'status': action.status,
            'result_detail': action.result_detail,
            'host': {'id': host.public_id, 'hostname': host.hostname},
            'extension': {
                'extension_id': action.extension_id,
                'name': action.extension_name,
                'version': action.extension_version,
                'ide_type': action.ide_type,
            },
            'completed_at': action.completed_at.isoformat() + 'Z' if action.completed_at else None,
        },
    )

    return jsonify({'success': True, 'action': action.to_dict()})


@api_bp.route('/heartbeat', methods=['POST'])
def heartbeat():
    """
    Receive heartbeat from daemon to confirm it's alive.
    Updates the host's last_heartbeat_at timestamp.
    """
    key, host_from_token, error, status = authenticate_request()
    if error:
        return jsonify(error), status

    data = request.get_json() or {}
    hostname = data.get('hostname')

    if not hostname:
        return jsonify({'error': 'hostname is required'}), 400

    err = _enforce_hostname_binding(host_from_token, hostname)
    if err:
        return jsonify(err[0]), err[1]

    enroll_err = _reject_customer_key_if_enrolled(key, host_from_token, hostname)
    if enroll_err:
        return jsonify(enroll_err[0]), enroll_err[1]

    host = host_from_token
    if host is None:
        host = Host.query.filter_by(
            hostname=hostname,
            customer_key_id=key.id
        ).first()

    if host:
        host.last_heartbeat_at = datetime.utcnow()
        host.daemon_version = data.get('daemon_version')
        key.last_used_at = datetime.utcnow()
        # A heartbeat clears any server-side "silent" alarm for this host (B2).
        from app.jobs.integrity_monitor import clear_silent_state
        clear_silent_state(host)
        db.session.commit()

    return jsonify({
        'acknowledged': True,
        'timestamp': datetime.utcnow().isoformat()
    })


@api_bp.route('/alert', methods=['POST'])
def receive_alert():
    """
    Receive tamper/integrity alert from daemon.
    Alert types: file_deleted, file_modified, daemon_stopping, uninstall_attempt
    """
    key, host_from_token, error, status = authenticate_request()
    if error:
        return jsonify(error), status

    data = request.get_json() or {}
    hostname = data.get('hostname')
    alert_type = data.get('alert_type')
    details = data.get('details', '')

    if not hostname or not alert_type:
        return jsonify({'error': 'hostname and alert_type are required'}), 400

    err = _enforce_hostname_binding(host_from_token, hostname)
    if err:
        return jsonify(err[0]), err[1]

    enroll_err = _reject_customer_key_if_enrolled(key, host_from_token, hostname)
    if enroll_err:
        return jsonify(enroll_err[0]), enroll_err[1]

    host = host_from_token
    if host is None:
        host = Host.query.filter_by(
            hostname=hostname,
            customer_key_id=key.id
        ).first()

    if not host:
        return jsonify({'error': 'Host not found'}), 404

    # Determine severity based on alert type
    severity_map = {
        'daemon_stopping': 'high',
        'file_deleted': 'critical',
        'file_modified': 'critical',
        'uninstall_attempt': 'critical',
    }
    
    alert = TamperAlert(
        host_id=host.id,
        alert_type=alert_type,
        details=details,
        severity=severity_map.get(alert_type, 'high'),
    )
    db.session.add(alert)
    db.session.commit()

    emit_event(
        'tamper_alert.created',
        customer_key_id=key.id,
        data={
            'alert_id': alert.id,
            'alert_type': alert.alert_type,
            'severity': alert.severity,
            'details': alert.details,
            'host': {
                'id': host.public_id,
                'hostname': host.hostname,
            },
            'created_at': alert.created_at.isoformat() + 'Z' if alert.created_at else None,
        },
    )

    return jsonify({
        'received': True,
        'alert_id': alert.id,
    })


@api_bp.route('/deregister-host', methods=['POST'])
def deregister_host():
    """
    Deregister a host during uninstallation.
    Marks the host as inactive.

    Request:
        Headers:
            X-Customer-Key: <uuid>
        Body:
            {
                "hostname": "machine-name",
                "reason": "uninstall"
            }

    Response:
        {
            "success": true,
            "message": "Host deregistered successfully"
        }
    """
    key, host_from_token, error, status = authenticate_request()
    if error:
        return jsonify(error), status

    data = request.get_json() or {}
    hostname = data.get('hostname')

    if not hostname:
        return jsonify({'error': 'hostname is required'}), 400

    err = _enforce_hostname_binding(host_from_token, hostname)
    if err:
        return jsonify(err[0]), err[1]

    enroll_err = _reject_customer_key_if_enrolled(key, host_from_token, hostname)
    if enroll_err:
        return jsonify(enroll_err[0]), enroll_err[1]

    host = host_from_token
    if host is None:
        host = Host.query.filter_by(
            hostname=hostname,
            customer_key_id=key.id
        ).first()

    if not host:
        return jsonify({'error': 'Host not found'}), 404

    # Mark host as inactive rather than deleting — preserves audit trail
    host.is_active = False
    host.last_seen_at = datetime.utcnow()

    # Log a tamper alert for the deregistration
    reason = data.get('reason', 'uninstall')
    alert = TamperAlert(
        host_id=host.id,
        alert_type='host_deregistered',
        details=f'Host deregistered via API. Reason: {reason}',
        severity='high',
    )
    db.session.add(alert)
    db.session.commit()

    emit_event(
        'tamper_alert.created',
        customer_key_id=key.id,
        data={
            'alert_id': alert.id,
            'alert_type': alert.alert_type,
            'severity': alert.severity,
            'details': alert.details,
            'host': {
                'id': host.public_id,
                'hostname': host.hostname,
            },
            'created_at': alert.created_at.isoformat() + 'Z' if alert.created_at else None,
        },
    )

    return jsonify({
        'success': True,
        'message': 'Host deregistered successfully'
    })


@api_bp.route('/realtime-event', methods=['POST'])
def receive_realtime_event():
    """
    Receive a real-time filesystem change event from the daemon.
    Triggered when IDE extension directories change (install/uninstall/update).
    """
    key, host_from_token, error, status = authenticate_request()
    if error:
        return jsonify(error), status

    data = request.get_json() or {}
    hostname = data.get('hostname')

    if not hostname:
        return jsonify({'error': 'hostname is required'}), 400

    err = _enforce_hostname_binding(host_from_token, hostname)
    if err:
        return jsonify(err[0]), err[1]

    enroll_err = _reject_customer_key_if_enrolled(key, host_from_token, hostname)
    if enroll_err:
        return jsonify(enroll_err[0]), enroll_err[1]

    host = host_from_token
    if host is None:
        host = Host.query.filter_by(
            hostname=hostname,
            customer_key_id=key.id
        ).first()

    if not host:
        return jsonify({'error': 'Host not found'}), 404

    # Update the host's last realtime event timestamp
    host.last_realtime_event = datetime.utcnow()
    host.last_seen_at = datetime.utcnow()

    # Process scan data if included (extension changes trigger a rescan)
    scan_data = data.get('scan_data')
    high_risk_extensions = []
    if scan_data:
        # Update extension info from the rescan
        total_ides = scan_data.get('total_ides', 0)
        total_extensions = scan_data.get('total_extensions', 0)

        dangerous_count = 0
        for ide in scan_data.get('ides', []):
            for ext in (ide.get('extensions') or []):
                permissions = (ext.get('permissions') or [])
                risk = calculate_risk_level(permissions)
                if risk in ['high', 'critical']:
                    dangerous_count += 1
                    high_risk_extensions.append({
                        'extension_id': ext.get('id') or ext.get('extension_id'),
                        'name': ext.get('name'),
                        'version': ext.get('version'),
                        'publisher': ext.get('publisher'),
                        'ide': ide.get('name'),
                        'risk_level': risk,
                        'permissions': permissions,
                    })

        # Create a lightweight scan report
        report = ScanReport(
            host_id=host.id,
            scan_data=scan_data,
            total_ides=total_ides,
            total_extensions=total_extensions,
            dangerous_extensions=dangerous_count
        )
        db.session.add(report)

    # Process dependency data if included — upsert to preserve first_seen_at
    deps_data = data.get('dependencies', {})
    if deps_data and deps_data.get('packages'):
        fallback_report_id = report.id if scan_data else (host.scan_reports.first().id if host.scan_reports.first() else 1)
        current_pkg_keys = set()

        for pkg in deps_data['packages']:
            source_type = pkg.get('source_type') or pkg.get('install_type', 'project')
            name = pkg.get('name', 'unknown')
            version = pkg.get('version', 'unknown')
            manager = pkg.get('package_manager', 'unknown')

            pkg_key = f"{manager}:{name}:{version}:{source_type}"
            current_pkg_keys.add(pkg_key)

            existing = PackageInfo.query.filter_by(
                host_id=host.id,
                name=name,
                version=version,
                package_manager=manager,
                source_type=source_type,
            ).first()

            if existing:
                existing.scan_report_id = fallback_report_id
                existing.last_seen_at = datetime.utcnow()
                existing.install_type = pkg.get('install_type', 'project')
                existing.project_path = pkg.get('project_path')
                existing.lifecycle_hooks = pkg.get('lifecycle_hooks')
                existing.source_extension = pkg.get('source_extension')
            else:
                package = PackageInfo(
                    host_id=host.id,
                    scan_report_id=fallback_report_id,
                    name=name,
                    version=version,
                    package_manager=manager,
                    install_type=pkg.get('install_type', 'project'),
                    project_path=pkg.get('project_path'),
                    lifecycle_hooks=pkg.get('lifecycle_hooks'),
                    source_type=source_type,
                    source_extension=pkg.get('source_extension'),
                )
                db.session.add(package)

        # Remove packages no longer present
        for existing_pkg in PackageInfo.query.filter_by(host_id=host.id).all():
            pkg_key = f"{existing_pkg.package_manager}:{existing_pkg.name}:{existing_pkg.version}:{existing_pkg.source_type}"
            if pkg_key not in current_pkg_keys:
                db.session.delete(existing_pkg)

    key.last_used_at = datetime.utcnow()
    db.session.commit()

    for ext_data in high_risk_extensions:
        emit_event(
            'extension.high_risk_detected',
            customer_key_id=key.id,
            data={
                'host': {'id': host.public_id, 'hostname': host.hostname},
                'extension': ext_data,
                'source': 'realtime_event',
            },
        )

    if scan_data:
        evaluate_and_record(
            host,
            customer_key_id=key.id,
            extensions=build_extensions_from_scan(scan_data, calculate_risk_level),
        )
        enqueue_pending_enrichments(scan_data)

    # Log the event
    changes = data.get('changes', [])
    api_logger.info(f"Realtime event from {hostname}: {len(changes)} change(s)")

    return jsonify({
        'received': True,
        'changes_processed': len(changes),
        'timestamp': datetime.utcnow().isoformat()
    })


@api_bp.route('/hook-bypass', methods=['POST'])
def receive_hook_bypass():
    """
    Receive a hook bypass event from the daemon.
    This is triggered when a developer uses --no-verify to skip the pre-commit hook.
    """
    key, host_from_token, error, status = authenticate_request()
    if error:
        return jsonify(error), status

    data = request.get_json() or {}
    hostname = data.get('hostname')

    if not hostname:
        return jsonify({'error': 'hostname is required'}), 400

    err = _enforce_hostname_binding(host_from_token, hostname)
    if err:
        return jsonify(err[0]), err[1]

    enroll_err = _reject_customer_key_if_enrolled(key, host_from_token, hostname)
    if enroll_err:
        return jsonify(enroll_err[0]), enroll_err[1]

    host = host_from_token
    if host is None:
        host = Host.query.filter_by(
            hostname=hostname,
            customer_key_id=key.id
        ).first()

    if not host:
        return jsonify({'error': 'Host not found'}), 404

    bypass = HookBypass(
        host_id=host.id,
        commit_hash=data.get('commit_hash', '')[:40],
        commit_message=data.get('commit_message', '')[:500],
        commit_author=data.get('commit_author', '')[:200],
        repo_path=data.get('repo_path', '')[:500],
    )
    db.session.add(bypass)
    db.session.commit()

    emit_event(
        'hook_bypass.detected',
        customer_key_id=key.id,
        data={
            'bypass_id': bypass.id,
            'commit_hash': bypass.commit_hash,
            'commit_message': bypass.commit_message,
            'commit_author': bypass.commit_author,
            'repo_path': bypass.repo_path,
            'host': {
                'id': host.public_id,
                'hostname': host.hostname,
            },
            'detected_at': bypass.detected_at.isoformat() + 'Z' if bypass.detected_at else None,
        },
    )

    return jsonify({
        'received': True,
        'bypass_id': bypass.id,
    })
