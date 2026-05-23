"""
API routes for daemon communication.

All API endpoints require a valid customer key in the X-Customer-Key header.
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
import hashlib
import socket
import traceback

import logging

from app import db
from app.models import CustomerKey, Host, ScanReport, ExtensionInfo, SecretFinding, PackageInfo, ScanRequest, TamperAlert, Vulnerability, HookBypass, AIToolInfo
from app.main.routes import calculate_risk_level
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

    return jsonify({
        'valid': True,
        'key_name': key.name,
        'current_hosts': key.host_count,
        'portal_url': request.host_url.rstrip('/'),
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

    return jsonify({
        'success': True,
        'host_id': host.public_id,
        'host_token': plaintext,
        'message': message,
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
    for ide in scan_data.get('ides', []):
        for ext in (ide.get('extensions') or []):
            permissions = (ext.get('permissions') or [])
            risk = calculate_risk_level(permissions)
            if risk in ['high', 'critical']:
                dangerous_count += 1
    
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

    # Run vulnerability enrichment. Async path uses RQ; sync fallback runs
    # inline so first-run UX is preserved when Redis is unavailable.
    host_id_for_vuln = host.id
    job_id = None
    if is_async():
        job = enqueue(scan_host_vulnerabilities, host_id_for_vuln)
        if job is not None:
            job_id = job.id
    else:
        try:
            scan_host_vulnerabilities(host_id_for_vuln)
        except Exception as e:
            current_app.logger.error("inline vuln scan failed: %s", e)

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

    return jsonify({
        'received': True,
        'bypass_id': bypass.id,
    })
