"""
API routes for daemon communication.

All API endpoints require a valid customer key in the X-Customer-Key header.
"""

from flask import Blueprint, request, jsonify, current_app
from datetime import datetime
import socket
import traceback

import logging

from app import db
from app.models import CustomerKey, Host, ScanReport, ExtensionInfo, SecretFinding, PackageInfo, ScanRequest, TamperAlert, Vulnerability, HookBypass, AIToolInfo
from app.main.routes import calculate_risk_level

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
    sensitive_headers = {'x-customer-key', 'authorization', 'x-api-key', 'cookie'}
    
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
            "max_hosts": 10,
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
        'max_hosts': key.max_hosts,
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
            "host_id": 1,
            "message": "Host registered successfully"
        }
    """
    
    key, error, status = get_customer_key()
    if error:
        return jsonify(error), status
    
    data = request.get_json() or {}
    
    hostname = data.get('hostname')
    if not hostname:
        return jsonify({'error': 'hostname is required'}), 400
    
    platform = data.get('platform', 'Unknown')
    ip_address = data.get('ip_address') or request.remote_addr
    
    # Check host limit (0 = unlimited)
    if key.max_hosts > 0 and key.host_count >= key.max_hosts:
        # Check if this host already exists
        existing = Host.query.filter_by(
            hostname=hostname,
            customer_key_id=key.id
        ).first()

        if not existing:
            return jsonify({
                'error': f'Host limit reached ({key.max_hosts}). Increase FREE_TIER_HOST_LIMIT in your portal configuration or set to 0 for unlimited.'
            }), 403

    # Find or create host
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
    
    key.last_used_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({
        'success': True,
        'host_id': host.public_id,
        'message': message
    })


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
    
    key, error, status = get_customer_key()
    if error:
        return jsonify(error), status
    
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Request body is required'}), 400
    
    hostname = data.get('hostname')
    if not hostname:
        return jsonify({'error': 'hostname is required'}), 400
    
    scan_data = data.get('scan_data')
    if not scan_data:
        return jsonify({'error': 'scan_data is required'}), 400
    
    platform = data.get('platform', 'Unknown')
    ip_address = data.get('ip_address') or request.remote_addr
    
    # Find or create host
    host = Host.query.filter_by(
        hostname=hostname,
        customer_key_id=key.id
    ).first()
    
    if not host:
        # Check host limit (0 = unlimited)
        if key.max_hosts > 0 and key.host_count >= key.max_hosts:
            return jsonify({
                'error': f'Host limit reached ({key.max_hosts}). Increase FREE_TIER_HOST_LIMIT in your portal configuration or set to 0 for unlimited.'
            }), 403
        
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
            key = f"{existing_pkg.package_manager}:{existing_pkg.name}:{existing_pkg.version}:{existing_pkg.source_type}"
            if key not in current_pkg_keys:
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

    # Run vulnerability scan in a background thread so it doesn't block the API
    import threading
    host_id_for_vuln = host.id
    app = current_app._get_current_object()

    def _background_vuln_scan():
        with app.app_context():
            try:
                _scan_vulnerabilities(Host.query.get(host_id_for_vuln))
                db.session.commit()
                vuln_logger.info(f"Background vulnerability scan completed for host {host_id_for_vuln}")
            except Exception as e:
                db.session.rollback()
                vuln_logger.error(f"Background vulnerability scan failed: {e}")

    thread = threading.Thread(target=_background_vuln_scan, daemon=True)
    thread.start()

    return jsonify({
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
        }
    })


def _scan_vulnerabilities(host):
    """Scan a host's packages against OSV.dev and update the Vulnerability table."""
    from app.osv_client import query_packages_batch, get_ecosystem

    packages = PackageInfo.query.filter_by(host_id=host.id).all()
    if not packages:
        return 0

    # Build batch query — only packages with a supported ecosystem
    batch = []
    pkg_map = {}  # (name, version, ecosystem) -> PackageInfo
    for pkg in packages:
        ecosystem = get_ecosystem(pkg.package_manager)
        if not ecosystem:
            continue
        key = (pkg.name, pkg.version or '', ecosystem)
        if key not in pkg_map:
            batch.append({'name': pkg.name, 'version': pkg.version or '', 'ecosystem': ecosystem})
            pkg_map[key] = pkg

    if not batch:
        return 0

    vuln_logger.info(f"Querying OSV.dev for {len(batch)} packages on host {host.hostname}")

    results = query_packages_batch(batch)

    # Track which vulns we found in this scan
    found_vuln_keys = set()
    vuln_count = 0

    for (name, version, ecosystem), vulns in results.items():
        pkg = pkg_map.get((name, version, ecosystem))
        if not pkg:
            continue

        for v in vulns:
            vuln_id = v.get('vuln_id', '')
            if not vuln_id:
                continue

            found_vuln_keys.add((vuln_id, name, version, pkg.package_manager))

            # Check if this vulnerability already exists for this host
            existing = Vulnerability.query.filter_by(
                host_id=host.id,
                vuln_id=vuln_id,
                package_name=name,
                package_version=version,
            ).first()

            if existing:
                existing.last_seen_at = datetime.utcnow()
                existing.is_resolved = False
                existing.package_info_id = pkg.id
            else:
                vuln = Vulnerability(
                    host_id=host.id,
                    package_info_id=pkg.id,
                    package_name=name,
                    package_version=version,
                    package_manager=pkg.package_manager,
                    ecosystem=ecosystem,
                    vuln_id=vuln_id,
                    summary=v.get('summary', ''),
                    severity_label=v.get('severity_label', 'UNKNOWN'),
                    cvss_score=v.get('cvss_score'),
                    affected_versions=v.get('affected_versions', ''),
                    fixed_version=v.get('fixed_version'),
                    references=v.get('references', []),
                )
                db.session.add(vuln)
                vuln_count += 1

    # Mark vulns no longer present as resolved
    existing_vulns = Vulnerability.query.filter_by(
        host_id=host.id,
        is_resolved=False
    ).all()

    for ev in existing_vulns:
        key = (ev.vuln_id, ev.package_name, ev.package_version, ev.package_manager)
        if key not in found_vuln_keys:
            ev.is_resolved = True

    vuln_logger.info(f"Found {vuln_count} new vulnerabilities for host {host.hostname}")
    return vuln_count


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
    """
    key, error, status = get_customer_key()
    if error:
        return jsonify(error), status
    
    # Find pending requests for any hosts belonging to this key
    pending = ScanRequest.query.join(Host).filter(
        Host.customer_key_id == key.id,
        ScanRequest.status == 'pending'
    ).all()
    
    return jsonify({
        'requests': [r.to_dict() for r in pending]
    })


@api_bp.route('/scan-requests/<int:request_id>/update', methods=['POST'])
def update_scan_request(request_id):
    """
    Update the status/progress of an on-demand scan request.
    Called by the daemon to report progress.
    """
    key, error, status = get_customer_key()
    if error:
        return jsonify(error), status
    
    scan_req = ScanRequest.query.get_or_404(request_id)
    
    # Verify the scan request belongs to this key's host
    host = Host.query.get(scan_req.host_id)
    if not host or host.customer_key_id != key.id:
        return jsonify({'error': 'Access denied'}), 403
    
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
    key, error, status = get_customer_key()
    if error:
        return jsonify(error), status
    
    data = request.get_json() or {}
    hostname = data.get('hostname')
    
    if not hostname:
        return jsonify({'error': 'hostname is required'}), 400
    
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
    key, error, status = get_customer_key()
    if error:
        return jsonify(error), status
    
    data = request.get_json() or {}
    hostname = data.get('hostname')
    alert_type = data.get('alert_type')
    details = data.get('details', '')
    
    if not hostname or not alert_type:
        return jsonify({'error': 'hostname and alert_type are required'}), 400
    
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
    Marks the host as inactive so it no longer counts against host limits.

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
    key, error, status = get_customer_key()
    if error:
        return jsonify(error), status

    data = request.get_json() or {}
    hostname = data.get('hostname')

    if not hostname:
        return jsonify({'error': 'hostname is required'}), 400

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
    key, error, status = get_customer_key()
    if error:
        return jsonify(error), status

    data = request.get_json() or {}
    hostname = data.get('hostname')

    if not hostname:
        return jsonify({'error': 'hostname is required'}), 400

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
    key, error, status = get_customer_key()
    if error:
        return jsonify(error), status

    data = request.get_json() or {}
    hostname = data.get('hostname')

    if not hostname:
        return jsonify({'error': 'hostname is required'}), 400

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
