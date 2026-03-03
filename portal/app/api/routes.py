"""
API routes for daemon communication.

All API endpoints require a valid customer key in the X-Customer-Key header.
"""

from flask import Blueprint, request, jsonify
from datetime import datetime
import socket
import traceback

from app import db
from app.models import CustomerKey, Host, ScanReport, ExtensionInfo, SecretFinding, PackageInfo, ScanRequest, TamperAlert
from app.main.routes import calculate_risk_level

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
    from flask import current_app
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
    
    # Check host limit
    if key.host_count >= key.max_hosts:
        # Check if this host already exists
        existing = Host.query.filter_by(
            hostname=hostname,
            customer_key_id=key.id
        ).first()
        
        if not existing:
            return jsonify({
                'error': f'Host limit reached ({key.max_hosts}). Upgrade your plan or remove existing hosts.'
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
        # Check host limit
        if key.host_count >= key.max_hosts:
            return jsonify({
                'error': f'Host limit reached ({key.max_hosts})'
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
        for ext in ide.get('extensions', []):
            permissions = ext.get('permissions', [])
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
    
    if secrets_data and secrets_data.get('findings'):
        for finding in secrets_data['findings']:
            # Check if this finding already exists (by file_path and variable_name)
            existing = SecretFinding.query.filter_by(
                host_id=host.id,
                file_path=finding.get('file_path', ''),
                variable_name=finding.get('variable_name'),
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
                    file_path=finding.get('file_path', ''),
                    secret_type=finding.get('secret_type', 'unknown'),
                    variable_name=finding.get('variable_name'),
                    line_number=finding.get('line_number'),
                    severity=finding.get('severity', 'critical'),
                    description=finding.get('description', ''),
                    recommendation=finding.get('recommendation', ''),
                )
                db.session.add(secret)
            
            secrets_count += 1
            if finding.get('severity') == 'critical':
                critical_secrets += 1
    
    # Process dependency data
    deps_data = scan_data.get('dependencies', {})
    packages_count = 0
    
    if deps_data and deps_data.get('packages'):
        # Clear old package info for this host to get fresh data
        PackageInfo.query.filter_by(host_id=host.id).delete()
        
        for pkg in deps_data['packages']:
            package = PackageInfo(
                host_id=host.id,
                scan_report_id=report.id,
                name=pkg.get('name', 'unknown'),
                version=pkg.get('version', 'unknown'),
                package_manager=pkg.get('package_manager', 'unknown'),
                install_type=pkg.get('install_type', 'project'),
                project_path=pkg.get('project_path'),
                lifecycle_hooks=pkg.get('lifecycle_hooks'),
            )
            db.session.add(package)
            packages_count += 1
    
    # Update key last used
    key.last_used_at = datetime.utcnow()
    
    db.session.commit()
    
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
        }
    })


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
