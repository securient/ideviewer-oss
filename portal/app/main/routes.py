"""
Main application routes - Dashboard and Key Management.
"""

from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify, current_app
from flask_login import login_required, current_user
from datetime import datetime, timedelta
from sqlalchemy import or_

from app import db
from app.models import CustomerKey, Host, ScanReport, ExtensionInfo, SecretFinding, PackageInfo, ScanRequest, TamperAlert, Vulnerability, HookBypass, AIToolInfo
from app.auth.forms import CustomerKeyForm
from app.marketplace import fetch_extension_details

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    """Landing page."""
    if current_user.is_authenticated:
        return redirect(url_for('main.dashboard'))
    return redirect(url_for('auth.login'))


@main_bp.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard showing all hosts and their IDE data."""
    
    # Get all hosts for this user's keys
    customer_keys = current_user.customer_keys.filter_by(is_active=True).all()
    key_ids = [k.id for k in customer_keys]
    
    # Get hosts
    hosts = Host.query.filter(Host.customer_key_id.in_(key_ids)).order_by(Host.last_seen_at.desc()).all()
    host_ids = [h.id for h in hosts]
    
    # Calculate statistics
    total_hosts = len(hosts)
    active_hosts = sum(1 for h in hosts if h.last_seen_at and 
                       h.last_seen_at > datetime.utcnow() - timedelta(hours=24))
    
    # Get extension statistics
    total_extensions = 0
    dangerous_count = 0
    ide_counts = {}
    
    for host in hosts:
        latest = host.latest_report
        if latest:
            total_extensions += latest.total_extensions
            dangerous_count += latest.dangerous_extensions
            
            # Count IDEs
            if latest.scan_data and 'ides' in latest.scan_data:
                for ide in latest.scan_data['ides']:
                    ide_name = ide.get('name', 'Unknown')
                    ide_counts[ide_name] = ide_counts.get(ide_name, 0) + 1
    
    # Get secrets statistics
    total_secrets = SecretFinding.query.filter(
        SecretFinding.host_id.in_(host_ids),
        SecretFinding.is_resolved == False
    ).count() if host_ids else 0
    
    # Get package statistics
    total_packages = PackageInfo.query.filter(
        PackageInfo.host_id.in_(host_ids)
    ).count() if host_ids else 0
    
    # Get hosts with secrets for alert
    hosts_with_secrets = []
    if host_ids:
        for host in hosts:
            secret_count = SecretFinding.query.filter_by(
                host_id=host.id, is_resolved=False
            ).count()
            if secret_count > 0:
                hosts_with_secrets.append({
                    'host': host,
                    'count': secret_count
                })
    
    # Identify missing hosts (no heartbeat in 2x the expected interval, default 30 min)
    missing_hosts = []
    missing_threshold = datetime.utcnow() - timedelta(minutes=30)
    for host in hosts:
        heartbeat_time = host.last_heartbeat_at or host.last_seen_at
        if heartbeat_time and heartbeat_time < missing_threshold:
            minutes_ago = int((datetime.utcnow() - heartbeat_time).total_seconds() / 60)
            missing_hosts.append({
                'host': host,
                'last_contact': heartbeat_time,
                'minutes_ago': minutes_ago,
            })
    
    # Get unacknowledged tamper alerts
    tamper_alerts = []
    if host_ids:
        alerts = TamperAlert.query.filter(
            TamperAlert.host_id.in_(host_ids),
            TamperAlert.is_acknowledged == False
        ).order_by(TamperAlert.created_at.desc()).limit(20).all()
        
        host_map = {h.id: h for h in hosts}
        for alert in alerts:
            tamper_alerts.append({
                'alert': alert,
                'host': host_map.get(alert.host_id),
            })
    
    # Vulnerability statistics
    total_vulnerabilities = 0
    vulnerable_packages_count = 0
    vulnerable_hosts_count = 0
    critical_vuln_count = 0
    top_vulnerable_packages = []

    if host_ids:
        total_vulnerabilities = Vulnerability.query.filter(
            Vulnerability.host_id.in_(host_ids),
            Vulnerability.is_resolved == False
        ).count()

        # Count distinct vulnerable packages (name + version + manager)
        vulnerable_packages_sub = db.session.query(
            Vulnerability.package_name,
            Vulnerability.package_version,
            Vulnerability.package_manager
        ).filter(
            Vulnerability.host_id.in_(host_ids),
            Vulnerability.is_resolved == False
        ).group_by(
            Vulnerability.package_name,
            Vulnerability.package_version,
            Vulnerability.package_manager
        ).subquery()
        vulnerable_packages_count = db.session.query(
            db.func.count()
        ).select_from(vulnerable_packages_sub).scalar() or 0

        vulnerable_hosts_count = db.session.query(
            db.func.count(db.func.distinct(Vulnerability.host_id))
        ).filter(
            Vulnerability.host_id.in_(host_ids),
            Vulnerability.is_resolved == False
        ).scalar() or 0

        critical_vuln_count = Vulnerability.query.filter(
            Vulnerability.host_id.in_(host_ids),
            Vulnerability.is_resolved == False,
            Vulnerability.severity_label == 'CRITICAL'
        ).count()

        # Top 5 most common vulnerable packages across all hosts
        top_pkgs = db.session.query(
            Vulnerability.package_name,
            Vulnerability.package_version,
            Vulnerability.package_manager,
            Vulnerability.severity_label,
            db.func.count(db.func.distinct(Vulnerability.host_id)).label('host_count')
        ).filter(
            Vulnerability.host_id.in_(host_ids),
            Vulnerability.is_resolved == False
        ).group_by(
            Vulnerability.package_name,
            Vulnerability.package_version,
            Vulnerability.package_manager,
            Vulnerability.severity_label
        ).order_by(
            db.desc('host_count')
        ).limit(5).all()

        top_vulnerable_packages = [
            {
                'name': row.package_name,
                'version': row.package_version,
                'manager': row.package_manager,
                'severity': row.severity_label,
                'host_count': row.host_count,
            }
            for row in top_pkgs
        ]

    # Hook bypass statistics
    total_hook_bypasses = 0
    if host_ids:
        total_hook_bypasses = HookBypass.query.filter(
            HookBypass.host_id.in_(host_ids),
            HookBypass.is_acknowledged == False
        ).count()

    stats = {
        'total_hosts': total_hosts,
        'active_hosts': active_hosts,
        'total_extensions': total_extensions,
        'dangerous_extensions': dangerous_count,
        'ide_counts': ide_counts,
        'total_secrets': total_secrets,
        'total_packages': total_packages,
        'missing_hosts': len(missing_hosts),
        'tamper_alerts': len(tamper_alerts),
        'total_hook_bypasses': total_hook_bypasses,
    }

    return render_template('main/dashboard.html',
                           hosts=hosts,
                           stats=stats,
                           customer_keys=customer_keys,
                           hosts_with_secrets=hosts_with_secrets,
                           missing_hosts=missing_hosts,
                           tamper_alerts=tamper_alerts,
                           total_vulnerabilities=total_vulnerabilities,
                           vulnerable_packages_count=vulnerable_packages_count,
                           vulnerable_hosts_count=vulnerable_hosts_count,
                           critical_vuln_count=critical_vuln_count,
                           top_vulnerable_packages=top_vulnerable_packages,
                           now=datetime.utcnow())


@main_bp.route('/vulnerabilities')
@login_required
def vulnerabilities():
    """Show all vulnerabilities across all hosts."""
    customer_keys = current_user.customer_keys.filter_by(is_active=True).all()
    key_ids = [k.id for k in customer_keys]
    hosts = Host.query.filter(Host.customer_key_id.in_(key_ids)).all() if key_ids else []
    host_ids = [h.id for h in hosts]
    host_map = {h.id: h for h in hosts}

    grouped = {}
    if host_ids:
        vulns = Vulnerability.query.filter(
            Vulnerability.host_id.in_(host_ids),
            Vulnerability.is_resolved == False
        ).order_by(
            Vulnerability.package_name,
            Vulnerability.package_version,
            Vulnerability.package_manager
        ).all()

        for v in vulns:
            key = (v.package_name, v.package_version or '', v.package_manager or '')
            if key not in grouped:
                grouped[key] = {
                    'package_name': v.package_name,
                    'package_version': v.package_version,
                    'package_manager': v.package_manager,
                    'severity': v.severity_label,
                    'cvss_score': v.cvss_score,
                    'vuln_ids': [],
                    'host_ids': set(),
                    'host_names': [],
                }
            entry = grouped[key]
            if v.vuln_id and v.vuln_id not in entry['vuln_ids']:
                entry['vuln_ids'].append(v.vuln_id)
            if v.host_id not in entry['host_ids']:
                entry['host_ids'].add(v.host_id)
                host_obj = host_map.get(v.host_id)
                if host_obj:
                    entry['host_names'].append(host_obj.hostname)
            # Keep the highest severity
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            if severity_order.get(v.severity_label, 4) < severity_order.get(entry['severity'], 4):
                entry['severity'] = v.severity_label
            if v.cvss_score and (entry['cvss_score'] is None or v.cvss_score > entry['cvss_score']):
                entry['cvss_score'] = v.cvss_score

    # Convert to list and sort by severity then host count
    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    packages = sorted(
        grouped.values(),
        key=lambda x: (severity_order.get(x['severity'], 4), -len(x['host_ids']))
    )
    for pkg in packages:
        pkg['host_count'] = len(pkg['host_ids'])
        del pkg['host_ids']

    # Collect distinct filter values
    all_managers = sorted(set(p['package_manager'] for p in packages if p['package_manager']))
    all_severities = sorted(set(p['severity'] for p in packages if p['severity']),
                            key=lambda s: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(s, 4))
    all_hosts = sorted(set(h for p in packages for h in p['host_names']))
    all_cves = sorted(set(vid for p in packages for vid in p['vuln_ids']))

    return render_template('main/vulnerabilities.html',
                           packages=packages,
                           total_packages=len(packages),
                           all_managers=all_managers,
                           all_severities=all_severities,
                           all_hosts=all_hosts,
                           all_cves=all_cves)


@main_bp.route('/hosts')
@login_required
def all_hosts():
    """Show all hosts across all customer keys."""
    customer_keys = current_user.customer_keys.filter_by(is_active=True).all()
    key_ids = [k.id for k in customer_keys]
    hosts = Host.query.filter(Host.customer_key_id.in_(key_ids)).order_by(Host.last_seen_at.desc()).all() if key_ids else []
    host_ids = [h.id for h in hosts]
    now = datetime.utcnow()

    filter_mode = request.args.get('filter', '')

    host_list = []
    platforms = set()
    for host in hosts:
        hb_time = host.last_heartbeat_at or host.last_seen_at
        if hb_time and (now - hb_time).total_seconds() < 300:
            status = 'online'
        elif hb_time and (now - hb_time).total_seconds() < 1800:
            status = 'idle'
        else:
            status = 'offline'

        if filter_mode == 'active':
            if not host.last_seen_at or host.last_seen_at < now - timedelta(hours=24):
                continue

        latest = host.latest_report
        ext_count = latest.total_extensions if latest else 0
        pkg_count = PackageInfo.query.filter_by(host_id=host.id).count()
        vuln_count = Vulnerability.query.filter(
            Vulnerability.host_id == host.id,
            Vulnerability.is_resolved == False
        ).count()
        secret_count = SecretFinding.query.filter_by(
            host_id=host.id, is_resolved=False
        ).count()

        if host.platform:
            platforms.add(host.platform)

        host_list.append({
            'host': host,
            'status': status,
            'ext_count': ext_count,
            'pkg_count': pkg_count,
            'vuln_count': vuln_count,
            'secret_count': secret_count,
        })

    return render_template('main/all_hosts.html',
                           host_list=host_list,
                           total_hosts=len(host_list),
                           platforms=sorted(platforms),
                           filter_mode=filter_mode,
                           now=now)


@main_bp.route('/extensions')
@login_required
def all_extensions():
    """Show all extensions across all hosts, deduplicated."""
    customer_keys = current_user.customer_keys.filter_by(is_active=True).all()
    key_ids = [k.id for k in customer_keys]
    hosts = Host.query.filter(Host.customer_key_id.in_(key_ids)).all() if key_ids else []
    host_map = {h.id: h for h in hosts}

    filter_mode = request.args.get('filter', '')

    # Group extensions by extension_id
    ext_groups = {}
    ides = set()
    risk_levels = set()

    for host in hosts:
        latest = host.latest_report
        if not latest or not latest.scan_data:
            continue
        for ide in latest.scan_data.get('ides', []):
            ide_name = ide.get('name', 'Unknown')
            ides.add(ide_name)
            for ext in (ide.get('extensions') or []):
                ext_id = ext.get('id', ext.get('name', 'Unknown'))
                permissions = (ext.get('permissions') or [])
                risk_level = calculate_risk_level(permissions)
                risk_levels.add(risk_level)

                if ext_id not in ext_groups:
                    ext_groups[ext_id] = {
                        'extension_id': ext_id,
                        'name': ext.get('name', 'Unknown'),
                        'ide': ide_name,
                        'version': ext.get('version', ''),
                        'publisher': ext.get('publisher', 'Unknown'),
                        'risk_level': risk_level,
                        'host_ids': set(),
                        'host_names': [],
                    }
                entry = ext_groups[ext_id]
                if host.id not in entry['host_ids']:
                    entry['host_ids'].add(host.id)
                    entry['host_names'].append(host.hostname)
                # Keep highest risk
                risk_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
                if risk_order.get(risk_level, 4) < risk_order.get(entry['risk_level'], 4):
                    entry['risk_level'] = risk_level

    extensions_list = list(ext_groups.values())
    for e in extensions_list:
        e['host_count'] = len(e['host_ids'])
        del e['host_ids']

    if filter_mode == 'risky':
        extensions_list = [e for e in extensions_list if e['risk_level'] in ('high', 'critical')]

    risk_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    extensions_list.sort(key=lambda x: (risk_order.get(x['risk_level'], 4), -x['host_count']))

    all_hostnames = sorted(set(h.hostname for h in hosts))

    return render_template('main/all_extensions.html',
                           extensions=extensions_list,
                           total_extensions=len(extensions_list),
                           all_ides=sorted(ides),
                           all_risk_levels=sorted(risk_levels, key=lambda r: risk_order.get(r, 4)),
                           all_hosts=all_hostnames,
                           filter_mode=filter_mode)


@main_bp.route('/secrets')
@login_required
def all_secrets():
    """Show all unresolved secrets across all hosts."""
    customer_keys = current_user.customer_keys.filter_by(is_active=True).all()
    key_ids = [k.id for k in customer_keys]
    hosts = Host.query.filter(Host.customer_key_id.in_(key_ids)).all() if key_ids else []
    host_ids = [h.id for h in hosts]
    host_map = {h.id: h for h in hosts}

    secrets = []
    all_severities = set()
    all_sources = set()
    all_types = set()

    if host_ids:
        findings = SecretFinding.query.filter(
            SecretFinding.host_id.in_(host_ids),
            SecretFinding.is_resolved == False
        ).order_by(SecretFinding.severity.asc(), SecretFinding.last_seen_at.desc()).all()

        for s in findings:
            host_obj = host_map.get(s.host_id)
            all_severities.add(s.severity or 'unknown')
            all_sources.add(s.source or 'filesystem')
            all_types.add(s.secret_type)
            secrets.append({
                'finding': s,
                'host': host_obj,
            })

    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    return render_template('main/all_secrets.html',
                           secrets=secrets,
                           total_secrets=len(secrets),
                           all_severities=sorted(all_severities, key=lambda x: severity_order.get(x, 4)),
                           all_sources=sorted(all_sources),
                           all_types=sorted(all_types))


@main_bp.route('/packages')
@login_required
def all_packages():
    """Show all packages across all hosts, deduplicated."""
    customer_keys = current_user.customer_keys.filter_by(is_active=True).all()
    key_ids = [k.id for k in customer_keys]
    hosts = Host.query.filter(Host.customer_key_id.in_(key_ids)).all() if key_ids else []
    host_ids = [h.id for h in hosts]
    host_map = {h.id: h for h in hosts}

    filter_mode = request.args.get('filter', '')

    pkg_groups = {}
    all_managers = set()

    if host_ids:
        packages_query = PackageInfo.query.filter(
            PackageInfo.host_id.in_(host_ids)
        ).all()

        for pkg in packages_query:
            key = (pkg.name, pkg.version or '', pkg.package_manager or '')
            all_managers.add(pkg.package_manager)
            if key not in pkg_groups:
                pkg_groups[key] = {
                    'name': pkg.name,
                    'version': pkg.version,
                    'manager': pkg.package_manager,
                    'host_ids': set(),
                    'host_names': [],
                    'vuln_ids': [],
                    'severity': None,
                    'has_hooks': False,
                }
            entry = pkg_groups[key]
            if pkg.host_id not in entry['host_ids']:
                entry['host_ids'].add(pkg.host_id)
                host_obj = host_map.get(pkg.host_id)
                if host_obj:
                    entry['host_names'].append(host_obj.hostname)
            if pkg.lifecycle_hooks:
                entry['has_hooks'] = True

        # Attach vulnerability info
        vulns = Vulnerability.query.filter(
            Vulnerability.host_id.in_(host_ids),
            Vulnerability.is_resolved == False
        ).all()

        for v in vulns:
            key = (v.package_name, v.package_version or '', v.package_manager or '')
            if key in pkg_groups:
                entry = pkg_groups[key]
                if v.vuln_id and v.vuln_id not in entry['vuln_ids']:
                    entry['vuln_ids'].append(v.vuln_id)
                severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
                if entry['severity'] is None or severity_order.get(v.severity_label, 4) < severity_order.get(entry['severity'], 4):
                    entry['severity'] = v.severity_label

    packages_list = list(pkg_groups.values())
    for p in packages_list:
        p['host_count'] = len(p['host_ids'])
        del p['host_ids']

    if filter_mode == 'vulnerable':
        packages_list = [p for p in packages_list if p['vuln_ids']]
    elif filter_mode == 'hooks':
        packages_list = [p for p in packages_list if p['has_hooks']]

    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    packages_list.sort(key=lambda x: (
        severity_order.get(x['severity'], 99),
        -len(x['vuln_ids']),
        -x['host_count'],
        x['name']
    ))

    all_severities = sorted(set(p['severity'] for p in packages_list if p['severity']),
                            key=lambda s: severity_order.get(s, 4))

    return render_template('main/all_packages.html',
                           packages=packages_list,
                           total_packages=len(packages_list),
                           all_managers=sorted(all_managers),
                           all_severities=all_severities,
                           filter_mode=filter_mode)


@main_bp.route('/hook-bypasses')
@login_required
def all_hook_bypasses():
    """Show all hook bypass events across all hosts."""
    customer_keys = current_user.customer_keys.filter_by(is_active=True).all()
    key_ids = [k.id for k in customer_keys]
    hosts = Host.query.filter(Host.customer_key_id.in_(key_ids)).all() if key_ids else []
    host_ids = [h.id for h in hosts]
    host_map = {h.id: h for h in hosts}

    bypasses = []
    all_host_names = set()

    if host_ids:
        records = HookBypass.query.filter(
            HookBypass.host_id.in_(host_ids)
        ).order_by(HookBypass.detected_at.desc()).all()

        for b in records:
            host_obj = host_map.get(b.host_id)
            if host_obj:
                all_host_names.add(host_obj.hostname)
            bypasses.append({
                'bypass': b,
                'host': host_obj,
            })

    return render_template('main/all_hook_bypasses.html',
                           bypasses=bypasses,
                           total_bypasses=len(bypasses),
                           all_hosts=sorted(all_host_names))


@main_bp.route('/host/<host_id>')
@login_required
def host_detail(host_id):
    """Detailed view of a specific host."""
    
    # Verify host belongs to user (use public_id for unguessable URLs)
    host = Host.query.filter_by(public_id=host_id).first_or_404()
    if host.customer_key.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('main.dashboard'))
    
    # Get latest scan report
    latest_report = host.latest_report
    
    # Get extension details
    extensions = []
    if latest_report and latest_report.scan_data:
        for ide in latest_report.scan_data.get('ides', []):
            ide_name = ide.get('name', 'Unknown')
            ide_version = ide.get('version', 'Unknown')
            
            for ext in (ide.get('extensions') or []):
                permissions = (ext.get('permissions') or [])
                # Calculate risk level
                risk_level = calculate_risk_level(permissions)
                risk_explanation = get_risk_explanation(permissions, risk_level)
                risk_info = get_risk_level_info(risk_level)
                
                # Enrich permissions with detailed info
                enriched_permissions = []
                for perm in permissions:
                    perm_name = perm.get('name', '') if isinstance(perm, dict) else str(perm)
                    perm_info = get_permission_info(perm_name)
                    enriched_permissions.append({
                        'name': perm_name,
                        'display_name': perm_info['name'],
                        'description': perm_info['description'],
                        'concern': perm_info['concern'],
                        'risk': perm_info['risk'],
                        'is_dangerous': perm.get('is_dangerous', False) if isinstance(perm, dict) else perm_info['risk'] in ['critical', 'high'],
                    })
                
                extensions.append({
                    'ide_name': ide_name,
                    'ide_version': ide_version,
                    'name': ext.get('name', 'Unknown'),
                    'version': ext.get('version', 'Unknown'),
                    'publisher': ext.get('publisher', 'Unknown'),
                    'maintainer': ext.get('maintainer') or ext.get('publisher', 'Unknown'),
                    'permissions': enriched_permissions,
                    'risk_level': risk_level,
                    'risk_title': risk_info['title'],
                    'risk_description': risk_info['description'],
                    'risk_details': risk_info['details'],
                    'risk_recommendation': risk_info['recommendation'],
                    'risk_explanation': risk_explanation,
                    'is_dangerous': risk_level in ['high', 'critical'],
                })
    
    # Sort by risk level
    risk_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    extensions.sort(key=lambda x: risk_order.get(x['risk_level'], 4))
    
    # Get secrets findings for this host
    secrets = SecretFinding.query.filter_by(
        host_id=host.id,
        is_resolved=False
    ).order_by(SecretFinding.severity.asc(), SecretFinding.last_seen_at.desc()).all()
    
    # Get package info for this host, grouped by package manager
    packages_query = PackageInfo.query.filter_by(host_id=host.id).order_by(
        PackageInfo.package_manager, PackageInfo.name
    ).all()
    
    packages_by_manager = {}
    for pkg in packages_query:
        if pkg.package_manager not in packages_by_manager:
            packages_by_manager[pkg.package_manager] = []
        packages_by_manager[pkg.package_manager].append(pkg)
    
    # Serialize secrets for JavaScript
    secrets_json = [s.to_dict() for s in secrets]

    # Get vulnerability findings for this host, indexed by package for quick lookup
    host_vulns = Vulnerability.query.filter_by(
        host_id=host.id,
        is_resolved=False
    ).order_by(Vulnerability.cvss_score.desc().nullslast()).all()

    # Build lookup: "package_name:package_version:package_manager" -> [vulns]
    # Using string keys because Jinja2 can't use tuple keys in .get()
    pkg_vuln_map = {}
    for v in host_vulns:
        key = f"{v.package_name}:{v.package_version}:{v.package_manager}"
        if key not in pkg_vuln_map:
            pkg_vuln_map[key] = []
        pkg_vuln_map[key].append(v)

    total_vuln_count = len(host_vulns)

    # Get hook bypass events for this host
    hook_bypasses = HookBypass.query.filter_by(
        host_id=host.id
    ).order_by(HookBypass.detected_at.desc()).limit(50).all()

    # Get AI tool info for this host
    ai_tools = AIToolInfo.query.filter_by(host_id=host.id).order_by(AIToolInfo.tool_name).all()

    return render_template('main/host_detail.html',
                           host=host,
                           extensions=extensions,
                           latest_report=latest_report,
                           permission_info=PERMISSION_INFO,
                           risk_level_info=RISK_LEVEL_INFO,
                           secrets=secrets,
                           secrets_json=secrets_json,
                           packages_by_manager=packages_by_manager,
                           total_packages=len(packages_query),
                           pkg_vuln_map=pkg_vuln_map,
                           total_vuln_count=total_vuln_count,
                           hook_bypasses=hook_bypasses,
                           ai_tools=ai_tools)


@main_bp.route('/keys')
@login_required
def keys():
    """Customer key management page."""
    
    customer_keys = current_user.customer_keys.order_by(CustomerKey.created_at.desc()).all()
    form = CustomerKeyForm()
    
    return render_template('main/keys.html', 
                           customer_keys=customer_keys, 
                           form=form)


@main_bp.route('/keys/create', methods=['POST'])
@login_required
def create_key():
    """Create a new customer key."""
    
    form = CustomerKeyForm()
    
    if form.validate_on_submit():
        try:
            max_hosts = min(int(form.max_hosts.data), current_app.config.get('FREE_TIER_HOST_LIMIT', 5))
        except (ValueError, TypeError):
            max_hosts = current_app.config.get('FREE_TIER_HOST_LIMIT', 5)
        
        key = CustomerKey(
            key=CustomerKey.generate_key(),
            name=form.name.data,
            user_id=current_user.id,
            max_hosts=max_hosts
        )
        
        db.session.add(key)
        db.session.commit()
        
        flash(f'New key created: {key.key}', 'success')
    else:
        flash('Invalid form data', 'error')
    
    return redirect(url_for('main.keys'))


@main_bp.route('/keys/<int:key_id>/toggle', methods=['POST'])
@login_required
def toggle_key(key_id):
    """Enable/disable a customer key."""
    
    key = CustomerKey.query.get_or_404(key_id)
    
    if key.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('main.keys'))
    
    key.is_active = not key.is_active
    db.session.commit()
    
    status = 'enabled' if key.is_active else 'disabled'
    flash(f'Key {key.name} has been {status}', 'success')
    
    return redirect(url_for('main.keys'))


@main_bp.route('/keys/<int:key_id>/delete', methods=['POST'])
@login_required
def delete_key(key_id):
    """Delete a customer key."""
    
    key = CustomerKey.query.get_or_404(key_id)
    
    if key.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('main.keys'))
    
    # Delete associated data
    for host in key.hosts:
        ScanReport.query.filter_by(host_id=host.id).delete()
        ExtensionInfo.query.filter_by(host_id=host.id).delete()
        SecretFinding.query.filter_by(host_id=host.id).delete()
        PackageInfo.query.filter_by(host_id=host.id).delete()
    Host.query.filter_by(customer_key_id=key.id).delete()
    
    db.session.delete(key)
    db.session.commit()
    
    flash(f'Key {key.name} has been deleted', 'success')
    
    return redirect(url_for('main.keys'))


@main_bp.route('/alert/<int:alert_id>/acknowledge', methods=['POST'])
@login_required
def acknowledge_alert(alert_id):
    """Acknowledge a tamper alert."""
    alert = TamperAlert.query.get_or_404(alert_id)
    
    # Verify alert belongs to user's host
    host = Host.query.get(alert.host_id)
    if not host or host.customer_key.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('main.dashboard'))
    
    alert.is_acknowledged = True
    alert.acknowledged_by = current_user.id
    alert.acknowledged_at = datetime.utcnow()
    db.session.commit()
    
    flash('Alert acknowledged', 'success')
    return redirect(url_for('main.dashboard'))


@main_bp.route('/host/<host_id>/trigger-scan', methods=['POST'])
@login_required
def trigger_scan(host_id):
    """Trigger an on-demand scan for a specific host."""
    host = Host.query.filter_by(public_id=host_id).first_or_404()
    if host.customer_key.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    # Check if there's already a pending/running scan
    active_scan = ScanRequest.query.filter(
        ScanRequest.host_id == host.id,
        ScanRequest.status.in_(['pending', 'connecting', 'scanning_ides', 
                                 'scanning_secrets', 'scanning_packages'])
    ).first()
    
    if active_scan:
        return jsonify({
            'error': 'A scan is already in progress for this host',
            'scan_request': active_scan.to_dict()
        }), 409
    
    # Create scan request
    scan_req = ScanRequest(
        host_id=host.id,
        requested_by=current_user.id,
        status='pending',
        log_entries=[{
            'timestamp': datetime.utcnow().isoformat(),
            'level': 'info',
            'message': f'Scan requested by {current_user.username}'
        }, {
            'timestamp': datetime.utcnow().isoformat(),
            'level': 'info',
            'message': 'Waiting for daemon to pick up request...'
        }]
    )
    db.session.add(scan_req)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'scan_request': scan_req.to_dict()
    })


@main_bp.route('/host/<host_id>/cancel-scan', methods=['POST'])
@login_required
def cancel_scan(host_id):
    """Cancel an in-progress on-demand scan."""
    host = Host.query.filter_by(public_id=host_id).first_or_404()
    if host.customer_key.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403

    active_scan = ScanRequest.query.filter(
        ScanRequest.host_id == host.id,
        ScanRequest.status.in_(['pending', 'connecting', 'scanning_ides',
                                 'scanning_secrets', 'scanning_packages'])
    ).first()

    if not active_scan:
        return jsonify({'error': 'No active scan to cancel'}), 404

    active_scan.status = 'cancelled'
    active_scan.completed_at = datetime.utcnow()
    active_scan.add_log(f'Scan cancelled by {current_user.username}', level='warning')
    db.session.commit()

    return jsonify({
        'success': True,
        'scan_request': active_scan.to_dict()
    })


@main_bp.route('/host/<host_id>/delete', methods=['POST'])
@login_required
def delete_host(host_id):
    """Delete a host and all its associated data."""
    host = Host.query.filter_by(public_id=host_id).first_or_404()
    if host.customer_key.user_id != current_user.id:
        flash('Access denied', 'error')
        return redirect(url_for('main.dashboard'))

    hostname = host.hostname

    # Delete all associated data
    Vulnerability.query.filter_by(host_id=host.id).delete()
    HookBypass.query.filter_by(host_id=host.id).delete()
    ScanRequest.query.filter_by(host_id=host.id).delete()
    ScanReport.query.filter_by(host_id=host.id).delete()
    ExtensionInfo.query.filter_by(host_id=host.id).delete()
    SecretFinding.query.filter_by(host_id=host.id).delete()
    PackageInfo.query.filter_by(host_id=host.id).delete()
    TamperAlert.query.filter_by(host_id=host.id).delete()
    AIToolInfo.query.filter_by(host_id=host.id).delete()

    db.session.delete(host)
    db.session.commit()

    flash(f'Host "{hostname}" has been deleted', 'success')
    return redirect(url_for('main.dashboard'))


@main_bp.route('/host/<host_id>/scan-status')
@login_required
def scan_status(host_id):
    """Get the latest on-demand scan status for a host."""
    host = Host.query.filter_by(public_id=host_id).first_or_404()
    if host.customer_key.user_id != current_user.id:
        return jsonify({'error': 'Access denied'}), 403
    
    # Get the most recent scan request
    scan_req = ScanRequest.query.filter_by(
        host_id=host.id
    ).order_by(ScanRequest.created_at.desc()).first()
    
    if not scan_req:
        return jsonify({'scan_request': None})
    
    return jsonify({'scan_request': scan_req.to_dict()})


# Permission descriptions with security implications
PERMISSION_INFO = {
    # Critical permissions
    '*': {
        'name': 'Wildcard Activation',
        'description': 'Extension activates for ALL events and file types. This gives it maximum access and ability to run code at any time.',
        'risk': 'critical',
        'concern': 'Can execute code whenever VS Code is running, monitor all file operations, and intercept any user action.',
    },
    'onFileSystem': {
        'name': 'File System Access',
        'description': 'Full read/write access to your file system beyond the workspace.',
        'risk': 'critical',
        'concern': 'Can read, modify, or delete any file on your system including sensitive data, SSH keys, and credentials.',
    },
    'shellExecution': {
        'name': 'Shell Command Execution',
        'description': 'Can execute arbitrary shell commands on your system.',
        'risk': 'critical',
        'concern': 'Can run any command as your user, install malware, exfiltrate data, or modify system configurations.',
    },
    'processExecution': {
        'name': 'Process Execution',
        'description': 'Can spawn and manage external processes.',
        'risk': 'critical',
        'concern': 'Can launch any program, run background processes, and potentially execute malicious code.',
    },
    
    # High risk permissions
    'authentication': {
        'name': 'Authentication Provider',
        'description': 'Registers authentication providers and handles credentials.',
        'risk': 'high',
        'concern': 'Has access to authentication flows and may intercept or store credentials.',
    },
    'terminal': {
        'name': 'Terminal Access',
        'description': 'Can create terminals and send commands to them.',
        'risk': 'high',
        'concern': 'Can execute commands in your terminal, potentially running malicious scripts.',
    },
    'taskDefinitions': {
        'name': 'Task Definitions',
        'description': 'Defines tasks that can execute commands when triggered.',
        'risk': 'high',
        'concern': 'Tasks may execute arbitrary commands when run manually or automatically.',
    },
    'onUri': {
        'name': 'URI Handler',
        'description': 'Registers custom URI handlers that can be triggered externally.',
        'risk': 'high',
        'concern': 'External websites or apps can trigger actions in this extension via URIs.',
    },
    'onAuthenticationRequest': {
        'name': 'Authentication Requests',
        'description': 'Responds to authentication requests from the IDE.',
        'risk': 'high',
        'concern': 'Handles sensitive authentication data and credential flows.',
    },
    
    # Medium risk permissions
    'buildSystems': {
        'name': 'Build System',
        'description': 'Registers build systems that execute compilation commands.',
        'risk': 'medium',
        'concern': 'Build commands may execute arbitrary code during builds.',
    },
    'onStartupFinished': {
        'name': 'Startup Execution',
        'description': 'Extension code runs automatically when the IDE starts.',
        'risk': 'medium',
        'concern': 'Runs code every time you open the IDE without explicit user action.',
    },
    'debuggers': {
        'name': 'Debugger Integration',
        'description': 'Provides debugging capabilities for code.',
        'risk': 'medium',
        'concern': 'Has deep access to running processes during debugging sessions.',
    },
    'onDebug': {
        'name': 'Debug Events',
        'description': 'Activates when debugging sessions start.',
        'risk': 'medium',
        'concern': 'Can intercept and monitor debugging sessions.',
    },
    'onTerminalProfile': {
        'name': 'Terminal Profiles',
        'description': 'Provides custom terminal profiles.',
        'risk': 'medium',
        'concern': 'Custom terminals may have modified environments or behaviors.',
    },
    
    # Low risk permissions
    'commands': {
        'name': 'Commands',
        'description': 'Registers commands that users can execute.',
        'risk': 'low',
        'concern': 'Commands only run when explicitly triggered by the user.',
    },
    'keybindings': {
        'name': 'Keybindings',
        'description': 'Registers keyboard shortcuts.',
        'risk': 'low',
        'concern': 'Keyboard shortcuts trigger extension functionality.',
    },
    'autoload': {
        'name': 'Autoload Functions',
        'description': 'Has autoload functions for lazy loading.',
        'risk': 'low',
        'concern': 'Standard plugin architecture pattern.',
    },
    'plugin': {
        'name': 'Plugin Scripts',
        'description': 'Runs plugin scripts on startup.',
        'risk': 'low',
        'concern': 'Standard plugin loading behavior.',
    },
    'ftplugin': {
        'name': 'Filetype Plugin',
        'description': 'Activates for specific file types.',
        'risk': 'low',
        'concern': 'Only runs when editing specific file types.',
    },
    'actions': {
        'name': 'IDE Actions',
        'description': 'Registers actions in the IDE.',
        'risk': 'low',
        'concern': 'Actions are user-triggered.',
    },
    'toolWindow': {
        'name': 'Tool Window',
        'description': 'Creates tool windows in the IDE.',
        'risk': 'low',
        'concern': 'UI component with no special privileges.',
    },
    'services': {
        'name': 'Services',
        'description': 'Registers application services.',
        'risk': 'low',
        'concern': 'Standard service pattern for IDE integration.',
    },
}

# Risk level descriptions
RISK_LEVEL_INFO = {
    'critical': {
        'title': 'Critical Risk',
        'description': 'This extension has permissions that could compromise your entire system.',
        'details': 'Critical risk extensions can execute arbitrary code, access your file system without restrictions, or run shell commands. A malicious extension with these permissions could steal data, install malware, or take control of your system.',
        'recommendation': 'Only install if you absolutely trust the publisher and have verified the source code.',
    },
    'high': {
        'title': 'High Risk',
        'description': 'This extension has elevated permissions that require careful consideration.',
        'details': 'High risk extensions can access sensitive features like authentication, terminal access, or external URI handling. While not as dangerous as critical, they could still be used to compromise credentials or execute commands.',
        'recommendation': 'Review the extension carefully and ensure the publisher is reputable.',
    },
    'medium': {
        'title': 'Medium Risk',
        'description': 'This extension has some potentially concerning permissions.',
        'details': 'Medium risk extensions have permissions like startup execution, build systems, or debugger access. These features are often necessary for development tools but should be monitored.',
        'recommendation': 'Generally safe from trusted sources, but be aware of the capabilities.',
    },
    'low': {
        'title': 'Low Risk',
        'description': 'This extension has standard permissions with minimal security concerns.',
        'details': 'Low risk extensions have only basic permissions like registering commands or keybindings. These require explicit user action to trigger and pose minimal security risk.',
        'recommendation': 'Safe for normal use.',
    },
}


def get_permission_info(perm_name: str) -> dict:
    """Get detailed information about a permission."""
    if perm_name in PERMISSION_INFO:
        return PERMISSION_INFO[perm_name]
    
    # Default for unknown permissions
    return {
        'name': perm_name,
        'description': f'Permission: {perm_name}',
        'risk': 'low',
        'concern': 'Unknown permission type.',
    }


def get_risk_level_info(risk_level: str) -> dict:
    """Get detailed information about a risk level."""
    return RISK_LEVEL_INFO.get(risk_level, RISK_LEVEL_INFO['low'])


def calculate_risk_level(permissions):
    """Calculate risk level based on permissions."""
    
    if not permissions:
        return 'low'
    
    critical_perms = {'*', 'onFileSystem', 'shellExecution', 'processExecution'}
    high_perms = {'authentication', 'terminal', 'taskDefinitions', 'onUri', 'onAuthenticationRequest'}
    medium_perms = {'buildSystems', 'onStartupFinished', 'debuggers', 'onDebug', 'onTerminalProfile'}
    
    has_dangerous = False
    
    for perm in permissions:
        perm_name = perm.get('name', '') if isinstance(perm, dict) else str(perm)
        
        if perm_name in critical_perms:
            return 'critical'
        if perm_name in high_perms:
            has_dangerous = True
        if isinstance(perm, dict) and perm.get('is_dangerous'):
            has_dangerous = True
    
    if has_dangerous:
        return 'high'
    
    for perm in permissions:
        perm_name = perm.get('name', '') if isinstance(perm, dict) else str(perm)
        if perm_name in medium_perms:
            return 'medium'
    
    return 'low'


def get_risk_explanation(permissions, risk_level: str) -> str:
    """Generate a detailed explanation of why an extension has its risk level."""
    if not permissions:
        return "No special permissions detected."
    
    critical_found = []
    high_found = []
    medium_found = []
    
    critical_perms = {'*', 'onFileSystem', 'shellExecution', 'processExecution'}
    high_perms = {'authentication', 'terminal', 'taskDefinitions', 'onUri', 'onAuthenticationRequest'}
    medium_perms = {'buildSystems', 'onStartupFinished', 'debuggers', 'onDebug', 'onTerminalProfile'}
    
    for perm in permissions:
        perm_name = perm.get('name', '') if isinstance(perm, dict) else str(perm)
        
        if perm_name in critical_perms:
            info = get_permission_info(perm_name)
            critical_found.append(f"• {info['name']}: {info['concern']}")
        elif perm_name in high_perms or (isinstance(perm, dict) and perm.get('is_dangerous')):
            info = get_permission_info(perm_name)
            high_found.append(f"• {info['name']}: {info['concern']}")
        elif perm_name in medium_perms:
            info = get_permission_info(perm_name)
            medium_found.append(f"• {info['name']}: {info['concern']}")
    
    explanation_parts = []
    
    if critical_found:
        explanation_parts.append("CRITICAL PERMISSIONS:\n" + "\n".join(critical_found))
    if high_found:
        explanation_parts.append("HIGH RISK PERMISSIONS:\n" + "\n".join(high_found))
    if medium_found:
        explanation_parts.append("MEDIUM RISK PERMISSIONS:\n" + "\n".join(medium_found))
    
    return "\n\n".join(explanation_parts) if explanation_parts else "Standard permissions only."


@main_bp.route('/search')
@login_required
def search():
    """Global search for hosts and extensions."""
    query = request.args.get('q', '').strip()
    
    if not query or len(query) < 2:
        return jsonify({'hosts': [], 'extensions': []})
    
    # Get user's key IDs for filtering
    customer_keys = current_user.customer_keys.filter_by(is_active=True).all()
    key_ids = [k.id for k in customer_keys]
    
    results = {
        'hosts': [],
        'extensions': [],
        'packages': [],
        'ai_components': [],
    }
    
    # Search hosts
    hosts = Host.query.filter(
        Host.customer_key_id.in_(key_ids),
        or_(
            Host.hostname.ilike(f'%{query}%'),
            Host.ip_address.ilike(f'%{query}%'),
            Host.platform.ilike(f'%{query}%')
        )
    ).limit(10).all()
    
    for host in hosts:
        results['hosts'].append({
            'id': host.public_id,
            'hostname': host.hostname,
            'ip_address': host.ip_address,
            'platform': host.platform,
            'url': url_for('main.host_detail', host_id=host.public_id),
        })
    
    # Search extensions across all hosts
    extension_set = {}  # Use dict to deduplicate by extension ID
    
    for host in Host.query.filter(Host.customer_key_id.in_(key_ids)).all():
        latest_report = host.latest_report
        if not latest_report or not latest_report.scan_data:
            continue
        
        for ide in latest_report.scan_data.get('ides', []):
            ide_name = ide.get('name') or 'Unknown'
            ide_type = ide.get('ide_type') or 'vscode'
            
            for ext in (ide.get('extensions') or []):
                ext_id = ext.get('id') or ''
                ext_name = ext.get('name') or ''
                publisher = ext.get('publisher') or ''
                
                # Check if matches query
                if query.lower() in ext_name.lower() or \
                   query.lower() in ext_id.lower() or \
                   query.lower() in publisher.lower():
                    
                    if ext_id not in extension_set:
                        # Determine marketplace
                        marketplace = 'vscode'
                        if 'jetbrains' in ide_type.lower() or ide_name.lower() in ['pycharm', 'intellij', 'webstorm', 'goland']:
                            marketplace = 'jetbrains'
                        elif 'vscodium' in ide_type.lower():
                            marketplace = 'vscodium'
                        elif 'cursor' in ide_type.lower() or 'cursor' in ide_name.lower():
                            marketplace = 'cursor'
                        
                        permissions = (ext.get('permissions') or [])
                        risk_level = calculate_risk_level(permissions)
                        
                        extension_set[ext_id] = {
                            'id': ext_id,
                            'name': ext_name,
                            'publisher': publisher,
                            'version': ext.get('version', 'unknown'),
                            'marketplace': marketplace,
                            'risk_level': risk_level,
                            'hosts_count': 1,
                            'url': url_for('main.extension_detail', extension_id=ext_id, marketplace=marketplace),
                        }
                    else:
                        extension_set[ext_id]['hosts_count'] += 1
    
    results['extensions'] = list(extension_set.values())[:15]
    
    # Search packages (from database)
    all_user_hosts = Host.query.filter(Host.customer_key_id.in_(key_ids)).all()
    pkg_host_ids = [h.id for h in all_user_hosts]
    if pkg_host_ids:
        package_set = {}
        matching_packages = PackageInfo.query.filter(
            PackageInfo.host_id.in_(pkg_host_ids),
            PackageInfo.name.ilike(f'%{query}%')
        ).limit(200).all()
        
        for pkg in matching_packages:
            pkg_key = f"{pkg.package_manager}:{pkg.name}"
            if pkg_key not in package_set:
                package_set[pkg_key] = {
                    'name': pkg.name,
                    'package_manager': pkg.package_manager,
                    'version': pkg.version,
                    'hosts_count': 1,
                    'has_lifecycle_hooks': bool(pkg.lifecycle_hooks),
                    'url': url_for('main.package_detail', 
                                   package_name=pkg.name,
                                   manager=pkg.package_manager),
                }
            else:
                package_set[pkg_key]['hosts_count'] += 1
        
        results['packages'] = list(package_set.values())[:15]

    # Search AI tools, MCP servers, skills, and integrations
    ai_component_set = {}
    if pkg_host_ids:
        ai_tools = AIToolInfo.query.filter(
            AIToolInfo.host_id.in_(pkg_host_ids)
        ).all()

        for tool in ai_tools:
            # Search tool name itself
            if query.lower() in tool.tool_name.lower():
                key = f"tool:{tool.tool_name}"
                if key not in ai_component_set:
                    ai_component_set[key] = {
                        'name': tool.tool_name,
                        'type': 'tool',
                        'source_tool': tool.tool_name,
                        'version': tool.version,
                        'risk': None,
                        'hosts_count': 1,
                    }
                else:
                    ai_component_set[key]['hosts_count'] += 1

            # Search components (MCP servers, skills, integrations, permissions)
            for comp in (tool.mcp_servers or []):
                comp_name = comp.get('name', '')
                comp_type = comp.get('type', '')
                comp_risk = comp.get('risk', 'info')

                if query.lower() in comp_name.lower() or \
                   query.lower() in comp_type.lower():
                    key = f"{comp_type}:{comp_name}:{tool.tool_name}"
                    if key not in ai_component_set:
                        ai_component_set[key] = {
                            'name': comp_name,
                            'type': comp_type,
                            'source_tool': tool.tool_name,
                            'risk': comp_risk,
                            'risk_reason': comp.get('risk_reason', ''),
                            'hosts_count': 1,
                        }
                    else:
                        ai_component_set[key]['hosts_count'] += 1

    results['ai_components'] = list(ai_component_set.values())[:15]

    return jsonify(results)


@main_bp.route('/extension/<extension_id>')
@login_required
def extension_detail(extension_id):
    """Detailed view of an extension with marketplace data."""
    
    marketplace = request.args.get('marketplace', 'vscode')
    
    # Fetch from marketplace API
    marketplace_data = fetch_extension_details(extension_id, marketplace)
    
    # Get installation data from our database
    customer_keys = current_user.customer_keys.filter_by(is_active=True).all()
    key_ids = [k.id for k in customer_keys]
    
    # Find all hosts with this extension (deduplicated by host)
    hosts_with_extension = []
    seen_host_ids = set()
    extension_permissions = []
    local_data = None
    
    for host in Host.query.filter(Host.customer_key_id.in_(key_ids)).all():
        latest_report = host.latest_report
        if not latest_report or not latest_report.scan_data:
            continue
        
        for ide in latest_report.scan_data.get('ides', []):
            for ext in (ide.get('extensions') or []):
                if ext.get('id') == extension_id:
                    # Deduplicate: only add each host once
                    if host.id not in seen_host_ids:
                        seen_host_ids.add(host.id)
                        hosts_with_extension.append({
                            'host_id': host.public_id,
                            'hostname': host.hostname,
                            'ip_address': host.ip_address,
                            'ide_name': ide.get('name'),
                            'ide_version': ide.get('version'),
                            'ext_version': ext.get('version'),
                            'last_seen': host.last_seen_at,
                        })
                    
                    # Capture local extension data
                    if not local_data:
                        local_data = ext
                        extension_permissions = (ext.get('permissions') or [])
    
    # Calculate risk assessment
    risk_level = calculate_risk_level(extension_permissions)
    risk_info = get_risk_level_info(risk_level)
    risk_explanation = get_risk_explanation(extension_permissions, risk_level)
    
    # Enrich permissions with descriptions
    enriched_permissions = []
    for perm in extension_permissions:
        perm_name = perm.get('name', '') if isinstance(perm, dict) else str(perm)
        perm_info = get_permission_info(perm_name)
        enriched_permissions.append({
            'name': perm_name,
            'display_name': perm_info['name'],
            'description': perm_info['description'],
            'concern': perm_info['concern'],
            'risk': perm_info['risk'],
            'is_dangerous': perm_info['risk'] in ['critical', 'high'],
        })
    
    # Combine marketplace and local data
    extension_data = {
        'id': extension_id,
        'marketplace': marketplace,
        'marketplace_data': marketplace_data,
        'local_data': local_data,
        'hosts': hosts_with_extension,
        'hosts_count': len(hosts_with_extension),
        'permissions': enriched_permissions,
        'risk_level': risk_level,
        'risk_info': risk_info,
        'risk_explanation': risk_explanation,
    }
    
    return render_template('main/extension_detail.html', 
                           extension=extension_data,
                           permission_info=PERMISSION_INFO)


@main_bp.route('/package/<path:package_name>')
@login_required
def package_detail(package_name):
    """Detailed view of a package showing which hosts have it installed."""
    manager = request.args.get('manager', '')
    
    # Get user's hosts
    customer_keys = current_user.customer_keys.filter_by(is_active=True).all()
    key_ids = [k.id for k in customer_keys]
    user_hosts = Host.query.filter(Host.customer_key_id.in_(key_ids)).all()
    host_ids = [h.id for h in user_hosts]
    host_map = {h.id: h for h in user_hosts}
    
    # Query packages matching name (and optionally manager)
    query = PackageInfo.query.filter(
        PackageInfo.host_id.in_(host_ids),
        PackageInfo.name == package_name
    )
    if manager:
        query = query.filter(PackageInfo.package_manager == manager)
    
    packages = query.order_by(PackageInfo.host_id).all()
    
    # Deduplicate by host, collecting versions and hooks
    hosts_with_package = []
    seen_host_ids = set()
    all_versions = set()
    has_hooks = False
    hooks_detail = {}
    
    for pkg in packages:
        all_versions.add(pkg.version)
        if pkg.lifecycle_hooks:
            has_hooks = True
            hooks_detail = pkg.lifecycle_hooks
        
        if pkg.host_id not in seen_host_ids:
            seen_host_ids.add(pkg.host_id)
            host = host_map.get(pkg.host_id)
            if host:
                hosts_with_package.append({
                    'host_id': host.public_id,
                    'hostname': host.hostname,
                    'ip_address': host.ip_address or '',
                    'platform': host.platform or '',
                    'version': pkg.version,
                    'install_type': pkg.install_type,
                    'package_manager': pkg.package_manager,
                    'last_seen': host.last_seen_at,
                })
    
    package_data = {
        'name': package_name,
        'package_manager': manager or (packages[0].package_manager if packages else 'unknown'),
        'versions': sorted(all_versions),
        'hosts': hosts_with_package,
        'hosts_count': len(hosts_with_package),
        'total_installs': len(packages),
        'has_lifecycle_hooks': has_hooks,
        'lifecycle_hooks': hooks_detail,
    }
    
    return render_template('main/package_detail.html', package=package_data)


@main_bp.route('/package/<path:package_name>/export-csv')
@login_required
def export_package_csv(package_name):
    """Export hosts with a specific package as CSV."""
    import csv
    import io
    from flask import Response
    
    manager = request.args.get('manager', '')
    
    # Get user's hosts
    customer_keys = current_user.customer_keys.filter_by(is_active=True).all()
    key_ids = [k.id for k in customer_keys]
    user_hosts = Host.query.filter(Host.customer_key_id.in_(key_ids)).all()
    host_ids = [h.id for h in user_hosts]
    host_map = {h.id: h for h in user_hosts}
    
    # Query packages
    query = PackageInfo.query.filter(
        PackageInfo.host_id.in_(host_ids),
        PackageInfo.name == package_name
    )
    if manager:
        query = query.filter(PackageInfo.package_manager == manager)
    
    packages = query.all()
    
    # Build CSV - deduplicated by host
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Hostname', 'IP Address', 'Platform', 'Package', 'Version', 
        'Package Manager', 'Install Type', 'Lifecycle Hooks', 'Last Seen'
    ])
    
    seen_host_ids = set()
    for pkg in packages:
        if pkg.host_id not in seen_host_ids:
            seen_host_ids.add(pkg.host_id)
            host = host_map.get(pkg.host_id)
            if host:
                hooks_str = ''
                if pkg.lifecycle_hooks:
                    hooks_str = '; '.join(f'{k}: {v}' for k, v in pkg.lifecycle_hooks.items())
                
                writer.writerow([
                    host.hostname,
                    host.ip_address or '',
                    host.platform or '',
                    pkg.name,
                    pkg.version or '',
                    pkg.package_manager,
                    pkg.install_type or '',
                    hooks_str,
                    host.last_seen_at.isoformat() if host.last_seen_at else '',
                ])
    
    output.seek(0)
    safe_name = package_name.replace('/', '_').replace('@', '')
    
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename=hosts_with_{safe_name}.csv'
        }
    )


@main_bp.route('/extension/<extension_id>/export-csv')
@login_required
def export_extension_csv(extension_id):
    """Export hosts with a specific extension as CSV."""
    import csv
    import io
    from flask import Response

    customer_keys = current_user.customer_keys.filter_by(is_active=True).all()
    key_ids = [k.id for k in customer_keys]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Hostname', 'IP Address', 'Platform', 'IDE', 'IDE Version',
        'Extension', 'Extension Version', 'Publisher', 'Risk Level', 'Last Seen'
    ])

    seen_host_ids = set()
    for host in Host.query.filter(Host.customer_key_id.in_(key_ids)).all():
        latest_report = host.latest_report
        if not latest_report or not latest_report.scan_data:
            continue

        for ide in latest_report.scan_data.get('ides', []):
            for ext in (ide.get('extensions') or []):
                if ext.get('id') == extension_id and host.id not in seen_host_ids:
                    seen_host_ids.add(host.id)
                    permissions = (ext.get('permissions') or [])
                    risk_level = calculate_risk_level(permissions)

                    writer.writerow([
                        host.hostname,
                        host.ip_address or '',
                        host.platform or '',
                        ide.get('name', ''),
                        ide.get('version', ''),
                        ext.get('name', ''),
                        ext.get('version', ''),
                        ext.get('publisher', ''),
                        risk_level,
                        host.last_seen_at.isoformat() if host.last_seen_at else '',
                    ])

    output.seek(0)
    safe_name = extension_id.replace('/', '_').replace('@', '')

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename=hosts_with_{safe_name}.csv'
        }
    )


@main_bp.route('/host/<host_id>/export-extensions-csv')
@login_required
def export_host_extensions_csv(host_id):
    """Export all extensions for a specific host as CSV."""
    import csv
    import io
    from flask import Response

    host = Host.query.filter_by(public_id=host_id).first_or_404()
    if host.customer_key.user_id != current_user.id:
        return "Access denied", 403

    latest_report = host.latest_report

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Extension', 'Version', 'Publisher', 'IDE', 'IDE Version',
        'Risk Level', 'Permissions'
    ])

    if latest_report and latest_report.scan_data:
        for ide in latest_report.scan_data.get('ides', []):
            for ext in (ide.get('extensions') or []):
                permissions = (ext.get('permissions') or [])
                risk_level = calculate_risk_level(permissions)
                perm_names = ', '.join(
                    p.get('name', str(p)) if isinstance(p, dict) else str(p)
                    for p in permissions
                )

                writer.writerow([
                    ext.get('name', ''),
                    ext.get('version', ''),
                    ext.get('publisher', ''),
                    ide.get('name', ''),
                    ide.get('version', ''),
                    risk_level,
                    perm_names,
                ])

    output.seek(0)
    safe_hostname = host.hostname.replace(' ', '_')

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename={safe_hostname}_extensions.csv'
        }
    )


@main_bp.route('/host/<host_id>/export-packages-csv')
@login_required
def export_host_packages_csv(host_id):
    """Export all packages for a specific host as CSV."""
    import csv
    import io
    from flask import Response

    host = Host.query.filter_by(public_id=host_id).first_or_404()
    if host.customer_key.user_id != current_user.id:
        return "Access denied", 403

    packages = PackageInfo.query.filter_by(host_id=host.id).order_by(
        PackageInfo.package_manager, PackageInfo.name
    ).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Package', 'Version', 'Package Manager', 'Install Type',
        'Project Path', 'Lifecycle Hooks'
    ])

    for pkg in packages:
        hooks_str = ''
        if pkg.lifecycle_hooks:
            hooks_str = '; '.join(f'{k}: {v}' for k, v in pkg.lifecycle_hooks.items())

        writer.writerow([
            pkg.name,
            pkg.version or '',
            pkg.package_manager,
            pkg.install_type or '',
            pkg.project_path or '',
            hooks_str,
        ])

    output.seek(0)
    safe_hostname = host.hostname.replace(' ', '_')

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename={safe_hostname}_packages.csv'
        }
    )


@main_bp.route('/host/<host_id>/export-secrets-csv')
@login_required
def export_host_secrets_csv(host_id):
    """Export all unresolved secrets for a specific host as CSV."""
    import csv
    import io
    from flask import Response

    host = Host.query.filter_by(public_id=host_id).first_or_404()
    if host.customer_key.user_id != current_user.id:
        return "Access denied", 403

    secrets = SecretFinding.query.filter_by(
        host_id=host.id,
        is_resolved=False
    ).order_by(SecretFinding.severity.asc()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Secret Type', 'Severity', 'Variable Name', 'File Path',
        'Line Number', 'Description', 'Recommendation',
        'First Detected', 'Last Seen'
    ])

    for s in secrets:
        writer.writerow([
            s.secret_type,
            s.severity,
            s.variable_name or '',
            s.file_path,
            s.line_number or '',
            s.description or '',
            s.recommendation or '',
            s.first_detected_at.isoformat() if s.first_detected_at else '',
            s.last_seen_at.isoformat() if s.last_seen_at else '',
        ])

    output.seek(0)
    safe_hostname = host.hostname.replace(' ', '_')

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename={safe_hostname}_secrets.csv'
        }
    )


@main_bp.route('/host/<host_id>/export-vulns-csv')
@login_required
def export_host_vulns_csv(host_id):
    """Export all unresolved vulnerabilities for a specific host as CSV."""
    import csv
    import io
    from flask import Response

    host = Host.query.filter_by(public_id=host_id).first_or_404()
    if host.customer_key.user_id != current_user.id:
        return "Access denied", 403

    vulns = Vulnerability.query.filter_by(
        host_id=host.id,
        is_resolved=False
    ).order_by(Vulnerability.cvss_score.desc().nullslast()).all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'Vulnerability ID', 'Package', 'Version', 'Package Manager',
        'Severity', 'CVSS Score', 'Summary', 'Fixed Version',
        'First Detected', 'Last Seen'
    ])

    for v in vulns:
        writer.writerow([
            v.vuln_id,
            v.package_name,
            v.package_version,
            v.package_manager,
            v.severity_label,
            f'{v.cvss_score:.1f}' if v.cvss_score else '',
            v.summary or '',
            v.fixed_version or '',
            v.first_detected_at.isoformat() if v.first_detected_at else '',
            v.last_seen_at.isoformat() if v.last_seen_at else '',
        ])

    output.seek(0)
    safe_hostname = host.hostname.replace(' ', '_')

    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={
            'Content-Disposition': f'attachment; filename={safe_hostname}_vulnerabilities.csv'
        }
    )
