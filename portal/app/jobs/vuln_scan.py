"""OSV.dev vulnerability scan, runnable inline or via RQ.

This module is imported by RQ workers, so it must avoid heavy module-level
side effects. All Flask/SQLAlchemy state is acquired lazily inside the
``scan_host_vulnerabilities`` function.
"""
import logging
import os
from datetime import datetime
from typing import Any, Dict

vuln_logger = logging.getLogger("ideviewer.vuln_scan")


def scan_host_vulnerabilities(host_id: int) -> Dict[str, Any]:
    """Idempotent: upserts vulnerabilities for one host's packages.

    Safe to retry — the underlying upsert is keyed on
    (host_id, vuln_id, package_name, package_version). Designed to be
    enqueued as an RQ job; the worker reconstructs Flask app context so
    the job can use the DB session.

    Reuses the current Flask app context if there is one (sync fallback
    path), otherwise builds a fresh app via ``create_app``.
    """
    # Imports are intentionally local to avoid circular imports when this
    # module is loaded by the Flask app and to keep RQ worker startup light.
    from flask import has_app_context

    from app import db
    from app.models import Host

    if has_app_context():
        return _run(host_id, db, Host)

    from app import create_app
    app = create_app(os.environ.get("FLASK_CONFIG", "production"))
    with app.app_context():
        return _run(host_id, db, Host)


def _run(host_id, db, Host) -> Dict[str, Any]:
    host = Host.query.get(host_id)
    if host is None:
        return {"skipped": True, "reason": "host not found", "host_id": host_id}
    try:
        count = _scan_impl(host, db)
        db.session.commit()
    except Exception:
        db.session.rollback()
        raise
    return {"host_id": host_id, "vulnerabilities_found": count}


def _scan_impl(host, db) -> int:
    """The actual OSV.dev lookup body. Returns count of new vulnerabilities.

    Idempotent: existing vulnerabilities are refreshed; missing ones are
    marked resolved. Safe to call repeatedly with the same DB state.
    """
    from app.models import PackageInfo, Vulnerability
    from app.osv_client import get_ecosystem, query_packages_batch

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
        key = (pkg.name, pkg.version or "", ecosystem)
        if key not in pkg_map:
            batch.append({"name": pkg.name, "version": pkg.version or "", "ecosystem": ecosystem})
            pkg_map[key] = pkg

    if not batch:
        return 0

    vuln_logger.info(
        "Querying OSV.dev for %d packages on host %s", len(batch), host.hostname
    )

    results = query_packages_batch(batch)

    # Track which vulns we found in this scan
    found_vuln_keys = set()
    vuln_count = 0

    for (name, version, ecosystem), vulns in results.items():
        pkg = pkg_map.get((name, version, ecosystem))
        if not pkg:
            continue

        for v in vulns:
            vuln_id = v.get("vuln_id", "")
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
                    summary=v.get("summary", ""),
                    severity_label=v.get("severity_label", "UNKNOWN"),
                    cvss_score=v.get("cvss_score"),
                    affected_versions=v.get("affected_versions", ""),
                    fixed_version=v.get("fixed_version"),
                    references=v.get("references", []),
                )
                db.session.add(vuln)
                vuln_count += 1

    # Mark vulns no longer present as resolved
    existing_vulns = Vulnerability.query.filter_by(
        host_id=host.id,
        is_resolved=False,
    ).all()

    for ev in existing_vulns:
        key = (ev.vuln_id, ev.package_name, ev.package_version, ev.package_manager)
        if key not in found_vuln_keys:
            ev.is_resolved = True

    vuln_logger.info(
        "Found %d new vulnerabilities for host %s", vuln_count, host.hostname
    )
    return vuln_count
