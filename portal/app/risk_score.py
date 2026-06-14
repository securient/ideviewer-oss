"""Composite risk scoring v2 (Phase 1 B8).

The original model classifies each extension on a single axis — its permissions
(``risk_rules.calculate_risk_level``). That misses everything else we now know
about a host: vulnerable bundled dependencies (OSV), plaintext secrets,
extensions pulled from the marketplace (unpublished), and known-bad
threat-intel matches (B5).

This module folds those signals into one explainable host score (0–100) with a
breakdown of the contributing factors, so hosts can be ranked and triaged. The
model is deliberately transparent and additive (no ML): every point is
attributable to a named factor, and a scan re-derives it from current state.
"""

# Score thresholds -> level. Tuned so a single known-malicious extension lands
# in the danger zone and a clean host stays low.
_LEVEL_THRESHOLDS = [
    (75, "critical"),
    (50, "high"),
    (25, "medium"),
    (0, "low"),
]


def _level_for(score: int, force_critical: bool = False) -> str:
    if force_critical:
        return "critical"
    for threshold, level in _LEVEL_THRESHOLDS:
        if score >= threshold:
            return level
    return "low"


def _factor(label, points, detail):
    return {"label": label, "points": points, "detail": detail}


def _latest_extensions(host):
    """(extension_id, publisher, name, risk_level) tuples from the latest scan."""
    report = host.latest_report
    if not report or not report.scan_data:
        return []
    out = []
    for ide in report.scan_data.get("ides", []) or []:
        for ext in ide.get("extensions") or []:
            out.append((
                ext.get("id") or ext.get("extension_id") or "",
                ext.get("publisher") or "",
                ext.get("name") or "",
                ext.get("permissions") or [],
            ))
    return out


def score_host(host) -> dict:
    """Compute the composite risk score for a host.

    Returns ``{score, level, factors}`` where ``factors`` lists every
    contributing signal with its point value and a human explanation. Pure read
    of current DB + latest scan state; safe to call any time.
    """
    from app.models import Vulnerability, SecretFinding, ExtensionMetadata
    from app.risk_rules import calculate_risk_level
    from app import threat_intel

    factors = []
    force_critical = False

    extensions = _latest_extensions(host)
    ext_ids = [e[0] for e in extensions if e[0]]

    # 1. Permission-risk distribution (the v1 heuristic, now one factor of many).
    crit_perm = high_perm = 0
    for _id, _pub, _name, perms in extensions:
        lvl = calculate_risk_level(perms)
        if lvl == "critical":
            crit_perm += 1
        elif lvl == "high":
            high_perm += 1
    perm_points = min(crit_perm * 8 + high_perm * 4, 30)
    if perm_points:
        factors.append(_factor(
            "Over-privileged extensions", perm_points,
            f"{crit_perm} critical-permission, {high_perm} high-permission extension(s)."))

    # 2. Threat-intel matches (B5) — the strongest signal.
    crit_threat = high_threat = 0
    for ext_id, pub, name, _perms in extensions:
        for m in threat_intel.evaluate_extension(ext_id, pub, name):
            if m["severity"] == "critical":
                crit_threat += 1
            else:
                high_threat += 1
    threat_points = min(crit_threat * 25 + high_threat * 12, 50)
    if threat_points:
        force_critical = force_critical or crit_threat > 0
        factors.append(_factor(
            "Known-bad / typosquat extensions", threat_points,
            f"{crit_threat} known-malicious, {high_threat} suspected-typosquat match(es)."))

    # 3. Vulnerable bundled dependencies (OSV).
    vuln_q = Vulnerability.query.filter_by(host_id=host.id, is_resolved=False)
    vuln_crit = vuln_q.filter(Vulnerability.severity_label == "critical").count()
    vuln_high = vuln_q.filter(Vulnerability.severity_label == "high").count()
    vuln_points = min(vuln_crit * 5 + vuln_high * 2, 25)
    if vuln_points:
        factors.append(_factor(
            "Vulnerable dependencies", vuln_points,
            f"{vuln_crit} critical, {vuln_high} high CVE(s) in bundled packages."))

    # 4. Plaintext secrets on disk.
    sec_crit = SecretFinding.query.filter_by(
        host_id=host.id, is_resolved=False, severity="critical").count()
    sec_points = min(sec_crit * 6, 24)
    if sec_points:
        factors.append(_factor(
            "Plaintext secrets", sec_points,
            f"{sec_crit} critical plaintext secret(s) detected."))

    # 5. Unpublished extensions (pulled from the marketplace — a takedown signal).
    unpublished = 0
    if ext_ids:
        unpublished = ExtensionMetadata.query.filter(
            ExtensionMetadata.extension_id.in_(ext_ids),
            ExtensionMetadata.is_unpublished.is_(True),
        ).count()
    unpub_points = min(unpublished * 10, 20)
    if unpub_points:
        factors.append(_factor(
            "Unpublished extensions", unpub_points,
            f"{unpublished} installed extension(s) no longer on the marketplace."))

    score = min(perm_points + threat_points + vuln_points + sec_points + unpub_points, 100)
    return {
        "score": score,
        "level": _level_for(score, force_critical),
        "factors": factors,
    }


def score_extension(extension_id, publisher="", name="", permissions=None,
                    is_unpublished=False) -> dict:
    """Lightweight per-extension score, for display next to an extension row."""
    from app.risk_rules import calculate_risk_level
    from app import threat_intel

    factors = []
    force_critical = False
    score = 0

    perm_level = calculate_risk_level(permissions or [])
    perm_points = {"critical": 30, "high": 18, "medium": 8}.get(perm_level, 0)
    if perm_points:
        factors.append(_factor("Permissions", perm_points,
                               f"{perm_level} permission profile."))
        score += perm_points

    for m in threat_intel.evaluate_extension(extension_id, publisher, name):
        pts = 50 if m["severity"] == "critical" else 25
        force_critical = force_critical or m["severity"] == "critical"
        factors.append(_factor(m["indicator_type"], pts, m["detail"]))
        score += pts

    if is_unpublished:
        factors.append(_factor("Unpublished", 15,
                               "No longer present on the marketplace."))
        score += 15

    score = min(score, 100)
    return {"score": score, "level": _level_for(score, force_critical), "factors": factors}
