"""SBOM / VEX / attestation generation (Phase 1 B11).

Turns the inventory IDEViewer already collects (PackageInfo + ExtensionInfo) and
its OSV correlation (Vulnerability) into a CycloneDX 1.5 SBOM. Vulnerabilities
carry a lightweight VEX-style ``analysis.state`` (resolved vs in_triage); the
full VEX waiver workflow (who waived, justification) is a documented follow-up.

The attestation piece folds into Phase 1 B1: ``sign_attestation`` wraps the SBOM
in the same ed25519 signed envelope used for command signing, so the SBOM's
provenance is verifiable with the portal's published signing key.
"""
import uuid
from datetime import datetime

# package_manager -> purl type (https://github.com/package-url/purl-spec)
_PURL_TYPE = {
    "npm": "npm", "yarn": "npm", "pnpm": "npm",
    "pip": "pypi", "pipenv": "pypi", "poetry": "pypi",
    "cargo": "cargo", "go": "golang", "gomod": "golang",
    "gem": "gem", "composer": "composer", "maven": "maven",
}

_VALID_SEVERITY = {"critical", "high", "medium", "low", "info", "none", "unknown"}


def _purl(manager, name, version):
    ptype = _PURL_TYPE.get((manager or "").lower(), "generic")
    v = f"@{version}" if version else ""
    return f"pkg:{ptype}/{name}{v}"


def build_cyclonedx(host, serial=None, timestamp=None) -> dict:
    """Build a CycloneDX 1.5 SBOM document for one host."""
    from app.models import PackageInfo, ExtensionInfo, Vulnerability

    timestamp = timestamp or datetime.utcnow()
    serial = serial or f"urn:uuid:{uuid.uuid4()}"

    components = []
    ref_by_pkg = {}

    packages = PackageInfo.query.filter_by(host_id=host.id).all()
    for p in packages:
        ref = _purl(p.package_manager, p.name, p.version)
        ref_by_pkg[(p.name, p.version)] = ref
        components.append({
            "type": "library",
            "bom-ref": ref,
            "name": p.name,
            "version": p.version or "",
            "purl": ref,
            "properties": [
                {"name": "ideviewer:package_manager", "value": p.package_manager or ""},
                {"name": "ideviewer:source_type", "value": getattr(p, "source_type", "") or ""},
            ],
        })

    # Extensions are first-class components too (type: application).
    exts = (ExtensionInfo.query.filter_by(host_id=host.id)
            .group_by(ExtensionInfo.extension_id).all())
    seen_ext = set()
    for e in exts:
        if e.extension_id in seen_ext:
            continue
        seen_ext.add(e.extension_id)
        components.append({
            "type": "application",
            "bom-ref": f"ext:{e.extension_id}",
            "name": e.extension_id,
            "version": e.extension_version or "",
            "publisher": e.publisher or "",
            "properties": [
                {"name": "ideviewer:risk_level", "value": e.risk_level or "unknown"},
            ],
        })

    # Vulnerabilities with a lightweight VEX analysis state.
    vulns = []
    for v in Vulnerability.query.filter_by(host_id=host.id).all():
        sev = (v.severity_label or "unknown").lower()
        if sev not in _VALID_SEVERITY:
            sev = "unknown"
        ref = ref_by_pkg.get((v.package_name, v.package_version)) or \
            _purl(v.package_manager, v.package_name, v.package_version)
        vulns.append({
            "id": v.vuln_id,
            "source": {"name": v.source or "osv.dev"},
            "ratings": [{"severity": sev}],
            "description": v.summary or "",
            "affects": [{"ref": ref}],
            "analysis": {
                # VEX-style state: resolved findings are recorded as such.
                "state": "resolved" if v.is_resolved else "in_triage",
            },
        })

    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp.isoformat() + "Z",
            "tools": [{"vendor": "IDEViewer", "name": "ideviewer-portal"}],
            "component": {
                "type": "device",
                "bom-ref": f"host:{host.public_id}",
                "name": host.hostname,
            },
        },
        "components": components,
    }
    if vulns:
        doc["vulnerabilities"] = vulns
    return doc


def sign_attestation(sbom: dict) -> dict:
    """Wrap an SBOM in the B1 ed25519 signed envelope (provenance attestation)."""
    from app.signing import sign_envelope
    return sign_envelope({"sbom": sbom})
