"""
OSV.dev vulnerability database client for IDEViewer.

Queries the OSV.dev API to find known vulnerabilities in packages
detected on monitored hosts.
"""

import json
import logging
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Ecosystem mapping
# ---------------------------------------------------------------------------

_ECOSYSTEM_MAP: dict[str, str] = {
    'pip': 'PyPI',
    'npm': 'npm',
    'go': 'Go',
    'cargo': 'crates.io',
    'gem': 'RubyGems',
    'composer': 'Packagist',
}

# Package managers with no corresponding OSV ecosystem
_SKIP_MANAGERS: set[str] = {'brew', 'brew-cask'}

OSV_QUERY_URL = 'https://api.osv.dev/v1/query'
OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch'

# Batch endpoint supports up to 1000 queries per request
_MAX_BATCH_SIZE = 1000

# ---------------------------------------------------------------------------
# In-memory TTL cache
# ---------------------------------------------------------------------------

_cache: dict[tuple[str, str, str], tuple[float, list[dict]]] = {}
_CACHE_TTL_SECONDS = 3600  # 1 hour


def _cache_key(name: str, version: str, ecosystem: str) -> tuple[str, str, str]:
    return (name, version, ecosystem)


def _cache_get(name: str, version: str, ecosystem: str) -> Optional[list[dict]]:
    key = _cache_key(name, version, ecosystem)
    entry = _cache.get(key)
    if entry is None:
        return None
    ts, data = entry
    if time.time() - ts > _CACHE_TTL_SECONDS:
        del _cache[key]
        return None
    return data


def _cache_set(name: str, version: str, ecosystem: str, data: list[dict]) -> None:
    _cache[_cache_key(name, version, ecosystem)] = (time.time(), data)


def clear_cache() -> None:
    """Clear the entire in-memory vulnerability cache."""
    _cache.clear()


def set_cache_ttl(seconds: int) -> None:
    """Override the default cache TTL (in seconds)."""
    global _CACHE_TTL_SECONDS
    _CACHE_TTL_SECONDS = seconds


# ---------------------------------------------------------------------------
# HTTP helper
# ---------------------------------------------------------------------------

def _post_json(url: str, payload: dict, *, max_retries: int = 3) -> dict:
    """POST JSON to *url* with retry + exponential backoff on rate-limit."""
    data = json.dumps(payload).encode('utf-8')
    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    req = urllib.request.Request(url, data=data, headers=headers, method='POST')

    for attempt in range(max_retries):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = resp.read()
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                wait = 2 ** attempt
                logger.warning('OSV rate-limited (429), retrying in %ds (attempt %d/%d)',
                               wait, attempt + 1, max_retries)
                time.sleep(wait)
                continue
            # Read error body for diagnostics, then re-raise
            err_body = ''
            try:
                err_body = exc.read().decode('utf-8', errors='replace')
            except Exception:
                pass
            logger.error('OSV HTTP %d for %s: %s', exc.code, url, err_body)
            raise
        except urllib.error.URLError as exc:
            if attempt < max_retries - 1:
                wait = 2 ** attempt
                logger.warning('OSV connection error (%s), retrying in %ds', exc.reason, wait)
                time.sleep(wait)
                continue
            raise
    # All retries exhausted (only reachable for 429s)
    raise RuntimeError(f'OSV request to {url} failed after {max_retries} retries')


# ---------------------------------------------------------------------------
# Response parsing helpers
# ---------------------------------------------------------------------------

def _parse_cvss_score(vector: str) -> Optional[float]:
    """Extract the approximate base score from a CVSS v3 vector string.

    Uses a simplified calculation based on the exploitability and impact
    metrics in the vector. Not a full CVSS calculator, but good enough
    to derive a severity label.
    """
    if not vector or not vector.startswith('CVSS:'):
        return None

    # Parse metrics from the vector
    metrics = {}
    for part in vector.split('/'):
        if ':' in part:
            k, v = part.split(':', 1)
            metrics[k] = v

    # Approximate base score from key metrics
    # Attack Vector: Network=0.85, Adjacent=0.62, Local=0.55, Physical=0.20
    av_scores = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
    # Attack Complexity: Low=0.77, High=0.44
    ac_scores = {'L': 0.77, 'H': 0.44}
    # Privileges Required: None=0.85, Low=0.62/0.68, High=0.27/0.50
    pr_scores = {'N': 0.85, 'L': 0.62, 'H': 0.27}
    # User Interaction: None=0.85, Required=0.62
    ui_scores = {'N': 0.85, 'R': 0.62}
    # Impact: High=0.56, Low=0.22, None=0
    impact_scores = {'H': 0.56, 'L': 0.22, 'N': 0.0}

    av = av_scores.get(metrics.get('AV', ''), 0.55)
    ac = ac_scores.get(metrics.get('AC', ''), 0.44)
    pr = pr_scores.get(metrics.get('PR', ''), 0.62)
    ui = ui_scores.get(metrics.get('UI', ''), 0.62)

    c = impact_scores.get(metrics.get('C', ''), 0.0)
    i = impact_scores.get(metrics.get('I', ''), 0.0)
    a = impact_scores.get(metrics.get('A', ''), 0.0)

    # Simplified CVSS calculation
    exploitability = 8.22 * av * ac * pr * ui
    impact_base = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)

    if impact_base <= 0:
        return 0.0

    scope_changed = metrics.get('S') == 'C'
    if scope_changed:
        impact = 7.52 * (impact_base - 0.029) - 3.25 * ((impact_base - 0.02) ** 15)
    else:
        impact = 6.42 * impact_base

    if impact <= 0:
        return 0.0

    base = min(impact + exploitability, 10.0)
    return round(base, 1)


def _score_to_severity(score: float) -> str:
    """Map CVSS score to severity label.

    9.0 - 10.0  → CRITICAL
    7.0 -  8.9  → HIGH
    4.0 -  6.9  → MEDIUM
    0.1 -  3.9  → LOW
    """
    if score >= 9.0:
        return 'CRITICAL'
    elif score >= 7.0:
        return 'HIGH'
    elif score >= 4.0:
        return 'MEDIUM'
    elif score >= 0.1:
        return 'LOW'
    return 'LOW'


def _extract_severity(vuln: dict) -> tuple[Optional[float], str]:
    """Return (cvss_score, severity_label) from an OSV vulnerability dict.

    Severity is derived purely from the CVSS score using our matrix.
    If no score is available, we fall back to the database_specific severity
    field that some sources (e.g., GitHub) provide.
    """
    cvss_score: Optional[float] = None

    # Try to extract CVSS score from severity field
    for sev in vuln.get('severity', []):
        score_str = sev.get('score', '')
        sev_type = sev.get('type', '')
        if sev_type.startswith('CVSS') and score_str:
            try:
                cvss_score = float(score_str)
            except ValueError:
                # It's a CVSS vector string — parse it
                cvss_score = _parse_cvss_score(score_str)

    # Also look in database_specific for a numeric CVSS score
    db_specific = vuln.get('database_specific', {})
    if cvss_score is None and db_specific.get('cvss_score'):
        try:
            cvss_score = float(db_specific['cvss_score'])
        except (ValueError, TypeError):
            pass

    # Derive severity label from CVSS score
    if cvss_score is not None:
        return cvss_score, _score_to_severity(cvss_score)

    # No numeric score available — fall back to text severity from source
    # OSV/GitHub uses "CRITICAL", "HIGH", "MODERATE", "LOW"
    raw = db_specific.get('severity', '').upper()
    fallback_map = {
        'CRITICAL': ('CRITICAL', 9.5),
        'HIGH': ('HIGH', 7.5),
        'MODERATE': ('MEDIUM', 5.5),
        'MEDIUM': ('MEDIUM', 5.5),
        'LOW': ('LOW', 2.5),
    }
    if raw in fallback_map:
        label, estimated_score = fallback_map[raw]
        return estimated_score, label

    return None, 'MEDIUM'


def _extract_affected_versions(vuln: dict, pkg_name: str, ecosystem: str) -> tuple[str, Optional[str]]:
    """Return (affected_versions_text, first_fixed_version)."""
    affected_ranges: list[str] = []
    fixed_version: Optional[str] = None

    for affected in vuln.get('affected', []):
        pkg = affected.get('package', {})
        if pkg.get('name', '').lower() != pkg_name.lower():
            continue
        if pkg.get('ecosystem', '') != ecosystem:
            continue

        # Specific affected versions list
        for v in affected.get('versions', []):
            affected_ranges.append(v)

        # Range events
        for rng in affected.get('ranges', []):
            for event in rng.get('events', []):
                if 'fixed' in event and event['fixed']:
                    fixed_version = event['fixed']

    affected_text = ', '.join(affected_ranges[:50])  # cap for storage
    if not affected_text:
        affected_text = 'see advisory'

    return affected_text, fixed_version


def _parse_vuln(vuln: dict, pkg_name: str, ecosystem: str) -> dict:
    """Parse a single OSV vulnerability object into our structured format."""
    vuln_id = vuln.get('id', '')

    # Prefer CVE alias if available
    aliases = vuln.get('aliases', [])
    cve_ids = [a for a in aliases if a.startswith('CVE-')]
    display_id = cve_ids[0] if cve_ids else vuln_id

    summary = vuln.get('summary', '') or vuln.get('details', '')[:300]

    cvss_score, severity_label = _extract_severity(vuln)
    affected_text, fixed_version = _extract_affected_versions(vuln, pkg_name, ecosystem)

    references: list[str] = []
    for ref in vuln.get('references', []):
        url = ref.get('url')
        if url:
            references.append(url)

    return {
        'vuln_id': display_id,
        'osv_id': vuln_id,
        'aliases': aliases,
        'summary': summary,
        'severity_label': severity_label,
        'cvss_score': cvss_score,
        'affected_versions': affected_text,
        'fixed_version': fixed_version,
        'references': references,
        'source': 'osv.dev',
        'published': vuln.get('published'),
        'modified': vuln.get('modified'),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_ecosystem(package_manager: str) -> Optional[str]:
    """Map an IDEViewer package manager name to an OSV ecosystem name.

    Returns ``None`` for managers that have no OSV ecosystem (e.g. brew).
    """
    pm = package_manager.lower().strip()
    if pm in _SKIP_MANAGERS:
        return None
    return _ECOSYSTEM_MAP.get(pm)


def query_package(name: str, version: str, ecosystem: str) -> list[dict]:
    """Query OSV for vulnerabilities affecting *name*@*version* in *ecosystem*.

    Returns a list of structured vulnerability dicts.
    """
    cached = _cache_get(name, version, ecosystem)
    if cached is not None:
        logger.debug('Cache hit for %s@%s (%s)', name, version, ecosystem)
        return cached

    payload: dict = {
        'package': {
            'name': name,
            'ecosystem': ecosystem,
        },
    }
    if version:
        payload['version'] = version

    try:
        resp = _post_json(OSV_QUERY_URL, payload)
    except Exception:
        logger.exception('Failed to query OSV for %s@%s (%s)', name, version, ecosystem)
        return []

    vulns_raw = resp.get('vulns', [])
    results = [_parse_vuln(v, name, ecosystem) for v in vulns_raw]

    _cache_set(name, version, ecosystem, results)
    logger.info('OSV returned %d vulns for %s@%s (%s)', len(results), name, version, ecosystem)
    return results


def query_packages_batch(packages: list[dict]) -> dict[tuple[str, str, str], list[dict]]:
    """Batch-query OSV for multiple packages.

    *packages* is a list of dicts each containing ``name``, ``version``, and
    ``ecosystem`` (the OSV ecosystem string, **not** the IDEViewer manager name).

    Returns a mapping of ``(name, version, ecosystem)`` to a list of
    vulnerability dicts.  Packages whose ecosystem is ``None`` or empty are
    silently skipped.
    """
    results: dict[tuple[str, str, str], list[dict]] = {}

    # Separate cached vs uncached
    to_query: list[dict] = []
    query_keys: list[tuple[str, str, str]] = []

    for pkg in packages:
        name = pkg.get('name', '')
        version = pkg.get('version', '')
        ecosystem = pkg.get('ecosystem', '')
        if not name or not ecosystem:
            continue

        key = (name, version, ecosystem)
        cached = _cache_get(name, version, ecosystem)
        if cached is not None:
            results[key] = cached
        else:
            to_query.append(pkg)
            query_keys.append(key)

    if not to_query:
        return results

    # Split into batches of _MAX_BATCH_SIZE
    for batch_start in range(0, len(to_query), _MAX_BATCH_SIZE):
        batch = to_query[batch_start:batch_start + _MAX_BATCH_SIZE]
        batch_keys = query_keys[batch_start:batch_start + _MAX_BATCH_SIZE]

        queries = []
        for pkg in batch:
            q: dict = {
                'package': {
                    'name': pkg['name'],
                    'ecosystem': pkg['ecosystem'],
                },
            }
            if pkg.get('version'):
                q['version'] = pkg['version']
            queries.append(q)

        payload = {'queries': queries}

        try:
            resp = _post_json(OSV_BATCH_URL, payload)
        except Exception:
            logger.exception('Failed batch OSV query (%d packages)', len(batch))
            # Mark all as empty so caller can proceed
            for key in batch_keys:
                results.setdefault(key, [])
            continue

        resp_results = resp.get('results', [])
        for idx, key in enumerate(batch_keys):
            name, version, ecosystem = key
            if idx < len(resp_results):
                vulns_raw = resp_results[idx].get('vulns', [])
                parsed = [_parse_vuln(v, name, ecosystem) for v in vulns_raw]
            else:
                parsed = []

            _cache_set(name, version, ecosystem, parsed)
            results[key] = parsed

    total_vulns = sum(len(v) for v in results.values())
    logger.info('Batch OSV query: %d packages, %d total vulns found',
                len(packages), total_vulns)
    return results
