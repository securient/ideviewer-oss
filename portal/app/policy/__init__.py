"""Policy engine (T2.2).

Pure evaluation logic — no DB writes. The caller persists matches into
PolicyViolation rows and fires events. See ``evaluate``.
"""
import fnmatch
from typing import Iterable, List, NamedTuple, Optional


RISK_RANK = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4,
}


class Match(NamedTuple):
    """One (extension, policy) pairing produced by evaluate()."""
    extension: dict
    policy: 'ExtensionPolicy'  # noqa: F821 (forward ref)
    action: str


def evaluate(extensions: Iterable[dict], policies: Iterable['ExtensionPolicy']) -> List[Match]:  # noqa: F821
    """Return one Match per extension that matches a policy.

    ``extensions`` is an iterable of dicts with keys:
      - ``extension_id`` (or ``id``)
      - ``publisher``
      - ``permissions`` (list of dicts with ``name`` or just strings)
      - ``risk_level`` (one of low/medium/high/critical)

    ``policies`` is an iterable of ExtensionPolicy rows (active only —
    the caller is responsible for filtering ``is_active``).

    First-match-wins by priority (lower number = higher priority). An
    ``allow`` action surfaces as a Match too so the caller can record
    the explicit allow and skip violation emission for that extension.
    """
    sorted_policies = sorted(policies, key=lambda p: (p.priority, p.id))
    matches: List[Match] = []
    for ext in extensions:
        for policy in sorted_policies:
            if _ext_matches_policy(ext, policy):
                matches.append(Match(extension=ext, policy=policy, action=policy.action))
                break
    return matches


def _ext_matches_policy(ext: dict, policy) -> bool:
    if policy.match_publisher:
        publisher = (ext.get('publisher') or '').strip()
        if not _glob_match(policy.match_publisher, publisher):
            return False

    if policy.match_extension_id:
        ext_id = (ext.get('extension_id') or ext.get('id') or '').strip()
        if not _glob_match(policy.match_extension_id, ext_id):
            return False

    if policy.match_permission_glob:
        names = _permission_names(ext.get('permissions') or [])
        if not any(_glob_match(policy.match_permission_glob, n) for n in names):
            return False

    if policy.match_risk_level:
        threshold = RISK_RANK.get(policy.match_risk_level.lower(), 0)
        ext_rank = RISK_RANK.get((ext.get('risk_level') or '').lower(), 0)
        if ext_rank < threshold:
            return False

    # No populated criterion ruled the extension out — it matches.
    # But if the policy has zero criteria, it would match everything;
    # require at least one criterion to be set.
    return _has_any_criterion(policy)


def _has_any_criterion(policy) -> bool:
    return any([
        policy.match_publisher,
        policy.match_extension_id,
        policy.match_permission_glob,
        policy.match_risk_level,
    ])


def _glob_match(pattern: str, value: str) -> bool:
    return fnmatch.fnmatchcase(value, pattern)


def _permission_names(perms) -> List[str]:
    out = []
    for p in perms:
        if isinstance(p, str):
            out.append(p)
        elif isinstance(p, dict):
            name = p.get('name')
            if name:
                out.append(name)
    return out
