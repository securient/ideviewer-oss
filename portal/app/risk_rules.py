"""Single source of truth for extension permission risk tiers.

Previously the critical/high/medium permission sets were duplicated inside
``app.main.routes`` (in both ``calculate_risk_level`` and
``get_risk_explanation``) and again, independently, in the Go scanner — three
copies guaranteed to drift. This module centralizes the portal-side
definition and loads the canonical ``rules/extension_risk_tiers.json`` when it
is available, falling back to the embedded defaults so the container image
(which only ships ``portal/``) still works.

The Go scanner is being converged onto the same JSON; a parity test guards
the two against drift.
"""
import json
import os

# Embedded defaults — kept identical to rules/extension_risk_tiers.json.
_DEFAULT_CRITICAL = ['*', 'onFileSystem', 'shellExecution', 'processExecution']
_DEFAULT_HIGH = ['authentication', 'terminal', 'taskDefinitions', 'onUri', 'onAuthenticationRequest']
_DEFAULT_MEDIUM = ['buildSystems', 'onStartupFinished', 'debuggers', 'onDebug', 'onTerminalProfile']


def _candidate_paths():
    """Locations to look for the canonical rules file, best first."""
    # Explicit override.
    env = os.environ.get('EXTENSION_RISK_RULES')
    if env:
        yield env
    here = os.path.dirname(os.path.abspath(__file__))
    # portal/app/ -> repo root rules/ (source checkout)
    yield os.path.join(here, '..', '..', 'rules', 'extension_risk_tiers.json')
    # portal-local copy (if shipped alongside the app)
    yield os.path.join(here, 'risk_rules.json')


def _load_tiers():
    for path in _candidate_paths():
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            crit = data.get('critical')
            high = data.get('high')
            med = data.get('medium')
            if crit and high and med:
                return set(crit), set(high), set(med)
        except (OSError, ValueError):
            continue
    return set(_DEFAULT_CRITICAL), set(_DEFAULT_HIGH), set(_DEFAULT_MEDIUM)


CRITICAL_PERMISSIONS, HIGH_PERMISSIONS, MEDIUM_PERMISSIONS = _load_tiers()


def _perm_name(perm):
    return perm.get('name', '') if isinstance(perm, dict) else str(perm)


def calculate_risk_level(permissions):
    """Classify a permissions list into low/medium/high/critical.

    Behaviour is identical to the previous inline implementation: a critical
    permission wins immediately; any high permission (or a permission flagged
    ``is_dangerous``) yields high; a medium permission yields medium; else low.
    """
    if not permissions:
        return 'low'

    has_dangerous = False
    for perm in permissions:
        name = _perm_name(perm)
        if name in CRITICAL_PERMISSIONS:
            return 'critical'
        if name in HIGH_PERMISSIONS:
            has_dangerous = True
        if isinstance(perm, dict) and perm.get('is_dangerous'):
            has_dangerous = True

    if has_dangerous:
        return 'high'

    for perm in permissions:
        if _perm_name(perm) in MEDIUM_PERMISSIONS:
            return 'medium'

    return 'low'
