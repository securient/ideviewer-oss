"""P9: risk tiers are a single source of truth, and the canonical JSON,
the portal's loaded tiers, and the classifier all agree.

This guards against the drift that came from having the critical/high/medium
permission sets copy-pasted in multiple places.
"""
import json
from pathlib import Path

from app.risk_rules import (
    calculate_risk_level,
    CRITICAL_PERMISSIONS,
    HIGH_PERMISSIONS,
    MEDIUM_PERMISSIONS,
)

CANONICAL = Path(__file__).resolve().parent.parent / "rules" / "extension_risk_tiers.json"


def test_portal_tiers_match_canonical_file():
    data = json.loads(CANONICAL.read_text())
    assert CRITICAL_PERMISSIONS == set(data["critical"])
    assert HIGH_PERMISSIONS == set(data["high"])
    assert MEDIUM_PERMISSIONS == set(data["medium"])


def test_classification_is_unchanged():
    # Empty / unknown -> low
    assert calculate_risk_level([]) == "low"
    assert calculate_risk_level(["totally-unknown-permission"]) == "low"

    # Critical permissions win immediately
    assert calculate_risk_level(["onFileSystem"]) == "critical"
    assert calculate_risk_level(["*"]) == "critical"
    assert calculate_risk_level(["shellExecution"]) == "critical"

    # High permissions
    assert calculate_risk_level(["terminal"]) == "high"
    assert calculate_risk_level([{"name": "authentication"}]) == "high"

    # is_dangerous flag forces high
    assert calculate_risk_level([{"name": "whatever", "is_dangerous": True}]) == "high"

    # Medium
    assert calculate_risk_level(["onStartupFinished"]) == "medium"

    # Precedence: a critical present alongside lower tiers still wins
    assert calculate_risk_level(["onStartupFinished", "onFileSystem"]) == "critical"


def test_dict_and_string_permissions_are_equivalent():
    assert calculate_risk_level(["terminal"]) == calculate_risk_level([{"name": "terminal"}])
