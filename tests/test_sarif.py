"""Tests for the SARIF v2.1.0 formatter."""

import json
import pytest

from ideviewer.sarif_formatter import (
    scan_result_to_sarif,
    secrets_result_to_sarif,
    to_sarif_json,
    SARIF_VERSION,
    SARIF_SCHEMA,
    _severity_to_sarif_level,
    _risk_to_sarif_level,
)


class TestSeverityMapping:
    """Test severity / risk level to SARIF level mapping."""

    @pytest.mark.parametrize("severity,expected", [
        ("critical", "error"),
        ("high", "error"),
        ("medium", "warning"),
        ("low", "note"),
        ("unknown", "note"),
    ])
    def test_severity_mapping(self, severity, expected):
        assert _severity_to_sarif_level(severity) == expected

    @pytest.mark.parametrize("risk,expected", [
        ("critical", "error"),
        ("high", "error"),
        ("medium", "warning"),
        ("low", "note"),
    ])
    def test_risk_mapping(self, risk, expected):
        assert _risk_to_sarif_level(risk) == expected

    def test_case_insensitive(self):
        assert _severity_to_sarif_level("CRITICAL") == "error"
        assert _severity_to_sarif_level("High") == "error"


class TestScanResultToSarif:
    """Test IDE scan result to SARIF conversion."""

    def test_basic_structure(self, sample_scan_result):
        sarif = scan_result_to_sarif(sample_scan_result.to_dict(), version="1.2.3")
        assert sarif["$schema"] == SARIF_SCHEMA
        assert sarif["version"] == SARIF_VERSION
        assert len(sarif["runs"]) == 1

    def test_tool_driver(self, sample_scan_result):
        sarif = scan_result_to_sarif(sample_scan_result.to_dict(), version="1.2.3")
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "ideviewer"
        assert driver["version"] == "1.2.3"
        assert "rules" in driver

    def test_dangerous_extensions_produce_results(self, sample_scan_result):
        """Extensions with dangerous permissions should generate SARIF results."""
        sarif = scan_result_to_sarif(sample_scan_result.to_dict())
        results = sarif["runs"][0]["results"]
        assert len(results) >= 1

        # Each result should have a ruleId starting with "dangerous-permission/"
        for r in results:
            assert r["ruleId"].startswith("dangerous-permission/")
            assert r["level"] == "error"
            assert "message" in r

    def test_rule_ids_match_results(self, sample_scan_result):
        sarif = scan_result_to_sarif(sample_scan_result.to_dict())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = {r["id"] for r in rules}
        result_rule_ids = {r["ruleId"] for r in sarif["runs"][0]["results"]}
        assert result_rule_ids.issubset(rule_ids)

    def test_no_results_for_safe_extensions(self):
        """Scan with only safe extensions should produce zero results."""
        scan_data = {
            "ides": [
                {
                    "name": "VS Code",
                    "extensions": [
                        {
                            "id": "safe.ext",
                            "name": "Safe",
                            "version": "1.0",
                            "publisher": "good",
                            "permissions": [
                                {"name": "colors", "is_dangerous": False}
                            ],
                        }
                    ],
                }
            ],
            "timestamp": "2024-01-15T10:30:00",
        }
        sarif = scan_result_to_sarif(scan_data)
        assert len(sarif["runs"][0]["results"]) == 0
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 0

    def test_invocations(self, sample_scan_result):
        sarif = scan_result_to_sarif(sample_scan_result.to_dict())
        invocations = sarif["runs"][0]["invocations"]
        assert len(invocations) == 1
        assert invocations[0]["executionSuccessful"] is True

    def test_to_sarif_json_produces_valid_json(self, sample_scan_result):
        sarif = scan_result_to_sarif(sample_scan_result.to_dict())
        json_str = to_sarif_json(sarif)
        parsed = json.loads(json_str)
        assert parsed["version"] == "2.1.0"


class TestSecretsResultToSarif:
    """Test secrets scan result to SARIF conversion."""

    def test_basic_structure(self, sample_secrets_result):
        sarif = secrets_result_to_sarif(sample_secrets_result.to_dict())
        assert sarif["$schema"] == SARIF_SCHEMA
        assert sarif["version"] == SARIF_VERSION
        assert len(sarif["runs"]) == 1

    def test_findings_produce_results(self, sample_secrets_result):
        sarif = secrets_result_to_sarif(sample_secrets_result.to_dict())
        results = sarif["runs"][0]["results"]
        assert len(results) == 1
        assert results[0]["ruleId"] == "secret/ethereum_private_key"
        assert results[0]["level"] == "error"  # critical -> error

    def test_location_with_line_number(self, sample_secrets_result):
        sarif = secrets_result_to_sarif(sample_secrets_result.to_dict())
        result = sarif["runs"][0]["results"][0]
        assert len(result["locations"]) == 1
        loc = result["locations"][0]["physicalLocation"]
        assert "region" in loc
        assert loc["region"]["startLine"] == 3

    def test_rules_include_help_text(self, sample_secrets_result):
        sarif = secrets_result_to_sarif(sample_secrets_result.to_dict())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert "help" in rules[0]

    def test_empty_findings(self):
        sarif = secrets_result_to_sarif({"findings": [], "timestamp": "2024-01-01"})
        assert len(sarif["runs"][0]["results"]) == 0

    def test_multiple_findings_same_type(self):
        findings_data = {
            "findings": [
                {
                    "file_path": "/a/.env",
                    "secret_type": "ethereum_private_key",
                    "variable_name": "KEY1",
                    "line_number": 1,
                    "severity": "critical",
                    "description": "Key found",
                    "recommendation": "Remove it",
                },
                {
                    "file_path": "/b/.env",
                    "secret_type": "ethereum_private_key",
                    "variable_name": "KEY2",
                    "line_number": 5,
                    "severity": "critical",
                    "description": "Key found",
                    "recommendation": "Remove it",
                },
            ],
            "timestamp": "2024-01-01",
        }
        sarif = secrets_result_to_sarif(findings_data)
        # Two results but only one rule (same type)
        assert len(sarif["runs"][0]["results"]) == 2
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
