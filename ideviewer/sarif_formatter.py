"""
SARIF v2.1.0 output formatter for IDEViewer scan results.

Generates Static Analysis Results Interchange Format (SARIF) output
compatible with GitHub Security tab, CodeQL, and other SARIF consumers.
"""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional


SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
TOOL_NAME = "ideviewer"
TOOL_INFORMATION_URI = "https://github.com/securient/ideviewer"


def _severity_to_sarif_level(severity: str) -> str:
    """Map IDEViewer severity to SARIF result level."""
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }
    return mapping.get(severity.lower(), "note")


def _risk_to_sarif_level(risk_level: str) -> str:
    """Map extension risk level to SARIF result level."""
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
    }
    return mapping.get(risk_level.lower(), "note")


def _build_tool_component(version: str = "0.1.0") -> Dict[str, Any]:
    """Build the SARIF tool component."""
    return {
        "driver": {
            "name": TOOL_NAME,
            "version": version,
            "informationUri": TOOL_INFORMATION_URI,
            "rules": [],
        }
    }


def scan_result_to_sarif(scan_result: dict, version: str = "0.1.0") -> Dict[str, Any]:
    """
    Convert an IDE scan result to SARIF format.

    Args:
        scan_result: Dictionary from ScanResult.to_dict()
        version: IDEViewer version string

    Returns:
        SARIF v2.1.0 compliant dictionary
    """
    rules = {}
    results = []

    for ide in scan_result.get("ides", []):
        ide_name = ide.get("name", "Unknown IDE")
        for ext in ide.get("extensions", []):
            permissions = ext.get("permissions", [])
            dangerous_perms = [p for p in permissions if p.get("is_dangerous")]

            if not dangerous_perms:
                continue

            ext_id = ext.get("id", ext.get("name", "unknown"))
            ext_name = ext.get("name", "unknown")
            publisher = ext.get("publisher", "unknown")

            for perm in dangerous_perms:
                rule_id = f"dangerous-permission/{perm['name'].replace(' ', '-').lower()}"

                if rule_id not in rules:
                    rules[rule_id] = {
                        "id": rule_id,
                        "name": f"DangerousPermission_{perm['name'].replace(' ', '_')}",
                        "shortDescription": {
                            "text": f"Dangerous permission: {perm['name']}"
                        },
                        "fullDescription": {
                            "text": perm.get("description", f"Extension requests dangerous permission: {perm['name']}")
                        },
                        "defaultConfiguration": {
                            "level": "error"
                        },
                        "properties": {
                            "tags": ["security", "extensions", "permissions"]
                        },
                    }

                install_path = ext.get("install_path", "")
                result_entry = {
                    "ruleId": rule_id,
                    "level": "error",
                    "message": {
                        "text": f"Extension '{ext_name}' by {publisher} in {ide_name} has dangerous permission: {perm['name']}"
                    },
                    "locations": [],
                }

                if install_path:
                    result_entry["locations"].append({
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": install_path,
                            },
                        },
                        "message": {
                            "text": f"{ide_name} extension: {ext_name} v{ext.get('version', 'unknown')}"
                        },
                    })

                results.append(result_entry)

    tool = _build_tool_component(version)
    tool["driver"]["rules"] = list(rules.values())

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": tool,
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": scan_result.get("timestamp", datetime.utcnow().isoformat()),
                    }
                ],
            }
        ],
    }

    return sarif


def secrets_result_to_sarif(secrets_result: dict, version: str = "0.1.0") -> Dict[str, Any]:
    """
    Convert a secrets scan result to SARIF format.

    Args:
        secrets_result: Dictionary from SecretsResult.to_dict()
        version: IDEViewer version string

    Returns:
        SARIF v2.1.0 compliant dictionary
    """
    rules = {}
    results = []

    for finding in secrets_result.get("findings", []):
        secret_type = finding.get("secret_type", "unknown")
        rule_id = f"secret/{secret_type}"

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f"ExposedSecret_{secret_type.replace('-', '_')}",
                "shortDescription": {
                    "text": f"Exposed secret: {secret_type.replace('_', ' ').title()}"
                },
                "fullDescription": {
                    "text": finding.get("description", f"Detected exposed {secret_type} in configuration file")
                },
                "defaultConfiguration": {
                    "level": _severity_to_sarif_level(finding.get("severity", "critical"))
                },
                "help": {
                    "text": finding.get("recommendation", "Remove the secret from the file and use a secrets manager instead."),
                },
                "properties": {
                    "tags": ["security", "secrets", secret_type]
                },
            }

        file_path = finding.get("file_path", "")
        line_number = finding.get("line_number")
        variable_name = finding.get("variable_name", "unknown")

        result_entry = {
            "ruleId": rule_id,
            "level": _severity_to_sarif_level(finding.get("severity", "critical")),
            "message": {
                "text": f"Potential {secret_type.replace('_', ' ')} detected in variable '{variable_name}'"
            },
            "locations": [],
        }

        if file_path:
            location = {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": file_path,
                    },
                },
            }
            if line_number:
                location["physicalLocation"]["region"] = {
                    "startLine": line_number,
                }
            result_entry["locations"].append(location)

        results.append(result_entry)

    tool = _build_tool_component(version)
    tool["driver"]["rules"] = list(rules.values())

    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": tool,
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "endTimeUtc": secrets_result.get("timestamp", datetime.utcnow().isoformat()),
                    }
                ],
            }
        ],
    }

    return sarif


def to_sarif_json(sarif_dict: Dict[str, Any], indent: int = 2) -> str:
    """Serialize a SARIF dictionary to a JSON string."""
    return json.dumps(sarif_dict, indent=indent, default=str)
