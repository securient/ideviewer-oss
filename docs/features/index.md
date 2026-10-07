---
title: Features
nav_order: 3
has_children: true
---

# Features

IDEViewer provides comprehensive security scanning for developer workstations. Each feature can be used standalone via the CLI or monitored centrally through the portal.

## Detection

| Feature | What it covers |
|---------|----------------|
| [IDE Scanning](ide-scanning.html) | Extensions and plugins across 7+ IDEs, scored against a 4-tier permission risk model |
| [AI Tools](ai-tools.html) | Claude Code, Cursor, Kiro and OpenClaw configuration — skills, MCP servers, permissions |
| [Secrets](secrets.html) | Plaintext credentials in files and git history. Values are redacted on the host and never transmitted |
| [Packages](packages.html) | Dependencies from 8+ package managers, correlated with OSV.dev for known CVEs |
| [Threat Intel & Drift](threat-intel.html) | Known-bad publishers and extension IDs, typosquats, and fleet-level spread detection |

## Response

| Feature | What it covers |
|---------|----------------|
| [Real-Time Monitoring](realtime.html) | Filesystem watchers across extensions, AI tool config and project directories |
| [Policies & Enforcement](policies.html) | Allow/warn/alert/quarantine rules, signed enforcement commands, SOAR playbooks |
| [Security](security.html) | Tamper detection, host integrity, SARIF output |

## Reporting

| Feature | What it covers |
|---------|----------------|
| [SBOM & Attestation](sbom.html) | CycloneDX 1.5 export with VEX-style vulnerability states, optionally ed25519-signed |

Portal-side configuration — webhooks, metrics, roles and the audit log — is covered under [Portal](../portal/).
