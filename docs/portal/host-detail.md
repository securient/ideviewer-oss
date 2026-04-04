---
title: Host Detail
nav_order: 2
parent: Portal
---

# Host Detail

The host detail page provides a deep view into a single machine's security posture, organized into tabs.

## Tabs

### Extensions

Lists all IDE extensions installed on the host with:

- Extension name, version, publisher
- IDE association
- Risk level (Critical/High/Medium/Low)
- Permission details

Click any extension to open the **Extension Detail** view showing marketplace data, full permission list, and cross-host installation info.

### Packages

Lists all detected packages from all package managers with:

- Package name, version, manager
- Install type (global, project, extension-bundled)
- CVE indicators for vulnerable packages

Use the **Extension Deps** filter to show only packages bundled inside IDE extensions -- these are invisible to standard SCA tools.

Click any package to open the **Package Detail Modal** showing source tracking, lifecycle hooks, and associated CVEs.

### Secrets

Lists all detected plaintext secrets with:

- Secret type (AWS key, API token, mnemonic, etc.)
- File path and line number
- Variable name
- Severity
- Resolution status (active vs. resolved)

### AI Tools

A unified table of all detected AI components with:

- Component name and parent tool
- Component type (skill, mcp-server, cloud-mcp, integration, permission)
- Risk score (Critical/High/Medium/Low/Info)
- Configuration details

## Multi-Select Filters

Each tab supports multi-select filters that can be combined. For example, on the Packages tab:

- Filter by package manager (npm, pip, cargo, etc.)
- Filter by install type (global, project, extension)
- Filter by vulnerability status (vulnerable, safe)
- Combine filters (e.g., "npm" + "extension deps" + "vulnerable")

## On-Demand Scans

Trigger a scan from the portal UI. The daemon picks up the scan request on its next heartbeat and submits results when complete.
