---
title: Home
nav_order: 0
---

# IDEViewer Documentation

IDEViewer is a cross-platform security scanner for developer workstations. It detects risky IDE extensions, vulnerable dependencies, plaintext secrets, insecure AI tool configurations, and MCP server permissions — all from a single Go binary with an optional self-hosted portal for team-wide visibility.

---

## Feature Highlights

| Feature | What It Does |
|---------|-------------|
| **IDE Extension Analysis** | Scans 7+ IDEs, analyzes extension permissions against a 4-tier risk model |
| **AI Tool Detection** | Discovers Claude Code, Cursor, OpenClaw configs — skills, MCP servers, permissions |
| **Secrets Detection** | Finds plaintext credentials in `.env` files and git history (values never transmitted) |
| **Package Inventory + CVE** | Inventories packages from 8+ managers, correlates with OSV.dev for known CVEs |
| **Extension Dependency Scanning** | Scans packages bundled inside VS Code `node_modules` and JetBrains plugin JARs |
| **Real-Time Monitoring** | Filesystem watchers detect extension installs/removals within 30 seconds |
| **Tamper Detection** | SHA-256 checksums on daemon binary, config, and service files |
| **SARIF Output** | Integrates with GitHub Code Scanning and CI/CD pipelines |

---

## Quick Start

```bash
# Install (macOS example — see Installation for all platforms)
brew install securient/tap/ideviewer   # or download from GitHub Releases

# Scan your machine
ideviewer scan          # IDEs and extensions
ideviewer secrets       # Plaintext secrets
ideviewer packages      # Installed packages + CVEs

# Optional: connect to a portal for team visibility
./start.sh              # Start portal locally (SQLite, zero config)
ideviewer register --customer-key YOUR-KEY --portal-url http://localhost:5000
```

---

## Key Sections

- [Installation](installation.md) -- Download binaries or build from source
- [Configuration](configuration.md) -- Portal setup, environment variables, OAuth
- [Features](features/ide-scanning.md) -- IDE scanning, packages, secrets, AI tools, real-time monitoring
- [Deployment](deployment/local.md) -- Local, Docker, AWS, MDM deployment options
- [Portal](portal/dashboard.md) -- Dashboard, host detail, search
- [CLI Reference](cli-reference.md) -- All commands and flags
- [Contributing](contributing.md) -- Development setup and PR guidelines

---

## Why IDEViewer?

Developer workstations are one of the most privileged and least monitored attack surfaces. IDE extensions run with full process permissions, npm packages execute lifecycle hooks silently, AI coding assistants connect to external services, and secrets sit in plaintext across config files. EDR and SCA tools don't see any of this. IDEViewer does.

## Privacy by Design

- Secret values are **never transmitted** -- only type, location, and redacted indicators
- AI conversation content is **never read** -- only config metadata and permission sets
- All scanning happens locally on the developer's machine
- The daemon reports only security-relevant metadata to the portal
