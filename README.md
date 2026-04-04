# IDEViewer

A cross-platform security tool that scans developer workstations for supply chain threats — risky IDE extensions, vulnerable dependencies, plaintext secrets, insecure AI tool configurations, and MCP server permissions. Built as a single Go binary with an optional self-hosted portal for team-wide visibility.

**[Documentation](https://securient.github.io/ideviewer-oss)** | **[Releases](https://github.com/securient/ideviewer-oss/releases)** | **[Portal Container](https://github.com/securient/ideviewer-oss/pkgs/container/ideviewer-oss-portal)**

## Why IDEViewer?

Developer workstations are one of the most privileged and least monitored attack surfaces. IDE extensions run with full process permissions, npm packages execute lifecycle hooks silently, AI coding assistants connect to external services, and secrets sit in plaintext across config files. EDR and SCA tools don't see any of this. IDEViewer does.

## Key Features

| Feature | Description |
|---------|-------------|
| **IDE Extension Analysis** | Scans 7+ IDEs, analyzes extension permissions against a 4-tier risk model (Critical/High/Medium/Low) |
| **AI Tool Detection** | Discovers Claude Code, Cursor, OpenClaw — their skills, MCP servers, cloud integrations, and granted permissions |
| **AI Risk Scoring** | Flags insecure configurations: wildcard bash access, plaintext API keys, autonomous execution, unencrypted transports |
| **Extension Dependency Scanning** | Inventories packages bundled inside VS Code `node_modules` and JetBrains plugin JARs — invisible to standard SCA |
| **Secrets Detection** | Finds plaintext credentials in `.env` files and git history. Never transmits actual values — only type and location |
| **CVE Correlation** | All packages (project + extension-bundled) checked against OSV.dev for known vulnerabilities |
| **Real-Time Monitoring** | Filesystem watchers detect extension changes within 30 seconds |
| **Tamper Detection** | SHA-256 checksums on daemon binary, config, and service files with instant alerting |
| **Git Hook Bypass Detection** | Detects `--no-verify` usage and reports to portal |
| **SARIF Output** | Integrates with GitHub Code Scanning, CodeQL, and CI/CD pipelines |

## Screenshots

| Dashboard | Host Detail |
|-----------|------------|
| ![Dashboard](images/Dashboard.png) | ![Host Status](images/Host%20Status.png) |

| Extension Analysis | Secrets Detection |
|-------------------|-------------------|
| ![Extensions](images/Extension%20Details%20and%20Installed%20on.png) | ![Secrets](images/Exposed%20Secrets.png) |

## Quick Start

### Option A: Download a Pre-built Binary

Download from the [Releases](https://github.com/securient/ideviewer-oss/releases) page:

| Platform | File |
|----------|------|
| macOS (Apple Silicon) | `IDEViewer-*-arm64.pkg` |
| Windows (64-bit) | `IDEViewer-Setup-*.exe` |
| Linux (amd64) | `ideviewer_*_amd64.deb` |
| Linux (arm64) | `ideviewer_*_arm64.deb` |

### Option B: Build from Source

```bash
git clone https://github.com/securient/ideviewer-oss.git
cd ideviewer-oss
make build          # Single platform
make build-all      # All platforms
```

### Standalone Scanning (No Portal)

```bash
ideviewer scan              # Scan IDEs and extensions
ideviewer secrets           # Detect plaintext secrets
ideviewer packages          # Inventory all packages
ideviewer dangerous         # List high-risk extensions
ideviewer scan --output-sarif > results.sarif  # SARIF for CI/CD
```

## Portal Setup

The portal is a self-hosted web dashboard for monitoring multiple developer machines. It's optional — the CLI works standalone.

### One-Command Start

```bash
./start.sh              # Local dev (SQLite, zero config)
./start.sh --docker     # Docker + PostgreSQL
./start.sh --aws        # Deploy to AWS (ECS + RDS + ALB)
```

Default login: `admin` / `ideviewer` (you'll be prompted to change the password).

### Connect a Daemon

```bash
ideviewer register \
  --customer-key YOUR-KEY \
  --portal-url http://localhost:5000
```

The daemon starts automatically after registration and runs continuously in the background.

### Portal Container

```bash
docker pull ghcr.io/securient/ideviewer-oss-portal:latest
docker run -p 8080:8080 \
  -e SECRET_KEY=$(openssl rand -base64 32) \
  -e DATABASE_URL=postgresql://user:pass@host:5432/ideviewer \
  ghcr.io/securient/ideviewer-oss-portal:latest
```

## What Gets Detected

### Supported IDEs

| IDE | Extensions Path |
|-----|----------------|
| VS Code | `~/.vscode/extensions` |
| Cursor | `~/.cursor/extensions` |
| VSCodium | `~/.vscode-oss/extensions` |
| JetBrains (IntelliJ, PyCharm, WebStorm, GoLand, CLion, Rider, PhpStorm, RubyMine, DataGrip) | `~/.config/JetBrains/*/plugins` |
| Sublime Text | `~/Library/Application Support/Sublime Text/Packages` |
| Vim / Neovim | `~/.vim`, `~/.config/nvim` |
| Xcode | `/Applications/Xcode.app` |

### Supported Package Managers

| Language | Manager | Detection |
|----------|---------|-----------|
| Python | pip, pipenv, poetry | Global + project-level |
| Node.js | npm | Global + project + extension-bundled |
| Go | go | `~/go/bin` + `go.mod` |
| Rust | cargo | Global + `Cargo.lock` |
| Ruby | gem | Global + `Gemfile.lock` |
| PHP | composer | `composer.lock` |
| Java | maven | JetBrains plugin JARs |
| macOS | Homebrew | Formula + casks |

### AI Tools & MCP Detection

| Tool | What's Detected |
|------|----------------|
| **Claude Code** | Enabled skills/plugins, cloud MCP servers (Gmail, Calendar, etc.), per-project permissions (Bash, Read, Write, MCP tools), API keys (redacted) |
| **Cursor** | MCP server configs from `mcp.json` and VS Code settings, env vars, permissions |
| **OpenClaw** | LLM providers, Slack/Telegram integrations, bot tokens (redacted), autonomous execution flags, insecure transport |

Each component is classified by type (`skill`, `mcp-server`, `cloud-mcp`, `integration`, `permission`) and assigned a risk score:

| Risk | Examples |
|------|---------|
| **Critical** | Wildcard bash access (`Bash(*)`), plaintext API keys |
| **High** | Autonomous execution enabled, external integrations, insecure HTTP transport |
| **Medium** | Cloud MCP with data access, shell command permissions |
| **Low** | Skills with network access |

### Extension Risk Model

| Level | Criteria | Examples |
|-------|----------|----------|
| **Critical** | Full system compromise potential | Wildcard activation (`*`), filesystem + shell |
| **High** | Elevated permissions | Authentication, terminal access, URI handlers |
| **Medium** | Potentially concerning | Startup execution, debugger access |
| **Low** | Standard permissions | Commands, keybindings, themes |

## Portal Features

- **Dashboard** — security posture overview across all registered machines
- **Host Detail** — tabbed view: Extensions, Packages, Secrets, AI Tools
- **AI Tools Tab** — unified table of all AI components with type/risk filters and risk scores
- **Extension Detail** — marketplace data, permissions, risk assessment, cross-host installation
- **Package Detail** — source tracking (project vs extension-bundled), lifecycle hooks, CVEs
- **Multi-Select Filters** — combine filters (e.g., "vulnerable" + "extension deps")
- **Global Search** — search across hosts, extensions, packages, AI tools, and MCP servers
- **Real-Time Updates** — live update indicator when filesystem watcher detects changes
- **On-Demand Scans** — trigger scans from the portal UI
- **Tamper Alerts** — instant alerts on daemon file modification/deletion
- **CSV Export** — export any data view
- **Google OAuth** — optional SSO alongside username/password
- **Database Migrations** — Alembic-managed schema for safe upgrades

## Deployment

### AWS (ECS Fargate + RDS)

```bash
./start.sh --aws    # Guided wizard with cost estimates
```

Creates: VPC, ALB (HTTPS optional), ECS Fargate (autoscaling 1-4), RDS PostgreSQL, Secrets Manager, CloudWatch, ECR. See [deploy/README.md](deploy/README.md).

### MDM (JAMF / Mosyle / Kandji)

For managed fleets, deploy the PPPC profile first (grants Full Disk Access silently), then the .pkg:

```bash
# 1. Deploy PPPC profile: deploy/mdm/ideviewer-tcc.mobileconfig
# 2. Deploy .pkg installer via MDM
# 3. Register silently via post-install script
```

See [deploy/mdm/README.md](deploy/mdm/README.md) for step-by-step JAMF instructions.

### Linux (systemd)

```bash
sudo dpkg -i ideviewer_0.3.0_amd64.deb
ideviewer register --customer-key KEY --portal-url URL
sudo systemctl enable --now ideviewer
```

## Privacy by Design

- Secret values are **never transmitted** — only type, location, and redacted indicators
- AI conversation content is **never read** — only config metadata and permission sets
- All scanning happens locally on the developer's machine
- The daemon reports only security-relevant metadata to the portal

## Uninstalling

```bash
# macOS
sudo ideviewer-uninstall

# Linux
sudo dpkg -P ideviewer

# Windows
Settings > Apps > IDE Viewer > Uninstall
```

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 — Copyright 2024-2026 Securient

See [LICENSE](LICENSE) for the full text.
