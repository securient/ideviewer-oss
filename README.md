# IDEViewer

A cross-platform security scanner that discovers installed IDEs, analyzes their extensions for security risks, detects plaintext secrets, and inventories software dependencies. Results can be viewed locally or reported to a centralized portal for team-wide visibility.

## Screenshots

### Dashboard
Monitor all registered hosts, IDE distribution, exposed secrets alerts, and security posture at a glance.

![Dashboard](images/Dashboard.png)
![Dashboard - Registered Hosts](images/Dashboard%20Bottom.png)

### Host Detail
Drill into any host to see extensions, packages, and secrets across all detected IDEs.

![Host Status](images/Host%20Status.png)

### Extension Details
View marketplace info, install counts, risk assessment, and which hosts have an extension installed.

![Extension Details](images/Extension%20Details%20and%20Installed%20on.png)

### Search
Search across all extensions and packages with risk-level indicators.

![Search](images/Search%20Extension.png)

### Secrets Detection
Identify exposed secrets with severity, file location, and remediation guidance. Actual secret values are never transmitted.

![Exposed Secrets](images/Exposed%20Secrets.png)

## Getting Started

There are two components:

- **Scanner (CLI)** — runs on each developer machine, scans locally
- **Portal (Web Dashboard)** — optional centralized server that collects reports from scanners

You can use the scanner standalone (no portal needed) or connect it to a portal for team monitoring.

### Option A: Download a Pre-built Binary

Download the latest release for your platform from the [Releases](https://github.com/securient/ideviewer-oss/releases) page:

| Platform | File |
|----------|------|
| macOS (Apple Silicon) | `IDEViewer-*-arm64.pkg` |
| Windows (64-bit) | `IDEViewer-Setup-*.exe` |
| Linux (amd64) | `ideviewer_*_amd64.deb` |
| Linux (arm64) | `ideviewer_*_arm64.deb` |

After installing, `ideviewer` is available in your terminal.

#### macOS: Bypass Gatekeeper

The `.pkg` installer is not yet signed with an Apple Developer certificate, so macOS will show "Apple could not verify" when you try to open it. To install:

**Option 1 — Right-click method:**
1. Right-click (or Control-click) the `.pkg` file
2. Select **Open**
3. Click **Open** in the dialog that appears

**Option 2 — Terminal:**
```bash
# Remove the quarantine attribute, then install normally
sudo xattr -rd com.apple.quarantine IDEViewer-*-arm64.pkg
```

**Option 3 — System Settings:**
1. Double-click the `.pkg` (it will be blocked)
2. Go to **System Settings > Privacy & Security**
3. Scroll down — you'll see a message about the blocked installer
4. Click **Open Anyway**

#### Windows

Run `IDEViewer-Setup-*.exe` and follow the installer wizard. The installer will optionally add `ideviewer` to your system PATH.

#### Linux (Debian/Ubuntu)

```bash
sudo dpkg -i ideviewer_*_amd64.deb    # or _arm64.deb
```

### Option B: Build from Source

Requires [Go 1.25+](https://go.dev/dl/).

```bash
git clone https://github.com/securient/ideviewer-oss.git
cd ideviewer-oss

# Build for your current platform
make build
# Output: dist/ideviewer (or ideviewer.exe on Windows)

# Or cross-compile for all platforms
make build-all
# Output: dist/ideviewer-{linux,darwin}-{amd64,arm64}, dist/ideviewer-windows-amd64.exe

# Install locally
sudo cp dist/ideviewer /usr/local/bin/

# Verify
ideviewer --version
ideviewer scan
```

### Updating

Update to the latest release directly from the CLI:

```bash
ideviewer update --check    # Check if an update is available
ideviewer update            # Download and install the latest release
ideviewer update --yes      # Skip confirmation prompt
```

This auto-detects your platform and installs the correct package (.pkg, .deb, or .exe).

## Using the Scanner (Standalone)

No portal or account required. Just run:

```bash
# Scan for IDEs and their extensions
ideviewer scan

# Scan a specific IDE
ideviewer scan --ide vscode

# Output as JSON
ideviewer scan --json

# Output in SARIF format (for GitHub Code Scanning / CI integration)
ideviewer scan --output-sarif

# Save SARIF to a file
ideviewer scan --output-sarif -o results.sarif
```

### Scan for Secrets

Detects plaintext secrets in `.env` files (Ethereum keys, mnemonic phrases, AWS credentials). **Never transmits actual secret values** — only reports type and location.

```bash
ideviewer secrets
ideviewer secrets --json
ideviewer secrets --output-sarif
```

### Scan for Packages

Inventories installed packages across pip, npm, Go, Cargo, Gem, Homebrew, and Composer.

```bash
ideviewer packages
ideviewer packages --json
```

### Other Commands

```bash
ideviewer stats         # Summary statistics
ideviewer dangerous     # List extensions with dangerous permissions
ideviewer update        # Update to latest version
ideviewer --version     # Show version
```

## Setting Up the Portal

The portal gives you a web dashboard to monitor multiple machines. It's optional — the scanner works fine without it.

### Quick Start (SQLite — good for trying it out)

```bash
cd portal
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate
pip install -r requirements.txt
FLASK_CONFIG=development flask run
```

Open http://localhost:5000 in your browser.

### Docker Compose (PostgreSQL — recommended for ongoing use)

```bash
cd portal
docker-compose up -d
```

Open http://localhost:8080 in your browser.

### First-Time Portal Setup

1. Open the portal in your browser
2. Click **Register** to create an account
3. Log in and go to **Customer Keys**
4. Click **Create Key** — copy the UUID key that's generated

You'll use this key to connect scanners to the portal.

### Configuring the Host Limit

By default, each customer key supports up to **5 hosts**. You can change this by setting `FREE_TIER_HOST_LIMIT` in your portal configuration:

```bash
# In portal/config.py, modify the Config class:
FREE_TIER_HOST_LIMIT = 20  # or any number you need
```

Or set it via environment variable before starting the portal:

```bash
FREE_TIER_HOST_LIMIT=20 FLASK_CONFIG=development flask run
```

## Connecting the Scanner to the Portal

Once you have a portal running and a customer key:

```bash
# Register and start the daemon (starts automatically after registration)
ideviewer register \
  --customer-key YOUR-UUID-KEY \
  --portal-url http://localhost:5000
```

The daemon will:
- Run full scans at a regular interval (default: 30 minutes, configurable with `--interval`)
- Monitor IDE extension directories in real-time via filesystem watchers (detects changes within 30 seconds)
- Detect AI tools (Claude Code, Cursor, OpenClaw) and their MCP server configurations
- Check for on-demand scan requests every 5 seconds
- Send heartbeats every 2 minutes so the portal knows the machine is online
- Monitor its own files for tampering and alert the portal
- Detect and report git hook bypasses (`--no-verify` usage)

### Custom Scan Interval

```bash
# Register with a 15-minute scan interval
ideviewer register \
  --customer-key YOUR-UUID-KEY \
  --portal-url http://localhost:5000 \
  --interval 15
```

### Running One-Off Portal Reports

If you don't want continuous monitoring, you can send a single report:

```bash
ideviewer scan --portal        # Scan IDEs + extensions and send to portal
ideviewer secrets --portal     # Scan secrets and send to portal
ideviewer packages --portal    # Scan packages and send to portal
```

### Stopping the Daemon

```bash
ideviewer stop
```

## Portal Features

- **Dashboard** — all registered machines and their security posture at a glance
- **Host Detail** — tabbed view with Extensions, Packages, Secrets, and AI Tools for each machine
- **Extension Detail** — marketplace data, risk assessment, install counts, and which hosts have it
- **Extension Dependency Scanning** — inventories packages bundled inside VS Code node_modules and JetBrains plugin JARs, with CVE correlation via OSV.dev
- **AI Tools Detection** — discovers Claude Code, Cursor, and OpenClaw configurations, MCP server permissions, open ports, and redacted secrets
- **Real-Time Monitoring** — filesystem watcher detects extension installs/uninstalls/updates within 30 seconds
- **Package Search** — search for any package across all machines, filter by "Extension Deps" to isolate extension-bundled packages
- **Marketplace Integration** — extension details from VS Code, JetBrains, and Open VSX marketplaces
- **On-Demand Scans** — trigger a scan on any machine from the portal UI (picked up within ~5 seconds)
- **Tamper Alerts** — warnings when daemon files are modified, deleted, or the daemon is stopped
- **Missing Host Alerts** — visual warnings when hosts go offline
- **CSV Export** — export extensions, packages, or secrets per host, or export hosts-with-extension/package lists
- **Google OAuth** — optional Google login alongside email/password authentication

## Supported IDEs

| IDE | Detected Extensions |
|-----|---------------------|
| VS Code | `~/.vscode/extensions` |
| Cursor | `~/.cursor/extensions` |
| VSCodium | `~/.vscode-oss/extensions` |
| JetBrains (IntelliJ, PyCharm, WebStorm, GoLand, etc.) | `~/.config/JetBrains/*/plugins` |
| Sublime Text | `~/Library/Application Support/Sublime Text/Packages` |
| Vim / Neovim | `~/.vim`, `~/.config/nvim` |
| Xcode | `/Applications/Xcode.app` |

## Supported Package Managers

| Language | Manager | Detection |
|----------|---------|-----------|
| Python | pip | `pip list --format=json` |
| Node.js | npm | `npm list -g --json` + project `package.json` / `package-lock.json` |
| Go | go | `~/go/bin` directory scan |
| Rust | cargo | `cargo install --list` |
| Ruby | gem | `gem list --local` |
| PHP | composer | `composer.lock` parsing |
| macOS | Homebrew | `brew list --formula/--cask --versions` |

## Security Features

### Extension Risk Levels

| Level | Meaning | Examples |
|-------|---------|----------|
| **Critical** | Can compromise your entire system | Wildcard activation, file system access, shell execution |
| **High** | Elevated permissions requiring review | Authentication, terminal access, URI handlers |
| **Medium** | Potentially concerning | Startup execution, debugger access, build systems |
| **Low** | Standard permissions | Commands, keybindings, tool windows |

### Secrets Detection

Detects but **never transmits** actual secret values:
- Ethereum/EVM private keys (64-char hex)
- Mnemonic/seed phrases (12/24-word BIP-39)
- AWS access keys and secret keys

Secrets are automatically marked as resolved in the portal when they are no longer detected in subsequent scans.

### npm Lifecycle Hook Detection

Flags npm packages with `preinstall`, `postinstall`, `prepare`, and other lifecycle hooks. Shows the exact commands they execute to help identify supply chain risks.

### Tamper Detection

The daemon monitors its own files (binary, config, service files) using SHA256 checksums. If any file is modified or deleted, the portal is alerted immediately. The daemon also notifies the portal when it receives a shutdown signal.

### AI Tool Detection

Detects AI development tools and their security-relevant configurations:

| Tool | Detection |
|------|-----------|
| Claude Code | `~/.claude/settings.json`, per-project configs, MCP servers, permissions |
| Cursor | `~/.cursor/mcp.json`, VS Code-like settings, MCP servers |
| OpenClaw | `~/.openclaw/` configs, Slack/Telegram bot tokens, LLM API keys |

For each tool, IDEViewer reports:
- MCP server names, commands, and transport types
- Environment variable names (never values)
- Filesystem read/write and network permissions
- Open listening ports from AI-related processes
- Redacted API keys and tokens found in configs

**Privacy**: Conversation content and tool outputs are never read or transmitted.

### Extension Dependency Scanning

IDE extensions bundle their own dependencies that are invisible to project-level SCA tools:
- **VS Code/Cursor/VSCodium**: Scans `node_modules/` inside each extension directory
- **JetBrains**: Inspects JAR files in plugin `lib/` directories for Maven `pom.properties`
- All extension-bundled packages are correlated against OSV.dev for known CVEs

### Real-Time Monitoring

The daemon uses filesystem watchers (fsnotify) to monitor IDE extension directories. When extensions are installed, uninstalled, or updated, a targeted rescan is triggered within 30 seconds and results are reported to the portal.

### Heartbeat Monitoring

The daemon sends a heartbeat every 2 minutes. The portal shows:
- **Green** — online (heartbeat within 5 minutes)
- **Yellow** — idle (heartbeat within 30 minutes)
- **Red** — offline (no heartbeat in 30+ minutes)

## SARIF Output

IDEViewer outputs [SARIF v2.1.0](https://sarifweb.azurewebsites.net/) for integration with GitHub Code Scanning, CodeQL, and other security tools.

```bash
ideviewer scan --output-sarif > extensions.sarif
ideviewer secrets --output-sarif > secrets.sarif
```

## Building Installers from Source

Requires [Go 1.25+](https://go.dev/dl/).

### macOS (.pkg)

```bash
make build                          # Build the binary
./build_scripts/build_macos.sh      # Package as .pkg installer
# Output: dist/IDEViewer-<version>-arm64.pkg

# Install
sudo installer -pkg dist/IDEViewer-*-arm64.pkg -target /

# Uninstall
sudo ideviewer-uninstall
```

### Windows (.exe installer)

Requires [Inno Setup 6](https://jrsoftware.org/isinfo.php).

```powershell
# Cross-compile from any platform, or build natively on Windows
make build-all
# Then compile the installer:
& "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" build_scripts\windows_installer.iss
```

Uninstall via **Settings > Apps > IDE Viewer > Uninstall**.

### Linux (.deb)

```bash
make build-all
# .deb packages are created by the GitHub Actions workflow
# For manual builds, the Makefile produces the binary at dist/ideviewer-linux-amd64
```

### Automated Builds via GitHub Actions

Push a version tag to trigger builds for all platforms:

```bash
git tag v0.3.0
git push origin v0.3.0
```

The CI pipeline cross-compiles for Linux (amd64/arm64), macOS (arm64), and Windows (amd64), then creates platform-specific installers (.pkg, .deb, .exe) and drafts a GitHub release.

## Portal Deployment (Production)

```bash
docker build -t ideviewer-portal ./portal

# Required environment variables:
# SECRET_KEY=<random-secret>
# DATABASE_URL=postgresql://user:pass@host:5432/ideviewer

# Optional:
# PORTAL_URL=https://your-domain.com
# GOOGLE_CLIENT_ID=...          (enables Google OAuth)
# GOOGLE_CLIENT_SECRET=...
```

See [portal/README.md](portal/README.md) for detailed deployment instructions (Google Cloud Run, AWS ECS, etc).

## Uninstalling

### macOS

```bash
sudo ideviewer-uninstall
```

This stops the daemon, removes the binary, LaunchDaemon, logs, and the package receipt.

### Windows

Uninstall via **Settings > Apps > IDE Viewer > Uninstall**. This stops the daemon, removes the binary, and cleans up PATH.

### Linux

```bash
sudo dpkg -r ideviewer          # remove, keep config
sudo dpkg -P ideviewer          # purge config + logs too
```

## Enterprise Deployment (MDM)

For deploying IDEViewer to managed fleets via JAMF, Mosyle, Kandji, or other MDM solutions:

### macOS (JAMF / MDM)

**1. Deploy the PPPC profile** (prevents macOS access prompts):
```bash
# Upload deploy/mdm/ideviewer-tcc.mobileconfig as a Configuration Profile in your MDM
# This grants Full Disk Access to the daemon — deploy BEFORE the .pkg
```

**2. Deploy the .pkg installer** via your MDM's package deployment.

**3. Register silently** with a post-install script:
```bash
#!/bin/bash
LOGGED_IN_USER=$(stat -f%Su /dev/console)
sudo -u "$LOGGED_IN_USER" /usr/local/bin/ideviewer register \
    --customer-key YOUR-KEY \
    --portal-url https://portal.yourcompany.com
```

**4. Upgrade** — deploy a new .pkg version. The preinstall script stops the old daemon, and the LaunchAgent auto-restarts.

**5. Uninstall** silently:
```bash
sudo /usr/local/bin/ideviewer-uninstall <<< "y"
```

See [deploy/mdm/README.md](deploy/mdm/README.md) for detailed JAMF, Mosyle, and Kandji instructions, PPPC profile configuration, and code signing guidance.

### Linux (Fleet Management)

```bash
# Deploy the .deb package via your package manager
sudo dpkg -i ideviewer_0.3.0_amd64.deb

# Register
ideviewer register --customer-key YOUR-KEY --portal-url https://portal.yourcompany.com

# Enable as systemd service
sudo systemctl enable --now ideviewer
```

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 — Copyright 2024-2026 Securient

See [LICENSE](LICENSE) for the full text.
