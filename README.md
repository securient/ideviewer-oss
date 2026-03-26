# IDEViewer

A cross-platform security scanner that discovers installed IDEs, analyzes their extensions for security risks, detects plaintext secrets, and inventories software dependencies. Results can be viewed locally or reported to a centralized portal for team-wide visibility.

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
| macOS (Intel) | `IDEViewer-*-x64.pkg` |
| Windows (64-bit) | `IDEViewer-Setup-*.exe` |
| Linux (amd64) | `ideviewer_*_amd64.deb` |
| Linux (arm64) | `ideviewer_*_arm64.deb` |

After installing, `ideviewer` is available in your terminal.

### Option B: Install from Source

```bash
git clone https://github.com/securient/ideviewer-oss.git
cd ideviewer-oss
python -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate
pip install -e .
```

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
flask run
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

## Connecting the Scanner to the Portal

Once you have a portal running and a customer key:

```bash
# Step 1: Register this machine with the portal
ideviewer register \
  --customer-key YOUR-UUID-KEY \
  --portal-url http://localhost:5000

# Step 2: Start the daemon for continuous monitoring
ideviewer daemon --foreground
```

The daemon will:
- Run scans at a regular interval (default: 60 minutes, configurable with `--interval`)
- Send results to the portal automatically
- Send heartbeats so the portal knows the machine is online
- Monitor its own files for tampering

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

## What the Portal Shows

- **Dashboard** — all registered machines and their security posture at a glance
- **Host Detail** — tabbed view with Extensions, Packages, and Secrets for each machine
- **Package Search** — search for any package across all machines (with CSV export)
- **Marketplace Info** — extension details from VS Code, JetBrains, and Open VSX marketplaces
- **Alerts** — warnings when machines go offline or daemon files are tampered with
- **On-Demand Scans** — trigger a scan on any machine from the portal UI

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

pip, npm, Go, Cargo, Gem, Composer, Homebrew

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

### npm Lifecycle Hook Detection

Flags npm packages with `preinstall`, `postinstall`, `prepare`, and other lifecycle hooks. Shows the exact commands they execute to help identify supply chain risks.

### Tamper Detection

The daemon monitors its own files (binary, config, service files) and alerts the portal if anything is modified or deleted.

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

```bash
# macOS (.pkg)
pip install pyinstaller
./build_scripts/build_macos.sh

# Linux (.deb) via Docker
./build_scripts/build_linux_docker.sh          # amd64
./build_scripts/build_linux_docker.sh arm64    # arm64

# Windows (.exe) — requires Inno Setup
pip install pyinstaller pywin32
pyinstaller --clean --noconfirm ideviewer.spec
# Then compile build_scripts/windows_installer.iss with Inno Setup
```

### Automated Builds via GitHub Actions

Push a version tag to trigger builds for all platforms:

```bash
git tag v0.1.0
git push origin v0.1.0
```

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

## Free vs Enterprise

| Feature | Free (OSS) | Enterprise |
|---------|-----------|------------|
| IDE & extension scanning | Yes | Yes |
| Secrets detection | Yes | Yes |
| Dependency inventory | Yes | Yes |
| SARIF output | Yes | Yes |
| Self-hosted portal | Yes | Yes |
| Max hosts per key | 5 | Unlimited |
| SSO / SAML | — | Yes |
| Priority support | — | Yes |

For teams needing more, see [IDEViewer Enterprise](https://securient.io).

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 — Copyright 2024-2026 Securient

See [LICENSE](LICENSE) for the full text.
