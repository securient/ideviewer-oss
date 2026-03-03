# IDEViewer

A cross-platform security tool that discovers installed IDEs, analyzes their extensions for security risks, detects plaintext secrets, inventories software dependencies, and reports findings to a centralized portal.

## Features

### Daemon (Agent)
- **IDE Detection** — Discovers VS Code, Cursor, VSCodium, JetBrains IDEs, Sublime Text, Vim/Neovim, and Xcode
- **Extension Analysis** — Extracts metadata, permissions, and assigns risk levels (critical, high, medium, low)
- **Secrets Detection** — Scans `.env` files for plaintext Ethereum private keys, mnemonic phrases, and AWS credentials (never transmits actual secret values)
- **Dependency Inventory** — Catalogs installed packages across pip, npm, Go, Cargo, Gem, Homebrew, and Composer
- **npm Lifecycle Hooks** — Flags npm packages with `preinstall`/`postinstall` hooks and shows the exact commands they execute
- **Heartbeat Monitoring** — Sends periodic heartbeats to the portal so admins know the agent is alive
- **Tamper Detection** — Monitors its own critical files for modification/deletion and alerts the portal
- **On-Demand Scanning** — Responds to admin-triggered scans from the portal with live progress reporting

### Portal (Dashboard)
- **Centralized Dashboard** — View all registered hosts and their security posture at a glance
- **Host Detail** — Tabbed view with Extensions, Packages, and Secrets for each host
- **Extension Marketplace Integration** — Pull details from VS Code, JetBrains, and Open VSX marketplaces
- **Package Search** — Search for any package and see which hosts have it installed, with CSV export
- **Missing Host Alerts** — Warns when hosts stop reporting (offline/uninstalled)
- **Tamper Alerts** — Alerts when daemon files are modified, deleted, or the daemon is stopped
- **On-Demand Scans** — Trigger scans from the portal with live log output
- **Google OAuth** — Optional Google login alongside email/password authentication
- **Customer Keys** — UUID-based API keys for daemon authentication with configurable host limits

## Quick Start

### Portal

```bash
cd portal
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
flask run
```

Access at http://localhost:5000. Create an account, then generate a customer key.

### Daemon

```bash
python -m venv venv
source venv/bin/activate
pip install -e .

# Register with the portal
ideviewer register \
  --customer-key YOUR-KEY \
  --portal-url http://localhost:5000 \
  --interval 15

# Run in foreground
ideviewer daemon --foreground --verbose
```

## CLI Commands

### `ideviewer scan`

Scan for installed IDEs and their extensions.

```bash
ideviewer scan                     # Pretty-printed output
ideviewer scan --output-json       # JSON output
ideviewer scan --ide vscode        # Scan specific IDE
ideviewer scan --portal            # Send results to portal
```

### `ideviewer secrets`

Scan for plaintext secrets in `.env` files.

```bash
ideviewer secrets                  # Local scan
ideviewer secrets --portal         # Send results to portal
```

### `ideviewer packages`

Inventory installed packages across all package managers.

```bash
ideviewer packages                 # Local scan
ideviewer packages --portal        # Send results to portal
```

### `ideviewer daemon`

Start the daemon for continuous monitoring.

```bash
ideviewer daemon --foreground                  # Run in foreground
ideviewer daemon --foreground --interval 15    # Custom interval (minutes)
ideviewer daemon --foreground --verbose        # Verbose logging
ideviewer daemon --log-file ~/ideviewer.log    # Log to file
```

### `ideviewer register`

Register this machine with the portal.

```bash
ideviewer register \
  --customer-key YOUR-UUID-KEY \
  --portal-url https://portal.example.com \
  --interval 15
```

### `ideviewer stop`

Stop a running daemon.

```bash
ideviewer stop
```

## Supported IDEs

| IDE | Extensions Location |
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

### Risk Levels

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

Flags npm packages with `preinstall`, `postinstall`, `install`, `preuninstall`, `postuninstall`, `prepare`, or `prepublish` hooks. Shows the exact commands these hooks execute to help identify supply chain risks.

### Tamper Detection

The daemon monitors its own critical files (binary, config, service files) and sends alerts to the portal if:
- A file is deleted (possible uninstall attempt)
- A file is modified (possible tampering)
- The daemon receives a shutdown signal

### Heartbeat Monitoring

The daemon sends a heartbeat every 2 minutes. The portal shows:
- **Green dot** — online (heartbeat within 5 minutes)
- **Yellow dot** — idle (heartbeat within 30 minutes)
- **Red dot** — offline (no heartbeat in 30+ minutes)

Missing hosts are highlighted in a warning banner on the dashboard.

## Portal Deployment

### Docker Compose (Development)

```bash
cd portal
docker-compose up -d
```

### Production (Cloud Run / ECS)

```bash
# Build container
docker build -t ideviewer-portal ./portal

# Required environment variables
SECRET_KEY=<random-secret>           # Required
DATABASE_URL=postgresql://...        # Required
PORTAL_URL=https://your-domain.com   # Recommended
GOOGLE_CLIENT_ID=...                 # Optional (enables Google OAuth)
GOOGLE_CLIENT_SECRET=...             # Optional
```

See `portal/README.md` for detailed deployment instructions.

## Building Installers

### macOS (.pkg)

```bash
pip install pyinstaller
pyinstaller --clean --noconfirm ideviewer.spec
./build_scripts/build_macos.sh
```

Requires `sudo` to install and uninstall.

### Windows (.exe)

Requires Inno Setup. See `build_scripts/windows_installer.iss`.

### Linux (.deb)

```bash
./build_scripts/build_linux_docker.sh
```

### GitHub Actions

Push a tag to trigger automated builds for all platforms:

```bash
git tag v0.1.0
git push origin v0.1.0
```

## Project Structure

```
ideviewer/
├── ideviewer/                  # Daemon package
│   ├── cli.py                  # CLI interface (click + rich)
│   ├── daemon.py               # Daemon process with heartbeat and tamper detection
│   ├── scanner.py              # IDE scanner orchestrator
│   ├── api_client.py           # Portal API client
│   ├── secrets_scanner.py      # Plaintext secrets detector
│   ├── dependency_scanner.py   # Package inventory scanner
│   ├── models.py               # Data models (IDE, Extension, ScanResult)
│   └── detectors/              # IDE-specific detectors
│       ├── vscode.py           # VS Code, Cursor, VSCodium
│       ├── jetbrains.py        # IntelliJ, PyCharm, WebStorm, etc.
│       ├── sublime.py          # Sublime Text
│       ├── vim.py              # Vim / Neovim
│       └── xcode.py            # Xcode
├── portal/                     # Web portal (Flask)
│   ├── app/
│   │   ├── api/routes.py       # API endpoints for daemon communication
│   │   ├── auth/routes.py      # Authentication (email + Google OAuth)
│   │   ├── main/routes.py      # Dashboard, host detail, search, package detail
│   │   ├── models.py           # Database models
│   │   ├── marketplace.py      # Extension marketplace integration
│   │   └── templates/          # Jinja2 templates
│   ├── config.py               # Flask configuration
│   ├── Dockerfile              # Production container
│   └── docker-compose.yml      # Local dev with PostgreSQL
├── build_scripts/              # Platform-specific build scripts
├── tests/                      # Test suite
├── .github/workflows/build.yml # CI/CD for all platforms
└── LICENSE                     # PolyForm Noncommercial 1.0.0
```

## License

PolyForm Noncommercial License 1.0.0

This software may not be used for commercial purposes without explicit authorization from Securient.

See [LICENSE](LICENSE) for the full text.
