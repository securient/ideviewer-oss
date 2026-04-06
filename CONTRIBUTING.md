# Contributing to IDEViewer

Thank you for your interest in contributing to IDEViewer! This document provides guidelines for contributing to the project.

## Project Structure

```
ideviewer-oss/
├── cmd/ideviewer/       # CLI commands (cobra)
├── internal/
│   ├── config/          # Configuration management (HMAC-signed)
│   ├── platform/        # Platform-specific paths
│   └── version/         # Version info
├── pkg/
│   ├── aitools/         # AI tool detection (Claude Code, Cursor, OpenClaw)
│   ├── api/             # Portal API client
│   ├── daemon/          # Daemon loop, heartbeat, tamper detection
│   ├── dependencies/    # Package inventory + extension deps
│   ├── detectors/       # IDE detection (VS Code, JetBrains, etc.)
│   ├── gitleaks/        # Gitleaks installer
│   ├── hooks/           # Git pre-commit hook management
│   ├── sarif/           # SARIF v2.1.0 formatter
│   ├── scanner/         # Scanner orchestration
│   ├── secrets/         # Secrets detection
│   ├── updater/         # Self-update
│   └── watcher/         # Filesystem monitoring (fsnotify)
├── portal/              # Flask web portal (Python)
│   ├── app/             # Flask application
│   ├── migrations/      # Alembic database migrations
│   └── Dockerfile
├── deploy/              # AWS Terraform + MDM configs
├── docs/                # Jekyll documentation (GitHub Pages)
└── build_scripts/       # Installer packaging (.pkg, .deb, .exe)
```

## Development Setup

### Daemon (Go)

Requires [Go 1.25+](https://go.dev/dl/).

```bash
git clone https://github.com/securient/ideviewer-oss.git
cd ideviewer-oss

# Build
make build

# Run tests
make test

# Run a specific package's tests
go test -v ./pkg/detectors/...

# Lint
go vet ./...
```

### Portal (Python)

Requires Python 3.10+.

```bash
cd portal
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start the portal
cd .. && ./start.sh

# Run portal tests
cd portal && python3 -m pytest ../tests/ -v
```

## Running Tests

```bash
# Go tests (daemon)
go test -race ./...

# Portal tests
cd portal && python3 -m pytest ../tests/ -v

# Build for all platforms (verifies cross-compilation)
make build-all
```

## Pull Request Guidelines

1. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Keep PRs focused.** One feature or fix per PR.

3. **Write tests** for new functionality.

4. **Update documentation** if your change affects user-facing behavior (CLI flags, API endpoints, portal UI).

5. **Ensure tests pass** before submitting:
   ```bash
   go test -race ./...
   go vet ./...
   ```

6. **Describe your changes** in the PR description. Explain the "why", not just the "what".

## Adding IDE Detectors

To add support for a new IDE:

1. Create a new detector in `pkg/detectors/` (see `vscode.go` or `jetbrains.go` as reference).
2. Implement the `scanner.Detector` interface:
   ```go
   type Detector interface {
       Name() string
       Detect() ([]IDE, error)
   }
   ```
3. Register it in `cmd/ideviewer/scan.go` in the `allDetectors()` function.
4. Add tests in `pkg/detectors/detectors_test.go`.

## Adding AI Tool Detectors

To add detection for a new AI tool:

1. Create a new file in `pkg/aitools/` (see `claude.go` or `cursor.go` as reference).
2. Implement a detect function: `func detectYourTool(ports []OpenPort) (*AITool, error)`
3. Register it in `pkg/aitools/scanner.go` in the `Scan()` method's detectors list.
4. Use the `AIComponent` type with proper `Type` classification (`skill`, `mcp-server`, `cloud-mcp`, `integration`, `permission`).
5. Call `calculateRisk()` on each component.

## Adding Secret Patterns

To add detection for a new secret type:

1. Add a new regex pattern in `pkg/secrets/patterns.go`.
2. Add the secret type classification in the scanner.
3. Add test cases in `pkg/secrets/secrets_test.go`.

## Adding Package Managers

To add a new package manager:

1. Create a new file in `pkg/dependencies/` (see `npm.go` or `pip.go` as reference).
2. Implement global scanning and/or project-level parsing functions.
3. Wire it into `pkg/dependencies/scanner.go` in the `Scan()` method.
4. Add tests in `pkg/dependencies/dependencies_test.go`.

## Portal Development

### Adding Database Models

1. Add the model in `portal/app/models.py`.
2. Generate a migration:
   ```bash
   cd portal
   FLASK_APP=run.py flask db migrate -m "Description of change"
   ```
3. Review the generated migration in `portal/migrations/versions/`.
4. The migration runs automatically on next portal start.

### Adding API Endpoints

1. Add the route in `portal/app/api/routes.py`.
2. Add the corresponding client method in `pkg/api/client.go` (Go side).
3. Add tests in `tests/test_portal_api.py`.

### Adding Portal UI

1. Templates are in `portal/app/templates/`.
2. The main host detail page is `portal/app/templates/main/host_detail.html`.
3. Follow existing patterns for filters, tables, and modals.
4. Use the CSS variable system (`--bg-primary`, `--text-secondary`, etc.).

## Issue Reporting

- Use the provided issue templates (Bug Report or Feature Request).
- For bugs, include: steps to reproduce, expected behavior, actual behavior, and your environment (OS, Go version, browser).
- For security vulnerabilities, do NOT open a public issue. Email security@securient.io instead.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
