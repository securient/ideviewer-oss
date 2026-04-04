---
title: Contributing
nav_order: 7
---

# Contributing

We welcome contributions to IDEViewer. This guide covers development setup, testing, and PR guidelines.

## Development Setup

### CLI (Go)

```bash
git clone https://github.com/securient/ideviewer-oss.git
cd ideviewer-oss

# Build
make build

# Run tests
make test
```

Requires Go 1.25+.

### Portal (Python)

```bash
cd portal
python -m venv venv
source venv/bin/activate    # macOS/Linux
pip install -r requirements.txt

FLASK_CONFIG=development flask run
```

Requires Python 3.10+.

## Code Structure

```
ideviewer-oss/
├── cmd/ideviewer/       # CLI entry point and commands
├── internal/
│   ├── config/          # Configuration loading/saving
│   ├── platform/        # Platform-specific paths and service management
│   └── version/         # Version info
├── pkg/
│   ├── api/             # Portal API client
│   ├── daemon/          # Daemon loop and PID management
│   ├── dependencies/    # Package manager scanners
│   ├── detectors/       # IDE-specific detectors (VS Code, JetBrains, etc.)
│   ├── gitleaks/        # Gitleaks installation and management
│   ├── hooks/           # Git pre-commit hook management
│   ├── sarif/           # SARIF output formatting
│   ├── scanner/         # Core scanning orchestration
│   ├── secrets/         # Secrets detection engine
│   └── updater/         # Self-update from GitHub Releases
├── portal/              # Flask web application
│   ├── app/             # Application package
│   ├── migrations/      # Alembic database migrations
│   ├── config.py        # Flask configuration
│   └── run.py           # Entry point
├── deploy/              # Deployment configs (Terraform, MDM)
├── build_scripts/       # Build and packaging scripts
├── tests/               # Go tests
├── start.sh             # Quick start script
└── Makefile             # Build targets
```

## Running Tests

```bash
# Go tests
make test

# Go tests with coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out

# Portal tests (if applicable)
cd portal
pytest
```

## Pull Request Guidelines

1. **Create a feature branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Keep PRs focused.** One feature or fix per PR. If you find an unrelated issue, open a separate PR.

3. **Write tests** for new functionality. Bug fixes should include a test that would have caught the bug.

4. **Update documentation** if your change affects user-facing behavior (CLI flags, API endpoints, configuration).

5. **Describe your changes** in the PR description. Explain the "why", not just the "what".

6. **Ensure tests pass** before submitting.

## Adding an IDE Detector

1. Create a new detector in `pkg/detectors/` (see `vscode.go` as a reference)
2. Implement the `scanner.Detector` interface (`Scan() (*scanner.IDE, error)`)
3. Register the detector in `cmd/ideviewer/scan.go` in the `allDetectors()` function
4. Add tests in `pkg/detectors/`

## Adding Secret Patterns

1. Add a new pattern in `pkg/secrets/`
2. Include `SecretType`, `Severity`, and `Recommendation`
3. Add test cases to verify detection and avoid false positives

## Security Vulnerabilities

For security vulnerabilities, do **not** open a public issue. Email `security@securient.io` instead.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
