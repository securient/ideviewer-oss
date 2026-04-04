---
title: CLI Reference
nav_order: 6
---

# CLI Reference

IDEViewer provides a single binary with subcommands for scanning, monitoring, and management.

## Global Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--verbose` | `-v` | Enable verbose output |

---

## `ideviewer scan`

Scan for installed IDEs and their extensions.

| Flag | Short | Description |
|------|-------|-------------|
| `--json` | | Output as JSON |
| `--output-sarif` | | Output in SARIF v2.1.0 format |
| `--output` | `-o` | Write output to file path |
| `--ide` | `-i` | Filter by IDE type (repeatable) |
| `--portal` | | Send results to the portal |

```bash
ideviewer scan                          # Table output
ideviewer scan --json                   # JSON output
ideviewer scan --output-sarif > scan.sarif   # SARIF output
ideviewer scan -o results.json          # Save to file
ideviewer scan --portal                 # Submit to portal
```

---

## `ideviewer secrets`

Scan for plaintext secrets in configuration files.

| Flag | Short | Description |
|------|-------|-------------|
| `--json` | | Output as JSON |
| `--output-sarif` | | Output in SARIF v2.1.0 format |
| `--portal` | | Send results to the portal |
| `--check-staged` | | Only scan files currently staged in git |
| `--exit-code` | | Exit with code 1 if secrets found (for CI/CD) |

```bash
ideviewer secrets                       # Table output
ideviewer secrets --json                # JSON output
ideviewer secrets --check-staged --exit-code  # Pre-commit hook mode
ideviewer secrets --output-sarif        # SARIF for CI/CD
```

---

## `ideviewer packages`

Scan for installed packages and dependencies.

| Flag | Short | Description |
|------|-------|-------------|
| `--json` | | Output as JSON |
| `--global-only` | | Only scan globally installed packages |
| `--portal` | | Send results to the portal |

```bash
ideviewer packages                      # Table output
ideviewer packages --json               # JSON output
ideviewer packages --global-only        # Global packages only
```

---

## `ideviewer dangerous`

List extensions with dangerous permissions.

```bash
ideviewer dangerous
```

Outputs a table with columns: IDE, Extension, Version, Dangerous Permissions.

---

## `ideviewer stats`

Show statistics about installed IDEs and extensions.

| Flag | Short | Description |
|------|-------|-------------|
| `--json` | | Output as JSON |

```bash
ideviewer stats                         # Summary table
ideviewer stats --json                  # JSON output
```

---

## `ideviewer register`

Register this machine with the portal and start the daemon.

| Flag | Short | Description | Required |
|------|-------|-------------|----------|
| `--customer-key` | `-k` | Customer key (UUID) | Yes |
| `--portal-url` | `-p` | Portal URL | Yes |
| `--interval` | `-i` | Full scan interval in minutes (default: 30) | No |

```bash
ideviewer register \
  --customer-key YOUR-UUID-KEY \
  --portal-url http://localhost:5000 \
  --interval 15
```

Registration performs these steps:
1. Validates the customer key with the portal
2. Registers the host
3. Saves configuration to `~/.ideviewer/config.json`
4. Runs an initial scan and submits results
5. Installs gitleaks and pre-commit hooks
6. Starts the daemon

---

## `ideviewer daemon`

Start the daemon for continuous monitoring.

| Flag | Short | Description |
|------|-------|-------------|
| `--customer-key` | `-k` | Customer key (UUID) |
| `--portal-url` | `-p` | Portal URL |
| `--interval` | `-i` | Check-in interval in minutes (default: 60) |
| `--output` | `-o` | Output file for results |
| `--log-file` | | Log file path |
| `--pid-file` | | PID file path |
| `--foreground` | `-f` | Run in foreground (do not daemonize) |

```bash
ideviewer daemon --foreground                    # Use saved config
ideviewer daemon --foreground --interval 15      # Override interval
ideviewer daemon -k KEY -p URL --foreground      # New config
```

---

## `ideviewer stop`

Stop the running daemon.

| Flag | Short | Description |
|------|-------|-------------|
| `--pid-file` | | PID file path |

```bash
ideviewer stop
```

---

## `ideviewer hooks`

Manage pre-commit hooks for secret scanning.

### `ideviewer hooks status`

Show the current status of global pre-commit hooks, including whether gitleaks is installed.

### `ideviewer hooks install`

Install gitleaks (if not present) and configure global pre-commit hooks.

### `ideviewer hooks uninstall`

Remove global pre-commit hooks.

```bash
ideviewer hooks status
ideviewer hooks install
ideviewer hooks uninstall
```

---

## `ideviewer update`

Check for and install updates from GitHub Releases.

| Flag | Short | Description |
|------|-------|-------------|
| `--check` | | Only check for updates, do not install |
| `--yes` | `-y` | Skip confirmation prompt |

```bash
ideviewer update --check    # Check only
ideviewer update            # Download and install
ideviewer update --yes      # Non-interactive update
```

---

## `ideviewer version`

Print the current version.

```bash
ideviewer version
```
