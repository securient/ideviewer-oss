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
| `--push` | | Send results to the portal **and** close any pending on-demand scan request for this host |

```bash
ideviewer scan                          # Table output
ideviewer scan --json                   # JSON output
ideviewer scan --output-sarif > scan.sarif   # SARIF output
ideviewer scan -o results.json          # Save to file
ideviewer scan --portal                 # Submit to portal
ideviewer scan --push                   # Submit and fulfil a pending scan request
```

### `--portal` vs `--push`

`--portal` submits a report. `--push` also looks for an on-demand scan request
the portal is waiting on for this host, marks it in progress, and closes it as
completed when the report is accepted — the manual escape hatch for a daemon
that is not collecting its work.

A push cannot overwrite daemon results: scan reports are append-only rows, and
retention only clears the raw payload of superseded reports. It can, however,
make a hand-run scan look like routine telemetry, so every push is recorded
with `source=cli` on the report and the fulfilled request's log says it was
completed manually rather than by the daemon.

If no request is pending, `--push` behaves exactly like `--portal`.

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
  --portal-url http://localhost:8090 \
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

## `ideviewer status`

Show the active configuration, daemon state, and portal connectivity — the
first thing to run when something is not working. See
[Troubleshooting](troubleshooting.md).

| Flag | Short | Description |
|------|-------|-------------|
| `--no-portal` | | Skip the portal connectivity check |
| `--pid-file` | | PID file path |

It lists every configuration path IDEViewer can load, marks the one actually in
force, and flags the rest as shadowed leftovers. Credentials are masked.

```bash
ideviewer status
ideviewer status --no-portal    # offline: config and daemon state only
```

---

## `ideviewer reset`

Remove the local state a reinstall would otherwise inherit. Nothing is sent to
the portal and no host records are deleted there.

| Flag | Short | Description |
|------|-------|-------------|
| `--config` | | Remove every IDEViewer configuration file (the default) |
| `--logs` | | Remove daemon log files |
| `--hooks` | | Uninstall the global git pre-commit hooks |
| `--quarantine` | | Remove the quarantine directory (quarantined extensions are deleted) |
| `--all` | | Everything above |
| `--yes` | `-y` | Skip the confirmation prompt |
| `--keep-daemon` | | Do not stop the running daemon first |

`reset` stops the daemon before deleting, because removing the config from
under a running daemon leaves it using the copy already in memory. Removing a
system-level config requires elevation.

```bash
ideviewer reset                 # stale configuration only
ideviewer reset --all           # configuration, logs, hooks, quarantine
ideviewer reset --all --yes     # non-interactive
```

---

## `ideviewer stop`

Stop the running daemon and wait for the process to exit. The PID file is
removed only once the process is actually gone, so a failed stop stays visible
to `ideviewer status`.

| Flag | Short | Description |
|------|-------|-------------|
| `--pid-file` | | PID file path |
| `--timeout` | | How long to wait for the daemon to exit (default `10s`) |

```bash
ideviewer stop
ideviewer stop --timeout 30s
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

The daemon is stopped before the installer runs and restarted afterwards. This
matters most on Windows, where the installer cannot replace a running
`ideviewer.exe` — a silent upgrade would otherwise defer the replacement and
leave the old daemon running while reporting success.

```bash
ideviewer update --check    # Check only
ideviewer update            # Download and install
ideviewer update --yes      # Non-interactive update
ideviewer status            # Confirm the new version is the one running
```

---

## `ideviewer version`

Print the current version.

```bash
ideviewer version
```
