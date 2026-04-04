---
title: Security Features
nav_order: 6
parent: Features
---

# Security Features

IDEViewer includes several security mechanisms to ensure the integrity of the scanning daemon and detect attempts to bypass security controls.

## Tamper Detection

The daemon computes SHA-256 checksums of its own critical files and reports changes to the portal:

- **Daemon binary** -- Detects if the `ideviewer` binary has been replaced or modified
- **Configuration file** -- Detects unauthorized changes to `~/.ideviewer/config.json`
- **Service files** -- Detects modifications to the LaunchAgent plist (macOS) or systemd unit (Linux)

When a checksum mismatch is detected, the daemon sends a tamper alert to the portal immediately. The portal displays these alerts prominently on the dashboard and host detail pages.

## Git Hook Bypass Detection

IDEViewer detects when developers use `--no-verify` to bypass pre-commit hooks. This is a common way to skip secret scanning checks, and it's reported to the portal so security teams have visibility into bypass behavior.

## Heartbeat Monitoring

The daemon sends periodic heartbeats to the portal. The portal uses these to determine host health:

| Status | Indicator | Meaning |
|--------|-----------|---------|
| **Online** | Green | Heartbeat received within the expected interval |
| **Stale** | Yellow | Heartbeat is overdue but within tolerance |
| **Offline** | Red | No heartbeat received beyond tolerance threshold |

## Pre-commit Hooks

IDEViewer installs global pre-commit hooks that scan staged files for secrets before each commit. The hooks integrate with [gitleaks](https://github.com/gitleaks/gitleaks) when available, falling back to IDEViewer's built-in scanner.

```bash
# Install hooks manually
ideviewer hooks install

# Check hook status
ideviewer hooks status

# Uninstall hooks
ideviewer hooks uninstall
```

The hook runs `ideviewer secrets --check-staged --exit-code` on every `git commit`. If a secret is detected, the commit is blocked and the developer sees the finding with file path and line number.

## Daemon Self-Protection

The daemon:

- Writes a PID file to prevent duplicate instances
- Handles `SIGTERM` gracefully for clean shutdown
- Automatically restarts via LaunchAgent (`KeepAlive=true` on macOS) or systemd (`Restart=always` on Linux)
- Logs all activity to a local log file for forensic review
