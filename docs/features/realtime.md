---
title: Real-Time Monitoring
nav_order: 5
parent: Features
---

# Real-Time Monitoring

IDEViewer uses filesystem watchers to detect extension changes in real time, triggering targeted rescans within 30 seconds of an install, update, or removal.

## How It Works

The daemon uses [fsnotify](https://github.com/fsnotify/fsnotify) to watch IDE extension directories for file system events. When a change is detected:

1. A 30-second debounce timer starts (to batch rapid changes like multi-file extension installs)
2. After the debounce period, a targeted rescan runs for the affected IDE only
3. Results are submitted to the portal immediately
4. The portal's live update indicator reflects the change

## Watched Directories

| IDE | Watched Path |
|-----|-------------|
| VS Code | `~/.vscode/extensions` |
| Cursor | `~/.cursor/extensions` |
| VSCodium | `~/.vscode-oss/extensions` |
| Kiro | `~/.kiro/extensions` |
| JetBrains | `~/.config/JetBrains/*/plugins` |

## 30-Second Debounce

When an extension is installed, the package manager often creates, modifies, and renames multiple files in rapid succession. The debounce timer ensures IDEViewer waits for the install to complete before scanning, avoiding partial reads and unnecessary API calls.

## Targeted Rescan

Rather than running a full scan of all IDEs when one extension changes, the daemon performs a targeted rescan of only the affected IDE. This is faster and reduces load on both the machine and the portal.

## Real-Time Event API

The portal exposes an API endpoint that the daemon uses to report real-time events. The portal UI displays a live update indicator showing when the last real-time event was received.

## Portal Integration

In the portal, the host detail page shows:

- A **live update indicator** (green dot) when the daemon is actively monitoring
- Timestamps showing when the last real-time change was detected
- The specific extension that was added, updated, or removed
