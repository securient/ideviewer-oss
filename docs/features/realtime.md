---
title: Real-Time Monitoring
nav_order: 5
parent: Features
---

# Real-Time Monitoring

IDEViewer watches the parts of a developer workstation where software arrives, and reacts within seconds rather than waiting for the next scheduled scan.

A periodic full scan still runs on the configured interval (30 minutes by default). Real-time monitoring sits alongside it and closes the window between "something was installed" and "the portal knows".

## What is watched

The daemon uses [fsnotify](https://github.com/fsnotify/fsnotify) and groups watched directories into three categories. Each category triggers only the rescan it invalidates — installing an extension does not re-walk every project on the machine.

| Category | Directories | Triggers a rescan of |
|----------|-------------|----------------------|
| `extensions` | `~/.vscode/extensions`, `~/.cursor/extensions`, `~/.vscode-oss/extensions`, `~/.kiro/extensions`, and JetBrains `*/plugins` | IDE extensions and plugins |
| `aitools` | `~/.claude`, `~/.cursor`, `~/.kiro/settings`, `~/.openclaw`, `~/.clawdbot`, `~/.config/openclaw`, `~/.config/clawdbot`, and the editor `User` settings directories | AI assistant config and MCP servers |
| `projects` | Any directory containing a dependency manifest | Packages **and** secrets |

The `projects` category covers both package manifests and secrets because `.env` files live in the same directories a lockfile does.

A directory counts as a project when it contains any of:

`package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `requirements.txt`, `Pipfile`, `Pipfile.lock`, `poetry.lock`, `pyproject.toml`, `go.mod`, `go.sum`, `Cargo.toml`, `Cargo.lock`, `Gemfile`, `Gemfile.lock`, `composer.json`, `composer.lock`

Project discovery walks the same roots as the dependency scanner (`~`, `~/Documents`, `~/Projects`, `~/dev`, `~/code`, `~/src`, `~/work`, `~/go/src` and similar), to a depth of 4.

## What is not watched, and why

**`node_modules` is excluded.** Watching it would cost tens of thousands of directory watches and buy nothing: installing a package rewrites the manifest and lockfile in the project directory, which *is* watched, so the change is caught there.

**Only manifest-bearing directories are watched, not every directory walked.** On a typical developer laptop the walk sees several thousand directories but only a couple of hundred are projects.

**Watch count is capped at 2048.** Each watch costs a file descriptor under kqueue on macOS and an inotify watch on Linux, where `max_user_watches` still defaults to 8192 on some distributions. If the cap is reached the daemon logs it, and the remaining projects are still covered by the periodic scan:

```
Watcher: monitoring 113 directories (1 extension, 2 AI tool, 110 project)
```

## Timing

A 30-second debounce batches rapid changes. Installing an extension or running `npm install` touches many files in quick succession; the debounce waits for the operation to finish rather than scanning a half-written tree.

In practice, from filesystem change to the portal having the data:

| Change | Typical end-to-end |
|--------|--------------------|
| Extension installed | ~30–40 seconds |
| AI tool or MCP config edited | ~30 seconds |
| Dependency manifest changed | ~35–50 seconds (varies with project count) |

## How a change is processed

1. fsnotify reports a change in a watched directory
2. The 30-second debounce timer starts, batching further events
3. The daemon runs a **targeted** rescan for the affected categories only
4. Results are posted to `POST /api/realtime-event`
5. The portal updates its inventory and emits any matching events (see [Integrations](../portal/integrations.html))

Several categories changing within one debounce window are handled in a single batch.

## Relationship to the periodic scan

The periodic scan is the safety net: it covers anything outside the watched set, re-establishes state after the daemon restarts, and re-checks categories a realtime event does not touch.

The daemon compares each scan's results against the previous cycle and **only reports when something differs**. On a stable machine it scans quietly and sends nothing. This is why the host page shows **Last change** rather than "last scan" — the portal is told when the inventory changed, not every time a scan ran. Daemon liveness is shown separately by the heartbeat indicator beside it.

## Verifying it works

```bash
ideviewer status
```

shows whether the daemon is running and reaching the portal. The daemon log records each watcher decision:

```
Realtime: 1 change(s) detected in [projects], rescanning
Realtime rescan: 7662 packages
Realtime rescan: 2 secret finding(s)
Realtime event submitted: map[changes_processed:1 received:true ...]
```

On the host detail page, a recent change appears as **Last live update**.
