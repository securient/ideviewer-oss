---
title: Installation
nav_order: 1
---

# Installation

## Pre-built Binaries

Download the latest release from the [GitHub Releases](https://github.com/securient/ideviewer-oss/releases) page:

| Platform | File | Notes |
|----------|------|-------|
| macOS (Apple Silicon) | `IDEViewer-*-arm64.pkg` | Installs to `/usr/local/bin/ideviewer` |
| Windows (64-bit) | `IDEViewer-Setup-*.exe` | Standard Windows installer |
| Linux (amd64) | `ideviewer_*_amd64.deb` | Debian/Ubuntu package |
| Linux (arm64) | `ideviewer_*_arm64.deb` | Debian/Ubuntu package (ARM) |

### macOS Gatekeeper

If macOS blocks the binary because it's from an unidentified developer:

```bash
# Option 1: Remove quarantine attribute
xattr -d com.apple.quarantine /usr/local/bin/ideviewer

# Option 2: Allow in System Preferences
# Go to System Preferences > Privacy & Security > "Allow Anyway"
```

{: .important }
The `.pkg` installer is not code-signed with an Apple Developer ID in the open-source release. For MDM deployments with code signing, see the [MDM deployment guide](deployment/mdm.md).

### Linux Installation

```bash
sudo dpkg -i ideviewer_0.3.0_amd64.deb
ideviewer version
```

The `.deb` package installs the binary to `/usr/local/bin/ideviewer` and sets up a systemd service file.

## Build from Source

Requires Go 1.25 or later.

```bash
git clone https://github.com/securient/ideviewer-oss.git
cd ideviewer-oss

# Build for your current platform
make build

# Build for all platforms (macOS, Linux, Windows)
make build-all
```

The binary is output to `dist/ideviewer-<os>-<arch>`.

## Self-Update

IDEViewer can update itself from GitHub Releases:

```bash
# Check for updates
ideviewer update --check

# Download and install the latest version
ideviewer update

# Skip confirmation prompt
ideviewer update --yes
```

After updating, restart the daemon to use the new version:

```bash
ideviewer stop
ideviewer daemon --foreground
```

## Verify Installation

```bash
ideviewer version
ideviewer scan        # Quick test — should list detected IDEs
```
