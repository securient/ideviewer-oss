# IDEViewer — MDM Deployment Guide

Deploy IDEViewer daemon silently to managed macOS devices via JAMF, Mosyle, Kandji, or other MDM solutions.

## What Gets Deployed

| Component | Path | Purpose |
|-----------|------|---------|
| Binary | `/usr/local/bin/ideviewer` | CLI + daemon |
| Uninstaller | `/usr/local/bin/ideviewer-uninstall` | Clean removal |
| LaunchAgent | `/Library/LaunchAgents/com.ideviewer.daemon.plist` | Auto-start as user |
| Logs | `/tmp/ideviewer-daemon.log` | Daemon output |
| Config | `~/.ideviewer/config.json` | Portal connection (created on register) |

## Deployment Steps

### 1. Build or download the .pkg

```bash
# Build from source
./build_scripts/build_all.sh --macos

# Or download from GitHub Releases
# https://github.com/securient/ideviewer-oss/releases
```

### 2. Upload PPPC profile (required — prevents access prompts)

The PPPC profile grants the daemon Full Disk Access so it can scan IDE extensions, project directories, and config files without prompting the user.

**File:** `deploy/mdm/ideviewer-tcc.mobileconfig`

#### JAMF Pro
1. Go to **Computers > Configuration Profiles**
2. Click **New**
3. Under **Privacy Preferences Policy Control**, click **Upload**
4. Upload `ideviewer-tcc.mobileconfig`
5. Scope to target devices/groups
6. Save

#### Mosyle
1. Go to **Management > Profiles**
2. Click **Add Profile > Custom**
3. Upload `ideviewer-tcc.mobileconfig`
4. Assign to devices

#### Kandji
1. Go to **Library > Custom Profile**
2. Upload `ideviewer-tcc.mobileconfig`
3. Assign to blueprint

#### Manual (testing)
```bash
sudo profiles install -path deploy/mdm/ideviewer-tcc.mobileconfig
```

### 3. Deploy the .pkg installer

#### JAMF Pro
1. Go to **Computer Management > Packages**
2. Upload `IDEViewer-0.3.0.pkg`
3. Create a **Policy**:
   - Trigger: Enrollment Complete + Recurring Check-in
   - Packages: Install `IDEViewer-0.3.0.pkg`
   - Scope: Target devices
4. The postinstall script handles directory creation and permissions

#### Mosyle / Kandji / Other
1. Upload the .pkg as a managed installer
2. Deploy to target devices

### 4. Register with portal (post-install script)

After the .pkg is installed, the daemon needs to be registered with your portal. Create a JAMF script or MDM command:

```bash
#!/bin/bash
# Run as the logged-in user (not root) so config goes to user's home
LOGGED_IN_USER=$(stat -f%Su /dev/console)
CUSTOMER_KEY="YOUR-CUSTOMER-KEY-HERE"
PORTAL_URL="https://portal.yourcompany.com"

sudo -u "$LOGGED_IN_USER" /usr/local/bin/ideviewer register \
    --customer-key "$CUSTOMER_KEY" \
    --portal-url "$PORTAL_URL"
```

**JAMF Pro:**
1. Go to **Computer Management > Scripts**
2. Create a new script with the above content
3. Set **Priority**: After
4. Add to the same Policy as the .pkg install
5. Set to run as **Current User** (not root)

### 5. Verify deployment

Check enrollment from the portal or run on a target machine:

```bash
ideviewer version
launchctl list | grep ideviewer
tail -f /tmp/ideviewer-daemon.log
```

## Silent Upgrade

To upgrade the daemon on managed devices:

1. Build/download the new .pkg
2. Upload to JAMF as a new package version
3. Create an upgrade policy (the preinstall script stops the old daemon)
4. The LaunchAgent will restart automatically (KeepAlive=true)

## Silent Uninstall

```bash
#!/bin/bash
sudo /usr/local/bin/ideviewer-uninstall <<< "y"
```

Or deploy as a JAMF script with the `-y` flag for non-interactive mode.

## Code Signing (Production)

For production MDM deployments, code sign the binary and update the PPPC profile:

```bash
# Sign the binary
codesign --sign "Developer ID Application: Your Company (TEAMID)" \
    --options runtime \
    dist/ideviewer-darwin-arm64

# Get the code requirement
codesign -dr - dist/ideviewer-darwin-arm64
```

Then update `ideviewer-tcc.mobileconfig`:
- Change `IdentifierType` from `path` to `bundleID`
- Set `Identifier` to `com.ideviewer.daemon`
- Add `CodeRequirement` with the output from `codesign -dr`

## Troubleshooting

| Issue | Solution |
|-------|----------|
| TCC prompt still appears | Ensure PPPC profile is deployed BEFORE the .pkg |
| Daemon not scanning | Check `launchctl list \| grep ideviewer` — exit code 0 = running |
| No data in portal | Verify registration: `cat ~/.ideviewer/config.json` |
| Wrong user context | LaunchAgent runs as logged-in user; don't use LaunchDaemon |
| Daemon stops on logout | Expected for LaunchAgent — restarts on next login |
