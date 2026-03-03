#!/bin/bash
#
# IDE Viewer Uninstaller for macOS
#
# This script completely removes IDE Viewer from your system.
#
# Usage:
#   sudo ./uninstall_macos.sh
#
# Or if installed via .pkg:
#   sudo /usr/local/bin/ideviewer-uninstall
#

set -e

# Configuration
BUNDLE_ID="com.ideviewer.daemon"
APP_NAME="IDE Viewer"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo ""
echo "======================================"
echo "  $APP_NAME Uninstaller"
echo "======================================"
echo ""

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root (sudo)${NC}"
    echo ""
    echo "Usage: sudo $0"
    exit 1
fi

# Confirm uninstallation
echo -e "${YELLOW}This will completely remove IDE Viewer from your system.${NC}"
echo ""
echo "The following will be removed:"
echo "  • /usr/local/bin/ideviewer"
echo "  • /usr/local/bin/ideviewer-uninstall"
echo "  • /Library/LaunchDaemons/$BUNDLE_ID.plist"
echo "  • /var/log/ideviewer/"
echo "  • Package receipt from system database"
echo ""
read -p "Are you sure you want to continue? [y/N] " -n 1 -r
echo ""

if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Uninstallation cancelled."
    exit 0
fi

echo ""
echo "Uninstalling $APP_NAME..."
echo ""

# Step 0: Send uninstall notification to the portal (before removing anything)
echo -n "Notifying portal of uninstallation... "
if [ -f "$HOME/.ideviewer/config.json" ]; then
    PORTAL_URL=$(python3 -c "import json; print(json.load(open('$HOME/.ideviewer/config.json'))['portal_url'])" 2>/dev/null || true)
    CUSTOMER_KEY=$(python3 -c "import json; print(json.load(open('$HOME/.ideviewer/config.json'))['customer_key'])" 2>/dev/null || true)
    HOSTNAME=$(hostname)
    
    if [ -n "$PORTAL_URL" ] && [ -n "$CUSTOMER_KEY" ]; then
        curl -s -X POST "$PORTAL_URL/api/alert" \
            -H "Content-Type: application/json" \
            -H "X-Customer-Key: $CUSTOMER_KEY" \
            -d "{\"hostname\": \"$HOSTNAME\", \"alert_type\": \"uninstall_attempt\", \"details\": \"IDE Viewer is being uninstalled via the uninstall script on macOS. Initiated by user $(whoami).\"}" \
            --connect-timeout 5 --max-time 10 > /dev/null 2>&1 && \
            echo -e "${GREEN}notified${NC}" || echo -e "${YELLOW}portal unreachable${NC}"
    else
        echo "no configuration found"
    fi
else
    echo "no configuration found"
fi

# Step 1: Stop the daemon if running
echo -n "Stopping daemon if running... "
if launchctl list 2>/dev/null | grep -q "$BUNDLE_ID"; then
    launchctl unload "/Library/LaunchDaemons/$BUNDLE_ID.plist" 2>/dev/null || true
    echo -e "${GREEN}stopped${NC}"
else
    echo "not running"
fi

# Step 2: Kill any running processes
echo -n "Stopping any running processes... "
pkill -f "ideviewer" 2>/dev/null || true
echo -e "${GREEN}done${NC}"

# Step 3: Remove the executable
echo -n "Removing executable... "
if [ -f "/usr/local/bin/ideviewer" ]; then
    rm -f "/usr/local/bin/ideviewer"
    echo -e "${GREEN}removed${NC}"
else
    echo "not found"
fi

# Step 4: Remove the uninstaller itself
echo -n "Removing uninstaller... "
if [ -f "/usr/local/bin/ideviewer-uninstall" ]; then
    rm -f "/usr/local/bin/ideviewer-uninstall"
    echo -e "${GREEN}removed${NC}"
else
    echo "not found"
fi

# Step 5: Remove LaunchDaemon
echo -n "Removing LaunchDaemon... "
if [ -f "/Library/LaunchDaemons/$BUNDLE_ID.plist" ]; then
    rm -f "/Library/LaunchDaemons/$BUNDLE_ID.plist"
    echo -e "${GREEN}removed${NC}"
else
    echo "not found"
fi

# Step 6: Remove log directory
echo -n "Removing log directory... "
if [ -d "/var/log/ideviewer" ]; then
    rm -rf "/var/log/ideviewer"
    echo -e "${GREEN}removed${NC}"
else
    echo "not found"
fi

# Step 7: Remove package receipt from system database
echo -n "Removing package receipt... "
if pkgutil --pkgs 2>/dev/null | grep -q "$BUNDLE_ID"; then
    pkgutil --forget "$BUNDLE_ID" 2>/dev/null || true
    echo -e "${GREEN}removed${NC}"
else
    echo "not found"
fi

# Step 8: Remove any user-level configurations (optional)
echo -n "Checking for user configurations... "
USER_CONFIG_DIR="$HOME/.config/ideviewer"
if [ -d "$USER_CONFIG_DIR" ]; then
    read -p "Remove user configuration at $USER_CONFIG_DIR? [y/N] " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$USER_CONFIG_DIR"
        echo -e "${GREEN}removed${NC}"
    else
        echo "kept"
    fi
else
    echo "none found"
fi

echo ""
echo "======================================"
echo -e "${GREEN}  $APP_NAME has been uninstalled${NC}"
echo "======================================"
echo ""
echo "Thank you for using IDE Viewer!"
echo ""
