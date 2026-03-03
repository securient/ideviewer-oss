#!/bin/bash
#
# Build script for Debian/Ubuntu .deb package
#
# Requirements:
#   - Python 3.8+
#   - dpkg-deb (standard on Debian/Ubuntu)
#   - OR fpm (gem install fpm) for advanced packaging
#
# Usage:
#   ./build_scripts/build_debian.sh
#
# Output:
#   dist/ideviewer_0.1.0_amd64.deb
#

set -e

# Configuration
APP_NAME="ideviewer"
APP_VERSION="0.1.0"
ARCHITECTURE="amd64"
MAINTAINER="IDE Viewer Team <support@ideviewer.com>"
DESCRIPTION="Cross-platform IDE and Extension Scanner daemon"

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build/deb"
DIST_DIR="$PROJECT_DIR/dist"
PACKAGE_DIR="$BUILD_DIR/${APP_NAME}_${APP_VERSION}_${ARCHITECTURE}"

echo "=== Building IDE Viewer for Debian/Ubuntu ==="
echo "Version: $APP_VERSION"
echo ""

# Clean previous builds
echo "Cleaning previous builds..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"
mkdir -p "$DIST_DIR"

# Create virtual environment if needed
if [ ! -d "$PROJECT_DIR/venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv "$PROJECT_DIR/venv"
fi

# Activate and install dependencies
echo "Installing dependencies..."
source "$PROJECT_DIR/venv/bin/activate"
pip install --upgrade pip
pip install -e "$PROJECT_DIR"
pip install pyinstaller

# Build executable with PyInstaller
echo "Building executable with PyInstaller..."
cd "$PROJECT_DIR"
pyinstaller --clean --noconfirm ideviewer.spec

# Verify executable
if [ ! -f "$DIST_DIR/ideviewer" ]; then
    echo "ERROR: Executable not found at $DIST_DIR/ideviewer"
    exit 1
fi

echo "Executable built successfully!"

# Create package directory structure
echo "Creating Debian package structure..."
mkdir -p "$PACKAGE_DIR/DEBIAN"
mkdir -p "$PACKAGE_DIR/usr/local/bin"
mkdir -p "$PACKAGE_DIR/etc/ideviewer"
mkdir -p "$PACKAGE_DIR/lib/systemd/system"
mkdir -p "$PACKAGE_DIR/var/log/ideviewer"

# Copy executable
cp "$DIST_DIR/ideviewer" "$PACKAGE_DIR/usr/local/bin/"
chmod 755 "$PACKAGE_DIR/usr/local/bin/ideviewer"

# Create control file
cat > "$PACKAGE_DIR/DEBIAN/control" << EOF
Package: $APP_NAME
Version: $APP_VERSION
Section: utils
Priority: optional
Architecture: $ARCHITECTURE
Maintainer: $MAINTAINER
Description: $DESCRIPTION
 IDE Viewer is a daemon that scans installed IDEs and their
 extensions for security analysis. It detects VS Code, Cursor,
 JetBrains IDEs, Sublime Text, Vim/Neovim, and Xcode.
 .
 Features:
  - Detects installed IDEs and their versions
  - Scans extensions for permissions and capabilities
  - Identifies potentially dangerous extensions
  - Reports to centralized portal for monitoring
Homepage: https://github.com/ideviewer/ideviewer
EOF

# Create conffiles (config files that should be preserved during upgrade)
cat > "$PACKAGE_DIR/DEBIAN/conffiles" << EOF
/etc/ideviewer/config.json
EOF

# Create default config file
cat > "$PACKAGE_DIR/etc/ideviewer/config.json" << EOF
{
    "portal_url": "",
    "customer_key": "",
    "host_uuid": "",
    "checkin_interval_minutes": 60
}
EOF
chmod 644 "$PACKAGE_DIR/etc/ideviewer/config.json"

# Create systemd service file
cat > "$PACKAGE_DIR/lib/systemd/system/ideviewer.service" << EOF
[Unit]
Description=IDE Viewer Daemon
Documentation=https://github.com/ideviewer/ideviewer
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ideviewer daemon --foreground
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/ideviewer /etc/ideviewer
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

# Create postinst script
cat > "$PACKAGE_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/bash
set -e

# Create log directory
mkdir -p /var/log/ideviewer
chmod 755 /var/log/ideviewer

# Reload systemd
systemctl daemon-reload

echo ""
echo "============================================"
echo "  IDE Viewer installed successfully!"
echo "============================================"
echo ""
echo "IMPORTANT: You need a Customer Key to use this daemon."
echo ""
echo "Step 1: Get your customer key from the IDE Viewer Portal"
echo ""
echo "Step 2: Register this machine:"
echo "  sudo ideviewer register --customer-key YOUR_KEY --portal-url https://portal.example.com"
echo ""
echo "Step 3: Enable and start the daemon:"
echo "  sudo systemctl enable ideviewer"
echo "  sudo systemctl start ideviewer"
echo ""
echo "Check status: sudo systemctl status ideviewer"
echo "View logs: sudo journalctl -u ideviewer -f"
echo ""

exit 0
EOF
chmod 755 "$PACKAGE_DIR/DEBIAN/postinst"

# Create prerm script
cat > "$PACKAGE_DIR/DEBIAN/prerm" << 'EOF'
#!/bin/bash
set -e

# Stop service if running
if systemctl is-active --quiet ideviewer; then
    echo "Stopping IDE Viewer service..."
    systemctl stop ideviewer
fi

# Disable service
if systemctl is-enabled --quiet ideviewer 2>/dev/null; then
    echo "Disabling IDE Viewer service..."
    systemctl disable ideviewer
fi

exit 0
EOF
chmod 755 "$PACKAGE_DIR/DEBIAN/prerm"

# Create postrm script
cat > "$PACKAGE_DIR/DEBIAN/postrm" << 'EOF'
#!/bin/bash
set -e

# Reload systemd
systemctl daemon-reload

# On purge, remove config and logs
if [ "$1" = "purge" ]; then
    rm -rf /etc/ideviewer
    rm -rf /var/log/ideviewer
fi

exit 0
EOF
chmod 755 "$PACKAGE_DIR/DEBIAN/postrm"

# Build the .deb package
echo "Building .deb package..."
DEB_FILE="$DIST_DIR/${APP_NAME}_${APP_VERSION}_${ARCHITECTURE}.deb"
dpkg-deb --build --root-owner-group "$PACKAGE_DIR" "$DEB_FILE"

echo ""
echo "=== Build Complete ==="
echo "Package: $DEB_FILE"
echo ""
echo "To install:"
echo "  sudo dpkg -i $DEB_FILE"
echo ""
echo "Or with dependencies:"
echo "  sudo apt install ./$DEB_FILE"
echo ""
