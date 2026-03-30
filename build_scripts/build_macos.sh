#!/bin/bash
#
# Build script for macOS .pkg installer
#
# Requirements:
#   - Python 3.8+
#   - PyInstaller: pip install pyinstaller
#   - Xcode Command Line Tools (for pkgbuild/productbuild)
#
# Usage:
#   ./build_scripts/build_macos.sh
#

set -e

# Configuration
APP_NAME="IDEViewer"
APP_VERSION="${APP_VERSION:-0.1.0}"
BUNDLE_ID="com.ideviewer.daemon"
INSTALL_LOCATION="/usr/local/bin"

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
DIST_DIR="$PROJECT_DIR/dist"
PKG_DIR="$BUILD_DIR/pkg"
SCRIPTS_DIR="$PKG_DIR/scripts"

echo "=== Building IDE Viewer for macOS ==="
echo "Version: $APP_VERSION"
echo ""

# Clean previous build artifacts (but preserve dist/ if executable already exists)
echo "Cleaning previous build artifacts..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR" "$DIST_DIR" "$PKG_DIR" "$SCRIPTS_DIR"

# Build executable if it doesn't already exist (CI may have built it already)
if [ -f "$DIST_DIR/ideviewer" ]; then
    echo "Executable already exists at $DIST_DIR/ideviewer, skipping build..."
else
    # Create virtual environment if it doesn't exist
    if [ ! -d "$PROJECT_DIR/venv" ]; then
        echo "Creating virtual environment..."
        python3 -m venv "$PROJECT_DIR/venv"
    fi

    # Activate virtual environment
    source "$PROJECT_DIR/venv/bin/activate"

    # Install dependencies
    echo "Installing dependencies..."
    pip install --upgrade pip
    pip install -e "$PROJECT_DIR"
    pip install pyinstaller

    # Build executable with PyInstaller
    echo "Building executable with PyInstaller..."
    cd "$PROJECT_DIR"
    pyinstaller --clean --noconfirm ideviewer.spec

    # Verify the executable was created
    if [ ! -f "$DIST_DIR/ideviewer" ]; then
        echo "ERROR: Executable not found at $DIST_DIR/ideviewer"
        exit 1
    fi

    echo "Executable built successfully!"
fi

# Create package structure
echo "Creating package structure..."
PKG_ROOT="$PKG_DIR/root"
mkdir -p "$PKG_ROOT/usr/local/bin"
mkdir -p "$PKG_ROOT/Library/LaunchDaemons"

# Copy executable
cp "$DIST_DIR/ideviewer" "$PKG_ROOT/usr/local/bin/"
chmod +x "$PKG_ROOT/usr/local/bin/ideviewer"

# Copy uninstaller script
cp "$SCRIPT_DIR/uninstall_macos.sh" "$PKG_ROOT/usr/local/bin/ideviewer-uninstall"
chmod +x "$PKG_ROOT/usr/local/bin/ideviewer-uninstall"

# Create LaunchDaemon plist for auto-start (optional)
cat > "$PKG_ROOT/Library/LaunchDaemons/com.ideviewer.daemon.plist" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ideviewer.daemon</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/ideviewer</string>
        <string>daemon</string>
        <string>--foreground</string>
        <string>--interval</string>
        <string>60</string>
        <string>--output</string>
        <string>/var/log/ideviewer/scan.json</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/var/log/ideviewer/stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/ideviewer/stderr.log</string>
</dict>
</plist>
EOF

# Create postinstall script
cat > "$SCRIPTS_DIR/postinstall" << 'EOF'
#!/bin/bash
# Post-installation script

# Create log directory
mkdir -p /var/log/ideviewer
chmod 755 /var/log/ideviewer

# Make executables accessible
chmod +x /usr/local/bin/ideviewer
chmod +x /usr/local/bin/ideviewer-uninstall

echo ""
echo "============================================"
echo "  IDE Viewer installed successfully!"
echo "============================================"
echo ""
echo "IMPORTANT: You need a Customer Key to use this daemon."
echo ""
echo "Step 1: Get your customer key from the IDE Viewer Portal"
echo "Step 2: Register this machine:"
echo ""
echo "  ideviewer register \\"
echo "    --customer-key YOUR_KEY_HERE \\"
echo "    --portal-url https://your-portal.example.com"
echo ""
echo "Step 3: Start the daemon:"
echo "  ideviewer daemon --foreground"
echo ""
echo "Other commands:"
echo "  ideviewer scan          - Scan for IDEs and extensions"
echo "  ideviewer stats         - Show statistics"
echo "  ideviewer dangerous     - List dangerous extensions"
echo ""
echo "To uninstall:"
echo "  sudo ideviewer-uninstall"
echo ""

exit 0
EOF
chmod +x "$SCRIPTS_DIR/postinstall"

# Create preinstall script
cat > "$SCRIPTS_DIR/preinstall" << 'EOF'
#!/bin/bash
# Pre-installation script

# Stop existing daemon if running
if launchctl list | grep -q "com.ideviewer.daemon"; then
    echo "Stopping existing IDE Viewer daemon..."
    sudo launchctl unload /Library/LaunchDaemons/com.ideviewer.daemon.plist 2>/dev/null || true
fi

# Remove old executable if exists
if [ -f /usr/local/bin/ideviewer ]; then
    rm -f /usr/local/bin/ideviewer
fi

exit 0
EOF
chmod +x "$SCRIPTS_DIR/preinstall"

# Build the component package
echo "Building component package..."
pkgbuild \
    --root "$PKG_ROOT" \
    --scripts "$SCRIPTS_DIR" \
    --identifier "$BUNDLE_ID" \
    --version "$APP_VERSION" \
    --install-location "/" \
    "$PKG_DIR/IDEViewer-component.pkg"

# Create distribution XML
cat > "$PKG_DIR/distribution.xml" << EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>IDE Viewer</title>
    <organization>com.ideviewer</organization>
    <domains enable_localSystem="true"/>
    <options customize="never" require-scripts="true" rootVolumeOnly="true"/>
    
    <welcome file="welcome.txt"/>
    <license file="license.txt"/>
    <conclusion file="conclusion.txt"/>
    
    <pkg-ref id="$BUNDLE_ID"/>
    
    <choices-outline>
        <line choice="default">
            <line choice="$BUNDLE_ID"/>
        </line>
    </choices-outline>
    
    <choice id="default"/>
    <choice id="$BUNDLE_ID" visible="false">
        <pkg-ref id="$BUNDLE_ID"/>
    </choice>
    
    <pkg-ref id="$BUNDLE_ID" version="$APP_VERSION" onConclusion="none">IDEViewer-component.pkg</pkg-ref>
</installer-gui-script>
EOF

# Create welcome text
cat > "$PKG_DIR/welcome.txt" << EOF
Welcome to IDE Viewer Installer

IDE Viewer is a cross-platform daemon that detects installed IDEs and scans their extensions for security analysis.

Features:
• Detects VS Code, Cursor, JetBrains IDEs, Sublime Text, Vim/Neovim, Xcode
• Analyzes extension permissions and capabilities
• Identifies potentially dangerous extensions
• Runs as a daemon for continuous monitoring

This installer will install:
• ideviewer command-line tool to /usr/local/bin
• LaunchDaemon configuration (optional auto-start)

Click Continue to proceed.
EOF

# Create license text
cat > "$PKG_DIR/license.txt" << EOF
Apache License 2.0

Copyright 2024-2026 Securient

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
EOF

# Create conclusion text
cat > "$PKG_DIR/conclusion.txt" << EOF
IDE Viewer has been installed successfully!

The ideviewer command is now available in your terminal.

╔════════════════════════════════════════════════════════╗
║  NEXT STEPS - Registration Required                   ║
╠════════════════════════════════════════════════════════╣
║                                                        ║
║  1. Get your Customer Key from the Portal              ║
║                                                        ║
║  2. Register this machine:                             ║
║                                                        ║
║     ideviewer register \\                               ║
║       --customer-key YOUR_KEY \\                        ║
║       --portal-url https://portal.example.com          ║
║                                                        ║
║  3. Start the daemon:                                  ║
║     ideviewer daemon --foreground                      ║
║                                                        ║
╚════════════════════════════════════════════════════════╝

Other Commands:
  ideviewer scan          - Local scan (no portal)
  ideviewer stats         - Show statistics
  ideviewer dangerous     - List dangerous extensions

To uninstall:
  sudo ideviewer-uninstall
EOF

# Build the final product package
echo "Building final installer package..."
productbuild \
    --distribution "$PKG_DIR/distribution.xml" \
    --resources "$PKG_DIR" \
    --package-path "$PKG_DIR" \
    "$DIST_DIR/IDEViewer-$APP_VERSION.pkg"

echo ""
echo "=== Build Complete ==="
echo "Installer: $DIST_DIR/IDEViewer-$APP_VERSION.pkg"
echo ""
echo "To install:"
echo "  sudo installer -pkg $DIST_DIR/IDEViewer-$APP_VERSION.pkg -target /"
echo ""
echo "Or double-click the .pkg file to open the graphical installer."
