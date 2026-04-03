#!/bin/bash
#
# IDEViewer — Build all platforms locally
#
# Cross-compiles Go binaries for all platforms and creates installers
# where possible. Works from any OS (macOS, Linux, Windows via Git Bash).
#
# Usage:
#   ./build_scripts/build_all.sh              # Build everything
#   ./build_scripts/build_all.sh --binaries   # Binaries only (no installers)
#   ./build_scripts/build_all.sh --macos      # macOS binary + .pkg only
#   ./build_scripts/build_all.sh --version 0.3.0  # Override version
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
DIST_DIR="$PROJECT_DIR/dist"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

# Parse args
BUILD_MODE="all"
VERSION=""
while [[ $# -gt 0 ]]; do
    case $1 in
        --binaries)  BUILD_MODE="binaries"; shift ;;
        --macos)     BUILD_MODE="macos"; shift ;;
        --linux)     BUILD_MODE="linux"; shift ;;
        --windows)   BUILD_MODE="windows"; shift ;;
        --version)   VERSION="$2"; shift 2 ;;
        *)           echo "Unknown option: $1"; exit 1 ;;
    esac
done

cd "$PROJECT_DIR"

# Detect version from source if not overridden
if [ -z "$VERSION" ]; then
    VERSION=$(grep 'var Version' internal/version/version.go | cut -d'"' -f2)
fi
# Strip -dev suffix for release builds
RELEASE_VERSION="${VERSION%-dev}"

echo ""
echo -e "${CYAN}════════════════════════════════════════${NC}"
echo -e "${CYAN}  IDEViewer Build — v$RELEASE_VERSION${NC}"
echo -e "${CYAN}════════════════════════════════════════${NC}"
echo ""

# Check Go
if ! command -v go &>/dev/null; then
    echo -e "${RED}Error: Go is required. Install from https://go.dev/dl/${NC}"
    exit 1
fi
echo -e "Go version: ${DIM}$(go version)${NC}"
echo ""

mkdir -p "$DIST_DIR"

# ── Cross-compile binaries ──
build_binary() {
    local os=$1 arch=$2 suffix=$3
    local output="$DIST_DIR/ideviewer-${os}-${arch}${suffix}"
    echo -ne "  Building ${CYAN}${os}/${arch}${NC}... "
    CGO_ENABLED=0 GOOS=$os GOARCH=$arch go build \
        -ldflags "-s -w -X github.com/securient/ideviewer-oss/internal/version.Version=$RELEASE_VERSION" \
        -o "$output" ./cmd/ideviewer/
    local size=$(du -h "$output" | cut -f1 | xargs)
    echo -e "${GREEN}$output${NC} ${DIM}($size)${NC}"
}

echo -e "${CYAN}Building binaries...${NC}"

case $BUILD_MODE in
    macos)
        build_binary darwin arm64 ""
        ;;
    linux)
        build_binary linux amd64 ""
        build_binary linux arm64 ""
        ;;
    windows)
        build_binary windows amd64 ".exe"
        ;;
    *)
        build_binary linux amd64 ""
        build_binary linux arm64 ""
        build_binary darwin arm64 ""
        build_binary windows amd64 ".exe"
        ;;
esac

echo ""

if [ "$BUILD_MODE" = "binaries" ]; then
    echo -e "${GREEN}Binaries built in $DIST_DIR/${NC}"
    ls -lh "$DIST_DIR"/ideviewer-*
    exit 0
fi

# ── Platform-specific installers ──
echo -e "${CYAN}Building installers...${NC}"

# macOS .pkg (requires pkgbuild/productbuild — macOS only)
if [[ "$BUILD_MODE" == "all" || "$BUILD_MODE" == "macos" ]]; then
    if command -v pkgbuild &>/dev/null; then
        echo -ne "  Building ${CYAN}macOS .pkg${NC}... "
        # The build_macos.sh script expects the binary at dist/ideviewer
        cp "$DIST_DIR/ideviewer-darwin-arm64" "$DIST_DIR/ideviewer"
        APP_VERSION="$RELEASE_VERSION" "$SCRIPT_DIR/build_macos.sh" > /tmp/ideviewer-pkg-build.log 2>&1
        rm -f "$DIST_DIR/ideviewer"
        if [ -f "$DIST_DIR/IDEViewer-$RELEASE_VERSION.pkg" ]; then
            size=$(du -h "$DIST_DIR/IDEViewer-$RELEASE_VERSION.pkg" | cut -f1 | xargs)
            echo -e "${GREEN}IDEViewer-$RELEASE_VERSION.pkg${NC} ${DIM}($size)${NC}"
        else
            echo -e "${YELLOW}failed (see /tmp/ideviewer-pkg-build.log)${NC}"
        fi
    else
        echo -e "  ${DIM}Skipping macOS .pkg (pkgbuild not available — macOS only)${NC}"
    fi
fi

# Windows .exe installer (requires Inno Setup — Windows only)
if [[ "$BUILD_MODE" == "all" || "$BUILD_MODE" == "windows" ]]; then
    if command -v iscc &>/dev/null || command -v ISCC &>/dev/null; then
        echo -ne "  Building ${CYAN}Windows installer${NC}... "
        iscc "$SCRIPT_DIR/windows_installer.iss" /Q > /tmp/ideviewer-win-build.log 2>&1 || \
            ISCC "$SCRIPT_DIR/windows_installer.iss" /Q > /tmp/ideviewer-win-build.log 2>&1
        echo -e "${GREEN}done${NC}"
    else
        echo -e "  ${DIM}Skipping Windows .exe installer (Inno Setup not available)${NC}"
    fi
fi

# Linux .deb (requires dpkg-deb)
if [[ "$BUILD_MODE" == "all" || "$BUILD_MODE" == "linux" ]]; then
    for arch in amd64 arm64; do
        binary="$DIST_DIR/ideviewer-linux-$arch"
        if [ ! -f "$binary" ]; then
            continue
        fi

        echo -ne "  Building ${CYAN}Linux .deb ($arch)${NC}... "
        DEB_DIR="$DIST_DIR/deb-$arch"
        rm -rf "$DEB_DIR"

        # Build .deb structure
        mkdir -p "$DEB_DIR/DEBIAN"
        mkdir -p "$DEB_DIR/usr/local/bin"
        mkdir -p "$DEB_DIR/etc/systemd/system"
        mkdir -p "$DEB_DIR/var/log/ideviewer"

        cp "$binary" "$DEB_DIR/usr/local/bin/ideviewer"
        chmod +x "$DEB_DIR/usr/local/bin/ideviewer"

        # Copy uninstaller
        cp "$SCRIPT_DIR/uninstall_macos.sh" "$DEB_DIR/usr/local/bin/ideviewer-uninstall" 2>/dev/null || true
        chmod +x "$DEB_DIR/usr/local/bin/ideviewer-uninstall" 2>/dev/null || true

        # systemd service
        cat > "$DEB_DIR/etc/systemd/system/ideviewer.service" << SVCEOF
[Unit]
Description=IDEViewer Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ideviewer daemon --foreground
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
SVCEOF

        # Control file
        cat > "$DEB_DIR/DEBIAN/control" << CTLEOF
Package: ideviewer
Version: $RELEASE_VERSION
Section: utils
Priority: optional
Architecture: $arch
Maintainer: Securient <support@securient.com>
Description: IDEViewer — Developer workstation security scanner
 Scans IDEs, extensions, packages, secrets, and AI tools for security risks.
 Reports to a centralized portal for team-wide visibility.
Homepage: https://github.com/securient/ideviewer-oss
CTLEOF

        # Post-install
        cat > "$DEB_DIR/DEBIAN/postinst" << 'POSTEOF'
#!/bin/bash
mkdir -p /var/log/ideviewer
chmod 755 /var/log/ideviewer
echo ""
echo "IDEViewer installed. Register with:"
echo "  ideviewer register --customer-key KEY --portal-url URL"
echo ""
POSTEOF
        chmod +x "$DEB_DIR/DEBIAN/postinst"

        # Build
        if command -v dpkg-deb &>/dev/null; then
            DEB_FILE="$DIST_DIR/ideviewer_${RELEASE_VERSION}_${arch}.deb"
            dpkg-deb --build "$DEB_DIR" "$DEB_FILE" > /dev/null 2>&1
            size=$(du -h "$DEB_FILE" | cut -f1 | xargs)
            echo -e "${GREEN}ideviewer_${RELEASE_VERSION}_${arch}.deb${NC} ${DIM}($size)${NC}"
        else
            echo -e "${YELLOW}skipped (dpkg-deb not available)${NC}"
        fi
        rm -rf "$DEB_DIR"
    done
fi

# ── Summary ──
echo ""
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo -e "${GREEN}  Build complete!${NC}"
echo -e "${GREEN}════════════════════════════════════════${NC}"
echo ""
echo "  Output directory: $DIST_DIR/"
echo ""
ls -lh "$DIST_DIR"/ideviewer* 2>/dev/null | while read -r line; do
    echo "  $line"
done
echo ""

# Install instructions
echo -e "${DIM}Install locally:${NC}"
echo -e "${DIM}  macOS:   sudo installer -pkg dist/IDEViewer-$RELEASE_VERSION.pkg -target /${NC}"
echo -e "${DIM}  Linux:   sudo dpkg -i dist/ideviewer_${RELEASE_VERSION}_amd64.deb${NC}"
echo -e "${DIM}  Manual:  sudo cp dist/ideviewer-\$(uname -s | tr A-Z a-z)-\$(uname -m) /usr/local/bin/ideviewer${NC}"
echo ""
