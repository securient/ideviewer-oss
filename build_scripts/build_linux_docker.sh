#!/bin/bash
#
# Build Linux .deb package using Docker (works on macOS/Windows)
#
# Requirements:
#   - Docker installed and running
#
# Usage:
#   ./build_scripts/build_linux_docker.sh              # Build for amd64
#   ./build_scripts/build_linux_docker.sh arm64        # Build for arm64
#   ./build_scripts/build_linux_docker.sh amd64        # Build for amd64 (explicit)
#
# Output:
#   dist/ideviewer_0.1.0_<arch>.deb
#   dist/ideviewer (Linux binary)
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Default architecture
ARCH="${1:-amd64}"

# Validate architecture
if [[ "$ARCH" != "amd64" && "$ARCH" != "arm64" ]]; then
    echo "ERROR: Invalid architecture '$ARCH'"
    echo "Usage: $0 [amd64|arm64]"
    exit 1
fi

echo "=== Building IDE Viewer for Linux ($ARCH) via Docker ==="
echo ""

# Check Docker is available
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is not installed or not in PATH"
    echo "Please install Docker from: https://www.docker.com/get-started"
    exit 1
fi

# Check Docker is running
if ! docker info &> /dev/null; then
    echo "ERROR: Docker daemon is not running"
    echo "Please start Docker and try again"
    exit 1
fi

cd "$PROJECT_DIR"

# Create dist directory if it doesn't exist
mkdir -p dist

# Determine the Docker platform
if [[ "$ARCH" == "arm64" ]]; then
    PLATFORM="linux/arm64"
else
    PLATFORM="linux/amd64"
fi

# Check if we need buildx for cross-platform builds
HOST_ARCH=$(uname -m)
NEEDS_BUILDX=false

if [[ "$HOST_ARCH" == "x86_64" && "$ARCH" == "arm64" ]]; then
    NEEDS_BUILDX=true
elif [[ "$HOST_ARCH" == "arm64" && "$ARCH" == "amd64" ]]; then
    NEEDS_BUILDX=true
elif [[ "$HOST_ARCH" == "aarch64" && "$ARCH" == "amd64" ]]; then
    NEEDS_BUILDX=true
fi

IMAGE_NAME="ideviewer-builder-${ARCH}"

if [[ "$NEEDS_BUILDX" == "true" ]]; then
    echo "Cross-platform build detected. Using docker buildx..."
    echo "Host: $HOST_ARCH, Target: $ARCH"
    echo ""
    
    # Ensure buildx is available
    if ! docker buildx version &> /dev/null; then
        echo "ERROR: docker buildx is required for cross-platform builds"
        echo "Please update Docker to a version that includes buildx"
        exit 1
    fi
    
    # Create builder if it doesn't exist
    docker buildx create --name ideviewer-builder --use 2>/dev/null || docker buildx use ideviewer-builder
    
    # Build with buildx
    docker buildx build \
        --platform "$PLATFORM" \
        -f build_scripts/Dockerfile.linux \
        -t "$IMAGE_NAME" \
        --load \
        .
else
    echo "Native build for $ARCH..."
    echo ""
    
    # Standard build
    docker build \
        -f build_scripts/Dockerfile.linux \
        -t "$IMAGE_NAME" \
        .
fi

# Run the container to extract the built files
echo ""
echo "Extracting built files..."
docker run --rm -v "$(pwd)/dist:/output" "$IMAGE_NAME"

echo ""
echo "=== Build Complete ==="
echo ""
echo "Output files:"
ls -la dist/ideviewer*.deb dist/ideviewer 2>/dev/null || echo "  (check dist/ directory)"
echo ""
echo "To install on Debian/Ubuntu ($ARCH):"
echo "  sudo dpkg -i dist/ideviewer_0.1.0_${ARCH}.deb"
echo ""
