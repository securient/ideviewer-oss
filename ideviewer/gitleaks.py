"""
Gitleaks installer and manager.

Handles installation and version detection of gitleaks for pre-commit secret scanning.
"""

import json
import logging
import os
import platform
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)

GITHUB_RELEASES_URL = "https://api.github.com/repos/gitleaks/gitleaks/releases/latest"
IDEVIEWER_BIN_DIR = Path.home() / ".ideviewer" / "bin"


def _get_gitleaks_binary_name() -> str:
    """Get the gitleaks binary name for this platform."""
    if sys.platform == "win32":
        return "gitleaks.exe"
    return "gitleaks"


def _get_ideviewer_gitleaks_path() -> Path:
    """Get the path to the ideviewer-managed gitleaks binary."""
    return IDEVIEWER_BIN_DIR / _get_gitleaks_binary_name()


def is_gitleaks_installed() -> bool:
    """Check if gitleaks is available (either in ideviewer bin or system PATH)."""
    # Check ideviewer-managed binary first
    ideviewer_path = _get_ideviewer_gitleaks_path()
    if ideviewer_path.exists() and os.access(str(ideviewer_path), os.X_OK):
        return True

    # Check system PATH
    return shutil.which("gitleaks") is not None


def get_gitleaks_version() -> Optional[str]:
    """Get the installed gitleaks version string, or None if not installed."""
    # Check ideviewer-managed binary first
    ideviewer_path = _get_ideviewer_gitleaks_path()
    gitleaks_cmd = None

    if ideviewer_path.exists() and os.access(str(ideviewer_path), os.X_OK):
        gitleaks_cmd = str(ideviewer_path)
    elif shutil.which("gitleaks"):
        gitleaks_cmd = "gitleaks"

    if not gitleaks_cmd:
        return None

    try:
        result = subprocess.run(
            [gitleaks_cmd, "version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0:
            return result.stdout.strip()
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def _get_platform_asset_pattern() -> str:
    """Get the expected asset filename pattern for this platform."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Normalize architecture names
    if machine in ("x86_64", "amd64"):
        arch = "x64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    elif machine in ("i386", "i686", "x86"):
        arch = "x32"
    else:
        arch = machine

    if system == "darwin":
        return f"gitleaks_{{}}_darwin_{arch}.tar.gz"
    elif system == "linux":
        return f"gitleaks_{{}}_linux_{arch}.tar.gz"
    elif system == "windows":
        return f"gitleaks_{{}}_windows_{arch}.zip"
    else:
        return f"gitleaks_{{}}_linux_{arch}.tar.gz"


def _download_from_github() -> bool:
    """Download the latest gitleaks release from GitHub."""
    logger.info("Downloading gitleaks from GitHub releases...")

    try:
        req = Request(
            GITHUB_RELEASES_URL,
            headers={"User-Agent": "IDEViewer/0.1.0"},
        )
        with urlopen(req, timeout=30) as response:
            release_data = json.loads(response.read().decode("utf-8"))
    except (URLError, HTTPError, json.JSONDecodeError) as e:
        logger.error(f"Failed to fetch GitHub release info: {e}")
        return False

    version = release_data.get("tag_name", "").lstrip("v")
    assets = release_data.get("assets", [])

    if not version or not assets:
        logger.error("No release version or assets found")
        return False

    # Find the right asset for this platform
    system = platform.system().lower()
    machine = platform.machine().lower()

    # Normalize architecture
    if machine in ("x86_64", "amd64"):
        arch = "x64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    elif machine in ("i386", "i686", "x86"):
        arch = "x32"
    else:
        arch = machine

    target_name = None
    download_url = None

    for asset in assets:
        name = asset.get("name", "").lower()
        # Match platform and architecture
        if system == "darwin" and "darwin" in name and arch in name:
            target_name = asset["name"]
            download_url = asset.get("browser_download_url")
            break
        elif system == "linux" and "linux" in name and arch in name and not name.endswith(".rpm") and not name.endswith(".deb"):
            target_name = asset["name"]
            download_url = asset.get("browser_download_url")
            break
        elif system == "windows" and "windows" in name and arch in name:
            target_name = asset["name"]
            download_url = asset.get("browser_download_url")
            break

    if not download_url:
        logger.error(f"No suitable gitleaks binary found for {system}/{arch}")
        return False

    logger.info(f"Downloading {target_name}...")

    try:
        req = Request(
            download_url,
            headers={"User-Agent": "IDEViewer/0.1.0"},
        )
        with urlopen(req, timeout=120) as response:
            archive_data = response.read()
    except (URLError, HTTPError) as e:
        logger.error(f"Failed to download gitleaks: {e}")
        return False

    # Create bin directory
    IDEVIEWER_BIN_DIR.mkdir(parents=True, exist_ok=True)

    binary_name = _get_gitleaks_binary_name()
    dest_path = _get_ideviewer_gitleaks_path()

    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmpdir_path = Path(tmpdir)
            archive_path = tmpdir_path / target_name

            archive_path.write_bytes(archive_data)

            if target_name.endswith(".tar.gz") or target_name.endswith(".tgz"):
                with tarfile.open(archive_path, "r:gz") as tar:
                    tar.extractall(path=tmpdir, filter="data")
            elif target_name.endswith(".zip"):
                with zipfile.ZipFile(archive_path, "r") as zf:
                    zf.extractall(path=tmpdir)
            else:
                logger.error(f"Unknown archive format: {target_name}")
                return False

            # Find the gitleaks binary in extracted files
            extracted_binary = None
            for root, dirs, files in os.walk(tmpdir):
                for f in files:
                    if f == binary_name or f == "gitleaks":
                        extracted_binary = Path(root) / f
                        break
                if extracted_binary:
                    break

            if not extracted_binary or not extracted_binary.exists():
                logger.error("Could not find gitleaks binary in archive")
                return False

            # Copy to destination
            shutil.copy2(str(extracted_binary), str(dest_path))

            # Make executable on Unix
            if sys.platform != "win32":
                dest_path.chmod(dest_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    except Exception as e:
        logger.error(f"Failed to extract gitleaks: {e}")
        return False

    logger.info(f"gitleaks installed to {dest_path}")
    return True


def _install_via_brew() -> bool:
    """Install gitleaks via Homebrew on macOS."""
    if not shutil.which("brew"):
        return False

    logger.info("Installing gitleaks via Homebrew...")
    try:
        result = subprocess.run(
            ["brew", "install", "gitleaks"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode == 0:
            logger.info("gitleaks installed via Homebrew")
            return True
        else:
            logger.warning(f"Homebrew install failed: {result.stderr.strip()}")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        logger.warning(f"Homebrew install failed: {e}")
        return False


def install_gitleaks() -> bool:
    """
    Install gitleaks. Returns True if installed successfully.

    Installation methods by platform:
    - macOS: brew install gitleaks (if brew available), otherwise GitHub release
    - Linux: GitHub release binary
    - Windows: GitHub release binary
    """
    if is_gitleaks_installed():
        version = get_gitleaks_version()
        logger.info(f"gitleaks already installed (version: {version})")
        return True

    system = platform.system().lower()

    # macOS: try Homebrew first
    if system == "darwin":
        if _install_via_brew():
            return True
        logger.info("Homebrew not available or failed, falling back to GitHub release")

    # All platforms: download from GitHub
    return _download_from_github()
