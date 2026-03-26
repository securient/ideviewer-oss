"""
Self-updater for IDE Viewer daemon.

Checks GitHub releases for newer versions and installs them.
"""

import os
import sys
import json
import platform
import tempfile
import subprocess
import logging
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger(__name__)

GITHUB_REPO = "securient/ideviewer-oss"
GITHUB_API_URL = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"


def get_current_version() -> str:
    """Get the currently installed version."""
    try:
        from . import __version__
    except ImportError:
        from ideviewer import __version__
    return __version__


def fetch_latest_release() -> dict:
    """Fetch the latest release info from GitHub."""
    req = Request(GITHUB_API_URL, headers={
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "IDEViewer-Updater",
    })

    with urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def parse_version(version_str: str) -> tuple:
    """Parse version string like '0.1.0' or 'v0.1.0' into comparable tuple."""
    v = version_str.lstrip("v")
    parts = []
    for part in v.split("."):
        try:
            parts.append(int(part))
        except ValueError:
            parts.append(0)
    return tuple(parts)


def get_platform_asset_pattern() -> str:
    """Determine which release asset to download for this platform."""
    system = platform.system()
    machine = platform.machine().lower()

    if system == "Darwin":
        return "IDEViewer-", ".pkg"
    elif system == "Windows":
        return "IDEViewer-Setup-", ".exe"
    elif system == "Linux":
        if machine in ("aarch64", "arm64"):
            return "ideviewer_", "_arm64.deb"
        else:
            return "ideviewer_", "_amd64.deb"
    else:
        raise RuntimeError(f"Unsupported platform: {system} {machine}")


def find_asset(release: dict) -> dict:
    """Find the matching release asset for this platform."""
    prefix, suffix = get_platform_asset_pattern()

    for asset in release.get("assets", []):
        name = asset.get("name", "")
        if name.startswith(prefix) and name.endswith(suffix):
            return asset

    raise RuntimeError(
        f"No matching release asset found for {platform.system()} {platform.machine()}. "
        f"Looking for: {prefix}*{suffix}"
    )


def download_asset(asset: dict, dest_dir: str) -> str:
    """Download a release asset to a temporary directory."""
    url = asset["browser_download_url"]
    filename = asset["name"]
    dest_path = os.path.join(dest_dir, filename)

    logger.info(f"Downloading {filename} ({asset.get('size', 0) / 1024 / 1024:.1f} MB)...")

    req = Request(url, headers={"User-Agent": "IDEViewer-Updater"})

    with urlopen(req, timeout=120) as resp:
        with open(dest_path, "wb") as f:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                f.write(chunk)

    return dest_path


def install_update(file_path: str) -> bool:
    """Install the downloaded update."""
    system = platform.system()

    if system == "Darwin":
        # macOS: Remove quarantine and run installer
        subprocess.run(
            ["xattr", "-rd", "com.apple.quarantine", file_path],
            capture_output=True,
        )
        result = subprocess.run(
            ["sudo", "installer", "-pkg", file_path, "-target", "/"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Installer failed: {result.stderr}")
        return True

    elif system == "Linux":
        result = subprocess.run(
            ["sudo", "dpkg", "-i", file_path],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"dpkg failed: {result.stderr}")
        return True

    elif system == "Windows":
        # Run the installer silently
        result = subprocess.run(
            [file_path, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Installer failed (exit code {result.returncode})")
        return True

    else:
        raise RuntimeError(f"Unsupported platform: {system}")


def check_for_update() -> tuple:
    """
    Check if a newer version is available.

    Returns:
        (has_update, current_version, latest_version, release_info)
    """
    current = get_current_version()
    release = fetch_latest_release()
    latest = release.get("tag_name", "v0.0.0")

    has_update = parse_version(latest) > parse_version(current)

    return has_update, current, latest.lstrip("v"), release
