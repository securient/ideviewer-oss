"""
Git hook manager for IDEViewer pre-commit secret scanning.

Installs global pre-commit and post-commit hooks that:
- Scan staged files for secrets before each commit
- Detect when --no-verify is used to bypass the pre-commit hook
"""

import logging
import os
import platform
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

HOOKS_DIR = Path.home() / ".ideviewer" / "hooks"
IDEVIEWER_DIR = Path.home() / ".ideviewer"

PRE_COMMIT_SCRIPT = r'''#!/bin/bash
# IDEViewer pre-commit hook — scans staged files for secrets

# Set flag so post-commit knows we ran
mkdir -p "$HOME/.ideviewer"
touch "$HOME/.ideviewer/.pre-commit-ran"

# Check if gitleaks is available
GITLEAKS=""
if [ -x "$HOME/.ideviewer/bin/gitleaks" ]; then
    GITLEAKS="$HOME/.ideviewer/bin/gitleaks"
elif command -v gitleaks &>/dev/null; then
    GITLEAKS="gitleaks"
fi

echo "IDEViewer: Scanning staged files for secrets..."

if [ -n "$GITLEAKS" ]; then
    echo "(using gitleaks)"
    $GITLEAKS protect --staged --no-banner --exit-code 1
    EXIT_CODE=$?
else
    echo "(using built-in scanner)"
    ideviewer secrets --check-staged --exit-code
    EXIT_CODE=$?
fi

if [ $EXIT_CODE -ne 0 ]; then
    echo ""
    echo "✗ Commit blocked: secrets detected in staged files"
    echo "Remove secrets and try again. Bypass: git commit --no-verify"
    exit 1
fi

# Record successful scan timestamp
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$HOME/.ideviewer/.last-hook-scan"

exit 0
'''

POST_COMMIT_SCRIPT = r'''#!/bin/bash
# IDEViewer post-commit hook — detects --no-verify bypass

FLAG="$HOME/.ideviewer/.pre-commit-ran"

if [ -f "$FLAG" ]; then
    # Pre-commit ran normally, clean up
    rm -f "$FLAG"
else
    # Pre-commit was bypassed (--no-verify used)
    COMMIT_HASH=$(git rev-parse HEAD)
    COMMIT_MSG=$(git log -1 --format='%s' HEAD)
    COMMIT_AUTHOR=$(git log -1 --format='%an' HEAD)
    REPO_PATH=$(git rev-parse --show-toplevel)

    echo ""
    echo "⚠ IDEViewer: --no-verify detected. This bypass has been recorded."
    echo ""

    # Record the bypass for the daemon to pick up
    mkdir -p "$HOME/.ideviewer/bypasses"
    echo "{\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"commit_hash\":\"$COMMIT_HASH\",\"commit_message\":\"$COMMIT_MSG\",\"commit_author\":\"$COMMIT_AUTHOR\",\"repo_path\":\"$REPO_PATH\"}" >> "$HOME/.ideviewer/bypasses/pending.jsonl"
fi
'''

# Windows batch equivalents
PRE_COMMIT_BATCH = r'''@echo off
REM IDEViewer pre-commit hook — scans staged files for secrets

if not exist "%USERPROFILE%\.ideviewer" mkdir "%USERPROFILE%\.ideviewer"
echo. > "%USERPROFILE%\.ideviewer\.pre-commit-ran"

set GITLEAKS=
if exist "%USERPROFILE%\.ideviewer\bin\gitleaks.exe" (
    set GITLEAKS=%USERPROFILE%\.ideviewer\bin\gitleaks.exe
) else (
    where gitleaks >nul 2>nul
    if not errorlevel 1 set GITLEAKS=gitleaks
)

echo IDEViewer: Scanning staged files for secrets...

if defined GITLEAKS (
    echo (using gitleaks)
    %GITLEAKS% protect --staged --no-banner --exit-code 1
) else (
    echo (using built-in scanner)
    ideviewer secrets --check-staged --exit-code
)

if errorlevel 1 (
    echo.
    echo X Commit blocked: secrets detected in staged files
    echo Remove secrets and try again. Bypass: git commit --no-verify
    exit /b 1
)

exit /b 0
'''

POST_COMMIT_BATCH = r'''@echo off
REM IDEViewer post-commit hook — detects --no-verify bypass

set FLAG=%USERPROFILE%\.ideviewer\.pre-commit-ran

if exist "%FLAG%" (
    del /f "%FLAG%"
) else (
    for /f "tokens=*" %%a in ('git rev-parse HEAD') do set COMMIT_HASH=%%a
    for /f "tokens=*" %%a in ('git log -1 --format^="%%s" HEAD') do set COMMIT_MSG=%%a
    for /f "tokens=*" %%a in ('git log -1 --format^="%%an" HEAD') do set COMMIT_AUTHOR=%%a
    for /f "tokens=*" %%a in ('git rev-parse --show-toplevel') do set REPO_PATH=%%a

    echo.
    echo WARNING: IDEViewer: --no-verify detected. This bypass has been recorded.
    echo.

    if not exist "%USERPROFILE%\.ideviewer\bypasses" mkdir "%USERPROFILE%\.ideviewer\bypasses"
    echo {"timestamp":"","commit_hash":"%COMMIT_HASH%","commit_message":"%COMMIT_MSG%","commit_author":"%COMMIT_AUTHOR%","repo_path":"%REPO_PATH%"} >> "%USERPROFILE%\.ideviewer\bypasses\pending.jsonl"
)
'''


def _is_git_installed() -> bool:
    """Check if git is installed."""
    return shutil.which("git") is not None


def install_global_hook() -> bool:
    """
    Install global pre-commit and post-commit hooks.

    Creates hook scripts in ~/.ideviewer/hooks/ and sets
    git config --global core.hooksPath to point there.

    Returns True if hooks were installed successfully.
    """
    if not _is_git_installed():
        logger.error("git is not installed; cannot set up hooks")
        return False

    try:
        # Create hooks directory
        HOOKS_DIR.mkdir(parents=True, exist_ok=True)

        is_windows = sys.platform == "win32"

        # Write pre-commit hook
        if is_windows:
            pre_commit_path = HOOKS_DIR / "pre-commit"
            pre_commit_path.write_text(PRE_COMMIT_BATCH, encoding="utf-8")
        else:
            pre_commit_path = HOOKS_DIR / "pre-commit"
            pre_commit_path.write_text(PRE_COMMIT_SCRIPT, encoding="utf-8")
            pre_commit_path.chmod(
                pre_commit_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
            )

        # Write post-commit hook
        if is_windows:
            post_commit_path = HOOKS_DIR / "post-commit"
            post_commit_path.write_text(POST_COMMIT_BATCH, encoding="utf-8")
        else:
            post_commit_path = HOOKS_DIR / "post-commit"
            post_commit_path.write_text(POST_COMMIT_SCRIPT, encoding="utf-8")
            post_commit_path.chmod(
                post_commit_path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
            )

        # Set global hooks path
        result = subprocess.run(
            ["git", "config", "--global", "core.hooksPath", str(HOOKS_DIR)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode != 0:
            logger.error(f"Failed to set global hooksPath: {result.stderr.strip()}")
            return False

        logger.info(f"Global hooks installed to {HOOKS_DIR}")
        return True

    except Exception as e:
        logger.error(f"Failed to install global hooks: {e}")
        return False


def uninstall_global_hook() -> bool:
    """
    Uninstall global hooks by unsetting core.hooksPath and removing hook scripts.

    Returns True if hooks were uninstalled successfully.
    """
    if not _is_git_installed():
        logger.error("git is not installed")
        return False

    try:
        # Unset global hooks path
        subprocess.run(
            ["git", "config", "--global", "--unset", "core.hooksPath"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        # Remove hook scripts
        for hook_name in ("pre-commit", "post-commit"):
            hook_path = HOOKS_DIR / hook_name
            if hook_path.exists():
                hook_path.unlink()

        logger.info("Global hooks uninstalled")
        return True

    except Exception as e:
        logger.error(f"Failed to uninstall global hooks: {e}")
        return False


def get_hook_status() -> dict:
    """
    Get the current status of the global hook installation.

    Returns dict with keys:
        installed: bool
        hook_path: str
        scanner: "gitleaks" | "builtin"
        gitleaks_version: str | None
    """
    from .gitleaks import is_gitleaks_installed, get_gitleaks_version

    # Check if hooks are installed
    pre_commit_path = HOOKS_DIR / "pre-commit"
    installed = pre_commit_path.exists()

    # Check if git global hooksPath is set to our directory
    hooks_path_configured = False
    if _is_git_installed():
        try:
            result = subprocess.run(
                ["git", "config", "--global", "core.hooksPath"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            configured_path = result.stdout.strip()
            if configured_path and Path(configured_path).resolve() == HOOKS_DIR.resolve():
                hooks_path_configured = True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    installed = installed and hooks_path_configured

    # Determine scanner
    gitleaks_available = is_gitleaks_installed()
    gitleaks_version = get_gitleaks_version() if gitleaks_available else None
    scanner = "gitleaks" if gitleaks_available else "builtin"

    return {
        "installed": installed,
        "hook_path": str(HOOKS_DIR),
        "scanner": scanner,
        "gitleaks_version": gitleaks_version,
    }
