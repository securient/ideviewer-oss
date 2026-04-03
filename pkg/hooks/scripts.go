package hooks

// Hook script content — copied exactly from the Python source (ideviewer/hooks.py).

const preCommitBash = `#!/bin/bash
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
`

const postCommitBash = `#!/bin/bash
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
`

const preCommitBatch = `@echo off
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
`

const postCommitBatch = `@echo off
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
`
