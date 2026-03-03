@echo off
REM Build script for Windows .exe installer
REM
REM Requirements:
REM   - Python 3.8+
REM   - PyInstaller: pip install pyinstaller
REM   - Inno Setup 6 (https://jrsoftware.org/isinfo.php)
REM
REM Usage:
REM   build_scripts\build_windows.bat
REM

setlocal enabledelayedexpansion

REM Configuration
set APP_NAME=IDEViewer
set APP_VERSION=0.1.0
set PUBLISHER=IDE Viewer Team

REM Directories
set SCRIPT_DIR=%~dp0
set PROJECT_DIR=%SCRIPT_DIR%..
set BUILD_DIR=%PROJECT_DIR%\build
set DIST_DIR=%PROJECT_DIR%\dist

echo === Building IDE Viewer for Windows ===
echo Version: %APP_VERSION%
echo.

REM Clean previous builds
echo Cleaning previous builds...
if exist "%BUILD_DIR%" rmdir /s /q "%BUILD_DIR%"
if exist "%DIST_DIR%" rmdir /s /q "%DIST_DIR%"
mkdir "%BUILD_DIR%"
mkdir "%DIST_DIR%"

REM Create virtual environment if needed
if not exist "%PROJECT_DIR%\venv" (
    echo Creating virtual environment...
    python -m venv "%PROJECT_DIR%\venv"
)

REM Activate virtual environment
call "%PROJECT_DIR%\venv\Scripts\activate.bat"

REM Install dependencies
echo Installing dependencies...
pip install --upgrade pip
pip install -e "%PROJECT_DIR%"
pip install pyinstaller pywin32

REM Build executable with PyInstaller
echo Building executable with PyInstaller...
cd /d "%PROJECT_DIR%"
pyinstaller --clean --noconfirm ideviewer.spec

REM Verify the executable was created
if not exist "%DIST_DIR%\ideviewer.exe" (
    echo ERROR: Executable not found at %DIST_DIR%\ideviewer.exe
    exit /b 1
)

echo Executable built successfully!

REM Check if Inno Setup is installed
set ISCC_PATH=
if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" (
    set ISCC_PATH=C:\Program Files (x86)\Inno Setup 6\ISCC.exe
) else if exist "C:\Program Files\Inno Setup 6\ISCC.exe" (
    set ISCC_PATH=C:\Program Files\Inno Setup 6\ISCC.exe
)

if "!ISCC_PATH!"=="" (
    echo.
    echo WARNING: Inno Setup not found!
    echo Please install Inno Setup 6 from: https://jrsoftware.org/isinfo.php
    echo.
    echo The standalone executable is available at:
    echo   %DIST_DIR%\ideviewer.exe
    echo.
    echo After installing Inno Setup, run this script again to create the installer.
    exit /b 0
)

REM Build installer with Inno Setup
echo Building installer with Inno Setup...
"!ISCC_PATH!" "%PROJECT_DIR%\build_scripts\windows_installer.iss"

echo.
echo === Build Complete ===
echo Installer: %DIST_DIR%\IDEViewer-Setup-%APP_VERSION%.exe
echo.
echo The installer will:
echo   - Install ideviewer.exe to Program Files
echo   - Add ideviewer to the system PATH
echo   - Create Start Menu shortcuts
echo.

endlocal
