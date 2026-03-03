#!/usr/bin/env python3
"""
Unified build script for IDE Viewer.

Builds native installers for the current platform:
  - macOS: .pkg installer
  - Windows: .exe installer (via Inno Setup)
  - Linux: .deb and .rpm packages

Usage:
    python build_scripts/build.py [--platform PLATFORM]
    
Options:
    --platform    Override platform detection (macos, windows, linux)
    --skip-installer  Only build the executable, skip installer creation
    --clean       Clean build artifacts before building
"""

import argparse
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path


# Configuration
APP_NAME = "IDEViewer"
APP_VERSION = "0.1.0"
BUNDLE_ID = "com.ideviewer.daemon"


def get_project_root() -> Path:
    """Get the project root directory."""
    return Path(__file__).parent.parent.resolve()


def clean_build(project_root: Path):
    """Clean previous build artifacts."""
    print("Cleaning previous builds...")
    
    dirs_to_clean = ["build", "dist", "*.egg-info"]
    
    for pattern in dirs_to_clean:
        for path in project_root.glob(pattern):
            if path.is_dir():
                shutil.rmtree(path)
                print(f"  Removed: {path}")
            elif path.is_file():
                path.unlink()
                print(f"  Removed: {path}")


def ensure_venv(project_root: Path) -> Path:
    """Ensure virtual environment exists and return path to Python."""
    venv_path = project_root / "venv"
    
    if not venv_path.exists():
        print("Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", str(venv_path)], check=True)
    
    if platform.system() == "Windows":
        python_path = venv_path / "Scripts" / "python.exe"
        pip_path = venv_path / "Scripts" / "pip.exe"
    else:
        python_path = venv_path / "bin" / "python"
        pip_path = venv_path / "bin" / "pip"
    
    return python_path, pip_path


def install_dependencies(pip_path: Path, project_root: Path):
    """Install project dependencies."""
    print("Installing dependencies...")
    
    subprocess.run([str(pip_path), "install", "--upgrade", "pip"], check=True)
    subprocess.run([str(pip_path), "install", "-e", str(project_root)], check=True)
    subprocess.run([str(pip_path), "install", "pyinstaller"], check=True)
    
    # Windows-specific
    if platform.system() == "Windows":
        subprocess.run([str(pip_path), "install", "pywin32"], check=True)


def build_executable(python_path: Path, project_root: Path) -> Path:
    """Build the executable with PyInstaller."""
    print("Building executable with PyInstaller...")
    
    spec_file = project_root / "ideviewer.spec"
    
    subprocess.run(
        [str(python_path), "-m", "PyInstaller", "--clean", "--noconfirm", str(spec_file)],
        cwd=str(project_root),
        check=True
    )
    
    dist_dir = project_root / "dist"
    
    if platform.system() == "Windows":
        exe_path = dist_dir / "ideviewer.exe"
    else:
        exe_path = dist_dir / "ideviewer"
    
    if not exe_path.exists():
        raise FileNotFoundError(f"Executable not found: {exe_path}")
    
    print(f"Executable built: {exe_path}")
    return exe_path


def build_macos_pkg(project_root: Path, exe_path: Path) -> Path:
    """Build macOS .pkg installer."""
    print("Building macOS .pkg installer...")
    
    build_dir = project_root / "build" / "pkg"
    dist_dir = project_root / "dist"
    
    # Create directory structure
    pkg_root = build_dir / "root"
    scripts_dir = build_dir / "scripts"
    
    for d in [pkg_root / "usr" / "local" / "bin", 
              pkg_root / "Library" / "LaunchDaemons",
              scripts_dir]:
        d.mkdir(parents=True, exist_ok=True)
    
    # Copy executable
    dest_exe = pkg_root / "usr" / "local" / "bin" / "ideviewer"
    shutil.copy2(exe_path, dest_exe)
    os.chmod(dest_exe, 0o755)
    
    # Copy uninstaller script
    uninstaller_src = project_root / "build_scripts" / "uninstall_macos.sh"
    uninstaller_dest = pkg_root / "usr" / "local" / "bin" / "ideviewer-uninstall"
    shutil.copy2(uninstaller_src, uninstaller_dest)
    os.chmod(uninstaller_dest, 0o755)
    
    # Create LaunchDaemon plist
    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{BUNDLE_ID}</string>
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
    <false/>
</dict>
</plist>
"""
    plist_path = pkg_root / "Library" / "LaunchDaemons" / f"{BUNDLE_ID}.plist"
    plist_path.write_text(plist_content)
    
    # Create postinstall script
    postinstall = scripts_dir / "postinstall"
    postinstall.write_text("""#!/bin/bash
mkdir -p /var/log/ideviewer
chmod 755 /var/log/ideviewer
chmod +x /usr/local/bin/ideviewer
chmod +x /usr/local/bin/ideviewer-uninstall
echo ""
echo "IDE Viewer installed successfully!"
echo ""
echo "Usage: ideviewer scan"
echo "To uninstall: sudo ideviewer-uninstall"
echo ""
exit 0
""")
    os.chmod(postinstall, 0o755)
    
    # Build component package
    component_pkg = build_dir / f"{APP_NAME}-component.pkg"
    subprocess.run([
        "pkgbuild",
        "--root", str(pkg_root),
        "--scripts", str(scripts_dir),
        "--identifier", BUNDLE_ID,
        "--version", APP_VERSION,
        "--install-location", "/",
        str(component_pkg)
    ], check=True)
    
    # Create distribution XML
    dist_xml = build_dir / "distribution.xml"
    dist_xml.write_text(f"""<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>{APP_NAME}</title>
    <organization>com.ideviewer</organization>
    <domains enable_localSystem="true"/>
    <options customize="never" require-scripts="true" rootVolumeOnly="true"/>
    <pkg-ref id="{BUNDLE_ID}"/>
    <choices-outline>
        <line choice="default"><line choice="{BUNDLE_ID}"/></line>
    </choices-outline>
    <choice id="default"/>
    <choice id="{BUNDLE_ID}" visible="false"><pkg-ref id="{BUNDLE_ID}"/></choice>
    <pkg-ref id="{BUNDLE_ID}" version="{APP_VERSION}">{APP_NAME}-component.pkg</pkg-ref>
</installer-gui-script>
""")
    
    # Build final package
    final_pkg = dist_dir / f"{APP_NAME}-{APP_VERSION}.pkg"
    subprocess.run([
        "productbuild",
        "--distribution", str(dist_xml),
        "--package-path", str(build_dir),
        str(final_pkg)
    ], check=True)
    
    print(f"macOS installer built: {final_pkg}")
    return final_pkg


def build_windows_installer(project_root: Path, exe_path: Path) -> Path:
    """Build Windows installer using Inno Setup."""
    print("Building Windows installer...")
    
    # Find Inno Setup compiler
    iscc_paths = [
        Path(r"C:\Program Files (x86)\Inno Setup 6\ISCC.exe"),
        Path(r"C:\Program Files\Inno Setup 6\ISCC.exe"),
    ]
    
    iscc_path = None
    for path in iscc_paths:
        if path.exists():
            iscc_path = path
            break
    
    if not iscc_path:
        print("WARNING: Inno Setup not found!")
        print("Please install Inno Setup 6 from: https://jrsoftware.org/isinfo.php")
        print(f"\nStandalone executable available at: {exe_path}")
        return exe_path
    
    # Run Inno Setup compiler
    iss_file = project_root / "build_scripts" / "windows_installer.iss"
    subprocess.run([str(iscc_path), str(iss_file)], check=True)
    
    installer_path = project_root / "dist" / f"{APP_NAME}-Setup-{APP_VERSION}.exe"
    print(f"Windows installer built: {installer_path}")
    return installer_path


def build_linux_deb_native(project_root: Path, exe_path: Path) -> Path:
    """Build .deb package using native dpkg-deb."""
    print("Building .deb package with dpkg-deb...")
    
    dist_dir = project_root / "dist"
    build_dir = project_root / "build" / "deb"
    package_dir = build_dir / f"ideviewer_{APP_VERSION}_amd64"
    
    # Clean and create directory structure
    if build_dir.exists():
        shutil.rmtree(build_dir)
    
    (package_dir / "DEBIAN").mkdir(parents=True)
    (package_dir / "usr" / "local" / "bin").mkdir(parents=True)
    (package_dir / "etc" / "ideviewer").mkdir(parents=True)
    (package_dir / "lib" / "systemd" / "system").mkdir(parents=True)
    (package_dir / "var" / "log" / "ideviewer").mkdir(parents=True)
    
    # Copy executable
    dest_exe = package_dir / "usr" / "local" / "bin" / "ideviewer"
    shutil.copy2(exe_path, dest_exe)
    os.chmod(dest_exe, 0o755)
    
    # Create control file
    control_content = f"""Package: ideviewer
Version: {APP_VERSION}
Section: utils
Priority: optional
Architecture: amd64
Maintainer: IDE Viewer Team <support@ideviewer.com>
Description: Cross-platform IDE and Extension Scanner daemon
 IDE Viewer is a daemon that scans installed IDEs and their
 extensions for security analysis. It detects VS Code, Cursor,
 JetBrains IDEs, Sublime Text, Vim/Neovim, and Xcode.
Homepage: https://github.com/ideviewer/ideviewer
"""
    (package_dir / "DEBIAN" / "control").write_text(control_content)
    
    # Create conffiles
    (package_dir / "DEBIAN" / "conffiles").write_text("/etc/ideviewer/config.json\n")
    
    # Create default config
    config_content = """{
    "portal_url": "",
    "customer_key": "",
    "host_uuid": "",
    "checkin_interval_minutes": 60
}
"""
    config_file = package_dir / "etc" / "ideviewer" / "config.json"
    config_file.write_text(config_content)
    os.chmod(config_file, 0o644)
    
    # Create systemd service
    service_content = """[Unit]
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
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/ideviewer /etc/ideviewer
PrivateTmp=true

[Install]
WantedBy=multi-user.target
"""
    (package_dir / "lib" / "systemd" / "system" / "ideviewer.service").write_text(service_content)
    
    # Create postinst script
    postinst_content = '''#!/bin/bash
set -e
mkdir -p /var/log/ideviewer
chmod 755 /var/log/ideviewer
systemctl daemon-reload
echo ""
echo "============================================"
echo "  IDE Viewer installed successfully!"
echo "============================================"
echo ""
echo "Next steps:"
echo "  1. Register: sudo ideviewer register --customer-key YOUR_KEY --portal-url URL"
echo "  2. Enable:   sudo systemctl enable ideviewer"
echo "  3. Start:    sudo systemctl start ideviewer"
echo ""
exit 0
'''
    postinst = package_dir / "DEBIAN" / "postinst"
    postinst.write_text(postinst_content)
    os.chmod(postinst, 0o755)
    
    # Create prerm script
    prerm_content = '''#!/bin/bash
set -e
if systemctl is-active --quiet ideviewer 2>/dev/null; then
    systemctl stop ideviewer
fi
if systemctl is-enabled --quiet ideviewer 2>/dev/null; then
    systemctl disable ideviewer
fi
exit 0
'''
    prerm = package_dir / "DEBIAN" / "prerm"
    prerm.write_text(prerm_content)
    os.chmod(prerm, 0o755)
    
    # Create postrm script
    postrm_content = '''#!/bin/bash
set -e
systemctl daemon-reload
if [ "$1" = "purge" ]; then
    rm -rf /etc/ideviewer
    rm -rf /var/log/ideviewer
fi
exit 0
'''
    postrm = package_dir / "DEBIAN" / "postrm"
    postrm.write_text(postrm_content)
    os.chmod(postrm, 0o755)
    
    # Build .deb package
    deb_path = dist_dir / f"ideviewer_{APP_VERSION}_amd64.deb"
    subprocess.run([
        "dpkg-deb", "--build", "--root-owner-group",
        str(package_dir), str(deb_path)
    ], check=True)
    
    print(f"DEB package built: {deb_path}")
    return deb_path


def build_linux_packages(project_root: Path, exe_path: Path):
    """Build Linux .deb and .rpm packages."""
    print("Building Linux packages...")
    
    dist_dir = project_root / "dist"
    
    # Try native dpkg-deb first (available on Debian/Ubuntu)
    try:
        subprocess.run(["dpkg-deb", "--version"], capture_output=True, check=True)
        build_linux_deb_native(project_root, exe_path)
        return
    except (subprocess.SubprocessError, FileNotFoundError):
        pass
    
    # Fall back to fpm if available
    try:
        subprocess.run(["fpm", "--version"], capture_output=True, check=True)
    except (subprocess.SubprocessError, FileNotFoundError):
        print("WARNING: Neither dpkg-deb nor fpm found!")
        print("  - On Debian/Ubuntu: dpkg-deb should be available")
        print("  - Or install fpm: gem install fpm")
        print(f"\nStandalone executable available at: {exe_path}")
        return
    
    # Build .deb package with fpm
    deb_path = dist_dir / f"ideviewer_{APP_VERSION}_amd64.deb"
    subprocess.run([
        "fpm",
        "-s", "dir",
        "-t", "deb",
        "-n", "ideviewer",
        "-v", APP_VERSION,
        "--description", "Cross-platform IDE and Extension Scanner",
        "--license", "MIT",
        "--url", "https://github.com/ideviewer/ideviewer",
        "-p", str(deb_path),
        f"{exe_path}=/usr/local/bin/ideviewer"
    ], check=True)
    print(f"DEB package built: {deb_path}")
    
    # Build .rpm package with fpm
    rpm_path = dist_dir / f"ideviewer-{APP_VERSION}-1.x86_64.rpm"
    subprocess.run([
        "fpm",
        "-s", "dir",
        "-t", "rpm",
        "-n", "ideviewer",
        "-v", APP_VERSION,
        "--description", "Cross-platform IDE and Extension Scanner",
        "--license", "MIT",
        "--url", "https://github.com/ideviewer/ideviewer",
        "-p", str(rpm_path),
        f"{exe_path}=/usr/local/bin/ideviewer"
    ], check=True)
    print(f"RPM package built: {rpm_path}")


def main():
    parser = argparse.ArgumentParser(description="Build IDE Viewer installers")
    parser.add_argument("--platform", choices=["macos", "windows", "linux"],
                        help="Override platform detection")
    parser.add_argument("--skip-installer", action="store_true",
                        help="Only build executable, skip installer")
    parser.add_argument("--clean", action="store_true",
                        help="Clean build artifacts before building")
    args = parser.parse_args()
    
    # Determine platform
    if args.platform:
        target_platform = args.platform
    else:
        system = platform.system().lower()
        if system == "darwin":
            target_platform = "macos"
        elif system == "windows":
            target_platform = "windows"
        else:
            target_platform = "linux"
    
    print(f"=== Building IDE Viewer for {target_platform.upper()} ===")
    print(f"Version: {APP_VERSION}")
    print()
    
    project_root = get_project_root()
    
    # Clean if requested
    if args.clean:
        clean_build(project_root)
    
    # Setup environment
    python_path, pip_path = ensure_venv(project_root)
    install_dependencies(pip_path, project_root)
    
    # Build executable
    exe_path = build_executable(python_path, project_root)
    
    if args.skip_installer:
        print(f"\nExecutable ready: {exe_path}")
        return
    
    # Build platform-specific installer
    if target_platform == "macos":
        build_macos_pkg(project_root, exe_path)
    elif target_platform == "windows":
        build_windows_installer(project_root, exe_path)
    elif target_platform == "linux":
        build_linux_packages(project_root, exe_path)
    
    print("\n=== Build Complete ===")


if __name__ == "__main__":
    main()
