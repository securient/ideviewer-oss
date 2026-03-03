#!/usr/bin/env python3
"""
Build .deb package from the compiled executable.
Called by Dockerfile.linux after PyInstaller creates the binary.

Usage:
    python build_deb_package.py [--arch amd64|arm64]
"""

import argparse
import os
import shutil
from pathlib import Path

APP_VERSION = '0.1.0'

def main():
    parser = argparse.ArgumentParser(description='Build .deb package')
    parser.add_argument('--arch', choices=['amd64', 'arm64'], default='amd64',
                        help='Target architecture (default: amd64)')
    args = parser.parse_args()
    
    arch = args.arch
    
    project_root = Path('/build') if Path('/build').exists() else Path(__file__).parent.parent
    dist_dir = project_root / 'dist'
    build_dir = project_root / 'build' / 'deb'
    package_dir = build_dir / f'ideviewer_{APP_VERSION}_{arch}'
    exe_path = dist_dir / 'ideviewer'
    
    if not exe_path.exists():
        print(f"ERROR: Executable not found at {exe_path}")
        return 1
    
    print(f"Building .deb package from {exe_path}")
    
    # Clean and create directory structure
    if build_dir.exists():
        shutil.rmtree(build_dir)
    
    (package_dir / 'DEBIAN').mkdir(parents=True)
    (package_dir / 'usr' / 'local' / 'bin').mkdir(parents=True)
    (package_dir / 'etc' / 'ideviewer').mkdir(parents=True)
    (package_dir / 'lib' / 'systemd' / 'system').mkdir(parents=True)
    
    # Copy executable
    dest_exe = package_dir / 'usr' / 'local' / 'bin' / 'ideviewer'
    shutil.copy2(exe_path, dest_exe)
    os.chmod(dest_exe, 0o755)
    print(f"Copied executable to {dest_exe}")
    
    # Create control file
    control = f"""Package: ideviewer
Version: {APP_VERSION}
Section: utils
Priority: optional
Architecture: {arch}
Maintainer: IDE Viewer Team <support@ideviewer.com>
Description: Cross-platform IDE and Extension Scanner daemon
 IDE Viewer scans installed IDEs and extensions for security analysis.
 It detects VS Code, Cursor, JetBrains IDEs, Sublime Text, Vim/Neovim.
Homepage: https://github.com/ideviewer/ideviewer
"""
    (package_dir / 'DEBIAN' / 'control').write_text(control)
    
    # Create conffiles
    (package_dir / 'DEBIAN' / 'conffiles').write_text('/etc/ideviewer/config.json\n')
    
    # Create default config
    config = """{
    "portal_url": "",
    "customer_key": "",
    "host_uuid": "",
    "checkin_interval_minutes": 60
}
"""
    config_file = package_dir / 'etc' / 'ideviewer' / 'config.json'
    config_file.write_text(config)
    os.chmod(config_file, 0o644)
    
    # Create systemd service
    service = """[Unit]
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

[Install]
WantedBy=multi-user.target
"""
    (package_dir / 'lib' / 'systemd' / 'system' / 'ideviewer.service').write_text(service)
    
    # Create postinst script
    postinst = """#!/bin/bash
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
echo "  1. Register: sudo ideviewer register --customer-key KEY --portal-url URL"
echo "  2. Enable:   sudo systemctl enable ideviewer"
echo "  3. Start:    sudo systemctl start ideviewer"
echo ""
exit 0
"""
    p = package_dir / 'DEBIAN' / 'postinst'
    p.write_text(postinst)
    os.chmod(p, 0o755)
    
    # Create prerm script
    prerm = """#!/bin/bash
set -e
systemctl stop ideviewer 2>/dev/null || true
systemctl disable ideviewer 2>/dev/null || true
exit 0
"""
    p = package_dir / 'DEBIAN' / 'prerm'
    p.write_text(prerm)
    os.chmod(p, 0o755)
    
    # Create postrm script
    postrm = """#!/bin/bash
set -e
systemctl daemon-reload
if [ "$1" = "purge" ]; then
    rm -rf /etc/ideviewer
    rm -rf /var/log/ideviewer
fi
exit 0
"""
    p = package_dir / 'DEBIAN' / 'postrm'
    p.write_text(postrm)
    os.chmod(p, 0o755)
    
    print("Package structure created successfully")
    print(f"Package directory: {package_dir}")
    return 0


if __name__ == '__main__':
    exit(main())
