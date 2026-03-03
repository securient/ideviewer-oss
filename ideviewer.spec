# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for IDE Viewer.

Build commands:
  macOS:   pyinstaller ideviewer.spec
  Windows: pyinstaller ideviewer.spec
"""

import sys
from pathlib import Path

block_cipher = None

# Determine platform-specific settings
is_windows = sys.platform == 'win32'
is_macos = sys.platform == 'darwin'

# Application metadata
APP_NAME = 'IDEViewer'
APP_VERSION = '0.1.0'
APP_BUNDLE_ID = 'com.ideviewer.daemon'

# Collect all detector modules
datas = []
hiddenimports = [
    'ideviewer.detectors.vscode',
    'ideviewer.detectors.jetbrains',
    'ideviewer.detectors.sublime',
    'ideviewer.detectors.vim',
    'ideviewer.detectors.xcode',
    'plistlib',  # For macOS plist parsing
]

# Windows-specific imports
if is_windows:
    hiddenimports.extend([
        'win32api',
        'win32con',
        'win32security',
        'pywintypes',
    ])

a = Analysis(
    ['ideviewer/cli.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'PIL',
        'cv2',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='ideviewer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.ico' if is_windows and Path('assets/icon.ico').exists() else None,
)

# macOS: Create .app bundle (optional, for GUI version in future)
if is_macos:
    app = BUNDLE(
        exe,
        name=f'{APP_NAME}.app',
        icon='assets/icon.icns' if Path('assets/icon.icns').exists() else None,
        bundle_identifier=APP_BUNDLE_ID,
        info_plist={
            'CFBundleName': APP_NAME,
            'CFBundleDisplayName': 'IDE Viewer',
            'CFBundleVersion': APP_VERSION,
            'CFBundleShortVersionString': APP_VERSION,
            'CFBundleIdentifier': APP_BUNDLE_ID,
            'LSMinimumSystemVersion': '10.14.0',
            'NSHighResolutionCapable': True,
        },
    )
