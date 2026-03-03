"""
Sublime Text detector.
"""

import json
import os
import sys
from pathlib import Path
from typing import List, Optional
from datetime import datetime

# Handle both direct execution and package import
try:
    from .base import BaseDetector
    from ..models import IDE, IDEType, Extension, Permission
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from ideviewer.detectors.base import BaseDetector
    from ideviewer.models import IDE, IDEType, Extension, Permission


class SublimeTextDetector(BaseDetector):
    """Detector for Sublime Text."""
    
    def detect(self) -> List[IDE]:
        """Detect Sublime Text installation."""
        ides = []
        
        install_path = self._find_sublime()
        packages_path = self._get_packages_path()
        
        if install_path or packages_path:
            version = None
            if install_path:
                version = self.get_version(install_path, ["--version"])
            
            ide = IDE(
                ide_type=IDEType.SUBLIME_TEXT,
                name="Sublime Text",
                version=version,
                install_path=install_path,
                config_path=str(self._get_config_path()) if self._get_config_path() else None,
                extensions_path=str(packages_path) if packages_path else None,
                is_running=self.is_process_running(["sublime_text", "subl", "Sublime Text"]),
            )
            
            ide.extensions = self.parse_extensions(ide)
            ides.append(ide)
        
        return ides
    
    def _find_sublime(self) -> Optional[str]:
        """Find Sublime Text executable."""
        paths = []
        
        if self.is_macos:
            paths = [
                "/Applications/Sublime Text.app/Contents/SharedSupport/bin/subl",
                "/Applications/Sublime Text 4.app/Contents/SharedSupport/bin/subl",
                "/usr/local/bin/subl",
            ]
        elif self.is_linux:
            paths = [
                "/usr/bin/subl",
                "/usr/bin/sublime_text",
                "/opt/sublime_text/sublime_text",
                "/snap/bin/subl",
            ]
        elif self.is_windows:
            paths = [
                "%ProgramFiles%\\Sublime Text\\subl.exe",
                "%ProgramFiles%\\Sublime Text 4\\subl.exe",
                "%ProgramFiles(x86)%\\Sublime Text\\subl.exe",
            ]
        
        return self.find_executable("subl", paths)
    
    def _get_packages_path(self) -> Optional[Path]:
        """Get path to installed packages."""
        if self.is_macos:
            path = self.home / "Library" / "Application Support" / "Sublime Text" / "Packages"
        elif self.is_linux:
            path = self.home / ".config" / "sublime-text" / "Packages"
        elif self.is_windows:
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                path = Path(appdata) / "Sublime Text" / "Packages"
            else:
                return None
        else:
            return None
        
        return path if path.exists() else None
    
    def _get_config_path(self) -> Optional[Path]:
        """Get Sublime Text config path."""
        if self.is_macos:
            path = self.home / "Library" / "Application Support" / "Sublime Text"
        elif self.is_linux:
            path = self.home / ".config" / "sublime-text"
        elif self.is_windows:
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                path = Path(appdata) / "Sublime Text"
            else:
                return None
        else:
            return None
        
        return path if path.exists() else None
    
    def parse_extensions(self, ide: IDE) -> List[Extension]:
        """Parse Sublime Text packages."""
        extensions = []
        
        if not ide.extensions_path or not os.path.isdir(ide.extensions_path):
            return extensions
        
        packages_dir = Path(ide.extensions_path)
        
        # User-installed packages
        for package_folder in packages_dir.iterdir():
            if not package_folder.is_dir():
                continue
            
            if package_folder.name.startswith(".") or package_folder.name == "User":
                continue
            
            extension = self._parse_package(package_folder)
            if extension:
                extensions.append(extension)
        
        # Also check Installed Packages (*.sublime-package files)
        installed_packages = packages_dir.parent / "Installed Packages"
        if installed_packages.exists():
            for pkg_file in installed_packages.glob("*.sublime-package"):
                extension = Extension(
                    id=pkg_file.stem,
                    name=pkg_file.stem,
                    version="unknown",
                    install_path=str(pkg_file),
                )
                extensions.append(extension)
        
        return extensions
    
    def _parse_package(self, package_folder: Path) -> Optional[Extension]:
        """Parse a Sublime Text package."""
        # Check for package metadata
        package_json = package_folder / "package.json"
        messages_json = package_folder / "messages.json"
        
        name = package_folder.name
        version = "unknown"
        description = None
        homepage = None
        
        # Try to get info from package.json (if exists)
        if package_json.exists():
            try:
                with open(package_json, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    name = data.get("name", name)
                    version = data.get("version", version)
                    description = data.get("description")
                    homepage = data.get("homepage")
            except (json.JSONDecodeError, IOError):
                pass
        
        # Get last updated from folder modification time
        last_updated = None
        try:
            stat = package_folder.stat()
            last_updated = datetime.fromtimestamp(stat.st_mtime)
        except OSError:
            pass
        
        # Check for keybindings and commands
        permissions = []
        
        keymaps = list(package_folder.glob("*.sublime-keymap"))
        if keymaps:
            permissions.append(Permission(
                name="keybindings",
                description=f"Registers {len(keymaps)} keymap files",
                is_dangerous=False,
            ))
        
        commands = list(package_folder.glob("*.sublime-commands"))
        if commands:
            permissions.append(Permission(
                name="commands",
                description=f"Registers {len(commands)} command files",
                is_dangerous=False,
            ))
        
        build_systems = list(package_folder.glob("*.sublime-build"))
        if build_systems:
            permissions.append(Permission(
                name="buildSystems",
                description=f"Registers {len(build_systems)} build systems (may execute commands)",
                is_dangerous=True,
            ))
        
        return Extension(
            id=package_folder.name,
            name=name,
            version=version,
            description=description,
            homepage=homepage,
            install_path=str(package_folder),
            permissions=permissions,
            last_updated=last_updated,
        )
