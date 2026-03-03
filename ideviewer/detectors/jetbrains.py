"""
JetBrains IDE detector.

Supports: IntelliJ IDEA, PyCharm, WebStorm, GoLand, CLion, Rider, PhpStorm, RubyMine, DataGrip, Android Studio
"""

import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from datetime import datetime

# Handle both direct execution and package import
try:
    from .base import BaseDetector
    from ..models import IDE, IDEType, Extension, Permission
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from ideviewer.detectors.base import BaseDetector
    from ideviewer.models import IDE, IDEType, Extension, Permission


class JetBrainsDetector(BaseDetector):
    """Detector for JetBrains IDEs."""
    
    # JetBrains IDE configurations
    JETBRAINS_IDES = {
        IDEType.JETBRAINS_IDEA: {
            "name": "IntelliJ IDEA",
            "folder_patterns": ["IntelliJIdea*", "IdeaIC*"],
            "app_names": {
                "darwin": ["IntelliJ IDEA.app", "IntelliJ IDEA CE.app", "IntelliJ IDEA Ultimate.app"],
                "windows": ["idea64.exe", "idea.exe"],
                "linux": ["idea.sh", "idea"],
            },
            "toolbox_id": "intellij-idea",
        },
        IDEType.JETBRAINS_PYCHARM: {
            "name": "PyCharm",
            "folder_patterns": ["PyCharm*"],
            "app_names": {
                "darwin": ["PyCharm.app", "PyCharm CE.app", "PyCharm Professional.app"],
                "windows": ["pycharm64.exe", "pycharm.exe"],
                "linux": ["pycharm.sh", "pycharm"],
            },
            "toolbox_id": "pycharm",
        },
        IDEType.JETBRAINS_WEBSTORM: {
            "name": "WebStorm",
            "folder_patterns": ["WebStorm*"],
            "app_names": {
                "darwin": ["WebStorm.app"],
                "windows": ["webstorm64.exe", "webstorm.exe"],
                "linux": ["webstorm.sh", "webstorm"],
            },
            "toolbox_id": "webstorm",
        },
        IDEType.JETBRAINS_GOLAND: {
            "name": "GoLand",
            "folder_patterns": ["GoLand*"],
            "app_names": {
                "darwin": ["GoLand.app"],
                "windows": ["goland64.exe", "goland.exe"],
                "linux": ["goland.sh", "goland"],
            },
            "toolbox_id": "goland",
        },
        IDEType.JETBRAINS_CLION: {
            "name": "CLion",
            "folder_patterns": ["CLion*"],
            "app_names": {
                "darwin": ["CLion.app"],
                "windows": ["clion64.exe", "clion.exe"],
                "linux": ["clion.sh", "clion"],
            },
            "toolbox_id": "clion",
        },
        IDEType.JETBRAINS_RIDER: {
            "name": "Rider",
            "folder_patterns": ["Rider*"],
            "app_names": {
                "darwin": ["Rider.app"],
                "windows": ["rider64.exe", "rider.exe"],
                "linux": ["rider.sh", "rider"],
            },
            "toolbox_id": "rider",
        },
        IDEType.JETBRAINS_PHPSTORM: {
            "name": "PhpStorm",
            "folder_patterns": ["PhpStorm*"],
            "app_names": {
                "darwin": ["PhpStorm.app"],
                "windows": ["phpstorm64.exe", "phpstorm.exe"],
                "linux": ["phpstorm.sh", "phpstorm"],
            },
            "toolbox_id": "phpstorm",
        },
        IDEType.JETBRAINS_RUBYMINE: {
            "name": "RubyMine",
            "folder_patterns": ["RubyMine*"],
            "app_names": {
                "darwin": ["RubyMine.app"],
                "windows": ["rubymine64.exe", "rubymine.exe"],
                "linux": ["rubymine.sh", "rubymine"],
            },
            "toolbox_id": "rubymine",
        },
        IDEType.JETBRAINS_DATAGRIP: {
            "name": "DataGrip",
            "folder_patterns": ["DataGrip*"],
            "app_names": {
                "darwin": ["DataGrip.app"],
                "windows": ["datagrip64.exe", "datagrip.exe"],
                "linux": ["datagrip.sh", "datagrip"],
            },
            "toolbox_id": "datagrip",
        },
        IDEType.ANDROID_STUDIO: {
            "name": "Android Studio",
            "folder_patterns": ["AndroidStudio*", "Google/AndroidStudio*"],
            "app_names": {
                "darwin": ["Android Studio.app"],
                "windows": ["studio64.exe", "studio.exe"],
                "linux": ["studio.sh", "android-studio"],
            },
            "toolbox_id": "android-studio",
        },
    }
    
    def detect(self) -> List[IDE]:
        """Detect all installed JetBrains IDEs."""
        ides = []
        
        for ide_type, config in self.JETBRAINS_IDES.items():
            detected = self._detect_jetbrains_ide(ide_type, config)
            for ide in detected:
                ide.extensions = self.parse_extensions(ide)
                ides.append(ide)
        
        return ides
    
    def _get_config_base_paths(self) -> List[Path]:
        """Get base paths for JetBrains configuration."""
        paths = []
        
        if self.is_macos:
            paths.append(self.home / "Library" / "Application Support" / "JetBrains")
            paths.append(self.home / "Library" / "Preferences")
        elif self.is_linux:
            paths.append(self.home / ".config" / "JetBrains")
            paths.append(self.home / ".local" / "share" / "JetBrains")
        elif self.is_windows:
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                paths.append(Path(appdata) / "JetBrains")
        
        return [p for p in paths if p.exists()]
    
    def _get_plugins_paths(self) -> List[Path]:
        """Get paths where JetBrains plugins are stored."""
        paths = []
        
        if self.is_macos:
            paths.append(self.home / "Library" / "Application Support" / "JetBrains")
        elif self.is_linux:
            paths.append(self.home / ".local" / "share" / "JetBrains")
        elif self.is_windows:
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                paths.append(Path(appdata) / "JetBrains")
        
        return [p for p in paths if p.exists()]
    
    def _get_install_paths(self) -> List[Path]:
        """Get paths where JetBrains IDEs might be installed."""
        paths = []
        
        if self.is_macos:
            paths.append(Path("/Applications"))
            paths.append(self.home / "Applications")
            # JetBrains Toolbox
            paths.append(self.home / "Library" / "Application Support" / "JetBrains" / "Toolbox" / "apps")
        elif self.is_linux:
            paths.append(Path("/opt"))
            paths.append(Path("/usr/share"))
            paths.append(self.home / ".local" / "share" / "JetBrains" / "Toolbox" / "apps")
            paths.append(Path("/snap"))
        elif self.is_windows:
            program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
            program_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")
            localappdata = os.environ.get("LOCALAPPDATA", "")
            
            paths.append(Path(program_files) / "JetBrains")
            paths.append(Path(program_files_x86) / "JetBrains")
            if localappdata:
                paths.append(Path(localappdata) / "JetBrains" / "Toolbox" / "apps")
        
        return [p for p in paths if p.exists()]
    
    def _detect_jetbrains_ide(self, ide_type: IDEType, config: Dict[str, Any]) -> List[IDE]:
        """Detect a specific JetBrains IDE."""
        found_ides = []
        
        # Search for installed applications
        for install_path in self._get_install_paths():
            for app_name in config["app_names"].get(self.system, []):
                if self.is_macos:
                    app_path = install_path / app_name
                    if app_path.exists():
                        ide = self._create_ide_from_app(ide_type, config, app_path)
                        if ide:
                            found_ides.append(ide)
                else:
                    # Search recursively for the executable
                    for root, dirs, files in os.walk(install_path):
                        if app_name in files:
                            ide = self._create_ide_from_app(ide_type, config, Path(root) / app_name)
                            if ide:
                                found_ides.append(ide)
        
        # Look for config directories even if app not found in standard locations
        for config_base in self._get_config_base_paths():
            for pattern in config["folder_patterns"]:
                for config_dir in config_base.glob(pattern):
                    if config_dir.is_dir():
                        # Check if this IDE config exists but app wasn't found
                        existing = any(ide.config_path == str(config_dir) for ide in found_ides)
                        if not existing:
                            version = self._extract_version_from_folder(config_dir.name)
                            plugins_path = self._find_plugins_path(config_dir)
                            
                            ide = IDE(
                                ide_type=ide_type,
                                name=config["name"],
                                version=version,
                                install_path=None,
                                config_path=str(config_dir),
                                extensions_path=str(plugins_path) if plugins_path else None,
                            )
                            found_ides.append(ide)
        
        return found_ides
    
    def _create_ide_from_app(self, ide_type: IDEType, config: Dict[str, Any], app_path: Path) -> Optional[IDE]:
        """Create an IDE object from an application path."""
        version = None
        config_path = None
        extensions_path = None
        
        if self.is_macos and app_path.suffix == ".app":
            # Try to get version from Info.plist
            plist_path = app_path / "Contents" / "Info.plist"
            if plist_path.exists():
                version = self._get_version_from_plist(plist_path)
        
        # Find corresponding config directory
        for config_base in self._get_config_base_paths():
            for pattern in config["folder_patterns"]:
                for config_dir in config_base.glob(pattern):
                    if config_dir.is_dir():
                        config_path = str(config_dir)
                        plugins_path = self._find_plugins_path(config_dir)
                        if plugins_path:
                            extensions_path = str(plugins_path)
                        break
                if config_path:
                    break
        
        return IDE(
            ide_type=ide_type,
            name=config["name"],
            version=version,
            install_path=str(app_path),
            config_path=config_path,
            extensions_path=extensions_path,
        )
    
    def _find_plugins_path(self, config_dir: Path) -> Optional[Path]:
        """Find the plugins directory for a JetBrains config."""
        # Try common plugin locations
        candidates = [
            config_dir / "plugins",
            config_dir.parent / (config_dir.name + "-plugins"),
        ]
        
        for candidate in candidates:
            if candidate.exists():
                return candidate
        
        return None
    
    def _extract_version_from_folder(self, folder_name: str) -> Optional[str]:
        """Extract version number from folder name like 'PyCharm2023.2'."""
        match = re.search(r'(\d+\.\d+(?:\.\d+)?)', folder_name)
        return match.group(1) if match else None
    
    def _get_version_from_plist(self, plist_path: Path) -> Optional[str]:
        """Get version from macOS Info.plist."""
        try:
            import plistlib
            with open(plist_path, "rb") as f:
                plist = plistlib.load(f)
                return plist.get("CFBundleShortVersionString") or plist.get("CFBundleVersion")
        except Exception:
            return None
    
    def parse_extensions(self, ide: IDE) -> List[Extension]:
        """Parse plugins for a JetBrains IDE."""
        extensions = []
        
        if not ide.extensions_path or not os.path.isdir(ide.extensions_path):
            return extensions
        
        plugins_dir = Path(ide.extensions_path)
        
        for plugin_folder in plugins_dir.iterdir():
            if not plugin_folder.is_dir():
                continue
            
            if plugin_folder.name.startswith("."):
                continue
            
            extension = self._parse_plugin(plugin_folder)
            if extension:
                extensions.append(extension)
        
        return extensions
    
    def _parse_plugin(self, plugin_folder: Path) -> Optional[Extension]:
        """Parse a JetBrains plugin from its folder."""
        # JetBrains plugins can have plugin.xml in different locations
        plugin_xml_paths = [
            plugin_folder / "META-INF" / "plugin.xml",
            plugin_folder / "lib" / "plugin.xml",
        ]
        
        # Also check inside JAR files in lib/
        lib_dir = plugin_folder / "lib"
        if lib_dir.exists():
            for jar_file in lib_dir.glob("*.jar"):
                # For now, we'll just use folder-based detection
                pass
        
        plugin_xml = None
        for path in plugin_xml_paths:
            if path.exists():
                plugin_xml = path
                break
        
        if plugin_xml:
            return self._parse_plugin_xml(plugin_xml, plugin_folder)
        else:
            # Create basic extension from folder name
            return Extension(
                id=plugin_folder.name,
                name=plugin_folder.name,
                version="unknown",
                install_path=str(plugin_folder),
            )
    
    def _parse_plugin_xml(self, plugin_xml: Path, plugin_folder: Path) -> Optional[Extension]:
        """Parse plugin.xml file."""
        try:
            tree = ET.parse(plugin_xml)
            root = tree.getroot()
        except ET.ParseError:
            return None
        
        # Extract info from XML
        plugin_id = root.findtext("id", plugin_folder.name)
        name = root.findtext("name", plugin_folder.name)
        version = root.findtext("version", "unknown")
        
        # Vendor info
        vendor_elem = root.find("vendor")
        publisher = None
        homepage = None
        if vendor_elem is not None:
            publisher = vendor_elem.text
            homepage = vendor_elem.get("url")
        
        description = root.findtext("description", "")
        
        # Parse permissions/extensions
        permissions = self._extract_jetbrains_permissions(root)
        
        # Get dependencies
        dependencies = []
        for dep in root.findall(".//depends"):
            if dep.text:
                dependencies.append(dep.text)
        
        # Last updated
        last_updated = None
        try:
            stat = plugin_xml.stat()
            last_updated = datetime.fromtimestamp(stat.st_mtime)
        except OSError:
            pass
        
        return Extension(
            id=plugin_id,
            name=name,
            version=version,
            publisher=publisher,
            homepage=homepage,
            install_path=str(plugin_folder),
            permissions=permissions,
            dependencies=dependencies,
            last_updated=last_updated,
            description=description[:200] if description else None,  # Truncate
        )
    
    def _extract_jetbrains_permissions(self, root: ET.Element) -> List[Permission]:
        """Extract permissions from JetBrains plugin XML."""
        permissions = []
        
        # Check for extension points that indicate capabilities
        for ext in root.findall(".//extensions"):
            for child in ext:
                tag = child.tag
                
                # Map extension points to permissions
                if "action" in tag.lower():
                    permissions.append(Permission(
                        name="actions",
                        description="Registers IDE actions",
                        is_dangerous=False,
                    ))
                elif "toolwindow" in tag.lower():
                    permissions.append(Permission(
                        name="toolWindow",
                        description="Creates tool windows",
                        is_dangerous=False,
                    ))
                elif "projectservice" in tag.lower() or "applicationservice" in tag.lower():
                    permissions.append(Permission(
                        name="services",
                        description="Registers application/project services",
                        is_dangerous=False,
                    ))
        
        # Check for dangerous capabilities
        for ext in root.findall(".//*"):
            text = ET.tostring(ext, encoding='unicode', method='text').lower()
            
            if "exec" in text or "process" in text:
                permissions.append(Permission(
                    name="processExecution",
                    description="May execute external processes",
                    is_dangerous=True,
                ))
                break
        
        return permissions
