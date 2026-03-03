"""
VS Code, Cursor, and VSCodium detector.

These IDEs share similar extension formats based on VS Code.
"""

import json
import os
import sys
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

# Handle both direct execution and package import
try:
    from .base import BaseDetector
    from ..models import IDE, IDEType, Extension, Permission
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from ideviewer.detectors.base import BaseDetector
    from ideviewer.models import IDE, IDEType, Extension, Permission


# Known dangerous VS Code extension permissions/capabilities
DANGEROUS_PERMISSIONS = {
    "onFileSystem": "Full file system access",
    "onStartupFinished": "Runs on startup",
    "onUri": "Can register URI handlers",
    "onAuthenticationRequest": "Authentication access",
    "onDebug": "Debugger access",
    "onTerminalProfile": "Terminal access",
    "*": "Wildcard activation (runs for everything)",
}

# Capability patterns that indicate elevated permissions
DANGEROUS_CAPABILITIES = {
    "untrustedWorkspaces.supported": "Can run in untrusted workspaces",
    "virtualWorkspaces.supported": "Virtual workspace access",
}


class VSCodeDetector(BaseDetector):
    """Detector for VS Code-based editors."""
    
    # Configuration for different VS Code variants
    VARIANTS = {
        IDEType.VSCODE: {
            "name": "Visual Studio Code",
            "executables": {
                "darwin": [
                    "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code",
                    "/usr/local/bin/code",
                ],
                "linux": [
                    "/usr/bin/code",
                    "/usr/share/code/bin/code",
                    "/snap/bin/code",
                ],
                "windows": [
                    "%LOCALAPPDATA%\\Programs\\Microsoft VS Code\\Code.exe",
                    "%ProgramFiles%\\Microsoft VS Code\\Code.exe",
                ],
            },
            "extensions_paths": {
                "darwin": ["~/.vscode/extensions"],
                "linux": ["~/.vscode/extensions"],
                "windows": ["%USERPROFILE%\\.vscode\\extensions"],
            },
            "config_paths": {
                "darwin": ["~/Library/Application Support/Code"],
                "linux": ["~/.config/Code"],
                "windows": ["%APPDATA%\\Code"],
            },
            "process_names": ["Code", "code", "Code.exe"],
        },
        IDEType.CURSOR: {
            "name": "Cursor",
            "executables": {
                "darwin": [
                    "/Applications/Cursor.app/Contents/Resources/app/bin/cursor",
                    "/usr/local/bin/cursor",
                ],
                "linux": [
                    "/usr/bin/cursor",
                    "/opt/Cursor/cursor",
                    "~/.local/bin/cursor",
                ],
                "windows": [
                    "%LOCALAPPDATA%\\Programs\\Cursor\\Cursor.exe",
                    "%LOCALAPPDATA%\\cursor\\Cursor.exe",
                ],
            },
            "extensions_paths": {
                "darwin": ["~/.cursor/extensions"],
                "linux": ["~/.cursor/extensions"],
                "windows": ["%USERPROFILE%\\.cursor\\extensions"],
            },
            "config_paths": {
                "darwin": ["~/Library/Application Support/Cursor"],
                "linux": ["~/.config/Cursor"],
                "windows": ["%APPDATA%\\Cursor"],
            },
            "process_names": ["Cursor", "cursor", "Cursor.exe"],
        },
        IDEType.VSCODIUM: {
            "name": "VSCodium",
            "executables": {
                "darwin": [
                    "/Applications/VSCodium.app/Contents/Resources/app/bin/codium",
                    "/usr/local/bin/codium",
                ],
                "linux": [
                    "/usr/bin/codium",
                    "/snap/bin/codium",
                ],
                "windows": [
                    "%LOCALAPPDATA%\\Programs\\VSCodium\\VSCodium.exe",
                    "%ProgramFiles%\\VSCodium\\VSCodium.exe",
                ],
            },
            "extensions_paths": {
                "darwin": ["~/.vscode-oss/extensions"],
                "linux": ["~/.vscode-oss/extensions"],
                "windows": ["%USERPROFILE%\\.vscode-oss\\extensions"],
            },
            "config_paths": {
                "darwin": ["~/Library/Application Support/VSCodium"],
                "linux": ["~/.config/VSCodium"],
                "windows": ["%APPDATA%\\VSCodium"],
            },
            "process_names": ["VSCodium", "codium", "VSCodium.exe"],
        },
    }
    
    def detect(self) -> List[IDE]:
        """Detect all installed VS Code variants."""
        ides = []
        
        for ide_type, config in self.VARIANTS.items():
            ide = self._detect_variant(ide_type, config)
            if ide:
                # Parse extensions for this IDE
                ide.extensions = self.parse_extensions(ide)
                ides.append(ide)
        
        return ides
    
    def _detect_variant(self, ide_type: IDEType, config: Dict[str, Any]) -> Optional[IDE]:
        """Detect a specific VS Code variant."""
        # Get platform-specific paths
        platform_key = self.system
        executables = config["executables"].get(platform_key, [])
        extensions_paths = config["extensions_paths"].get(platform_key, [])
        config_paths = config["config_paths"].get(platform_key, [])
        
        # Find executable
        install_path = None
        for exe_path in executables:
            expanded = self.expand_path(exe_path)
            if expanded.exists():
                install_path = str(expanded)
                break
        
        # Also check if just looking at extension directories (IDE might be installed differently)
        extensions_path = None
        for ext_path in extensions_paths:
            expanded = self.expand_path(ext_path)
            if expanded.exists():
                extensions_path = str(expanded)
                break
        
        # If neither executable nor extensions found, IDE is not installed
        if not install_path and not extensions_path:
            return None
        
        # Find config path
        config_path = None
        for cfg_path in config_paths:
            expanded = self.expand_path(cfg_path)
            if expanded.exists():
                config_path = str(expanded)
                break
        
        # Get version
        version = None
        if install_path:
            version = self.get_version(install_path)
        
        # Check if running
        is_running = self.is_process_running(config["process_names"])
        
        return IDE(
            ide_type=ide_type,
            name=config["name"],
            version=version,
            install_path=install_path,
            config_path=config_path,
            extensions_path=extensions_path,
            is_running=is_running,
        )
    
    def parse_extensions(self, ide: IDE) -> List[Extension]:
        """Parse all extensions for a VS Code variant."""
        extensions = []
        
        if not ide.extensions_path or not os.path.isdir(ide.extensions_path):
            return extensions
        
        extensions_dir = Path(ide.extensions_path)
        
        for ext_folder in extensions_dir.iterdir():
            if not ext_folder.is_dir():
                continue
            
            # Skip .obsolete folders
            if ext_folder.name.startswith("."):
                continue
            
            extension = self._parse_extension(ext_folder, ide.ide_type)
            if extension:
                extensions.append(extension)
        
        return extensions
    
    def _parse_extension(self, ext_folder: Path, ide_type: IDEType) -> Optional[Extension]:
        """Parse a single extension from its folder."""
        package_json = ext_folder / "package.json"
        
        if not package_json.exists():
            return None
        
        try:
            with open(package_json, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        except (json.JSONDecodeError, IOError):
            return None
        
        # Extract basic info
        ext_id = manifest.get("name", ext_folder.name)
        publisher = manifest.get("publisher", "")
        if publisher:
            ext_id = f"{publisher}.{ext_id}"
        
        # Parse permissions from activation events
        permissions = self._extract_permissions(manifest)
        
        # Get marketplace URL
        marketplace_url = None
        if ide_type == IDEType.VSCODE:
            marketplace_url = f"https://marketplace.visualstudio.com/items?itemName={ext_id}"
        elif ide_type == IDEType.VSCODIUM:
            marketplace_url = f"https://open-vsx.org/extension/{publisher}/{manifest.get('name', '')}"
        
        # Get repository info
        repository = manifest.get("repository")
        if isinstance(repository, dict):
            repository = repository.get("url", "")
        
        # Get last modified time
        last_updated = None
        try:
            stat = package_json.stat()
            last_updated = datetime.fromtimestamp(stat.st_mtime)
        except OSError:
            pass
        
        # Check if builtin
        is_builtin = "ms-vscode" in str(ext_folder).lower() and "builtin" in str(ext_folder).lower()
        
        return Extension(
            id=ext_id,
            name=manifest.get("displayName", manifest.get("name", ext_folder.name)),
            version=manifest.get("version", "unknown"),
            publisher=publisher,
            maintainer=manifest.get("author", {}).get("name") if isinstance(manifest.get("author"), dict) else manifest.get("author"),
            description=manifest.get("description"),
            homepage=manifest.get("homepage"),
            repository=repository,
            license=manifest.get("license"),
            install_path=str(ext_folder),
            permissions=permissions,
            contributes=self._summarize_contributes(manifest.get("contributes", {})),
            dependencies=list(manifest.get("extensionDependencies", [])),
            enabled=True,  # Would need to check settings to determine this
            builtin=is_builtin,
            last_updated=last_updated,
            marketplace_url=marketplace_url,
            activation_events=manifest.get("activationEvents", []),
            capabilities=manifest.get("capabilities", {}),
        )
    
    def _extract_permissions(self, manifest: Dict[str, Any]) -> List[Permission]:
        """Extract permissions from extension manifest."""
        permissions = []
        
        # Check activation events
        activation_events = manifest.get("activationEvents", [])
        for event in activation_events:
            event_type = event.split(":")[0] if ":" in event else event
            
            if event_type in DANGEROUS_PERMISSIONS:
                permissions.append(Permission(
                    name=event_type,
                    description=DANGEROUS_PERMISSIONS[event_type],
                    is_dangerous=True,
                ))
            elif event == "*":
                permissions.append(Permission(
                    name="*",
                    description=DANGEROUS_PERMISSIONS["*"],
                    is_dangerous=True,
                ))
        
        # Check capabilities
        capabilities = manifest.get("capabilities", {})
        for cap_name, cap_desc in DANGEROUS_CAPABILITIES.items():
            if cap_name in str(capabilities):
                permissions.append(Permission(
                    name=cap_name,
                    description=cap_desc,
                    is_dangerous=True,
                ))
        
        # Check contributes for sensitive contributions
        contributes = manifest.get("contributes", {})
        
        if "authentication" in contributes:
            permissions.append(Permission(
                name="authentication",
                description="Provides authentication providers",
                is_dangerous=True,
            ))
        
        if "terminal" in contributes:
            permissions.append(Permission(
                name="terminal",
                description="Terminal integration",
                is_dangerous=True,
            ))
        
        if "debuggers" in contributes:
            permissions.append(Permission(
                name="debuggers",
                description="Debugger integration",
                is_dangerous=False,
            ))
        
        if "taskDefinitions" in contributes:
            permissions.append(Permission(
                name="taskDefinitions",
                description="Can define tasks (may execute commands)",
                is_dangerous=True,
            ))
        
        if "commands" in contributes:
            permissions.append(Permission(
                name="commands",
                description=f"Registers {len(contributes['commands'])} commands",
                is_dangerous=False,
            ))
        
        return permissions
    
    def _summarize_contributes(self, contributes: Dict[str, Any]) -> Dict[str, Any]:
        """Summarize the contributes section."""
        summary = {}
        
        for key, value in contributes.items():
            if isinstance(value, list):
                summary[key] = len(value)
            elif isinstance(value, dict):
                summary[key] = len(value)
            else:
                summary[key] = 1
        
        return summary
