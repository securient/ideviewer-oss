"""
Xcode detector (macOS only).
"""

import os
import sys
import subprocess
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


class XcodeDetector(BaseDetector):
    """Detector for Xcode (macOS only)."""
    
    def detect(self) -> List[IDE]:
        """Detect Xcode installation."""
        if not self.is_macos:
            return []
        
        ides = []
        
        # Check for Xcode
        xcode = self._detect_xcode()
        if xcode:
            xcode.extensions = self.parse_extensions(xcode)
            ides.append(xcode)
        
        return ides
    
    def _detect_xcode(self) -> Optional[IDE]:
        """Detect Xcode installation."""
        # Standard location
        xcode_path = Path("/Applications/Xcode.app")
        
        if not xcode_path.exists():
            # Try xcode-select to find it
            try:
                result = subprocess.run(
                    ["xcode-select", "-p"],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    dev_path = Path(result.stdout.strip())
                    if "Xcode" in str(dev_path):
                        xcode_path = dev_path.parent.parent
            except (subprocess.SubprocessError, FileNotFoundError):
                pass
        
        if not xcode_path.exists():
            return None
        
        # Get version from plist
        version = None
        plist_path = xcode_path / "Contents" / "Info.plist"
        if plist_path.exists():
            try:
                import plistlib
                with open(plist_path, "rb") as f:
                    plist = plistlib.load(f)
                    version = plist.get("CFBundleShortVersionString")
            except Exception:
                pass
        
        # Extensions/plugins path
        extensions_path = self.home / "Library" / "Developer" / "Xcode" / "Plug-ins"
        
        return IDE(
            ide_type=IDEType.XCODE,
            name="Xcode",
            version=version,
            install_path=str(xcode_path),
            config_path=str(self.home / "Library" / "Developer" / "Xcode"),
            extensions_path=str(extensions_path) if extensions_path.exists() else None,
            is_running=self.is_process_running(["Xcode"]),
        )
    
    def parse_extensions(self, ide: IDE) -> List[Extension]:
        """Parse Xcode plugins."""
        extensions = []
        
        if not ide.extensions_path or not os.path.isdir(ide.extensions_path):
            return extensions
        
        plugins_dir = Path(ide.extensions_path)
        
        for plugin in plugins_dir.glob("*.xcplugin"):
            ext = self._parse_xcplugin(plugin)
            if ext:
                extensions.append(ext)
        
        # Also check for source editor extensions
        extensions.extend(self._find_source_editor_extensions())
        
        return extensions
    
    def _parse_xcplugin(self, plugin_path: Path) -> Optional[Extension]:
        """Parse an Xcode plugin bundle."""
        plist_path = plugin_path / "Contents" / "Info.plist"
        
        if not plist_path.exists():
            return Extension(
                id=plugin_path.stem,
                name=plugin_path.stem,
                version="unknown",
                install_path=str(plugin_path),
            )
        
        try:
            import plistlib
            with open(plist_path, "rb") as f:
                plist = plistlib.load(f)
        except Exception:
            return Extension(
                id=plugin_path.stem,
                name=plugin_path.stem,
                version="unknown",
                install_path=str(plugin_path),
            )
        
        name = plist.get("CFBundleName", plugin_path.stem)
        version = plist.get("CFBundleShortVersionString", plist.get("CFBundleVersion", "unknown"))
        identifier = plist.get("CFBundleIdentifier", plugin_path.stem)
        
        # Get last updated
        last_updated = None
        try:
            stat = plugin_path.stat()
            last_updated = datetime.fromtimestamp(stat.st_mtime)
        except OSError:
            pass
        
        return Extension(
            id=identifier,
            name=name,
            version=version,
            install_path=str(plugin_path),
            last_updated=last_updated,
        )
    
    def _find_source_editor_extensions(self) -> List[Extension]:
        """Find Xcode Source Editor Extensions from installed apps."""
        extensions = []
        
        # Source editor extensions are app extensions in installed apps
        app_dirs = [
            Path("/Applications"),
            self.home / "Applications",
        ]
        
        for app_dir in app_dirs:
            if not app_dir.exists():
                continue
            
            for app in app_dir.glob("*.app"):
                plugins_dir = app / "Contents" / "PlugIns"
                if not plugins_dir.exists():
                    continue
                
                for plugin in plugins_dir.glob("*.appex"):
                    plist_path = plugin / "Contents" / "Info.plist"
                    if not plist_path.exists():
                        continue
                    
                    try:
                        import plistlib
                        with open(plist_path, "rb") as f:
                            plist = plistlib.load(f)
                        
                        # Check if it's a source editor extension
                        ns_extension = plist.get("NSExtension", {})
                        ext_point = ns_extension.get("NSExtensionPointIdentifier", "")
                        
                        if ext_point == "com.apple.dt.Xcode.extension.source-editor":
                            name = plist.get("CFBundleName", plugin.stem)
                            version = plist.get("CFBundleShortVersionString", "unknown")
                            identifier = plist.get("CFBundleIdentifier", plugin.stem)
                            
                            extensions.append(Extension(
                                id=identifier,
                                name=f"{name} (Source Editor Extension)",
                                version=version,
                                install_path=str(plugin),
                                publisher=app.stem,  # Parent app name
                            ))
                    except Exception:
                        continue
        
        return extensions
