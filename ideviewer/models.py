"""
Data models for IDE and Extension information.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum
from datetime import datetime


class IDEType(Enum):
    """Supported IDE types."""
    VSCODE = "vscode"
    CURSOR = "cursor"
    VSCODIUM = "vscodium"
    JETBRAINS_IDEA = "intellij-idea"
    JETBRAINS_PYCHARM = "pycharm"
    JETBRAINS_WEBSTORM = "webstorm"
    JETBRAINS_GOLAND = "goland"
    JETBRAINS_CLION = "clion"
    JETBRAINS_RIDER = "rider"
    JETBRAINS_PHPSTORM = "phpstorm"
    JETBRAINS_RUBYMINE = "rubymine"
    JETBRAINS_DATAGRIP = "datagrip"
    SUBLIME_TEXT = "sublime-text"
    ATOM = "atom"
    VIM = "vim"
    NEOVIM = "neovim"
    EMACS = "emacs"
    ECLIPSE = "eclipse"
    ANDROID_STUDIO = "android-studio"
    XCODE = "xcode"
    UNKNOWN = "unknown"


@dataclass
class Permission:
    """Extension permission/capability."""
    name: str
    description: Optional[str] = None
    is_dangerous: bool = False


@dataclass
class Extension:
    """Represents an IDE extension/plugin."""
    id: str
    name: str
    version: str
    publisher: Optional[str] = None
    maintainer: Optional[str] = None
    description: Optional[str] = None
    homepage: Optional[str] = None
    repository: Optional[str] = None
    license: Optional[str] = None
    install_path: Optional[str] = None
    permissions: List[Permission] = field(default_factory=list)
    contributes: Dict[str, Any] = field(default_factory=dict)
    dependencies: List[str] = field(default_factory=list)
    enabled: bool = True
    builtin: bool = False
    last_updated: Optional[datetime] = None
    marketplace_url: Optional[str] = None
    
    # VS Code specific
    activation_events: List[str] = field(default_factory=list)
    capabilities: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "publisher": self.publisher,
            "maintainer": self.maintainer,
            "description": self.description,
            "homepage": self.homepage,
            "repository": self.repository,
            "license": self.license,
            "install_path": self.install_path,
            "permissions": [{"name": p.name, "description": p.description, "is_dangerous": p.is_dangerous} for p in self.permissions],
            "contributes": self.contributes,
            "dependencies": self.dependencies,
            "enabled": self.enabled,
            "builtin": self.builtin,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "marketplace_url": self.marketplace_url,
            "activation_events": self.activation_events,
            "capabilities": self.capabilities,
        }


@dataclass
class IDE:
    """Represents an installed IDE."""
    ide_type: IDEType
    name: str
    version: Optional[str] = None
    install_path: Optional[str] = None
    config_path: Optional[str] = None
    extensions_path: Optional[str] = None
    extensions: List[Extension] = field(default_factory=list)
    is_running: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "ide_type": self.ide_type.value,
            "name": self.name,
            "version": self.version,
            "install_path": self.install_path,
            "config_path": self.config_path,
            "extensions_path": self.extensions_path,
            "extensions": [ext.to_dict() for ext in self.extensions],
            "extension_count": len(self.extensions),
            "is_running": self.is_running,
        }


@dataclass
class ScanResult:
    """Result of an IDE scan."""
    timestamp: datetime
    platform: str
    ides: List[IDE] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "platform": self.platform,
            "ides": [ide.to_dict() for ide in self.ides],
            "total_ides": len(self.ides),
            "total_extensions": sum(len(ide.extensions) for ide in self.ides),
            "errors": self.errors,
        }
