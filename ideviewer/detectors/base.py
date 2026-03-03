"""
Base detector class for IDE detection.
"""

import platform
import os
import sys
import subprocess
from abc import ABC, abstractmethod
from typing import List, Optional
from pathlib import Path

# Handle both direct execution and package import
try:
    from ..models import IDE, Extension
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent.parent))
    from ideviewer.models import IDE, Extension


class BaseDetector(ABC):
    """Base class for IDE detection."""
    
    def __init__(self):
        self.system = platform.system().lower()
        self.home = Path.home()
    
    @property
    def is_windows(self) -> bool:
        return self.system == "windows"
    
    @property
    def is_macos(self) -> bool:
        return self.system == "darwin"
    
    @property
    def is_linux(self) -> bool:
        return self.system == "linux"
    
    @abstractmethod
    def detect(self) -> List[IDE]:
        """Detect installed IDEs of this type."""
        pass
    
    @abstractmethod
    def parse_extensions(self, ide: IDE) -> List[Extension]:
        """Parse extensions for a given IDE."""
        pass
    
    def find_executable(self, name: str, additional_paths: Optional[List[str]] = None) -> Optional[str]:
        """Find an executable in PATH or additional locations."""
        # Check PATH first
        try:
            if self.is_windows:
                result = subprocess.run(
                    ["where", name],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            else:
                result = subprocess.run(
                    ["which", name],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
            if result.returncode == 0:
                return result.stdout.strip().split("\n")[0]
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        # Check additional paths
        if additional_paths:
            for path in additional_paths:
                expanded = os.path.expandvars(os.path.expanduser(path))
                if os.path.isfile(expanded) and os.access(expanded, os.X_OK):
                    return expanded
        
        return None
    
    def get_version(self, executable: str, version_args: List[str] = None) -> Optional[str]:
        """Get version from an executable."""
        if version_args is None:
            version_args = ["--version"]
        
        try:
            result = subprocess.run(
                [executable] + version_args,
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                # Return first line of output
                output = result.stdout.strip() or result.stderr.strip()
                return output.split("\n")[0] if output else None
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        
        return None
    
    def path_exists(self, path: str) -> bool:
        """Check if a path exists, expanding variables."""
        expanded = os.path.expandvars(os.path.expanduser(path))
        return os.path.exists(expanded)
    
    def expand_path(self, path: str) -> Path:
        """Expand environment variables and ~ in path."""
        return Path(os.path.expandvars(os.path.expanduser(path)))
    
    def is_process_running(self, process_names: List[str]) -> bool:
        """Check if any of the given process names are running."""
        try:
            import psutil
            for proc in psutil.process_iter(["name"]):
                try:
                    if proc.info["name"] in process_names:
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except ImportError:
            pass
        return False
