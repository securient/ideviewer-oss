"""
Main scanner that orchestrates IDE detection and extension parsing.
"""

import platform
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional
import logging

# Handle both direct execution and package import
try:
    from .models import IDE, ScanResult
    from .detectors.vscode import VSCodeDetector
    from .detectors.jetbrains import JetBrainsDetector
    from .detectors.sublime import SublimeTextDetector
    from .detectors.vim import VimDetector
    from .detectors.xcode import XcodeDetector
except ImportError:
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from ideviewer.models import IDE, ScanResult
    from ideviewer.detectors.vscode import VSCodeDetector
    from ideviewer.detectors.jetbrains import JetBrainsDetector
    from ideviewer.detectors.sublime import SublimeTextDetector
    from ideviewer.detectors.vim import VimDetector
    from ideviewer.detectors.xcode import XcodeDetector


logger = logging.getLogger(__name__)


class IDEScanner:
    """Main scanner for detecting IDEs and their extensions."""
    
    def __init__(self):
        """Initialize the scanner with all detectors."""
        self.detectors = [
            VSCodeDetector(),
            JetBrainsDetector(),
            SublimeTextDetector(),
            VimDetector(),
            XcodeDetector(),
        ]
    
    def scan(self, ide_types: Optional[List[str]] = None) -> ScanResult:
        """
        Perform a full scan of all installed IDEs and their extensions.
        
        Args:
            ide_types: Optional list of IDE type names to scan. If None, scans all.
        
        Returns:
            ScanResult with all detected IDEs and extensions.
        """
        result = ScanResult(
            timestamp=datetime.now(),
            platform=f"{platform.system()} {platform.release()}",
        )
        
        for detector in self.detectors:
            try:
                logger.info(f"Running detector: {detector.__class__.__name__}")
                ides = detector.detect()
                
                # Filter by IDE types if specified
                if ide_types:
                    ides = [
                        ide for ide in ides 
                        if ide.ide_type.value in ide_types or ide.name.lower() in [t.lower() for t in ide_types]
                    ]
                
                result.ides.extend(ides)
                logger.info(f"Found {len(ides)} IDEs from {detector.__class__.__name__}")
                
            except Exception as e:
                error_msg = f"Error in {detector.__class__.__name__}: {str(e)}"
                logger.error(error_msg)
                result.errors.append(error_msg)
        
        return result
    
    def scan_quick(self) -> ScanResult:
        """
        Perform a quick scan that only checks for IDE presence without parsing extensions.
        
        Returns:
            ScanResult with detected IDEs (no extension details).
        """
        result = ScanResult(
            timestamp=datetime.now(),
            platform=f"{platform.system()} {platform.release()}",
        )
        
        for detector in self.detectors:
            try:
                # Get IDEs without parsing extensions
                ides = detector.detect()
                for ide in ides:
                    # Clear extensions for quick scan
                    ide.extensions = []
                result.ides.extend(ides)
                
            except Exception as e:
                error_msg = f"Error in {detector.__class__.__name__}: {str(e)}"
                logger.error(error_msg)
                result.errors.append(error_msg)
        
        return result
    
    def get_extension_stats(self, result: ScanResult) -> dict:
        """
        Get statistics about extensions from a scan result.
        
        Args:
            result: A ScanResult from a previous scan.
        
        Returns:
            Dictionary with extension statistics.
        """
        total_extensions = 0
        dangerous_extensions = 0
        extensions_by_ide = {}
        permission_counts = {}
        
        for ide in result.ides:
            ide_name = ide.name
            ext_count = len(ide.extensions)
            total_extensions += ext_count
            extensions_by_ide[ide_name] = ext_count
            
            for ext in ide.extensions:
                for perm in ext.permissions:
                    if perm.is_dangerous:
                        dangerous_extensions += 1
                        break
                
                for perm in ext.permissions:
                    perm_name = perm.name
                    if perm_name not in permission_counts:
                        permission_counts[perm_name] = {"count": 0, "is_dangerous": perm.is_dangerous}
                    permission_counts[perm_name]["count"] += 1
        
        return {
            "total_ides": len(result.ides),
            "total_extensions": total_extensions,
            "extensions_with_dangerous_permissions": dangerous_extensions,
            "extensions_by_ide": extensions_by_ide,
            "permission_counts": permission_counts,
        }
