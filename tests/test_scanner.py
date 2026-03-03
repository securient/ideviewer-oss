"""Tests for the IDE scanner."""

import pytest
from ideviewer.scanner import IDEScanner
from ideviewer.models import ScanResult, IDE, Extension


class TestIDEScanner:
    """Test the main scanner."""
    
    def test_scanner_creation(self):
        """Test scanner can be created."""
        scanner = IDEScanner()
        assert scanner is not None
        assert len(scanner.detectors) > 0
    
    def test_scan_returns_result(self):
        """Test scan returns a ScanResult object."""
        scanner = IDEScanner()
        result = scanner.scan()
        
        assert isinstance(result, ScanResult)
        assert result.timestamp is not None
        assert result.platform is not None
        assert isinstance(result.ides, list)
    
    def test_scan_quick(self):
        """Test quick scan."""
        scanner = IDEScanner()
        result = scanner.scan_quick()
        
        assert isinstance(result, ScanResult)
        # Quick scan should have empty extension lists
        for ide in result.ides:
            assert ide.extensions == []
    
    def test_scan_with_filter(self):
        """Test scan with IDE type filter."""
        scanner = IDEScanner()
        result = scanner.scan(ide_types=["vscode"])
        
        # Should only return VS Code if installed
        for ide in result.ides:
            assert "code" in ide.name.lower() or ide.ide_type.value == "vscode"
    
    def test_extension_stats(self):
        """Test extension statistics."""
        scanner = IDEScanner()
        result = scanner.scan()
        stats = scanner.get_extension_stats(result)
        
        assert "total_ides" in stats
        assert "total_extensions" in stats
        assert "extensions_by_ide" in stats
        assert "permission_counts" in stats


class TestModels:
    """Test data models."""
    
    def test_extension_to_dict(self):
        """Test Extension serialization."""
        ext = Extension(
            id="test.extension",
            name="Test Extension",
            version="1.0.0",
            publisher="test-publisher",
        )
        
        data = ext.to_dict()
        
        assert data["id"] == "test.extension"
        assert data["name"] == "Test Extension"
        assert data["version"] == "1.0.0"
        assert data["publisher"] == "test-publisher"
    
    def test_ide_to_dict(self):
        """Test IDE serialization."""
        from ideviewer.models import IDEType
        
        ide = IDE(
            ide_type=IDEType.VSCODE,
            name="Visual Studio Code",
            version="1.85.0",
        )
        
        data = ide.to_dict()
        
        assert data["ide_type"] == "vscode"
        assert data["name"] == "Visual Studio Code"
        assert data["version"] == "1.85.0"
        assert data["extension_count"] == 0
    
    def test_scan_result_to_dict(self):
        """Test ScanResult serialization."""
        from datetime import datetime
        
        result = ScanResult(
            timestamp=datetime.now(),
            platform="Darwin 23.0",
        )
        
        data = result.to_dict()
        
        assert "timestamp" in data
        assert data["platform"] == "Darwin 23.0"
        assert data["total_ides"] == 0
        assert data["total_extensions"] == 0
