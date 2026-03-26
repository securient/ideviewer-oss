"""Tests for the IDE scanner and detectors."""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime

from ideviewer.scanner import IDEScanner
from ideviewer.models import ScanResult, IDE, IDEType, Extension, Permission


class TestIDEScanner:
    """Test the main scanner."""

    def test_scanner_creation(self):
        """Scanner can be created with all detectors."""
        scanner = IDEScanner()
        assert scanner is not None
        assert len(scanner.detectors) == 5  # vscode, jetbrains, sublime, vim, xcode

    def test_scan_returns_result(self):
        """scan() returns a ScanResult with timestamp and platform."""
        scanner = IDEScanner()
        result = scanner.scan()
        assert isinstance(result, ScanResult)
        assert result.timestamp is not None
        assert result.platform is not None
        assert isinstance(result.ides, list)

    def test_scan_quick_clears_extensions(self):
        """Quick scan should clear extension lists."""
        scanner = IDEScanner()
        result = scanner.scan_quick()
        assert isinstance(result, ScanResult)
        for ide in result.ides:
            assert ide.extensions == []

    def test_scan_with_ide_type_filter(self):
        """Filtering by IDE type should only return matching IDEs."""
        scanner = IDEScanner()
        result = scanner.scan(ide_types=["vscode"])
        for ide in result.ides:
            assert "code" in ide.name.lower() or ide.ide_type.value == "vscode"

    def test_scan_with_unknown_filter_returns_empty(self):
        """Filtering by a non-existent IDE type returns no IDEs."""
        scanner = IDEScanner()
        result = scanner.scan(ide_types=["nonexistent-ide-xyz"])
        assert len(result.ides) == 0

    def test_extension_stats_structure(self, sample_scan_result):
        """get_extension_stats returns all expected keys."""
        scanner = IDEScanner()
        stats = scanner.get_extension_stats(sample_scan_result)
        assert stats["total_ides"] == 1
        assert stats["total_extensions"] == 2
        assert "Visual Studio Code" in stats["extensions_by_ide"]
        assert stats["extensions_by_ide"]["Visual Studio Code"] == 2
        assert isinstance(stats["permission_counts"], dict)
        assert "extensions_with_dangerous_permissions" in stats

    def test_extension_stats_counts_dangerous(self, sample_scan_result):
        """Dangerous extensions are counted correctly."""
        scanner = IDEScanner()
        stats = scanner.get_extension_stats(sample_scan_result)
        # sample_extension has a dangerous permission
        assert stats["extensions_with_dangerous_permissions"] >= 1

    def test_extension_stats_empty_result(self):
        """Stats on empty ScanResult should return zeros."""
        scanner = IDEScanner()
        result = ScanResult(timestamp=datetime.now(), platform="Test")
        stats = scanner.get_extension_stats(result)
        assert stats["total_ides"] == 0
        assert stats["total_extensions"] == 0
        assert stats["extensions_with_dangerous_permissions"] == 0

    def test_detector_error_captured(self):
        """If a detector raises, the error is captured in result.errors."""
        scanner = IDEScanner()
        bad_detector = MagicMock()
        bad_detector.__class__.__name__ = "BrokenDetector"
        bad_detector.detect.side_effect = RuntimeError("detector exploded")
        scanner.detectors = [bad_detector]

        result = scanner.scan()
        assert len(result.errors) == 1
        assert "BrokenDetector" in result.errors[0]
        assert "detector exploded" in result.errors[0]

    def test_scan_result_to_dict(self, sample_scan_result):
        """ScanResult.to_dict() produces valid structure."""
        data = sample_scan_result.to_dict()
        assert data["platform"] == "Darwin 23.0"
        assert data["total_ides"] == 1
        assert data["total_extensions"] == 2
        assert len(data["ides"]) == 1
        assert data["ides"][0]["ide_type"] == "vscode"
