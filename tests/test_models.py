"""Tests for the data models (ideviewer.models)."""

import pytest
from datetime import datetime

from ideviewer.models import Permission, Extension, IDE, IDEType, ScanResult


class TestPermission:
    """Test Permission dataclass."""

    def test_creation(self, sample_permission):
        assert sample_permission.name == "fileSystem"
        assert sample_permission.is_dangerous is True
        assert sample_permission.description == "Access the file system"

    def test_safe_permission(self, safe_permission):
        assert safe_permission.is_dangerous is False

    def test_defaults(self):
        perm = Permission(name="test")
        assert perm.description is None
        assert perm.is_dangerous is False


class TestExtension:
    """Test Extension dataclass."""

    def test_creation(self):
        ext = Extension(id="ext.id", name="My Extension", version="1.0.0")
        assert ext.id == "ext.id"
        assert ext.publisher is None
        assert ext.enabled is True
        assert ext.builtin is False
        assert ext.permissions == []
        assert ext.dependencies == []
        assert ext.activation_events == []

    def test_to_dict(self, sample_extension):
        data = sample_extension.to_dict()
        assert data["id"] == "pub.dangerous-ext"
        assert data["name"] == "Dangerous Extension"
        assert data["version"] == "2.1.0"
        assert data["publisher"] == "evil-corp"
        assert len(data["permissions"]) == 2
        assert data["permissions"][0]["is_dangerous"] is True
        assert data["enabled"] is True

    def test_to_dict_permission_structure(self, sample_extension):
        data = sample_extension.to_dict()
        perm = data["permissions"][0]
        assert "name" in perm
        assert "description" in perm
        assert "is_dangerous" in perm

    def test_to_dict_last_updated_none(self):
        ext = Extension(id="x", name="X", version="1.0")
        data = ext.to_dict()
        assert data["last_updated"] is None

    def test_to_dict_last_updated_iso(self):
        dt = datetime(2024, 6, 15, 12, 0, 0)
        ext = Extension(id="x", name="X", version="1.0", last_updated=dt)
        data = ext.to_dict()
        assert data["last_updated"] == "2024-06-15T12:00:00"


class TestIDE:
    """Test IDE dataclass."""

    def test_creation(self):
        ide = IDE(ide_type=IDEType.VSCODE, name="VS Code")
        assert ide.version is None
        assert ide.extensions == []
        assert ide.is_running is False

    def test_to_dict(self, sample_ide):
        data = sample_ide.to_dict()
        assert data["ide_type"] == "vscode"
        assert data["name"] == "Visual Studio Code"
        assert data["version"] == "1.85.0"
        assert data["extension_count"] == 2
        assert data["is_running"] is True
        assert len(data["extensions"]) == 2

    def test_all_ide_types_have_values(self):
        """All IDEType enum members should have string values."""
        for member in IDEType:
            assert isinstance(member.value, str)
            assert len(member.value) > 0


class TestScanResult:
    """Test ScanResult dataclass."""

    def test_creation(self):
        result = ScanResult(timestamp=datetime.now(), platform="Test 1.0")
        assert result.ides == []
        assert result.errors == []

    def test_to_dict(self, sample_scan_result):
        data = sample_scan_result.to_dict()
        assert data["platform"] == "Darwin 23.0"
        assert data["total_ides"] == 1
        assert data["total_extensions"] == 2
        assert "timestamp" in data
        assert "errors" in data
        assert isinstance(data["ides"], list)

    def test_total_extensions_sums_across_ides(self):
        ext1 = Extension(id="a", name="A", version="1.0")
        ext2 = Extension(id="b", name="B", version="1.0")
        ext3 = Extension(id="c", name="C", version="1.0")
        ide1 = IDE(ide_type=IDEType.VSCODE, name="Code", extensions=[ext1, ext2])
        ide2 = IDE(ide_type=IDEType.VIM, name="Vim", extensions=[ext3])
        result = ScanResult(
            timestamp=datetime.now(),
            platform="Test",
            ides=[ide1, ide2],
        )
        data = result.to_dict()
        assert data["total_extensions"] == 3
        assert data["total_ides"] == 2

    def test_errors_included(self):
        result = ScanResult(
            timestamp=datetime.now(),
            platform="Test",
            errors=["error 1", "error 2"],
        )
        data = result.to_dict()
        assert data["errors"] == ["error 1", "error 2"]
