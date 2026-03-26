"""Tests for the self-updater: version parsing, platform detection, update checking."""

import pytest
from unittest.mock import patch, MagicMock

from ideviewer.updater import (
    parse_version,
    get_platform_asset_pattern,
    find_asset,
    check_for_update,
)


class TestParseVersion:
    """Test version string parsing."""

    def test_simple_version(self):
        assert parse_version("0.1.0") == (0, 1, 0)

    def test_with_v_prefix(self):
        assert parse_version("v1.2.3") == (1, 2, 3)

    def test_two_part_version(self):
        assert parse_version("1.0") == (1, 0)

    def test_four_part_version(self):
        assert parse_version("1.2.3.4") == (1, 2, 3, 4)

    def test_non_numeric_part_becomes_zero(self):
        assert parse_version("1.2.beta") == (1, 2, 0)

    def test_comparison_newer(self):
        assert parse_version("v1.1.0") > parse_version("v1.0.0")
        assert parse_version("2.0.0") > parse_version("1.99.99")

    def test_comparison_equal(self):
        assert parse_version("1.0.0") == parse_version("v1.0.0")

    def test_comparison_older(self):
        assert parse_version("0.1.0") < parse_version("0.2.0")


class TestGetPlatformAssetPattern:
    """Test platform-specific asset pattern detection."""

    @patch("ideviewer.updater.platform")
    def test_darwin(self, mock_platform):
        mock_platform.system.return_value = "Darwin"
        mock_platform.machine.return_value = "arm64"
        prefix, suffix = get_platform_asset_pattern()
        assert prefix == "IDEViewer-"
        assert suffix == ".pkg"

    @patch("ideviewer.updater.platform")
    def test_windows(self, mock_platform):
        mock_platform.system.return_value = "Windows"
        mock_platform.machine.return_value = "AMD64"
        prefix, suffix = get_platform_asset_pattern()
        assert prefix == "IDEViewer-Setup-"
        assert suffix == ".exe"

    @patch("ideviewer.updater.platform")
    def test_linux_amd64(self, mock_platform):
        mock_platform.system.return_value = "Linux"
        mock_platform.machine.return_value = "x86_64"
        prefix, suffix = get_platform_asset_pattern()
        assert prefix == "ideviewer_"
        assert suffix == "_amd64.deb"

    @patch("ideviewer.updater.platform")
    def test_linux_arm64(self, mock_platform):
        mock_platform.system.return_value = "Linux"
        mock_platform.machine.return_value = "aarch64"
        prefix, suffix = get_platform_asset_pattern()
        assert prefix == "ideviewer_"
        assert suffix == "_arm64.deb"

    @patch("ideviewer.updater.platform")
    def test_unsupported_raises(self, mock_platform):
        mock_platform.system.return_value = "FreeBSD"
        mock_platform.machine.return_value = "amd64"
        with pytest.raises(RuntimeError, match="Unsupported platform"):
            get_platform_asset_pattern()


class TestFindAsset:
    """Test release asset matching."""

    @patch("ideviewer.updater.get_platform_asset_pattern")
    def test_finds_matching_asset(self, mock_pattern):
        mock_pattern.return_value = ("IDEViewer-", ".pkg")
        release = {
            "assets": [
                {"name": "IDEViewer-1.0.0.pkg", "browser_download_url": "https://example.com/pkg"},
                {"name": "ideviewer_1.0.0_amd64.deb", "browser_download_url": "https://example.com/deb"},
            ]
        }
        asset = find_asset(release)
        assert asset["name"] == "IDEViewer-1.0.0.pkg"

    @patch("ideviewer.updater.get_platform_asset_pattern")
    def test_no_matching_asset_raises(self, mock_pattern):
        mock_pattern.return_value = ("IDEViewer-Setup-", ".exe")
        release = {
            "assets": [
                {"name": "IDEViewer-1.0.0.pkg"},
            ]
        }
        with pytest.raises(RuntimeError, match="No matching release asset"):
            find_asset(release)

    @patch("ideviewer.updater.get_platform_asset_pattern")
    def test_empty_assets_raises(self, mock_pattern):
        mock_pattern.return_value = ("IDEViewer-", ".pkg")
        with pytest.raises(RuntimeError):
            find_asset({"assets": []})


class TestCheckForUpdate:
    """Test update checking logic."""

    @patch("ideviewer.updater.fetch_latest_release")
    @patch("ideviewer.updater.get_current_version")
    def test_update_available(self, mock_current, mock_fetch):
        mock_current.return_value = "0.1.0"
        mock_fetch.return_value = {
            "tag_name": "v0.2.0",
            "body": "New release",
            "assets": [],
        }
        has_update, current, latest, release = check_for_update()
        assert has_update is True
        assert current == "0.1.0"
        assert latest == "0.2.0"

    @patch("ideviewer.updater.fetch_latest_release")
    @patch("ideviewer.updater.get_current_version")
    def test_no_update_available(self, mock_current, mock_fetch):
        mock_current.return_value = "1.0.0"
        mock_fetch.return_value = {
            "tag_name": "v1.0.0",
            "assets": [],
        }
        has_update, current, latest, release = check_for_update()
        assert has_update is False

    @patch("ideviewer.updater.fetch_latest_release")
    @patch("ideviewer.updater.get_current_version")
    def test_current_newer_than_latest(self, mock_current, mock_fetch):
        mock_current.return_value = "2.0.0"
        mock_fetch.return_value = {
            "tag_name": "v1.0.0",
            "assets": [],
        }
        has_update, _, _, _ = check_for_update()
        assert has_update is False
