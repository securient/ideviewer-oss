"""Tests for the CLI commands using click.testing.CliRunner."""

import json
import pytest
from unittest.mock import patch, MagicMock
from click.testing import CliRunner

from ideviewer.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


class TestCLIGroup:
    """Test the main CLI group."""

    def test_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "IDE Viewer" in result.output

    def test_version(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "version" in result.output.lower()


class TestScanCommand:
    """Test the 'scan' command."""

    def test_scan_help(self, runner):
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--json" in result.output
        assert "--output-sarif" in result.output
        assert "--output" in result.output
        assert "--ide" in result.output
        assert "--portal" in result.output

    @patch("ideviewer.cli.IDEScanner")
    def test_scan_json(self, mock_scanner_cls, runner):
        mock_scanner = MagicMock()
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {"ides": [], "total_ides": 0, "total_extensions": 0}
        mock_scanner.scan.return_value = mock_result
        mock_scanner_cls.return_value = mock_scanner

        result = runner.invoke(cli, ["scan", "--json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "ides" in parsed

    @patch("ideviewer.cli.IDEScanner")
    @patch("ideviewer.cli.scan_result_to_sarif")
    @patch("ideviewer.cli.to_sarif_json")
    def test_scan_sarif(self, mock_to_json, mock_to_sarif, mock_scanner_cls, runner):
        mock_scanner = MagicMock()
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {"ides": []}
        mock_scanner.scan.return_value = mock_result
        mock_scanner_cls.return_value = mock_scanner
        mock_to_sarif.return_value = {"version": "2.1.0"}
        mock_to_json.return_value = '{"version": "2.1.0"}'

        result = runner.invoke(cli, ["scan", "--output-sarif"])
        assert result.exit_code == 0
        mock_to_sarif.assert_called_once()


class TestSecretsCommand:
    """Test the 'secrets' command."""

    def test_secrets_help(self, runner):
        result = runner.invoke(cli, ["secrets", "--help"])
        assert result.exit_code == 0
        assert "--json" in result.output
        assert "--output-sarif" in result.output
        assert "--portal" in result.output

    @patch("ideviewer.cli.SecretsScanner")
    def test_secrets_json(self, mock_scanner_cls, runner):
        mock_scanner = MagicMock()
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "findings": [],
            "total_findings": 0,
            "critical_count": 0,
            "scanned_paths": [],
            "errors": [],
        }
        mock_result.findings = []
        mock_scanner.scan.return_value = mock_result
        mock_scanner_cls.return_value = mock_scanner

        result = runner.invoke(cli, ["secrets", "--json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "findings" in parsed


class TestPackagesCommand:
    """Test the 'packages' command."""

    def test_packages_help(self, runner):
        result = runner.invoke(cli, ["packages", "--help"])
        assert result.exit_code == 0
        assert "--json" in result.output
        assert "--global-only" in result.output
        assert "--portal" in result.output

    @patch("ideviewer.cli.DependencyScanner")
    def test_packages_json(self, mock_scanner_cls, runner):
        mock_scanner = MagicMock()
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "packages": [],
            "total_packages": 0,
            "package_managers_found": [],
            "summary": {},
        }
        mock_result.packages = []
        mock_result.package_managers_found = []
        mock_scanner.scan.return_value = mock_result
        mock_scanner_cls.return_value = mock_scanner

        result = runner.invoke(cli, ["packages", "--json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "packages" in parsed


class TestStatsCommand:
    """Test the 'stats' command."""

    def test_stats_help(self, runner):
        result = runner.invoke(cli, ["stats", "--help"])
        assert result.exit_code == 0
        assert "--json" in result.output

    @patch("ideviewer.cli.IDEScanner")
    def test_stats_json(self, mock_scanner_cls, runner):
        mock_scanner = MagicMock()
        mock_result = MagicMock()
        mock_scanner.scan.return_value = mock_result
        mock_scanner.get_extension_stats.return_value = {
            "total_ides": 0,
            "total_extensions": 0,
            "extensions_with_dangerous_permissions": 0,
            "extensions_by_ide": {},
            "permission_counts": {},
        }
        mock_scanner_cls.return_value = mock_scanner

        result = runner.invoke(cli, ["stats", "--json"])
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert "total_ides" in parsed


class TestDangerousCommand:
    """Test the 'dangerous' command."""

    def test_dangerous_help(self, runner):
        result = runner.invoke(cli, ["dangerous", "--help"])
        assert result.exit_code == 0
        assert "--verbose" in result.output


class TestRegisterCommand:
    """Test the 'register' command."""

    def test_register_help(self, runner):
        result = runner.invoke(cli, ["register", "--help"])
        assert result.exit_code == 0
        assert "--customer-key" in result.output
        assert "--portal-url" in result.output
        assert "--interval" in result.output

    def test_register_requires_options(self, runner):
        result = runner.invoke(cli, ["register"])
        assert result.exit_code != 0


class TestDaemonCommand:
    """Test the 'daemon' command."""

    def test_daemon_help(self, runner):
        result = runner.invoke(cli, ["daemon", "--help"])
        assert result.exit_code == 0
        assert "--customer-key" in result.output
        assert "--portal-url" in result.output
        assert "--interval" in result.output
        assert "--foreground" in result.output
        assert "--pid-file" in result.output


class TestStopCommand:
    """Test the 'stop' command."""

    def test_stop_help(self, runner):
        result = runner.invoke(cli, ["stop", "--help"])
        assert result.exit_code == 0
        assert "--pid-file" in result.output


class TestUpdateCommand:
    """Test the 'update' command."""

    def test_update_help(self, runner):
        result = runner.invoke(cli, ["update", "--help"])
        assert result.exit_code == 0
        assert "--check" in result.output
        assert "--yes" in result.output
