"""Tests for all CSV export endpoints in the portal."""

import csv
import io
import pytest
from datetime import datetime


class TestExportHostExtensionsCSV:
    """Test /host/<host_id>/export-extensions-csv."""

    def test_export_extensions_csv(self, portal_app, logged_in_client, test_host, test_scan_report):
        with portal_app.app_context():
            resp = logged_in_client.get(f"/host/{test_host.public_id}/export-extensions-csv")
        assert resp.status_code == 200
        assert resp.mimetype == "text/csv"
        assert "attachment" in resp.headers.get("Content-Disposition", "")

        reader = csv.reader(io.StringIO(resp.data.decode("utf-8")))
        rows = list(reader)
        # Header row
        assert rows[0] == [
            "Extension", "Version", "Publisher", "IDE", "IDE Version",
            "Risk Level", "Permissions",
        ]
        # At least one data row from test_scan_report
        assert len(rows) >= 2
        assert rows[1][0] == "Test Extension"

    def test_export_extensions_csv_access_denied(self, portal_app, portal_client, test_host):
        """Unauthenticated request should redirect (login required)."""
        with portal_app.app_context():
            resp = portal_client.get(f"/host/{test_host.public_id}/export-extensions-csv")
        # Flask-Login redirects to login page
        assert resp.status_code in (302, 401)

    def test_export_extensions_csv_nonexistent_host(self, portal_app, logged_in_client):
        with portal_app.app_context():
            resp = logged_in_client.get("/host/nonexistent-uuid/export-extensions-csv")
        assert resp.status_code == 404


class TestExportHostPackagesCSV:
    """Test /host/<host_id>/export-packages-csv."""

    def test_export_packages_csv_empty(self, portal_app, logged_in_client, test_host, test_scan_report):
        """Export with no packages should return header-only CSV."""
        with portal_app.app_context():
            resp = logged_in_client.get(f"/host/{test_host.public_id}/export-packages-csv")
        assert resp.status_code == 200
        assert resp.mimetype == "text/csv"

        reader = csv.reader(io.StringIO(resp.data.decode("utf-8")))
        rows = list(reader)
        assert rows[0] == [
            "Package", "Version", "Package Manager", "Install Type",
            "Project Path", "Lifecycle Hooks",
        ]

    def test_export_packages_csv_with_data(self, portal_app, portal_db, logged_in_client, test_host, test_scan_report):
        from app.models import PackageInfo
        with portal_app.app_context():
            pkg = PackageInfo(
                host_id=test_host.id,
                scan_report_id=test_scan_report.id,
                name="flask",
                version="3.0.0",
                package_manager="pip",
                install_type="global",
            )
            portal_db.session.add(pkg)
            portal_db.session.commit()

            resp = logged_in_client.get(f"/host/{test_host.public_id}/export-packages-csv")
        assert resp.status_code == 200
        reader = csv.reader(io.StringIO(resp.data.decode("utf-8")))
        rows = list(reader)
        assert len(rows) >= 2
        assert rows[1][0] == "flask"


class TestExportHostSecretsCSV:
    """Test /host/<host_id>/export-secrets-csv."""

    def test_export_secrets_csv_empty(self, portal_app, logged_in_client, test_host, test_scan_report):
        with portal_app.app_context():
            resp = logged_in_client.get(f"/host/{test_host.public_id}/export-secrets-csv")
        assert resp.status_code == 200
        assert resp.mimetype == "text/csv"

        reader = csv.reader(io.StringIO(resp.data.decode("utf-8")))
        rows = list(reader)
        assert rows[0] == [
            "Secret Type", "Severity", "Variable Name", "File Path",
            "Line Number", "Description", "Recommendation",
            "First Detected", "Last Seen",
        ]

    def test_export_secrets_csv_with_data(self, portal_app, portal_db, logged_in_client, test_host, test_scan_report):
        from app.models import SecretFinding as PortalSecretFinding
        with portal_app.app_context():
            secret = PortalSecretFinding(
                host_id=test_host.id,
                scan_report_id=test_scan_report.id,
                file_path="/home/user/.env",
                secret_type="ethereum_private_key",
                variable_name="PRIVATE_KEY",
                line_number=3,
                severity="critical",
                description="Key found",
                recommendation="Remove it",
            )
            portal_db.session.add(secret)
            portal_db.session.commit()

            resp = logged_in_client.get(f"/host/{test_host.public_id}/export-secrets-csv")
        assert resp.status_code == 200
        reader = csv.reader(io.StringIO(resp.data.decode("utf-8")))
        rows = list(reader)
        assert len(rows) >= 2
        assert rows[1][0] == "ethereum_private_key"
        assert rows[1][1] == "critical"

    def test_resolved_secrets_excluded(self, portal_app, portal_db, logged_in_client, test_host, test_scan_report):
        """Resolved secrets should not appear in the CSV export."""
        from app.models import SecretFinding as PortalSecretFinding
        with portal_app.app_context():
            secret = PortalSecretFinding(
                host_id=test_host.id,
                scan_report_id=test_scan_report.id,
                file_path="/tmp/.env",
                secret_type="aws_access_key",
                variable_name="AWS_KEY",
                severity="high",
                is_resolved=True,
                resolved_at=datetime.utcnow(),
            )
            portal_db.session.add(secret)
            portal_db.session.commit()

            resp = logged_in_client.get(f"/host/{test_host.public_id}/export-secrets-csv")
        reader = csv.reader(io.StringIO(resp.data.decode("utf-8")))
        rows = list(reader)
        # Only the header row, since the finding is resolved
        assert len(rows) == 1


class TestExportExtensionCSV:
    """Test /extension/<extension_id>/export-csv."""

    def test_export_extension_csv(self, portal_app, logged_in_client, test_host, test_scan_report):
        with portal_app.app_context():
            resp = logged_in_client.get("/extension/pub.test-ext/export-csv")
        assert resp.status_code == 200
        assert resp.mimetype == "text/csv"

        reader = csv.reader(io.StringIO(resp.data.decode("utf-8")))
        rows = list(reader)
        assert rows[0] == [
            "Hostname", "IP Address", "Platform", "IDE", "IDE Version",
            "Extension", "Extension Version", "Publisher", "Risk Level", "Last Seen",
        ]
        assert len(rows) >= 2
        assert rows[1][0] == "test-machine"

    def test_export_extension_csv_no_match(self, portal_app, logged_in_client, test_host, test_scan_report):
        """Extension not installed anywhere should return header-only CSV."""
        with portal_app.app_context():
            resp = logged_in_client.get("/extension/nonexistent.ext/export-csv")
        assert resp.status_code == 200
        reader = csv.reader(io.StringIO(resp.data.decode("utf-8")))
        rows = list(reader)
        assert len(rows) == 1  # header only


class TestExportPackageCSV:
    """Test /package/<package_name>/export-csv."""

    def test_export_package_csv(self, portal_app, portal_db, logged_in_client, test_host, test_scan_report):
        from app.models import PackageInfo
        with portal_app.app_context():
            pkg = PackageInfo(
                host_id=test_host.id,
                scan_report_id=test_scan_report.id,
                name="numpy",
                version="1.26.0",
                package_manager="pip",
                install_type="global",
            )
            portal_db.session.add(pkg)
            portal_db.session.commit()

            resp = logged_in_client.get("/package/numpy/export-csv")
        assert resp.status_code == 200
        assert resp.mimetype == "text/csv"

        reader = csv.reader(io.StringIO(resp.data.decode("utf-8")))
        rows = list(reader)
        assert rows[0] == [
            "Hostname", "IP Address", "Platform", "Package", "Version",
            "Package Manager", "Install Type", "Lifecycle Hooks", "Last Seen",
        ]
        assert len(rows) >= 2
        assert rows[1][3] == "numpy"

    def test_export_package_csv_with_manager_filter(
        self, portal_app, portal_db, logged_in_client, test_host, test_scan_report
    ):
        from app.models import PackageInfo
        with portal_app.app_context():
            for mgr in ["pip", "conda"]:
                pkg = PackageInfo(
                    host_id=test_host.id,
                    scan_report_id=test_scan_report.id,
                    name="numpy",
                    version="1.26.0",
                    package_manager=mgr,
                    install_type="global",
                )
                portal_db.session.add(pkg)
            portal_db.session.commit()

            resp = logged_in_client.get("/package/numpy/export-csv?manager=pip")
        reader = csv.reader(io.StringIO(resp.data.decode("utf-8")))
        rows = list(reader)
        # Header + 1 row (only pip, not conda)
        assert len(rows) == 2
        assert rows[1][5] == "pip"
