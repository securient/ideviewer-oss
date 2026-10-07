"""Tests for portal API endpoints."""

import json
import uuid
import pytest
from datetime import datetime


class TestHealthCheck:
    """Test /api/health endpoint."""

    def test_health_returns_200(self, portal_client):
        resp = portal_client.get("/api/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "healthy"
        assert data["database"] == "connected"


class TestValidateKey:
    """Test /api/validate-key endpoint."""

    def test_missing_header(self, portal_client):
        resp = portal_client.post("/api/validate-key")
        assert resp.status_code == 401
        data = resp.get_json()
        assert data["valid"] is False

    def test_invalid_key(self, portal_client):
        resp = portal_client.post(
            "/api/validate-key",
            headers={"X-Customer-Key": "invalid-key"},
        )
        assert resp.status_code == 401

    def test_valid_key(self, portal_client, test_customer_key):
        resp = portal_client.post(
            "/api/validate-key",
            headers={"X-Customer-Key": test_customer_key.key},
            json={"hostname": "test-host", "platform": "Darwin"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["valid"] is True
        assert data["key_name"] == "Test Key"
        assert data["current_hosts"] == 0
        assert "max_hosts" not in data


class TestRegisterHost:
    """Test /api/register-host endpoint."""

    def test_register_new_host(self, portal_client, test_customer_key):
        resp = portal_client.post(
            "/api/register-host",
            headers={"X-Customer-Key": test_customer_key.key},
            json={"hostname": "new-machine", "platform": "Linux 6.0"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "host_id" in data
        # Phase 2 (T1.3): register-host now issues an enrollment token.
        assert "host_token" in data
        assert isinstance(data["host_token"], str) and len(data["host_token"]) == 43

    def test_register_missing_hostname(self, portal_client, test_customer_key):
        resp = portal_client.post(
            "/api/register-host",
            headers={"X-Customer-Key": test_customer_key.key},
            json={"platform": "Linux"},
        )
        assert resp.status_code == 400

    def test_reregister_existing_host(self, portal_client, test_customer_key, test_host):
        resp = portal_client.post(
            "/api/register-host",
            headers={"X-Customer-Key": test_customer_key.key},
            json={"hostname": "test-machine", "platform": "Darwin 24.0"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "updated" in data["message"].lower()

    def test_no_host_limit(self, portal_app, portal_db, portal_client, test_customer_key):
        """Hosts per customer key are unlimited."""
        from app.models import Host
        with portal_app.app_context():
            # Pre-create a large batch of hosts to confirm there is no cap.
            for i in range(25):
                host = Host(
                    hostname=f"host-{i}",
                    ip_address=f"10.0.0.{i}",
                    platform="Test",
                    customer_key_id=test_customer_key.id,
                )
                portal_db.session.add(host)
            portal_db.session.commit()

            # One more should still register successfully.
            resp = portal_client.post(
                "/api/register-host",
                headers={"X-Customer-Key": test_customer_key.key},
                json={"hostname": "host-overflow", "platform": "Test"},
            )
            assert resp.status_code == 200
            data = resp.get_json()
            assert data["success"] is True


class TestSubmitReport:
    """Test /api/report endpoint."""

    def test_submit_report(self, portal_client, test_customer_key, test_host):
        scan_data = {
            "ides": [
                {
                    "name": "VS Code",
                    "version": "1.85.0",
                    "extensions": [
                        {
                            "id": "ext.test",
                            "name": "Test",
                            "version": "1.0",
                            "publisher": "pub",
                            "permissions": [],
                        }
                    ],
                }
            ],
            "total_ides": 1,
            "total_extensions": 1,
        }
        resp = portal_client.post(
            "/api/report",
            headers={"X-Customer-Key": test_customer_key.key},
            json={
                "hostname": "test-machine",
                "platform": "Darwin",
                "scan_data": scan_data,
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        assert "report_id" in data
        assert data["stats"]["total_ides"] == 1

    def test_submit_report_missing_scan_data(self, portal_client, test_customer_key, test_host):
        resp = portal_client.post(
            "/api/report",
            headers={"X-Customer-Key": test_customer_key.key},
            json={"hostname": "test-machine"},
        )
        assert resp.status_code == 400

    def test_submit_report_with_secrets(self, portal_client, test_customer_key, test_host):
        """Secrets findings should be stored in the database."""
        scan_data = {
            "ides": [],
            "total_ides": 0,
            "total_extensions": 0,
            "secrets": {
                "findings": [
                    {
                        "file_path": "/home/user/.env",
                        "secret_type": "ethereum_private_key",
                        "variable_name": "PRIVATE_KEY",
                        "line_number": 3,
                        "severity": "critical",
                        "description": "Private key found",
                        "recommendation": "Remove it",
                    }
                ],
            },
        }
        resp = portal_client.post(
            "/api/report",
            headers={"X-Customer-Key": test_customer_key.key},
            json={
                "hostname": "test-machine",
                "platform": "Darwin",
                "scan_data": scan_data,
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["stats"]["secrets_found"] == 1
        assert data["stats"]["critical_secrets"] == 1

    def test_submit_report_with_packages(self, portal_client, test_customer_key, test_host):
        """Package data should be stored."""
        scan_data = {
            "ides": [],
            "total_ides": 0,
            "total_extensions": 0,
            "dependencies": {
                "packages": [
                    {
                        "name": "requests",
                        "version": "2.31.0",
                        "package_manager": "pip",
                        "install_type": "global",
                    },
                    {
                        "name": "express",
                        "version": "4.18.0",
                        "package_manager": "npm",
                        "install_type": "project",
                        "lifecycle_hooks": {"postinstall": "node setup.js"},
                    },
                ],
            },
        }
        resp = portal_client.post(
            "/api/report",
            headers={"X-Customer-Key": test_customer_key.key},
            json={
                "hostname": "test-machine",
                "platform": "Darwin",
                "scan_data": scan_data,
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["stats"]["packages_found"] == 2


class TestSecretsResolution:
    """Test that secrets are resolved when no longer reported."""

    def test_secret_resolved_when_removed(self, portal_app, portal_client, portal_db, test_customer_key, test_host):
        """If a secret disappears from the scan, it should be marked resolved."""
        from app.models import SecretFinding as PortalSecretFinding

        # First report: secret present
        scan_data_1 = {
            "ides": [],
            "total_ides": 0,
            "total_extensions": 0,
            "secrets": {
                "findings": [
                    {
                        "file_path": "/home/user/.env",
                        "secret_type": "ethereum_private_key",
                        "variable_name": "KEY",
                        "line_number": 1,
                        "severity": "critical",
                        "description": "Found",
                        "recommendation": "Remove",
                    }
                ],
            },
        }
        resp1 = portal_client.post(
            "/api/report",
            headers={"X-Customer-Key": test_customer_key.key},
            json={"hostname": "test-machine", "platform": "Darwin", "scan_data": scan_data_1},
        )
        assert resp1.status_code == 200

        with portal_app.app_context():
            unresolved = PortalSecretFinding.query.filter_by(
                host_id=test_host.id, is_resolved=False
            ).count()
            assert unresolved == 1

        # Second report: secret gone
        scan_data_2 = {
            "ides": [],
            "total_ides": 0,
            "total_extensions": 0,
            "secrets": {"findings": []},
        }
        resp2 = portal_client.post(
            "/api/report",
            headers={"X-Customer-Key": test_customer_key.key},
            json={"hostname": "test-machine", "platform": "Darwin", "scan_data": scan_data_2},
        )
        assert resp2.status_code == 200

        with portal_app.app_context():
            unresolved = PortalSecretFinding.query.filter_by(
                host_id=test_host.id, is_resolved=False
            ).count()
            assert unresolved == 0

            resolved = PortalSecretFinding.query.filter_by(
                host_id=test_host.id, is_resolved=True
            ).count()
            assert resolved == 1


class TestHeartbeat:
    """Test /api/heartbeat endpoint."""

    def test_heartbeat(self, portal_client, test_customer_key, test_host):
        resp = portal_client.post(
            "/api/heartbeat",
            headers={"X-Customer-Key": test_customer_key.key},
            json={"hostname": "test-machine", "daemon_version": "0.1.0"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["acknowledged"] is True

    def test_heartbeat_missing_hostname(self, portal_client, test_customer_key):
        resp = portal_client.post(
            "/api/heartbeat",
            headers={"X-Customer-Key": test_customer_key.key},
            json={},
        )
        assert resp.status_code == 400


class TestTamperAlert:
    """Test /api/alert endpoint."""

    def test_receive_alert(self, portal_client, test_customer_key, test_host):
        resp = portal_client.post(
            "/api/alert",
            headers={"X-Customer-Key": test_customer_key.key},
            json={
                "hostname": "test-machine",
                "alert_type": "daemon_stopping",
                "details": "Daemon received SIGTERM",
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["received"] is True
        assert "alert_id" in data

    def test_alert_missing_fields(self, portal_client, test_customer_key, test_host):
        resp = portal_client.post(
            "/api/alert",
            headers={"X-Customer-Key": test_customer_key.key},
            json={"hostname": "test-machine"},
        )
        assert resp.status_code == 400

    def test_alert_unknown_host(self, portal_client, test_customer_key):
        resp = portal_client.post(
            "/api/alert",
            headers={"X-Customer-Key": test_customer_key.key},
            json={
                "hostname": "nonexistent-host",
                "alert_type": "file_deleted",
                "details": "test",
            },
        )
        assert resp.status_code == 404

class TestSecretReappearance:
    """A secret that is resolved and then comes back must not 500 the report.

    The lookup used to filter on is_resolved=False, which hid an already
    resolved row, so the reappearing secret took the INSERT path and violated
    uq_secret_per_host_location. The IntegrityError failed the whole request,
    so the daemon's entire report was rejected -- extensions, packages and AI
    tools lost along with the secret -- and every later scan repeated it.
    """

    def _report(self, portal_client, key, hostname, findings):
        return portal_client.post(
            '/api/report',
            headers={'X-Customer-Key': key},
            json={
                'hostname': hostname,
                'platform': 'darwin arm64',
                'scan_data': {
                    'timestamp': '2026-10-07T14:00:00Z',
                    'platform': 'darwin',
                    'ides': [],
                    'total_ides': 0,
                    'total_extensions': 0,
                    'secrets': {'findings': findings},
                },
            },
        )

    FINDING = {
        'file_path': '/Users/dev/project/.env',
        'secret_type': 'api_credential',
        'variable_name': 'SECRET_KEY',
        'severity': 'high',
        'redacted_value': '[redacted]',
        'source': 'filesystem',
    }

    def test_secret_can_disappear_and_come_back(
        self, portal_app, portal_db, portal_client, test_customer_key, test_host
    ):
        from app.models import SecretFinding
        key, host = test_customer_key.key, test_host.hostname

        # Present.
        assert self._report(portal_client, key, host, [self.FINDING]).status_code == 200
        assert SecretFinding.query.filter_by(is_resolved=False).count() == 1

        # Gone -- the scan reports no findings, so it is marked resolved.
        assert self._report(portal_client, key, host, []).status_code == 200
        assert SecretFinding.query.filter_by(is_resolved=True).count() == 1

        # Back again. This is the request that used to 500.
        resp = self._report(portal_client, key, host, [self.FINDING])
        assert resp.status_code == 200, resp.get_data(as_text=True)

        # Revived in place, not duplicated -- the constraint allows only one.
        assert SecretFinding.query.count() == 1
        row = SecretFinding.query.one()
        assert row.is_resolved is False
        assert row.resolved_at is None

    def test_rest_of_the_report_survives_a_returning_secret(
        self, portal_app, portal_db, portal_client, test_customer_key, test_host
    ):
        """The real damage was collateral: one secret failed the whole report."""
        from app.models import PackageInfo
        key, host = test_customer_key.key, test_host.hostname

        self._report(portal_client, key, host, [self.FINDING])
        self._report(portal_client, key, host, [])

        resp = portal_client.post(
            '/api/report',
            headers={'X-Customer-Key': key},
            json={
                'hostname': host,
                'platform': 'darwin arm64',
                'scan_data': {
                    'timestamp': '2026-10-07T14:05:00Z',
                    'platform': 'darwin',
                    'ides': [],
                    'total_ides': 0,
                    'total_extensions': 0,
                    'secrets': {'findings': [self.FINDING]},
                    'dependencies': {'packages': [
                        {'name': 'lodash', 'version': '4.17.20',
                         'package_manager': 'npm', 'source_type': 'project'},
                    ]},
                },
            },
        )
        assert resp.status_code == 200, resp.get_data(as_text=True)
        assert PackageInfo.query.filter_by(name='lodash').count() == 1, \
            'the package must survive a report that also carries a returning secret'

    def test_same_variable_different_secret_type_is_a_separate_finding(
        self, portal_app, portal_db, portal_client, test_customer_key, test_host
    ):
        """secret_type is part of the unique key, so it must be part of the lookup."""
        from app.models import SecretFinding
        other = dict(self.FINDING, secret_type='aws_key')

        resp = self._report(portal_client, test_customer_key.key, test_host.hostname,
                            [self.FINDING, other])
        assert resp.status_code == 200, resp.get_data(as_text=True)
        assert SecretFinding.query.count() == 2, \
            'two findings differing only by secret_type are distinct rows'
