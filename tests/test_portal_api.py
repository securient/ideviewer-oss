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
        assert data["max_hosts"] == 5
        assert data["current_hosts"] == 0


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

    def test_host_limit_enforcement(self, portal_app, portal_db, portal_client, test_customer_key):
        """Free tier should enforce 5-host limit."""
        from app.models import Host
        with portal_app.app_context():
            # Register 5 hosts (the limit)
            for i in range(5):
                host = Host(
                    hostname=f"host-{i}",
                    ip_address=f"10.0.0.{i}",
                    platform="Test",
                    customer_key_id=test_customer_key.id,
                )
                portal_db.session.add(host)
            portal_db.session.commit()

            # The 6th host should be rejected
            resp = portal_client.post(
                "/api/register-host",
                headers={"X-Customer-Key": test_customer_key.key},
                json={"hostname": "host-overflow", "platform": "Test"},
            )
            assert resp.status_code == 403
            data = resp.get_json()
            assert "limit" in data["error"].lower() or "free tier" in data["error"].lower()


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
