"""Tests for per-host enrollment tokens (T1.3 portal side)."""

import hashlib
import pytest


class TestRegisterHostIssuesToken:
    def test_register_returns_plaintext_token(self, portal_client, test_customer_key):
        resp = portal_client.post(
            "/api/register-host",
            headers={"X-Customer-Key": test_customer_key.key},
            json={"hostname": "new-token-host", "platform": "Linux"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        token = data.get("host_token")
        assert isinstance(token, str)
        # base64url(32 bytes) without padding is 43 chars
        assert len(token) == 43

    def test_token_hash_persisted(
        self, portal_app, portal_client, test_customer_key
    ):
        resp = portal_client.post(
            "/api/register-host",
            headers={"X-Customer-Key": test_customer_key.key},
            json={"hostname": "hash-host", "platform": "Linux"},
        )
        token = resp.get_json()["host_token"]
        expected_hash = hashlib.sha256(token.encode("ascii")).hexdigest()

        from app.models import Host
        with portal_app.app_context():
            host = Host.query.filter_by(hostname="hash-host").first()
            assert host is not None
            assert host.token_hash == expected_hash
            assert host.token_issued_at is not None
            assert host.token_revoked_at is None


class TestHeartbeatWithToken:
    def test_heartbeat_token_auth_succeeds(self, portal_client, test_host_with_token):
        host, token = test_host_with_token
        resp = portal_client.post(
            "/api/heartbeat",
            headers={"X-Host-Token": token},
            json={"hostname": host.hostname, "daemon_version": "0.2.0"},
        )
        assert resp.status_code == 200
        assert resp.get_json()["acknowledged"] is True

    def test_heartbeat_invalid_token_401(self, portal_client, test_host):
        resp = portal_client.post(
            "/api/heartbeat",
            headers={"X-Host-Token": "garbage-not-a-real-token"},
            json={"hostname": "test-machine"},
        )
        assert resp.status_code == 401

    def test_heartbeat_revoked_token_401(
        self, portal_app, portal_db, portal_client, test_host_with_token
    ):
        host, token = test_host_with_token
        # Revoke via the same app context the test_client will see.
        from app.models import Host
        h = Host.query.filter_by(id=host.id).first()
        h.revoke_token()
        portal_db.session.commit()

        resp = portal_client.post(
            "/api/heartbeat",
            headers={"X-Host-Token": token},
            json={"hostname": host.hostname},
        )
        assert resp.status_code == 401


class TestHostnameBinding:
    def test_token_hostname_mismatch_403(
        self, portal_client, test_host_with_token
    ):
        host, token = test_host_with_token
        resp = portal_client.post(
            "/api/heartbeat",
            headers={"X-Host-Token": token},
            json={"hostname": "some-other-host", "daemon_version": "x"},
        )
        assert resp.status_code == 403


class TestLegacyCustomerKeyStillWorks:
    def test_heartbeat_with_customer_key_only(
        self, portal_client, test_customer_key, test_host
    ):
        """Legacy daemons (no token) must keep working with X-Customer-Key."""
        resp = portal_client.post(
            "/api/heartbeat",
            headers={"X-Customer-Key": test_customer_key.key},
            json={"hostname": "test-machine"},
        )
        assert resp.status_code == 200

    def test_report_with_customer_key_only(
        self, portal_client, test_customer_key, test_host
    ):
        resp = portal_client.post(
            "/api/report",
            headers={"X-Customer-Key": test_customer_key.key},
            json={
                "hostname": "test-machine",
                "platform": "Darwin",
                "scan_data": {"ides": [], "total_ides": 0, "total_extensions": 0},
            },
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["success"] is True
        # No async queue in tests, so no job_id in payload.
        assert "job_id" not in data


class TestRotateEndpoint:
    def test_rotate_with_valid_token_returns_new(
        self, portal_client, test_host_with_token
    ):
        host, token = test_host_with_token
        resp = portal_client.post(
            "/api/host-token/rotate",
            headers={"X-Host-Token": token},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        new_token = data["host_token"]
        assert isinstance(new_token, str)
        assert len(new_token) == 43
        assert new_token != token

        # Old token should now be invalid.
        resp2 = portal_client.post(
            "/api/heartbeat",
            headers={"X-Host-Token": token},
            json={"hostname": host.hostname},
        )
        assert resp2.status_code == 401

        # New token works.
        resp3 = portal_client.post(
            "/api/heartbeat",
            headers={"X-Host-Token": new_token},
            json={"hostname": host.hostname},
        )
        assert resp3.status_code == 200

    def test_rotate_requires_token_auth(
        self, portal_client, test_customer_key, test_host
    ):
        """Customer-key-only auth must NOT be able to rotate."""
        resp = portal_client.post(
            "/api/host-token/rotate",
            headers={"X-Customer-Key": test_customer_key.key},
        )
        assert resp.status_code == 401


class TestReRegisterRefreshesToken:
    def test_re_register_issues_new_token(
        self, portal_client, test_customer_key
    ):
        # First register
        r1 = portal_client.post(
            "/api/register-host",
            headers={"X-Customer-Key": test_customer_key.key},
            json={"hostname": "rotate-host", "platform": "Linux"},
        )
        t1 = r1.get_json()["host_token"]

        # Re-register with same customer key
        r2 = portal_client.post(
            "/api/register-host",
            headers={"X-Customer-Key": test_customer_key.key},
            json={"hostname": "rotate-host", "platform": "Linux"},
        )
        t2 = r2.get_json()["host_token"]
        assert t1 != t2


class TestScanRequestsAcceptHostToken:
    """Regression: daemons polling on-demand scan requests use X-Host-Token,
    not X-Customer-Key, after enrollment. If these endpoints reject the
    token the daemon falls into a re-enroll loop and rewrites its config
    file every poll, which trips tamper detection."""

    def test_pending_scan_requests_accepts_token(
        self, portal_client, test_host_with_token
    ):
        host, token = test_host_with_token
        resp = portal_client.get(
            "/api/scan-requests/pending",
            headers={"X-Host-Token": token},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "requests" in data

    def test_pending_scan_requests_rejects_invalid_token(self, portal_client):
        resp = portal_client.get(
            "/api/scan-requests/pending",
            headers={"X-Host-Token": "garbage-token"},
        )
        assert resp.status_code == 401

    def test_pending_scan_requests_still_works_with_customer_key(
        self, portal_client, test_customer_key, test_host
    ):
        resp = portal_client.get(
            "/api/scan-requests/pending",
            headers={"X-Customer-Key": test_customer_key.key},
        )
        assert resp.status_code == 200

    def test_pending_scoped_to_authenticated_host(
        self,
        portal_app,
        portal_db,
        portal_client,
        test_customer_key,
        test_host_with_token,
    ):
        """When token auth is used, only this host's pending requests should
        come back -- not requests for sibling hosts under the same customer."""
        from app.models import Host, ScanRequest
        host, token = test_host_with_token
        with portal_app.app_context():
            sibling = Host(
                hostname="sibling-host",
                ip_address="10.0.0.99",
                platform="Linux",
                customer_key_id=test_customer_key.id,
            )
            portal_db.session.add(sibling)
            portal_db.session.flush()
            user_id = test_customer_key.user_id
            mine = ScanRequest(host_id=host.id, status="pending", requested_by=user_id)
            theirs = ScanRequest(host_id=sibling.id, status="pending", requested_by=user_id)
            portal_db.session.add_all([mine, theirs])
            portal_db.session.commit()
            mine_id = mine.id
            theirs_id = theirs.id

        resp = portal_client.get(
            "/api/scan-requests/pending",
            headers={"X-Host-Token": token},
        )
        assert resp.status_code == 200
        ids = {r["id"] for r in resp.get_json()["requests"]}
        assert mine_id in ids
        assert theirs_id not in ids

    def test_update_cross_host_with_token_403(
        self,
        portal_app,
        portal_db,
        portal_client,
        test_customer_key,
        test_host_with_token,
    ):
        """A token bound to host A must not be able to update a scan
        request that belongs to host B (same customer)."""
        from app.models import Host, ScanRequest
        host, token = test_host_with_token
        with portal_app.app_context():
            sibling = Host(
                hostname="other-host",
                ip_address="10.0.0.42",
                platform="Linux",
                customer_key_id=test_customer_key.id,
            )
            portal_db.session.add(sibling)
            portal_db.session.flush()
            sibling_req = ScanRequest(
                host_id=sibling.id,
                status="pending",
                requested_by=test_customer_key.user_id,
            )
            portal_db.session.add(sibling_req)
            portal_db.session.commit()
            sibling_req_id = sibling_req.id

        resp = portal_client.post(
            f"/api/scan-requests/{sibling_req_id}/update",
            headers={"X-Host-Token": token},
            json={"status": "scanning_ides"},
        )
        assert resp.status_code == 403
