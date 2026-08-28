"""On-demand scan request lifecycle: trigger, cancel, expire, manual fulfilment.

Every test here corresponds to something a tester hit on Windows against
v0.6.0: Stop did nothing, the request sat at 'pending' forever, Trigger Scan
stayed disabled, and API errors that should have been 404s arrived as 500s.
"""

import pytest

from datetime import timedelta


@pytest.fixture(autouse=True)
def _no_csrf(portal_app):
    """The portal UI routes are CSRF-protected; the browser supplies the token."""
    portal_app.config['WTF_CSRF_ENABLED'] = False
    yield


@pytest.fixture
def scan_request(portal_app, portal_db, test_host):
    """A freshly queued (pending) scan request for test_host."""
    from app.models import ScanRequest
    req = ScanRequest(host_id=test_host.id, status='pending')
    req.add_log('Waiting for daemon to pick up request...')
    portal_db.session.add(req)
    portal_db.session.commit()
    return req


class TestCancelScan:
    """/host/<id>/cancel-scan — the Stop button."""

    def test_cancel_pending_request_succeeds(
        self, portal_app, portal_db, logged_in_client, test_host, scan_request
    ):
        """The regression: 'cancelled' was missing from ck_scan_requests_status,
        so committing the cancel raised a CheckViolation and the request stayed
        pending. Any 200 here means the constraint accepts the value."""
        from app.models import ScanRequest

        resp = logged_in_client.post(f"/host/{test_host.public_id}/cancel-scan")
        assert resp.status_code == 200, resp.data
        assert resp.get_json()["success"] is True

        refreshed = portal_db.session.get(ScanRequest, scan_request.id)
        portal_db.session.refresh(refreshed)
        assert refreshed.status == 'cancelled'
        assert refreshed.completed_at is not None
        assert refreshed.to_dict()['is_active'] is False

    def test_cancel_targets_every_active_request(
        self, portal_app, portal_db, logged_in_client, test_host, scan_request
    ):
        """With more than one active request, an unordered .first() cancelled a
        different row than /scan-status reports, so the page stayed 'Pending'."""
        from app.models import ScanRequest

        newer = ScanRequest(host_id=test_host.id, status='pending')
        portal_db.session.add(newer)
        portal_db.session.commit()
        newer_id = newer.id

        resp = logged_in_client.post(f"/host/{test_host.public_id}/cancel-scan")
        assert resp.status_code == 200
        assert resp.get_json()["cancelled_count"] == 2

        portal_db.session.expire_all()
        statuses = {r.id: r.status for r in
                    ScanRequest.query.filter_by(host_id=test_host.id).all()}
        assert statuses[scan_request.id] == 'cancelled'
        assert statuses[newer_id] == 'cancelled'

        # And the status the page polls agrees.
        status = logged_in_client.get(f"/host/{test_host.public_id}/scan-status")
        assert status.get_json()["scan_request"]["status"] == 'cancelled'

    def test_cancel_with_no_active_scan_is_404(self, logged_in_client, test_host):
        resp = logged_in_client.post(f"/host/{test_host.public_id}/cancel-scan")
        assert resp.status_code == 404

    def test_cancelled_request_is_not_handed_to_the_daemon(
        self, portal_client, logged_in_client, test_host_with_token, scan_request
    ):
        host, token = test_host_with_token
        logged_in_client.post(f"/host/{host.public_id}/cancel-scan")

        resp = portal_client.get(
            "/api/scan-requests/pending", headers={"X-Host-Token": token}
        )
        assert resp.status_code == 200
        assert resp.get_json()["requests"] == []


class TestStaleScanRequests:
    """A request nobody collects must age out instead of wedging the button."""

    def test_pending_request_times_out_after_the_pickup_window(
        self, portal_app, portal_db, logged_in_client, test_host, scan_request
    ):
        from app.models import (
            ScanRequest, utcnow, SCAN_REQUEST_PICKUP_TIMEOUT_MINUTES,
        )

        scan_request.created_at = utcnow() - timedelta(
            minutes=SCAN_REQUEST_PICKUP_TIMEOUT_MINUTES + 1)
        portal_db.session.commit()

        resp = logged_in_client.get(f"/host/{test_host.public_id}/scan-status")
        body = resp.get_json()["scan_request"]
        assert body["status"] == 'timeout'
        assert body["is_active"] is False
        assert 'No daemon claimed this request' in body["error_message"]

    def test_a_fresh_pending_request_is_left_alone(
        self, logged_in_client, test_host, scan_request
    ):
        resp = logged_in_client.get(f"/host/{test_host.public_id}/scan-status")
        assert resp.get_json()["scan_request"]["status"] == 'pending'

    def test_expired_request_unblocks_trigger_scan(
        self, portal_app, portal_db, logged_in_client, test_host, scan_request
    ):
        """trigger-scan returns 409 while a request is active. Before the
        timeout existed, one missed pickup made that 409 permanent."""
        from app.models import (
            ScanRequest, utcnow, SCAN_REQUEST_PICKUP_TIMEOUT_MINUTES,
        )

        blocked = logged_in_client.post(f"/host/{test_host.public_id}/trigger-scan")
        assert blocked.status_code == 409

        scan_request.created_at = utcnow() - timedelta(
            minutes=SCAN_REQUEST_PICKUP_TIMEOUT_MINUTES + 1)
        portal_db.session.commit()

        allowed = logged_in_client.post(f"/host/{test_host.public_id}/trigger-scan")
        assert allowed.status_code == 200
        assert allowed.get_json()["scan_request"]["status"] == 'pending'

    def test_a_claimed_request_uses_the_longer_run_window(
        self, portal_app, portal_db, logged_in_client, test_host, scan_request
    ):
        """A daemon mid-scan must not be timed out on the pickup clock."""
        from app.models import (
            ScanRequest, utcnow, SCAN_REQUEST_PICKUP_TIMEOUT_MINUTES,
            SCAN_REQUEST_RUN_TIMEOUT_MINUTES,
        )

        scan_request.status = 'scanning_ides'
        scan_request.started_at = utcnow() - timedelta(
            minutes=SCAN_REQUEST_PICKUP_TIMEOUT_MINUTES + 1)
        portal_db.session.commit()

        resp = logged_in_client.get(f"/host/{test_host.public_id}/scan-status")
        assert resp.get_json()["scan_request"]["status"] == 'scanning_ides'

        portal_db.session.refresh(scan_request)
        scan_request.started_at = utcnow() - timedelta(
            minutes=SCAN_REQUEST_RUN_TIMEOUT_MINUTES + 1)
        portal_db.session.commit()

        resp = logged_in_client.get(f"/host/{test_host.public_id}/scan-status")
        assert resp.get_json()["scan_request"]["status"] == 'timeout'


class TestManualPush:
    """'ideviewer scan --push' fulfilling a request the daemon never collected."""

    def _scan_body(self, hostname, source=None):
        body = {
            "hostname": hostname,
            "platform": "Windows 11",
            "scan_data": {"ides": [], "total_ides": 0, "total_extensions": 0},
        }
        if source is not None:
            body["source"] = source
        return body

    def test_report_defaults_to_daemon_provenance(
        self, portal_db, portal_client, test_host_with_token
    ):
        from app.models import ScanReport
        host, token = test_host_with_token

        resp = portal_client.post(
            "/api/report", headers={"X-Host-Token": token},
            json=self._scan_body(host.hostname),
        )
        assert resp.status_code == 200

        report = ScanReport.query.order_by(ScanReport.id.desc()).first()
        assert report.source == 'daemon'

    def test_cli_push_is_recorded_as_such(
        self, portal_db, portal_client, test_host_with_token
    ):
        from app.models import ScanReport
        host, token = test_host_with_token

        resp = portal_client.post(
            "/api/report", headers={"X-Host-Token": token},
            json=self._scan_body(host.hostname, source="cli"),
        )
        assert resp.status_code == 200

        report = ScanReport.query.order_by(ScanReport.id.desc()).first()
        assert report.source == 'cli'

    def test_unknown_source_is_rejected(self, portal_client, test_host_with_token):
        host, token = test_host_with_token
        resp = portal_client.post(
            "/api/report", headers={"X-Host-Token": token},
            json=self._scan_body(host.hostname, source="totally-made-up"),
        )
        assert resp.status_code == 400

    def test_a_push_does_not_destroy_the_daemons_history(
        self, portal_db, portal_client, test_host_with_token
    ):
        """The stated worry about --push. Reports are append-only rows, so a
        manual push adds one; retention only nulls the superseded raw payload."""
        from app.models import ScanReport
        host, token = test_host_with_token

        portal_client.post("/api/report", headers={"X-Host-Token": token},
                           json=self._scan_body(host.hostname))
        portal_client.post("/api/report", headers={"X-Host-Token": token},
                           json=self._scan_body(host.hostname, source="cli"))

        reports = (ScanReport.query
                   .filter_by(host_id=host.id)
                   .order_by(ScanReport.id).all())
        assert [r.source for r in reports] == ['daemon', 'cli']

    def test_cli_can_claim_and_close_a_pending_request(
        self, portal_db, portal_client, test_host_with_token, scan_request
    ):
        from app.models import ScanRequest
        host, token = test_host_with_token
        headers = {"X-Host-Token": token}

        pending = portal_client.get("/api/scan-requests/pending", headers=headers)
        ids = [r["id"] for r in pending.get_json()["requests"]]
        assert ids == [scan_request.id]

        claim = portal_client.post(
            f"/api/scan-requests/{scan_request.id}/update", headers=headers,
            json={"status": "scanning_ides",
                  "log_message": "Fulfilled manually with 'ideviewer scan --push'",
                  "log_level": "warning"},
        )
        assert claim.status_code == 200

        done = portal_client.post(
            f"/api/scan-requests/{scan_request.id}/update", headers=headers,
            json={"status": "completed",
                  "log_message": "Scan request fulfilled manually via "
                                 "'ideviewer scan --push'",
                  "log_level": "warning"},
        )
        assert done.status_code == 200

        portal_db.session.expire_all()
        req = portal_db.session.get(ScanRequest, scan_request.id)
        assert req.status == 'completed'
        messages = [e["message"] for e in req.log_entries]
        assert any('--push' in m for m in messages), messages

    def test_daemon_is_told_when_a_claimed_request_was_cancelled(
        self, portal_client, logged_in_client, test_host_with_token, scan_request
    ):
        host, token = test_host_with_token
        logged_in_client.post(f"/host/{host.public_id}/cancel-scan")

        resp = portal_client.post(
            f"/api/scan-requests/{scan_request.id}/update",
            headers={"X-Host-Token": token},
            json={"status": "scanning_ides"},
        )
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["cancelled"] is True
        assert body["success"] is False
