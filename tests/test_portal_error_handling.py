"""API error surfacing.

The blueprint's ``errorhandler(Exception)`` also matched HTTPException, because
Flask resolves error handlers through the exception's MRO. Every 404, 400 and
405 raised under /api/* therefore reached the daemon as
``500 {"error": "Internal server error"}``. A daemon carrying a config from a
rebuilt database -- a stale scan-request or enforcement-action id -- reported a
"500 HTTP Server error" when the honest answer was "that id no longer exists".
"""

import pytest


class TestHttpExceptionsKeepTheirStatus:

    def test_unknown_scan_request_is_404_not_500(
        self, portal_client, test_host_with_token
    ):
        host, token = test_host_with_token
        resp = portal_client.post(
            "/api/scan-requests/999999/update",
            headers={"X-Host-Token": token},
            json={"status": "completed"},
        )
        assert resp.status_code == 404
        assert resp.get_json()["type"] != "ServerError"

    def test_unknown_enforcement_action_is_404_not_500(
        self, portal_client, test_host_with_token
    ):
        host, token = test_host_with_token
        resp = portal_client.post(
            "/api/enforcement-actions/999999/report",
            headers={"X-Host-Token": token},
            json={"status": "applied"},
        )
        assert resp.status_code == 404

    def test_malformed_json_body_is_400_not_500(
        self, portal_client, test_customer_key
    ):
        resp = portal_client.post(
            "/api/report",
            headers={"X-Customer-Key": test_customer_key.key,
                     "Content-Type": "application/json"},
            data="{not valid json",
        )
        assert resp.status_code == 400
        assert resp.status_code != 500

    def test_wrong_method_is_405_not_500(self, portal_client):
        resp = portal_client.get("/api/report")
        assert resp.status_code == 405

    def test_error_responses_are_json(self, portal_client, test_host_with_token):
        host, token = test_host_with_token
        resp = portal_client.post(
            "/api/scan-requests/999999/update",
            headers={"X-Host-Token": token},
            json={"status": "completed"},
        )
        assert resp.content_type.startswith("application/json")
        assert "error" in resp.get_json()

    def test_the_session_survives_an_error(
        self, portal_client, test_host_with_token
    ):
        """Without a rollback in the handler, a failed statement poisons the
        session and the *next* request on the connection fails too."""
        host, token = test_host_with_token
        portal_client.post(
            "/api/scan-requests/999999/update",
            headers={"X-Host-Token": token},
            json={"status": "completed"},
        )
        ok = portal_client.post(
            "/api/heartbeat",
            headers={"X-Host-Token": token},
            json={"hostname": host.hostname},
        )
        assert ok.status_code == 200


class TestSigningNotConfigured:
    """Enrolment must not depend on the command-signing plane.

    A production portal with no COMMAND_SIGNING_PRIVATE_KEY made
    ``public_key_info()`` raise inside /api/validate-key, so the very first call
    a new daemon makes came back 500 -- reported as "customer key 500 HTTP
    Server error". Signing gates enforcement commands, nothing else.
    """

    @pytest.fixture
    def no_signer(self, portal_app, monkeypatch):
        import app.signing as signing

        portal_app.extensions.pop("command_signer", None)

        def boom(*_args, **_kwargs):
            raise ValueError(
                "Command signing requires a key in production. Set "
                "COMMAND_SIGNING_PRIVATE_KEY ..."
            )

        monkeypatch.setattr(signing, "get_signer", boom)
        # api.routes imported the symbol directly.
        import app.api.routes as api_routes
        monkeypatch.setattr(api_routes, "public_key_info", boom)
        yield
        portal_app.extensions.pop("command_signer", None)

    def test_validate_key_still_succeeds(
        self, portal_client, test_customer_key, no_signer
    ):
        resp = portal_client.post(
            "/api/validate-key",
            headers={"X-Customer-Key": test_customer_key.key},
            json={"hostname": "win-box", "platform": "Windows 11"},
        )
        assert resp.status_code == 200, resp.data
        body = resp.get_json()
        assert body["valid"] is True
        assert body["command_public_key"] is None

    def test_register_host_still_succeeds(
        self, portal_client, test_customer_key, no_signer
    ):
        resp = portal_client.post(
            "/api/register-host",
            headers={"X-Customer-Key": test_customer_key.key},
            json={"hostname": "win-box", "platform": "Windows 11"},
        )
        assert resp.status_code == 200, resp.data
        body = resp.get_json()
        assert body["success"] is True
        assert isinstance(body["host_token"], str)
        assert body["command_public_key"] is None

    def test_signing_key_endpoint_reports_503(
        self, portal_client, test_customer_key, no_signer
    ):
        resp = portal_client.get(
            "/api/signing-key",
            headers={"X-Customer-Key": test_customer_key.key},
        )
        assert resp.status_code == 503
        assert resp.get_json()["type"] == "SigningUnavailable"

    def test_enforcement_handout_refuses_rather_than_stranding_actions(
        self, portal_app, portal_db, portal_client, test_host_with_token, no_signer
    ):
        """Hand-out flips actions to 'dispatched'. If signing then failed, the
        action would be marked sent while no daemon ever received a verifiable
        command."""
        from app.models import EnforcementAction
        host, token = test_host_with_token

        with portal_app.app_context():
            action = EnforcementAction(
                host_id=host.id,
                action='quarantine',
                extension_id='pub.bad-ext',
                status=EnforcementAction.STATUS_PENDING,
            )
            portal_db.session.add(action)
            portal_db.session.commit()
            action_id = action.id

        resp = portal_client.get(
            "/api/enforcement-actions/pending", headers={"X-Host-Token": token}
        )
        assert resp.status_code == 503

        with portal_app.app_context():
            assert (EnforcementAction.query.get(action_id).status
                    == EnforcementAction.STATUS_PENDING)
