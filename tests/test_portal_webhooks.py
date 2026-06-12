"""Tests for the outbound webhook framework (T2.1)."""
import hashlib
import hmac
import json
import time
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def webhook_sub(portal_app, portal_db, test_customer_key):
    from app.models import WebhookSubscription
    with portal_app.app_context():
        sub = WebhookSubscription(
            customer_key_id=test_customer_key.id,
            name="Test webhook",
            url="https://example.test/hook",
            event_types=["tamper_alert.created"],
        )
        portal_db.session.add(sub)
        portal_db.session.commit()
        sub = WebhookSubscription.query.first()
        yield sub


class TestModel:
    def test_generate_secret_has_prefix_and_random(self, portal_app):
        from app.models import WebhookSubscription
        with portal_app.app_context():
            s1 = WebhookSubscription.generate_secret()
            s2 = WebhookSubscription.generate_secret()
            assert s1.startswith("whsec_")
            assert s2.startswith("whsec_")
            assert s1 != s2
            assert len(s1) >= 40

    def test_init_generates_secret_and_public_id(self, portal_app):
        from app.models import WebhookSubscription
        with portal_app.app_context():
            sub = WebhookSubscription(
                customer_key_id=1, name="x", url="https://x", event_types=["a"],
            )
            assert sub.secret.startswith("whsec_")
            assert sub.public_id

    def test_matches_event_wildcard(self, portal_app):
        from app.models import WebhookSubscription
        with portal_app.app_context():
            sub = WebhookSubscription(
                customer_key_id=1, name="x", url="https://x", event_types=["*"],
            )
            sub.is_active = True
            assert sub.matches_event("tamper_alert.created")
            assert sub.matches_event("anything.at.all")

    def test_matches_event_exact(self, portal_app):
        from app.models import WebhookSubscription
        with portal_app.app_context():
            sub = WebhookSubscription(
                customer_key_id=1, name="x", url="https://x",
                event_types=["tamper_alert.created", "policy.violation"],
            )
            sub.is_active = True
            assert sub.matches_event("tamper_alert.created")
            assert sub.matches_event("policy.violation")
            assert not sub.matches_event("hook_bypass.detected")

    def test_inactive_never_matches(self, portal_app):
        from app.models import WebhookSubscription
        with portal_app.app_context():
            sub = WebhookSubscription(
                customer_key_id=1, name="x", url="https://x", event_types=["*"],
            )
            sub.is_active = False
            assert not sub.matches_event("anything")

    def test_record_failure_autoacks_at_limit(self, portal_app):
        from app.models import WebhookSubscription
        with portal_app.app_context():
            sub = WebhookSubscription(
                customer_key_id=1, name="x", url="https://x", event_types=["*"],
            )
            sub.is_active = True
            sub.consecutive_failures = WebhookSubscription.CONSECUTIVE_FAILURE_LIMIT - 1
            sub.record_failure()
            assert sub.is_active is False

    def test_record_success_resets_failure_counter(self, portal_app):
        from app.models import WebhookSubscription
        with portal_app.app_context():
            sub = WebhookSubscription(
                customer_key_id=1, name="x", url="https://x", event_types=["*"],
            )
            sub.consecutive_failures = 10
            sub.record_success()
            assert sub.consecutive_failures == 0
            assert sub.last_success_at is not None


class TestEmitEvent:
    def test_emit_creates_delivery_for_matching_sub(self, portal_app, portal_db, webhook_sub):
        from app.events import emit_event
        from app.models import WebhookDelivery
        with portal_app.app_context():
            with patch("app.queue.enqueue", return_value=MagicMock()):
                ids = emit_event(
                    "tamper_alert.created",
                    customer_key_id=webhook_sub.customer_key_id,
                    data={"alert_id": 1},
                )
            assert len(ids) == 1
            d = WebhookDelivery.query.get(ids[0])
            assert d.event_type == "tamper_alert.created"
            assert d.payload["type"] == "tamper_alert.created"
            assert d.payload["data"] == {"alert_id": 1}
            assert d.payload["id"].startswith("evt_")
            assert d.status == WebhookDelivery.STATUS_PENDING

    def test_emit_skips_non_matching_event(self, portal_app, portal_db, webhook_sub):
        from app.events import emit_event
        from app.models import WebhookDelivery
        with portal_app.app_context():
            with patch("app.queue.enqueue", return_value=MagicMock()):
                ids = emit_event(
                    "hook_bypass.detected",
                    customer_key_id=webhook_sub.customer_key_id,
                    data={},
                )
            assert ids == []
            assert WebhookDelivery.query.count() == 0

    def test_emit_isolates_by_customer_key(self, portal_app, portal_db, webhook_sub):
        from app.events import emit_event
        from app.models import WebhookDelivery
        with portal_app.app_context():
            with patch("app.queue.enqueue", return_value=MagicMock()):
                ids = emit_event(
                    "tamper_alert.created",
                    customer_key_id=webhook_sub.customer_key_id + 99,
                    data={},
                )
            assert ids == []
            assert WebhookDelivery.query.count() == 0

    def test_emit_sync_fallback_runs_inline(self, portal_app, portal_db, webhook_sub):
        from app.events import emit_event
        from app.models import WebhookDelivery
        sent = {}

        def fake_post(url, data, headers, timeout):
            sent["url"] = url
            sent["headers"] = headers
            resp = MagicMock()
            resp.status_code = 200
            resp.text = "ok"
            return resp

        with portal_app.app_context():
            with patch("app.queue.enqueue", return_value=None), \
                 patch("app.jobs.webhook_delivery.requests.post", side_effect=fake_post):
                ids = emit_event(
                    "tamper_alert.created",
                    customer_key_id=webhook_sub.customer_key_id,
                    data={"x": 1},
                )
            d = WebhookDelivery.query.get(ids[0])
            assert d.status == WebhookDelivery.STATUS_SUCCEEDED
            assert d.response_code == 200
            assert sent["url"] == webhook_sub.url
            assert "X-IDEViewer-Signature" in sent["headers"]


class TestDelivery:
    def _make_delivery(self, portal_db, webhook_sub):
        from app.models import WebhookDelivery
        d = WebhookDelivery(
            subscription_id=webhook_sub.id,
            event_id="evt_test",
            event_type="tamper_alert.created",
            payload={"id": "evt_test", "type": "tamper_alert.created", "data": {"x": 1}},
        )
        portal_db.session.add(d)
        portal_db.session.commit()
        return d.id

    def test_signature_format_stripe_style(self, portal_app, portal_db, webhook_sub):
        from app.jobs.webhook_delivery import deliver_webhook, _send
        captured = {}

        def fake_post(url, data, headers, timeout):
            captured["data"] = data
            captured["headers"] = headers
            resp = MagicMock()
            resp.status_code = 200
            resp.text = ""
            return resp

        with portal_app.app_context():
            did = self._make_delivery(portal_db, webhook_sub)
            with patch("app.jobs.webhook_delivery.requests.post", side_effect=fake_post):
                deliver_webhook(did)

            sig = captured["headers"]["X-IDEViewer-Signature"]
            assert sig.startswith("t=")
            assert ",v1=" in sig
            t_part, v_part = sig.split(",")
            ts = int(t_part.split("=", 1)[1])
            received_sig = v_part.split("=", 1)[1]
            assert abs(ts - int(time.time())) < 5

            expected = hmac.new(
                webhook_sub.secret.encode("utf-8"),
                f"{ts}.{captured['data']}".encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            assert hmac.compare_digest(received_sig, expected)

    def test_success_marks_delivery_and_resets_counter(self, portal_app, portal_db, webhook_sub):
        from app.jobs.webhook_delivery import deliver_webhook
        from app.models import WebhookDelivery, WebhookSubscription

        with portal_app.app_context():
            sub = WebhookSubscription.query.get(webhook_sub.id)
            sub.consecutive_failures = 3
            portal_db.session.commit()

            did = self._make_delivery(portal_db, webhook_sub)
            with patch("app.jobs.webhook_delivery.requests.post") as p:
                p.return_value = MagicMock(status_code=200, text="ok")
                deliver_webhook(did)

            d = WebhookDelivery.query.get(did)
            sub = WebhookSubscription.query.get(webhook_sub.id)
            assert d.status == WebhookDelivery.STATUS_SUCCEEDED
            assert d.response_code == 200
            assert d.completed_at is not None
            assert sub.consecutive_failures == 0
            assert sub.last_success_at is not None

    def test_failure_schedules_next_attempt(self, portal_app, portal_db, webhook_sub):
        from app.jobs.webhook_delivery import deliver_webhook
        from app.models import WebhookDelivery

        scheduled = []

        def fake_enqueue_in(delay, func, *args, **kwargs):
            scheduled.append(delay)
            return MagicMock()

        with portal_app.app_context():
            did = self._make_delivery(portal_db, webhook_sub)
            with patch("app.jobs.webhook_delivery.requests.post") as p, \
                 patch("app.queue.enqueue_in", side_effect=fake_enqueue_in):
                p.return_value = MagicMock(status_code=500, text="oops")
                deliver_webhook(did)

            d = WebhookDelivery.query.get(did)
            assert d.status == WebhookDelivery.STATUS_RETRYING
            assert d.attempt_count == 1
            assert "HTTP 500" in (d.last_error or "")
            assert scheduled == [30]  # first retry delay

    def test_final_failure_marks_failed_and_bumps_sub_counter(
        self, portal_app, portal_db, webhook_sub
    ):
        from app.jobs.webhook_delivery import deliver_webhook, MAX_ATTEMPTS
        from app.models import WebhookDelivery, WebhookSubscription

        with portal_app.app_context():
            did = self._make_delivery(portal_db, webhook_sub)
            d = WebhookDelivery.query.get(did)
            d.attempt_count = MAX_ATTEMPTS - 1
            portal_db.session.commit()

            with patch("app.jobs.webhook_delivery.requests.post") as p, \
                 patch("app.queue.enqueue_in"):
                p.return_value = MagicMock(status_code=500, text="")
                deliver_webhook(did)

            d = WebhookDelivery.query.get(did)
            sub = WebhookSubscription.query.get(webhook_sub.id)
            assert d.status == WebhookDelivery.STATUS_FAILED
            assert d.completed_at is not None
            assert sub.consecutive_failures == 1

    def test_inactive_subscription_skips_delivery(self, portal_app, portal_db, webhook_sub):
        from app.jobs.webhook_delivery import deliver_webhook
        from app.models import WebhookDelivery, WebhookSubscription

        with portal_app.app_context():
            sub = WebhookSubscription.query.get(webhook_sub.id)
            sub.is_active = False
            portal_db.session.commit()

            did = self._make_delivery(portal_db, webhook_sub)
            with patch("app.jobs.webhook_delivery.requests.post") as p:
                deliver_webhook(did)
                p.assert_not_called()

            d = WebhookDelivery.query.get(did)
            assert d.status == WebhookDelivery.STATUS_FAILED
            assert "subscription inactive" in (d.last_error or "")


class TestUI:
    def test_webhooks_page_requires_login(self, portal_client):
        resp = portal_client.get("/webhooks")
        assert resp.status_code in (302, 401)

    def test_webhooks_page_renders_for_logged_in_user(
        self, logged_in_client, test_customer_key
    ):
        resp = logged_in_client.get("/webhooks")
        assert resp.status_code == 200
        assert b"Outbound Webhooks" in resp.data


class TestSlackFormatting:
    def test_slack_payload_policy_violation(self, portal_app):
        from app.jobs.webhook_delivery import _slack_payload
        out = _slack_payload('policy.violation', {
            'host': {'hostname': 'mac-1'},
            'policy': {'name': 'p', 'action': 'block-alert'},
            'extension': {'extension_id': 'evil.x', 'version': '1.0'},
        })
        assert 'text' in out
        assert 'evil.x' in out['text']
        assert 'mac-1' in out['text']

    def test_slack_payload_unknown_event_fallback(self, portal_app):
        from app.jobs.webhook_delivery import _slack_payload
        out = _slack_payload('weird.event', {'foo': 'bar'})
        assert 'text' in out and 'weird.event' in out['text']

    def test_send_uses_slack_format_for_slack_url(self, portal_app):
        import json as _json
        from app.jobs.webhook_delivery import _send
        captured = {}

        def fake_post(url, data=None, headers=None, timeout=None):
            captured['data'] = data
            captured['headers'] = headers or {}
            m = MagicMock()
            m.status_code = 200
            m.text = 'ok'
            return m

        with patch("app.jobs.webhook_delivery.requests.post", side_effect=fake_post):
            _send('https://hooks.slack.com/services/T/B/x', 'secret',
                  {'host': {'hostname': 'h'}, 'extension': {'extension_id': 'e'}},
                  'policy.violation', 'evt1')
        sent = _json.loads(captured['data'])
        assert 'text' in sent
        assert 'X-IDEViewer-Signature' not in captured['headers']

    def test_send_uses_generic_format_for_non_slack_url(self, portal_app):
        import json as _json
        from app.jobs.webhook_delivery import _send
        captured = {}

        def fake_post(url, data=None, headers=None, timeout=None):
            captured['data'] = data
            captured['headers'] = headers or {}
            m = MagicMock()
            m.status_code = 200
            m.text = 'ok'
            return m

        with patch("app.jobs.webhook_delivery.requests.post", side_effect=fake_post):
            _send('https://example.com/hook', 'secret', {'a': 1}, 'policy.violation', 'evt1')
        sent = _json.loads(captured['data'])
        assert 'text' not in sent
        assert 'X-IDEViewer-Signature' in captured['headers']

    def test_slack_payload_reads_envelope_and_enrichment(self, portal_app):
        from app.jobs.webhook_delivery import _slack_payload
        out = _slack_payload('policy.violation', {
            'id': 'evt_1', 'type': 'policy.violation',
            'data': {
                'host': {'hostname': 'mac-2'},
                'policy': {'name': 'testssh', 'action': 'block-alert'},
                'extension': {
                    'extension_id': 'anysphere.remote-ssh', 'version': '1.1.2',
                    'publisher': 'anysphere', 'risk_level': 'high', 'ide': 'Cursor',
                    'vulnerable_dependencies': {
                        'critical': 2, 'high': 1,
                        'examples': [{'vuln_id': 'CVE-2026-1', 'package': 'left-pad@1.0', 'severity': 'critical'}],
                    },
                },
            },
        })
        t = out['text']
        assert 'mac-2' in t                 # host unwrapped from envelope
        assert 'anysphere.remote-ssh' in t  # extension
        assert 'Cursor' in t                # IDE
        assert 'testssh' in t               # policy name
        assert '2 critical, 1 high' in t    # vuln summary
        assert 'CVE-2026-1' in t            # example CVE
