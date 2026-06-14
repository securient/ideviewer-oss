"""Tests for server-side integrity monitoring (Phase 1 B2)."""
from datetime import datetime, timedelta


class TestHeartbeatGapSweep:
    def test_silent_host_raises_one_alert(self, portal_app, portal_db, test_host):
        from app.models import Host, TamperAlert
        from app.jobs.integrity_monitor import sweep_host_integrity
        with portal_app.app_context():
            h = Host.query.get(test_host.id)
            h.last_heartbeat_at = datetime.utcnow() - timedelta(minutes=30)
            h.heartbeat_alarm_state = 'ok'
            portal_db.session.commit()

            result = sweep_host_integrity()
            assert result['newly_silent'] == 1

            h = Host.query.get(test_host.id)
            assert h.heartbeat_alarm_state == 'silent'
            assert h.silent_since is not None
            alerts = TamperAlert.query.filter_by(host_id=h.id,
                                                 alert_type='host.silent').all()
            assert len(alerts) == 1

            # A second sweep must not duplicate the alert (deduped via state).
            assert sweep_host_integrity()['newly_silent'] == 0
            assert TamperAlert.query.filter_by(
                host_id=h.id, alert_type='host.silent').count() == 1

    def test_healthy_host_not_flagged(self, portal_app, portal_db, test_host):
        from app.models import Host, TamperAlert
        from app.jobs.integrity_monitor import sweep_host_integrity
        with portal_app.app_context():
            h = Host.query.get(test_host.id)
            h.last_heartbeat_at = datetime.utcnow() - timedelta(minutes=2)
            portal_db.session.commit()

            assert sweep_host_integrity()['newly_silent'] == 0
            assert TamperAlert.query.filter_by(
                host_id=h.id, alert_type='host.silent').count() == 0

    def test_inactive_host_skipped(self, portal_app, portal_db, test_host):
        from app.models import Host
        from app.jobs.integrity_monitor import sweep_host_integrity
        with portal_app.app_context():
            h = Host.query.get(test_host.id)
            h.last_heartbeat_at = datetime.utcnow() - timedelta(hours=5)
            h.is_active = False
            portal_db.session.commit()
            assert sweep_host_integrity()['newly_silent'] == 0

    def test_emits_tamper_event(self, portal_app, portal_db, test_host, test_customer_key):
        """A newly-silent host fans out via the existing tamper-alert webhook."""
        from app.models import Host, WebhookSubscription
        from app.jobs.integrity_monitor import sweep_host_integrity
        with portal_app.app_context():
            sub = WebhookSubscription(
                customer_key_id=test_customer_key.id,
                name='sec', url='https://example.test/hook',
                event_types=['tamper_alert.created'],
                is_active=True,
            )
            portal_db.session.add(sub)
            h = Host.query.get(test_host.id)
            h.last_heartbeat_at = datetime.utcnow() - timedelta(minutes=30)
            portal_db.session.commit()

            from app.models import WebhookDelivery
            before = WebhookDelivery.query.count()
            sweep_host_integrity()
            after = WebhookDelivery.query.count()
            assert after == before + 1


class TestRecovery:
    def test_heartbeat_clears_silent_state(self, portal_app, portal_db, test_host_with_token):
        from app.models import Host
        host, token = test_host_with_token
        with portal_app.app_context():
            h = Host.query.get(host.id)
            h.heartbeat_alarm_state = 'silent'
            h.silent_since = datetime.utcnow() - timedelta(minutes=30)
            portal_db.session.commit()
        # Drop the scoped session so the heartbeat request reads the row fresh
        # (otherwise the test's cached host object masks the committed state).
        portal_db.session.remove()

        portal_client = portal_app.test_client()
        resp = portal_client.post('/api/heartbeat',
                                  headers={'X-Host-Token': token},
                                  json={'hostname': 'test-machine', 'daemon_version': '1.0'})
        assert resp.status_code == 200
        with portal_app.app_context():
            # The heartbeat committed in its own request session; drop any
            # identity-map cache so we read the persisted row.
            portal_db.session.expire_all()
            h = Host.query.get(host.id)
            assert h.heartbeat_alarm_state == 'ok'
            assert h.silent_since is None

    def test_clear_silent_state_helper(self, portal_app, portal_db, test_host):
        from app.models import Host
        from app.jobs.integrity_monitor import clear_silent_state
        with portal_app.app_context():
            h = Host.query.get(test_host.id)
            h.heartbeat_alarm_state = 'silent'
            assert clear_silent_state(h) is True
            assert h.heartbeat_alarm_state == 'ok'
            # Idempotent: a healthy host returns False.
            assert clear_silent_state(h) is False
