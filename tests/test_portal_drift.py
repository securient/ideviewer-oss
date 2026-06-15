"""Tests for fleet drift / anomaly detection (Phase 1 B7)."""


def _add_host(portal_db, key, hostname, extensions):
    from app.models import Host, ScanReport
    h = Host(hostname=hostname, customer_key_id=key.id)
    portal_db.session.add(h)
    portal_db.session.commit()
    sr = ScanReport(
        host_id=h.id,
        scan_data={'ides': [{'name': 'VS Code', 'extensions': extensions}]},
        total_ides=1, total_extensions=len(extensions),
    )
    portal_db.session.add(sr)
    portal_db.session.commit()
    return h


class TestFleetDrift:
    def test_baseline_sweep_is_silent(self, portal_app, portal_db, test_customer_key):
        from app.jobs.drift_monitor import detect_fleet_anomalies
        from app.models import ExtensionPrevalence
        with portal_app.app_context():
            _add_host(portal_db, test_customer_key, 'h1',
                      [{'id': 'ms-vscode.example-malware', 'publisher': 'ms-vscode', 'permissions': []}])
            res = detect_fleet_anomalies(test_customer_key.id)
            # First sweep only records baseline — no alerts.
            assert res == {'new_risky': 0, 'rapid_propagation': 0}
            assert ExtensionPrevalence.query.filter_by(
                customer_key_id=test_customer_key.id).count() == 1

    def test_new_risky_extension_after_baseline(self, portal_app, portal_db, test_customer_key):
        from app.jobs.drift_monitor import detect_fleet_anomalies
        with portal_app.app_context():
            _add_host(portal_db, test_customer_key, 'h1',
                      [{'id': 'acme.safe', 'publisher': 'acme', 'permissions': []}])
            detect_fleet_anomalies(test_customer_key.id)  # baseline
            # A new banned extension appears on a second host.
            _add_host(portal_db, test_customer_key, 'h2',
                      [{'id': 'darkpub.crypto-stealer', 'publisher': 'darkpub', 'permissions': []}])
            res = detect_fleet_anomalies(test_customer_key.id)
            assert res['new_risky'] == 1

    def test_rapid_propagation_flagged(self, portal_app, portal_db, test_customer_key):
        from app.jobs.drift_monitor import detect_fleet_anomalies
        with portal_app.app_context():
            # Baseline: one host has a high-permission extension.
            _add_host(portal_db, test_customer_key, 'h1',
                      [{'id': 'acme.tool', 'publisher': 'acme', 'permissions': [{'name': 'terminal'}]}])
            detect_fleet_anomalies(test_customer_key.id)  # baseline records count=1
            # Same extension now on 4 more hosts (+4 >= threshold 3).
            for i in range(4):
                _add_host(portal_db, test_customer_key, f'hx{i}',
                          [{'id': 'acme.tool', 'publisher': 'acme', 'permissions': [{'name': 'terminal'}]}])
            res = detect_fleet_anomalies(test_customer_key.id)
            assert res['rapid_propagation'] == 1

    def test_emits_event_to_webhook(self, portal_app, portal_db, test_customer_key):
        from app.jobs.drift_monitor import detect_fleet_anomalies
        from app.models import WebhookSubscription, WebhookDelivery
        with portal_app.app_context():
            sub = WebhookSubscription(
                customer_key_id=test_customer_key.id, name='sec',
                url='https://example.test/hook',
                event_types=['anomaly.new_risky_extension'], is_active=True)
            portal_db.session.add(sub)
            _add_host(portal_db, test_customer_key, 'h1',
                      [{'id': 'acme.safe', 'publisher': 'acme', 'permissions': []}])
            portal_db.session.commit()
            detect_fleet_anomalies(test_customer_key.id)  # baseline
            before = WebhookDelivery.query.count()
            _add_host(portal_db, test_customer_key, 'h2',
                      [{'id': 'darkpub.crypto-stealer', 'publisher': 'darkpub', 'permissions': []}])
            detect_fleet_anomalies(test_customer_key.id)
            assert WebhookDelivery.query.count() == before + 1
