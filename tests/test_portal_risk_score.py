"""Tests for composite risk scoring v2 (Phase 1 B8)."""


class TestScoreExtension:
    def test_banned_extension_forces_critical(self):
        from app.risk_score import score_extension
        r = score_extension('ms-vscode.example-malware', 'ms-vscode', 'x', permissions=[])
        assert r['level'] == 'critical'
        assert r['score'] >= 50

    def test_clean_low_permission_extension(self):
        from app.risk_score import score_extension
        r = score_extension('acme.helper', 'acme', 'Helper', permissions=[])
        assert r['level'] == 'low'
        assert r['score'] == 0

    def test_critical_permissions_contribute(self):
        from app.risk_score import score_extension
        r = score_extension('acme.helper', 'acme', 'Helper',
                            permissions=[{'name': 'shellExecution'}])
        assert r['score'] >= 30
        assert any(f['label'] == 'Permissions' for f in r['factors'])


class TestScoreHost:
    def _report(self, portal_db, host, extensions):
        from app.models import ScanReport
        sr = ScanReport(
            host_id=host.id,
            scan_data={'ides': [{'name': 'VS Code', 'extensions': extensions}]},
            total_ides=1, total_extensions=len(extensions),
        )
        portal_db.session.add(sr)
        portal_db.session.commit()
        return sr

    def test_clean_host_low(self, portal_app, portal_db, test_host):
        from app.risk_score import score_host
        with portal_app.app_context():
            self._report(portal_db, test_host, [
                {'id': 'acme.helper', 'publisher': 'acme', 'permissions': []},
            ])
            r = score_host(test_host)
            assert r['level'] == 'low'
            assert r['score'] == 0

    def test_threat_match_drives_critical(self, portal_app, portal_db, test_host):
        from app.risk_score import score_host
        with portal_app.app_context():
            self._report(portal_db, test_host, [
                {'id': 'ms-vscode.example-malware', 'publisher': 'ms-vscode', 'permissions': []},
            ])
            r = score_host(test_host)
            assert r['level'] == 'critical'
            assert any('Known-bad' in f['label'] for f in r['factors'])

    def test_over_privileged_extensions_scored(self, portal_app, portal_db, test_host):
        from app.risk_score import score_host
        with portal_app.app_context():
            self._report(portal_db, test_host, [
                {'id': 'acme.a', 'publisher': 'acme', 'permissions': [{'name': 'shellExecution'}]},
                {'id': 'acme.b', 'publisher': 'acme', 'permissions': [{'name': 'terminal'}]},
            ])
            r = score_host(test_host)
            assert r['score'] > 0
            assert any(f['label'] == 'Over-privileged extensions' for f in r['factors'])


class TestIngestionScores:
    def test_report_sets_composite_score_and_emits_threat_event(
        self, portal_app, portal_db, portal_client, test_customer_key, test_host
    ):
        from app.models import Host, WebhookSubscription, WebhookDelivery
        with portal_app.app_context():
            sub = WebhookSubscription(
                customer_key_id=test_customer_key.id, name='sec',
                url='https://example.test/hook',
                event_types=['extension.threat_matched'], is_active=True,
            )
            portal_db.session.add(sub)
            portal_db.session.commit()
            before = WebhookDelivery.query.count()

        scan_data = {
            'ides': [{'name': 'VS Code', 'extensions': [
                {'id': 'darkpub.crypto-stealer', 'name': 'x', 'version': '1.0',
                 'publisher': 'darkpub', 'permissions': []},
            ]}],
            'total_ides': 1, 'total_extensions': 1,
        }
        resp = portal_client.post('/api/report',
                                  headers={'X-Customer-Key': test_customer_key.key},
                                  json={'hostname': 'test-machine', 'platform': 'Darwin',
                                        'scan_data': scan_data})
        assert resp.status_code == 200
        with portal_app.app_context():
            portal_db.session.expire_all()
            h = Host.query.get(test_host.id)
            assert h.risk_score is not None and h.risk_score > 0
            assert h.risk_level_composite == 'critical'
            assert WebhookDelivery.query.count() == before + 1
