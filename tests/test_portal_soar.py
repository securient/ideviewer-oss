"""Tests for the SOAR remediation engine (Phase 1 B10)."""


def _playbook(portal_db, key, **kw):
    from app.models import RemediationPlaybook
    pb = RemediationPlaybook(
        customer_key_id=key.id,
        name=kw.get('name', 'pb'),
        trigger_event=kw.get('trigger_event', 'extension.threat_matched'),
        action=kw.get('action', 'auto_quarantine'),
        mode=kw.get('mode', 'active'),
        min_severity=kw.get('min_severity', 'high'),
        max_actions_per_hour=kw.get('max_actions_per_hour', 5),
    )
    portal_db.session.add(pb)
    portal_db.session.commit()
    return pb


class TestSoarEngine:
    def _ext(self):
        return {'extension_id': 'darkpub.crypto-stealer', 'name': 'x',
                'version': '1.0', 'severity': 'critical'}

    def test_active_auto_quarantine_creates_action(self, portal_app, portal_db, test_host, test_customer_key):
        from app.soar import run_playbooks_for_event
        from app.models import EnforcementAction
        with portal_app.app_context():
            _playbook(portal_db, test_customer_key, mode='active')
            out = run_playbooks_for_event('extension.threat_matched',
                                          test_customer_key.id, test_host, self._ext(), 'critical')
            assert any(o['outcome'] == 'quarantined' for o in out)
            assert EnforcementAction.query.filter_by(
                host_id=test_host.id, extension_id='darkpub.crypto-stealer').count() == 1

    def test_dry_run_does_not_create_action(self, portal_app, portal_db, test_host, test_customer_key):
        from app.soar import run_playbooks_for_event
        from app.models import EnforcementAction
        with portal_app.app_context():
            _playbook(portal_db, test_customer_key, mode='dry_run')
            out = run_playbooks_for_event('extension.threat_matched',
                                          test_customer_key.id, test_host, self._ext(), 'critical')
            assert any(o['outcome'] == 'simulated' for o in out)
            assert EnforcementAction.query.filter_by(host_id=test_host.id).count() == 0

    def test_severity_gate(self, portal_app, portal_db, test_host, test_customer_key):
        from app.soar import run_playbooks_for_event
        with portal_app.app_context():
            _playbook(portal_db, test_customer_key, mode='active', min_severity='critical')
            out = run_playbooks_for_event('extension.threat_matched',
                                          test_customer_key.id, test_host,
                                          {'extension_id': 'a.b', 'severity': 'high'}, 'high')
            assert out == []  # 'high' < required 'critical'

    def test_dedupe_existing_quarantine(self, portal_app, portal_db, test_host, test_customer_key):
        from app.soar import run_playbooks_for_event
        from app.models import EnforcementAction
        with portal_app.app_context():
            _playbook(portal_db, test_customer_key, mode='active')
            portal_db.session.add(EnforcementAction(
                host_id=test_host.id, action='quarantine', status='pending',
                extension_id='darkpub.crypto-stealer'))
            portal_db.session.commit()
            out = run_playbooks_for_event('extension.threat_matched',
                                          test_customer_key.id, test_host, self._ext(), 'critical')
            assert any(o['outcome'] == 'deduped' for o in out)
            assert EnforcementAction.query.filter_by(host_id=test_host.id).count() == 1

    def test_rate_limit(self, portal_app, portal_db, test_host, test_customer_key):
        from app.soar import run_playbooks_for_event
        from app.models import EnforcementAction
        with portal_app.app_context():
            _playbook(portal_db, test_customer_key, mode='active', max_actions_per_hour=1)
            # one existing quarantine this hour exhausts the budget
            portal_db.session.add(EnforcementAction(
                host_id=test_host.id, action='quarantine', status='applied',
                extension_id='other.ext'))
            portal_db.session.commit()
            out = run_playbooks_for_event('extension.threat_matched',
                                          test_customer_key.id, test_host, self._ext(), 'critical')
            assert any(o['outcome'] == 'rate_limited' for o in out)

    def test_writes_audit_entry(self, portal_app, portal_db, test_host, test_customer_key):
        from app.soar import run_playbooks_for_event
        from app.models import AuditLog
        with portal_app.app_context():
            _playbook(portal_db, test_customer_key, mode='active')
            run_playbooks_for_event('extension.threat_matched',
                                    test_customer_key.id, test_host, self._ext(), 'critical')
            assert AuditLog.query.filter_by(action='soar.auto_quarantine').count() == 1
