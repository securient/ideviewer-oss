"""Tests for the enforcement plane (quarantine) — portal side."""
from unittest.mock import MagicMock, patch

import pytest


def _quarantine_ext(**kw):
    ext = {
        'extension_id': 'evil.banned',
        'name': 'Banned',
        'version': '1.0',
        'publisher': 'evil',
        'permissions': [],
        'risk_level': 'high',
        'ide_type': 'vscode',
    }
    ext.update(kw)
    return ext


class TestRunnerQuarantine:
    def test_quarantine_policy_creates_enforcement_action(
        self, portal_app, portal_db, test_host, test_customer_key
    ):
        from app.policy.runner import evaluate_and_record
        from app.models import ExtensionPolicy, EnforcementAction
        with portal_app.app_context():
            p = ExtensionPolicy(
                customer_key_id=test_customer_key.id,
                name='Quarantine evil',
                priority=10,
                action=ExtensionPolicy.ACTION_QUARANTINE,
                match_publisher='evil',
            )
            portal_db.session.add(p)
            portal_db.session.commit()

            with patch('app.queue.enqueue', return_value=MagicMock()):
                evaluate_and_record(
                    test_host,
                    customer_key_id=test_customer_key.id,
                    extensions=[_quarantine_ext()],
                )

            actions = EnforcementAction.query.all()
            assert len(actions) == 1
            a = actions[0]
            assert a.action == EnforcementAction.ACTION_QUARANTINE
            assert a.status == EnforcementAction.STATUS_PENDING
            assert a.extension_id == 'evil.banned'
            assert a.ide_type == 'vscode'
            assert a.created_by_user_id is None  # policy-driven
            assert a.violation_id is not None

    def test_quarantine_is_idempotent_across_rescans(
        self, portal_app, portal_db, test_host, test_customer_key
    ):
        from app.policy.runner import evaluate_and_record
        from app.models import ExtensionPolicy, EnforcementAction
        with portal_app.app_context():
            p = ExtensionPolicy(
                customer_key_id=test_customer_key.id, name='q', priority=10,
                action=ExtensionPolicy.ACTION_QUARANTINE, match_publisher='evil',
            )
            portal_db.session.add(p)
            portal_db.session.commit()
            with patch('app.queue.enqueue', return_value=MagicMock()):
                evaluate_and_record(test_host, customer_key_id=test_customer_key.id,
                                    extensions=[_quarantine_ext()])
                evaluate_and_record(test_host, customer_key_id=test_customer_key.id,
                                    extensions=[_quarantine_ext()])
            assert EnforcementAction.query.count() == 1


def _make_action(db, host, **kw):
    from app.models import EnforcementAction
    a = EnforcementAction(
        host_id=host.id,
        action=EnforcementAction.ACTION_QUARANTINE,
        status=EnforcementAction.STATUS_PENDING,
        extension_id='evil.banned',
        extension_version='1.0',
        ide_type='vscode',
    )
    for k, v in kw.items():
        setattr(a, k, v)
    db.session.add(a)
    db.session.commit()
    return a


class TestEnforcementAPI:
    def test_pending_is_token_scoped_and_flips_to_dispatched(
        self, portal_app, portal_db, portal_client, test_host_with_token
    ):
        from app.models import EnforcementAction
        host, token = test_host_with_token
        with portal_app.app_context():
            aid = _make_action(portal_db, host).id

        resp = portal_client.get(
            '/api/enforcement-actions/pending',
            headers={'X-Host-Token': token},
        )
        assert resp.status_code == 200
        actions = resp.get_json()['actions']
        assert len(actions) == 1
        assert actions[0]['extension_id'] == 'evil.banned'

        with portal_app.app_context():
            assert EnforcementAction.query.get(aid).status == EnforcementAction.STATUS_DISPATCHED

    def test_report_applied_updates_action(
        self, portal_app, portal_db, portal_client, test_host_with_token
    ):
        from app.models import EnforcementAction
        host, token = test_host_with_token
        with portal_app.app_context():
            aid = _make_action(portal_db, host, status=EnforcementAction.STATUS_DISPATCHED).id

        resp = portal_client.post(
            f'/api/enforcement-actions/{aid}/report',
            headers={'X-Host-Token': token},
            json={'status': 'applied', 'result_detail': 'quarantined',
                  'quarantine_path': '/home/u/.ideviewer/quarantine/x'},
        )
        assert resp.status_code == 200
        with portal_app.app_context():
            a = EnforcementAction.query.get(aid)
            assert a.status == EnforcementAction.STATUS_APPLIED
            assert a.completed_at is not None
            assert a.quarantine_path.endswith('/x')

    def test_report_rejects_invalid_status(
        self, portal_app, portal_db, portal_client, test_host_with_token
    ):
        host, token = test_host_with_token
        with portal_app.app_context():
            aid = _make_action(portal_db, host).id
        resp = portal_client.post(
            f'/api/enforcement-actions/{aid}/report',
            headers={'X-Host-Token': token},
            json={'status': 'bogus'},
        )
        assert resp.status_code == 400

    def test_report_cross_host_rejected(
        self, portal_app, portal_db, portal_client, test_host_with_token, test_customer_key
    ):
        from app.models import Host, EnforcementAction
        host_a, token_a = test_host_with_token
        with portal_app.app_context():
            # A second host with its own token under the same key.
            host_b = Host(hostname='host-b', platform='Linux', customer_key_id=test_customer_key.id)
            portal_db.session.add(host_b)
            portal_db.session.flush()
            token_b = host_b.issue_token()
            portal_db.session.commit()
            aid = _make_action(portal_db, host_a, status=EnforcementAction.STATUS_DISPATCHED).id

        # host B's token must not be able to report on host A's action.
        resp = portal_client.post(
            f'/api/enforcement-actions/{aid}/report',
            headers={'X-Host-Token': token_b},
            json={'status': 'applied'},
        )
        assert resp.status_code == 403


class TestManualQuarantineRoute:
    def test_quarantine_violation_creates_action(
        self, portal_app, portal_db, logged_in_client, test_host
    ):
        from app.models import PolicyViolation, ExtensionPolicy, EnforcementAction
        portal_app.config['WTF_CSRF_ENABLED'] = False
        with portal_app.app_context():
            pol = ExtensionPolicy(
                customer_key_id=test_host.customer_key_id, name='warn', priority=10,
                action=ExtensionPolicy.ACTION_WARN, match_publisher='evil',
            )
            portal_db.session.add(pol)
            portal_db.session.flush()
            v = PolicyViolation(
                host_id=test_host.id, policy_id=pol.id,
                extension_id='evil.banned', extension_version='1.0',
                extension_name='Banned', publisher='evil', risk_level='high',
                action_taken='warn',
            )
            portal_db.session.add(v)
            portal_db.session.commit()
            vid = v.id

        with patch('app.queue.enqueue', return_value=MagicMock()):
            resp = logged_in_client.post(f'/violations/{vid}/quarantine')
        assert resp.status_code in (302, 303)

        with portal_app.app_context():
            a = EnforcementAction.query.filter_by(extension_id='evil.banned').first()
            assert a is not None
            assert a.action == EnforcementAction.ACTION_QUARANTINE
            assert a.created_by_user_id is not None  # manual


class TestHostDeletion:
    """Regression: deleting a host with dependent rows must not 500 on FK order."""

    def test_delete_host_with_dependent_rows(
        self, portal_app, portal_db, logged_in_client, test_host
    ):
        from app.models import (
            ScanReport, AIToolInfo, PackageInfo, ExtensionPolicy,
            PolicyViolation, EnforcementAction, Host,
        )
        portal_app.config['WTF_CSRF_ENABLED'] = False
        with portal_app.app_context():
            host_id = test_host.id
            public_id = test_host.public_id
            sr = ScanReport(host_id=host_id, scan_data={'ides': []},
                            total_ides=0, total_extensions=0, dangerous_extensions=0)
            portal_db.session.add(sr)
            portal_db.session.flush()
            # ai_tool_info -> scan_reports is the FK that produced the original 500
            portal_db.session.add(AIToolInfo(host_id=host_id, scan_report_id=sr.id, tool_name='Claude Code'))
            portal_db.session.add(PackageInfo(host_id=host_id, scan_report_id=sr.id,
                                              name='x', version='1', package_manager='pip'))
            pol = ExtensionPolicy(customer_key_id=test_host.customer_key_id, name='p',
                                  priority=10, action='warn', match_publisher='evil')
            portal_db.session.add(pol)
            portal_db.session.flush()
            v = PolicyViolation(host_id=host_id, policy_id=pol.id,
                                extension_id='e', action_taken='warn')
            portal_db.session.add(v)
            portal_db.session.flush()
            portal_db.session.add(EnforcementAction(host_id=host_id, violation_id=v.id,
                                                    action='quarantine', status='pending',
                                                    extension_id='e'))
            portal_db.session.commit()

        resp = logged_in_client.post(f'/host/{public_id}/delete')
        assert resp.status_code in (302, 303)
        with portal_app.app_context():
            assert Host.query.get(host_id) is None
            assert ScanReport.query.filter_by(host_id=host_id).count() == 0
            assert EnforcementAction.query.filter_by(host_id=host_id).count() == 0
            assert PolicyViolation.query.filter_by(host_id=host_id).count() == 0


class TestPolicyEdit:
    def test_edit_updates_policy(self, portal_app, portal_db, logged_in_client, test_customer_key):
        from app.models import ExtensionPolicy
        portal_app.config['WTF_CSRF_ENABLED'] = False
        with portal_app.app_context():
            p = ExtensionPolicy(customer_key_id=test_customer_key.id, name='old',
                                priority=100, action='warn', match_publisher='foo')
            portal_db.session.add(p)
            portal_db.session.commit()
            pid = p.public_id

        resp = logged_in_client.post(f'/policies/{pid}/edit', data={
            'name': 'newname', 'priority': '5', 'action': 'quarantine',
            'customer_key_id': str(test_customer_key.id),
            'match_publisher': 'evilcorp', 'match_extension_id': '',
            'match_permission_glob': '', 'match_risk_level': '',
        })
        assert resp.status_code in (302, 303)
        with portal_app.app_context():
            p = ExtensionPolicy.query.filter_by(public_id=pid).first()
            assert p.name == 'newname'
            assert p.priority == 5
            assert p.action == 'quarantine'
            assert p.match_publisher == 'evilcorp'


class TestDependencyRisk:
    def test_counts_critical_high_for_extension(self, portal_app, portal_db, test_host):
        from app.policy.runner import _extension_dependency_risk
        from app.models import PackageInfo, Vulnerability, ScanReport
        with portal_app.app_context():
            sr = ScanReport(host_id=test_host.id, scan_data={'ides': []},
                            total_ides=0, total_extensions=0, dangerous_extensions=0)
            portal_db.session.add(sr); portal_db.session.flush()
            pkg = PackageInfo(host_id=test_host.id, scan_report_id=sr.id, name='left-pad',
                              version='1.0', package_manager='npm',
                              source_type='extension', source_extension='evil.ext')
            portal_db.session.add(pkg); portal_db.session.flush()
            for sev in ('CRITICAL', 'HIGH', 'HIGH', 'low'):
                portal_db.session.add(Vulnerability(
                    host_id=test_host.id, package_info_id=pkg.id, package_name='left-pad',
                    package_version='1.0', package_manager='npm', ecosystem='npm',
                    vuln_id=f'CVE-{sev}', severity_label=sev, is_resolved=False))
            portal_db.session.commit()
            res = _extension_dependency_risk(test_host.id, 'evil.ext')
            assert res['critical'] == 1
            assert res['high'] == 2
            assert len(res['examples']) == 3  # critical + 2 high
            # unrelated extension id => nothing
            assert _extension_dependency_risk(test_host.id, 'other.ext')['critical'] == 0


class TestNotifications:
    def test_feed_lists_unacknowledged_and_marks_read(
        self, portal_app, portal_db, logged_in_client, test_host
    ):
        from app.models import TamperAlert
        portal_app.config['WTF_CSRF_ENABLED'] = False
        with portal_app.app_context():
            a1 = TamperAlert(host_id=test_host.id, alert_type='policy_violation',
                             details='evil ext', severity='critical')
            a2 = TamperAlert(host_id=test_host.id, alert_type='file_modified',
                             details='y', severity='critical', is_acknowledged=True)
            portal_db.session.add_all([a1, a2])
            portal_db.session.commit()
            a1id = a1.id

        data = logged_in_client.get('/notifications').get_json()
        assert data['count'] == 1  # only the unacknowledged one
        assert data['items'][0]['label'] == 'Policy violation'
        assert data['items'][0]['category'] == 'policy'

        assert logged_in_client.post(f'/notifications/{a1id}/read').status_code == 200
        assert logged_in_client.get('/notifications').get_json()['count'] == 0

    def test_read_all(self, portal_app, portal_db, logged_in_client, test_host):
        from app.models import TamperAlert
        portal_app.config['WTF_CSRF_ENABLED'] = False
        with portal_app.app_context():
            for _ in range(3):
                portal_db.session.add(TamperAlert(host_id=test_host.id, alert_type='file_modified',
                                                   details='d', severity='critical'))
            portal_db.session.commit()
        assert logged_in_client.get('/notifications').get_json()['count'] == 3
        assert logged_in_client.post('/notifications/read-all').status_code == 200
        assert logged_in_client.get('/notifications').get_json()['count'] == 0
