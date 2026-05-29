"""Tests for the extension-policy engine (T2.2)."""
from unittest.mock import MagicMock, patch

import pytest


def make_policy(**kwargs):
    """Build a transient ExtensionPolicy object (not persisted)."""
    from app.models import ExtensionPolicy
    defaults = dict(
        id=1,
        customer_key_id=1,
        name='p',
        priority=100,
        action=ExtensionPolicy.ACTION_BLOCK_ALERT,
        is_active=True,
        match_publisher=None,
        match_extension_id=None,
        match_permission_glob=None,
        match_risk_level=None,
    )
    defaults.update(kwargs)
    return ExtensionPolicy(**defaults)


class TestEvaluator:
    def test_no_criteria_never_matches(self, portal_app):
        from app.policy import evaluate
        with portal_app.app_context():
            ext = {'extension_id': 'pub.ext', 'publisher': 'pub', 'permissions': [], 'risk_level': 'high'}
            p = make_policy()
            assert evaluate([ext], [p]) == []

    def test_publisher_exact_match(self, portal_app):
        from app.policy import evaluate
        with portal_app.app_context():
            ext = {'extension_id': 'evil.x', 'publisher': 'evil', 'permissions': [], 'risk_level': 'low'}
            p = make_policy(match_publisher='evil')
            assert len(evaluate([ext], [p])) == 1

    def test_publisher_glob(self, portal_app):
        from app.policy import evaluate
        with portal_app.app_context():
            ext = {'extension_id': 'x', 'publisher': 'evil-corp', 'permissions': [], 'risk_level': 'low'}
            p = make_policy(match_publisher='evil-*')
            assert len(evaluate([ext], [p])) == 1
            ext2 = {'extension_id': 'x', 'publisher': 'good-corp', 'permissions': [], 'risk_level': 'low'}
            assert evaluate([ext2], [p]) == []

    def test_extension_id_glob(self, portal_app):
        from app.policy import evaluate
        with portal_app.app_context():
            ext = {'extension_id': 'pub.banned-ext', 'publisher': 'pub', 'permissions': [], 'risk_level': 'low'}
            p = make_policy(match_extension_id='*.banned-*')
            assert len(evaluate([ext], [p])) == 1

    def test_permission_glob(self, portal_app):
        from app.policy import evaluate
        with portal_app.app_context():
            ext_str = {'extension_id': 'x', 'publisher': 'p', 'permissions': ['fileSystem', 'network'], 'risk_level': 'low'}
            ext_dict = {'extension_id': 'y', 'publisher': 'p', 'permissions': [{'name': 'network.http'}], 'risk_level': 'low'}
            p = make_policy(match_permission_glob='network*')
            assert len(evaluate([ext_str, ext_dict], [p])) == 2

    def test_risk_level_threshold(self, portal_app):
        from app.policy import evaluate
        with portal_app.app_context():
            low = {'extension_id': 'x', 'publisher': 'p', 'permissions': [], 'risk_level': 'low'}
            high = {'extension_id': 'y', 'publisher': 'p', 'permissions': [], 'risk_level': 'high'}
            crit = {'extension_id': 'z', 'publisher': 'p', 'permissions': [], 'risk_level': 'critical'}
            p = make_policy(match_risk_level='high')
            matches = evaluate([low, high, crit], [p])
            assert {m.extension['extension_id'] for m in matches} == {'y', 'z'}

    def test_criteria_are_anded(self, portal_app):
        from app.policy import evaluate
        with portal_app.app_context():
            p = make_policy(match_publisher='evil', match_risk_level='high')
            evil_low = {'extension_id': 'x', 'publisher': 'evil', 'permissions': [], 'risk_level': 'low'}
            evil_high = {'extension_id': 'y', 'publisher': 'evil', 'permissions': [], 'risk_level': 'high'}
            assert evaluate([evil_low], [p]) == []
            assert len(evaluate([evil_high], [p])) == 1

    def test_priority_first_match_wins(self, portal_app):
        from app.policy import evaluate
        from app.models import ExtensionPolicy
        with portal_app.app_context():
            ext = {'extension_id': 'evil.x', 'publisher': 'evil', 'permissions': [], 'risk_level': 'high'}
            allow_first = make_policy(id=1, priority=10, action=ExtensionPolicy.ACTION_ALLOW, match_extension_id='evil.x')
            block_later = make_policy(id=2, priority=100, action=ExtensionPolicy.ACTION_BLOCK_ALERT, match_publisher='evil')
            matches = evaluate([ext], [allow_first, block_later])
            assert len(matches) == 1
            assert matches[0].action == ExtensionPolicy.ACTION_ALLOW

    def test_priority_tiebreak_by_id(self, portal_app):
        from app.policy import evaluate
        with portal_app.app_context():
            ext = {'extension_id': 'x', 'publisher': 'p', 'permissions': [], 'risk_level': 'low'}
            p1 = make_policy(id=5, priority=10, match_publisher='p', action='allow')
            p2 = make_policy(id=1, priority=10, match_publisher='p', action='warn')
            matches = evaluate([ext], [p1, p2])
            assert matches[0].policy.id == 1  # lower id wins ties


class TestRunner:
    @pytest.fixture
    def policy(self, portal_app, portal_db, test_customer_key):
        from app.models import ExtensionPolicy
        with portal_app.app_context():
            p = ExtensionPolicy(
                customer_key_id=test_customer_key.id,
                name='Block evil publisher',
                priority=10,
                action=ExtensionPolicy.ACTION_BLOCK_ALERT,
                match_publisher='evil',
            )
            portal_db.session.add(p)
            portal_db.session.commit()
            yield ExtensionPolicy.query.first()

    def test_block_alert_creates_violation_and_tamper_alert(
        self, portal_app, portal_db, test_host, test_customer_key, policy
    ):
        from app.policy.runner import evaluate_and_record
        from app.models import PolicyViolation, TamperAlert
        with portal_app.app_context():
            with patch('app.queue.enqueue', return_value=MagicMock()):
                ids = evaluate_and_record(
                    test_host,
                    customer_key_id=test_customer_key.id,
                    extensions=[{
                        'extension_id': 'evil.banned',
                        'name': 'Banned',
                        'version': '1.0',
                        'publisher': 'evil',
                        'permissions': [],
                        'risk_level': 'medium',
                    }],
                )
            assert len(ids) == 1
            v = PolicyViolation.query.get(ids[0])
            assert v.action_taken == 'block-alert'
            assert v.publisher == 'evil'
            alerts = TamperAlert.query.filter_by(host_id=test_host.id, alert_type='policy_violation').all()
            assert len(alerts) == 1
            assert alerts[0].severity == 'critical'

    def test_warn_does_not_create_tamper_alert(
        self, portal_app, portal_db, test_host, test_customer_key
    ):
        from app.policy.runner import evaluate_and_record
        from app.models import ExtensionPolicy, PolicyViolation, TamperAlert
        with portal_app.app_context():
            p = ExtensionPolicy(
                customer_key_id=test_customer_key.id,
                name='Warn',
                priority=20,
                action=ExtensionPolicy.ACTION_WARN,
                match_publisher='warn-me',
            )
            portal_db.session.add(p)
            portal_db.session.commit()

            with patch('app.queue.enqueue', return_value=MagicMock()):
                evaluate_and_record(
                    test_host,
                    customer_key_id=test_customer_key.id,
                    extensions=[{
                        'extension_id': 'warn-me.x', 'publisher': 'warn-me',
                        'permissions': [], 'risk_level': 'low',
                    }],
                )
            assert PolicyViolation.query.count() == 1
            assert TamperAlert.query.filter_by(alert_type='policy_violation').count() == 0

    def test_allow_creates_nothing(
        self, portal_app, portal_db, test_host, test_customer_key
    ):
        from app.policy.runner import evaluate_and_record
        from app.models import ExtensionPolicy, PolicyViolation, TamperAlert
        with portal_app.app_context():
            p = ExtensionPolicy(
                customer_key_id=test_customer_key.id,
                name='Allow',
                priority=1,
                action=ExtensionPolicy.ACTION_ALLOW,
                match_publisher='trusted',
            )
            portal_db.session.add(p)
            portal_db.session.commit()
            with patch('app.queue.enqueue', return_value=MagicMock()):
                ids = evaluate_and_record(
                    test_host,
                    customer_key_id=test_customer_key.id,
                    extensions=[{
                        'extension_id': 'trusted.x', 'publisher': 'trusted',
                        'permissions': [], 'risk_level': 'low',
                    }],
                )
            assert ids == []
            assert PolicyViolation.query.count() == 0
            assert TamperAlert.query.filter_by(alert_type='policy_violation').count() == 0

    def test_rescan_upserts_violation(
        self, portal_app, portal_db, test_host, test_customer_key, policy
    ):
        from app.policy.runner import evaluate_and_record
        from app.models import PolicyViolation
        ext = {
            'extension_id': 'evil.x', 'name': 'X', 'version': '1.0',
            'publisher': 'evil', 'permissions': [], 'risk_level': 'low',
        }
        with portal_app.app_context():
            with patch('app.queue.enqueue', return_value=MagicMock()):
                evaluate_and_record(test_host, customer_key_id=test_customer_key.id, extensions=[ext])
                first_id = PolicyViolation.query.first().id
                first_seen = PolicyViolation.query.first().first_detected_at

                evaluate_and_record(test_host, customer_key_id=test_customer_key.id, extensions=[ext])

            assert PolicyViolation.query.count() == 1
            refreshed = PolicyViolation.query.first()
            assert refreshed.id == first_id
            assert refreshed.first_detected_at == first_seen

    def test_emits_policy_violation_event(
        self, portal_app, portal_db, test_host, test_customer_key, policy
    ):
        from app.policy.runner import evaluate_and_record
        with portal_app.app_context():
            with patch('app.policy.runner.emit_event') as emit, \
                 patch('app.queue.enqueue', return_value=MagicMock()):
                evaluate_and_record(
                    test_host,
                    customer_key_id=test_customer_key.id,
                    extensions=[{
                        'extension_id': 'evil.x', 'publisher': 'evil',
                        'permissions': [], 'risk_level': 'low',
                    }],
                )
                emit.assert_called_once()
                args, kwargs = emit.call_args
                assert args[0] == 'policy.violation'
                assert kwargs['customer_key_id'] == test_customer_key.id


class TestUI:
    def test_policies_page_requires_login(self, portal_client):
        resp = portal_client.get('/policies')
        assert resp.status_code in (302, 401)

    def test_policies_page_renders(self, logged_in_client, test_customer_key):
        resp = logged_in_client.get('/policies')
        assert resp.status_code == 200
        assert b'Extension Policies' in resp.data

    def test_violations_page_renders(self, logged_in_client, test_customer_key):
        resp = logged_in_client.get('/violations')
        assert resp.status_code == 200
        assert b'Policy Violations' in resp.data
