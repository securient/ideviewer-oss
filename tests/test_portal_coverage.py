"""Tests for fleet coverage reporting (Phase 1 B12)."""
from datetime import datetime, timedelta


def _host(portal_db, key, hostname, heartbeat_minutes_ago=None, active=True):
    from app.models import Host
    h = Host(hostname=hostname, customer_key_id=key.id, is_active=active)
    if heartbeat_minutes_ago is not None:
        h.last_heartbeat_at = datetime.utcnow() - timedelta(minutes=heartbeat_minutes_ago)
    portal_db.session.add(h)
    portal_db.session.commit()
    return h


def _expected(portal_db, key, hostname):
    from app.models import ExpectedHost
    portal_db.session.add(ExpectedHost(customer_key_id=key.id, hostname=hostname))
    portal_db.session.commit()


class TestCoverage:
    def test_covered_missing_unmanaged(self, portal_app, portal_db, test_customer_key):
        from app.coverage import coverage_for_key
        with portal_app.app_context():
            # roster: a, b, c
            for n in ('a', 'b', 'c'):
                _expected(portal_db, test_customer_key, n)
            # reporting: a (recent), c (recent), d (recent, not on roster)
            _host(portal_db, test_customer_key, 'a', heartbeat_minutes_ago=5)
            _host(portal_db, test_customer_key, 'c', heartbeat_minutes_ago=5)
            _host(portal_db, test_customer_key, 'd', heartbeat_minutes_ago=5)
            # b never reports
            s = coverage_for_key(test_customer_key)
            assert s['covered'] == ['a', 'c']
            assert s['missing'] == ['b']
            assert s['unmanaged'] == ['d']
            assert s['coverage_pct'] == 67  # 2 of 3

    def test_stale_heartbeat_not_reporting(self, portal_app, portal_db, test_customer_key):
        from app.coverage import coverage_for_key
        with portal_app.app_context():
            _expected(portal_db, test_customer_key, 'a')
            _host(portal_db, test_customer_key, 'a', heartbeat_minutes_ago=60 * 48)  # 2 days
            s = coverage_for_key(test_customer_key)
            assert s['missing'] == ['a']
            assert s['covered'] == []

    def test_no_roster_pct_none(self, portal_app, portal_db, test_customer_key):
        from app.coverage import coverage_for_key
        with portal_app.app_context():
            _host(portal_db, test_customer_key, 'x', heartbeat_minutes_ago=5)
            s = coverage_for_key(test_customer_key)
            assert s['coverage_pct'] is None
            assert s['unmanaged'] == ['x']


class TestRoster:
    def test_bulk_add_and_dedupe(self, portal_app, portal_db, logged_in_client, test_customer_key):
        from app.models import ExpectedHost
        portal_app.config['WTF_CSRF_ENABLED'] = False
        resp = logged_in_client.post('/coverage/add', data={
            'customer_key_id': str(test_customer_key.id),
            'hostnames': 'h1\nh2, h3\nh1',  # h1 duplicated
        })
        assert resp.status_code in (302, 303)
        with portal_app.app_context():
            names = {e.hostname for e in ExpectedHost.query.filter_by(
                customer_key_id=test_customer_key.id)}
            assert names == {'h1', 'h2', 'h3'}

    def test_viewer_cannot_add(self, portal_app, portal_db, portal_client, test_customer_key):
        from app.models import User
        portal_app.config['WTF_CSRF_ENABLED'] = False
        with portal_app.app_context():
            u = User(email='v@x.com', username='vv', role='viewer')
            u.set_password('pw')
            portal_db.session.add(u)
            portal_db.session.commit()
            uid = u.id
        with portal_client.session_transaction() as sess:
            sess['_user_id'] = str(uid)
        resp = portal_client.post('/coverage/add', data={
            'customer_key_id': str(test_customer_key.id), 'hostnames': 'x'})
        assert resp.status_code == 403
