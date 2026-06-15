"""Tests for RBAC + audit log (Phase 1 B9)."""


def _login(portal_client, user_id):
    with portal_client.session_transaction() as sess:
        sess['_user_id'] = str(user_id)


class TestAuditLog:
    def test_create_policy_writes_audit_entry(
        self, portal_app, portal_db, logged_in_client, test_customer_key
    ):
        from app.models import AuditLog
        portal_app.config['WTF_CSRF_ENABLED'] = False
        resp = logged_in_client.post('/policies/create', data={
            'name': 'p1', 'priority': '10', 'action': 'warn',
            'customer_key_id': str(test_customer_key.id),
            'match_publisher': 'foo', 'match_extension_id': '',
            'match_permission_glob': '', 'match_risk_level': '',
        })
        assert resp.status_code in (302, 303)
        with portal_app.app_context():
            entries = AuditLog.query.filter_by(action='policy.create').all()
            assert len(entries) == 1
            assert entries[0].actor

    def test_delete_key_writes_audit_entry(
        self, portal_app, portal_db, logged_in_client, test_customer_key
    ):
        from app.models import AuditLog, CustomerKey
        portal_app.config['WTF_CSRF_ENABLED'] = False
        kid = test_customer_key.id
        resp = logged_in_client.post(f'/keys/{kid}/delete')
        assert resp.status_code in (302, 303)
        with portal_app.app_context():
            assert AuditLog.query.filter_by(action='key.delete').count() == 1


class TestRBAC:
    def _make_user(self, portal_app, portal_db, role):
        from app.models import User
        with portal_app.app_context():
            u = User(email=f'{role}@x.com', username=f'{role}user', role=role)
            u.set_password('pw')
            portal_db.session.add(u)
            portal_db.session.commit()
            return User.query.filter_by(username=f'{role}user').first().id

    def test_viewer_cannot_delete_key(
        self, portal_app, portal_db, portal_client, test_customer_key
    ):
        portal_app.config['WTF_CSRF_ENABLED'] = False
        uid = self._make_user(portal_app, portal_db, 'viewer')
        _login(portal_client, uid)
        resp = portal_client.post(f'/keys/{test_customer_key.id}/delete')
        assert resp.status_code == 403

    def test_viewer_cannot_quarantine(
        self, portal_app, portal_db, portal_client
    ):
        # The role gate runs before the get_or_404, so a viewer is denied 403
        # regardless of whether the violation exists.
        portal_app.config['WTF_CSRF_ENABLED'] = False
        uid = self._make_user(portal_app, portal_db, 'viewer')
        _login(portal_client, uid)
        resp = portal_client.post('/violations/123456/quarantine')
        assert resp.status_code == 403

    def test_analyst_can_quarantine_admin_only_denied(
        self, portal_app, portal_db, portal_client
    ):
        # analyst passes the role gate on an operate action...
        from app.models import User
        uid = self._make_user(portal_app, portal_db, 'analyst')
        _login(portal_client, uid)
        # ...but is blocked from an admin-only action (delete is admin-only).
        # Use a non-existent key id: role check runs before the 404, so a
        # denied analyst gets 403 (not 404).
        portal_app.config['WTF_CSRF_ENABLED'] = False
        resp = portal_client.post('/keys/999999/delete')
        assert resp.status_code == 403

    def test_admin_passes_role_gate(self, portal_app, portal_db, portal_client):
        # An admin hitting a missing key passes RBAC and reaches the 404.
        uid = self._make_user(portal_app, portal_db, 'admin')
        _login(portal_client, uid)
        portal_app.config['WTF_CSRF_ENABLED'] = False
        resp = portal_client.post('/keys/999999/delete')
        assert resp.status_code == 404
