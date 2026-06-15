"""Tests for command-envelope signing (Phase 1 B1)."""
import base64
import json


class TestSignEnvelope:
    def test_sign_and_verify_roundtrip(self, portal_app):
        from app.signing import sign_envelope, public_key_info, verify_envelope_body
        with portal_app.app_context():
            env = sign_envelope({'actions': [{'id': 1, 'action': 'quarantine'}]})
            assert 'sig' in env
            assert env['actions'] == [{'id': 1, 'action': 'quarantine'}]  # top-level kept
            sig = env['sig']
            assert sig['alg'] == 'ed25519'
            assert sig['key_id'] == public_key_info()['key_id']

            body = verify_envelope_body(env, public_key_info()['public_key_b64'])
            assert body['actions'][0]['action'] == 'quarantine'

    def test_canonical_body_is_compact_sorted(self, portal_app):
        from app.signing import sign_envelope
        with portal_app.app_context():
            env = sign_envelope({'actions': [], 'z': 1, 'a': 2})
            decoded = base64.standard_b64decode(env['sig']['body_b64']).decode()
            # sort_keys + compact separators
            assert decoded == json.dumps({'actions': [], 'z': 1, 'a': 2},
                                         separators=(',', ':'), sort_keys=True)

    def test_tampered_body_fails_verification(self, portal_app):
        from app.signing import sign_envelope, public_key_info, verify_envelope_body
        with portal_app.app_context():
            env = sign_envelope({'actions': []})
            env['sig']['body_b64'] = base64.standard_b64encode(
                b'{"actions":[{"id":99}]}').decode()
            try:
                verify_envelope_body(env, public_key_info()['public_key_b64'])
                assert False, "tampered body should not verify"
            except Exception:
                pass

    def test_signer_reads_key_from_env(self, portal_app, monkeypatch):
        """An explicit COMMAND_SIGNING_PRIVATE_KEY is honored over auto-gen."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        seed = Ed25519PrivateKey.generate().private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        monkeypatch.setenv('COMMAND_SIGNING_PRIVATE_KEY',
                           base64.standard_b64encode(seed).decode())
        # Fresh app so the signer is built with the env key.
        from app import create_app
        app = create_app('testing')
        app.extensions.pop('command_signer', None)
        with app.app_context():
            from app.signing import LocalEd25519Signer, get_signer
            signer = get_signer(app)
            expected = LocalEd25519Signer.from_seed_b64(
                base64.standard_b64encode(seed).decode())
            assert signer.key_id == expected.key_id


class TestSigningKeyEndpoint:
    def test_requires_auth(self, portal_app, portal_client):
        resp = portal_client.get('/api/signing-key')
        assert resp.status_code in (401, 403)

    def test_returns_key_with_token(self, portal_app, portal_client, test_host_with_token):
        from app.signing import public_key_info
        host, token = test_host_with_token
        resp = portal_client.get('/api/signing-key', headers={'X-Host-Token': token})
        assert resp.status_code == 200
        body = resp.get_json()
        assert body['algorithm'] == 'ed25519'
        with portal_app.app_context():
            assert body['public_key_b64'] == public_key_info()['public_key_b64']


class TestPendingEnvelopeSigned:
    def test_pending_response_is_signed_and_verifies(
        self, portal_app, portal_db, portal_client, test_host_with_token
    ):
        from app.models import EnforcementAction
        from app.signing import public_key_info, verify_envelope_body
        host, token = test_host_with_token
        with portal_app.app_context():
            action = EnforcementAction(
                host_id=host.id, action='quarantine',
                extension_id='evil.banned', status=EnforcementAction.STATUS_PENDING,
            )
            portal_db.session.add(action)
            portal_db.session.commit()
            pub = public_key_info()['public_key_b64']

        resp = portal_client.get('/api/enforcement-actions/pending',
                                 headers={'X-Host-Token': token})
        assert resp.status_code == 200
        env = resp.get_json()
        assert 'sig' in env
        # Old daemons still see the top-level actions list.
        assert env['actions'][0]['extension_id'] == 'evil.banned'
        # New daemons verify and decode the signed body.
        body = verify_envelope_body(env, pub)
        assert body['actions'][0]['extension_id'] == 'evil.banned'
