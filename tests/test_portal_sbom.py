"""Tests for SBOM / VEX / attestation generation (Phase 1 B11)."""


def _seed(portal_db, host):
    from app.models import PackageInfo, ExtensionInfo, Vulnerability, ScanReport
    sr = ScanReport(host_id=host.id, scan_data={'ides': []}, total_ides=0, total_extensions=0)
    portal_db.session.add(sr)
    portal_db.session.commit()
    portal_db.session.add(PackageInfo(
        host_id=host.id, scan_report_id=sr.id, name='lodash', version='4.17.20',
        package_manager='npm', source_type='project'))
    portal_db.session.add(ExtensionInfo(
        host_id=host.id, scan_report_id=sr.id, ide_name='VS Code',
        extension_id='ms-python.python', extension_name='Python',
        extension_version='2024.1', publisher='ms-python', risk_level='high'))
    portal_db.session.add(Vulnerability(
        host_id=host.id, package_name='lodash', package_version='4.17.20',
        package_manager='npm', ecosystem='npm', vuln_id='CVE-2021-23337',
        severity_label='high', summary='prototype pollution', is_resolved=False))
    portal_db.session.commit()


class TestBuildCycloneDX:
    def test_sbom_shape_and_components(self, portal_app, portal_db, test_host):
        from app.sbom import build_cyclonedx
        with portal_app.app_context():
            _seed(portal_db, test_host)
            doc = build_cyclonedx(test_host)
            assert doc['bomFormat'] == 'CycloneDX'
            assert doc['specVersion'] == '1.5'
            names = {c['name'] for c in doc['components']}
            assert 'lodash' in names                 # package component
            assert 'ms-python.python' in names       # extension component
            purls = {c.get('purl') for c in doc['components'] if c.get('purl')}
            assert 'pkg:npm/lodash@4.17.20' in purls

    def test_vulnerabilities_with_vex_state(self, portal_app, portal_db, test_host):
        from app.sbom import build_cyclonedx
        with portal_app.app_context():
            _seed(portal_db, test_host)
            doc = build_cyclonedx(test_host)
            vulns = doc.get('vulnerabilities', [])
            assert any(v['id'] == 'CVE-2021-23337' for v in vulns)
            v = next(v for v in vulns if v['id'] == 'CVE-2021-23337')
            assert v['analysis']['state'] == 'in_triage'
            assert v['affects'][0]['ref'] == 'pkg:npm/lodash@4.17.20'

    def test_signed_attestation_verifies(self, portal_app, portal_db, test_host):
        from app.sbom import build_cyclonedx, sign_attestation
        from app.signing import public_key_info, verify_envelope_body
        with portal_app.app_context():
            _seed(portal_db, test_host)
            env = sign_attestation(build_cyclonedx(test_host))
            assert 'sig' in env
            body = verify_envelope_body(env, public_key_info()['public_key_b64'])
            assert body['sbom']['bomFormat'] == 'CycloneDX'


class TestSbomEndpoint:
    def test_download_requires_ownership(self, portal_app, portal_db, logged_in_client, test_host):
        with portal_app.app_context():
            _seed(portal_db, test_host)
        resp = logged_in_client.get(f'/host/{test_host.public_id}/sbom')
        assert resp.status_code == 200
        assert resp.headers['Content-Type'].startswith('application/json')
        assert b'CycloneDX' in resp.data

    def test_signed_download(self, portal_app, portal_db, logged_in_client, test_host):
        with portal_app.app_context():
            _seed(portal_db, test_host)
        resp = logged_in_client.get(f'/host/{test_host.public_id}/sbom?sign=1')
        assert resp.status_code == 200
        assert b'"sig"' in resp.data
