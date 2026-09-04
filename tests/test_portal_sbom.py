"""Tests for SBOM / VEX / attestation generation (Phase 1 B11)."""


# Extensions live on the scan report's JSON, not in a table: report ingestion
# writes PackageInfo/Vulnerability rows but never ExtensionInfo ones. Seeding an
# ExtensionInfo row here (as this helper used to) built state production never
# produces, which is how an SBOM that omitted every extension passed its tests.
_SCAN_DATA = {
    'ides': [
        {
            'name': 'VS Code',
            'extensions': [{
                'id': 'ms-python.python',
                'name': 'Python',
                'version': '2024.1',
                'publisher': 'ms-python',
                # 'terminal' is a HIGH permission, so risk_level computes to 'high'.
                'permissions': ['terminal'],
            }],
        },
        {
            # Same extension installed in a second IDE: the SBOM must emit one
            # component for it, not two.
            'name': 'Cursor',
            'extensions': [{
                'id': 'ms-python.python',
                'name': 'Python',
                'version': '2024.1',
                'publisher': 'ms-python',
                'permissions': ['terminal'],
            }],
        },
    ],
    'total_ides': 2,
    'total_extensions': 2,
}


def _seed(portal_db, host):
    from app.models import PackageInfo, Vulnerability, ScanReport
    sr = ScanReport(host_id=host.id, scan_data=_SCAN_DATA, total_ides=2, total_extensions=2)
    portal_db.session.add(sr)
    portal_db.session.commit()
    portal_db.session.add(PackageInfo(
        host_id=host.id, scan_report_id=sr.id, name='lodash', version='4.17.20',
        package_manager='npm', source_type='project'))
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

    def test_extensions_come_from_scan_data(self, portal_app, portal_db, test_host):
        """Extensions must be read off the scan report, and deduped across IDEs.

        Nothing writes ExtensionInfo rows, so an SBOM sourced from that table is
        always extension-less -- the regression this guards.
        """
        from app.sbom import build_cyclonedx
        from app.models import ExtensionInfo
        with portal_app.app_context():
            _seed(portal_db, test_host)
            assert ExtensionInfo.query.filter_by(host_id=test_host.id).count() == 0

            doc = build_cyclonedx(test_host)
            exts = [c for c in doc['components'] if c['type'] == 'application']
            assert len(exts) == 1, 'extension installed in two IDEs must yield one component'

            ext = exts[0]
            assert ext['name'] == 'ms-python.python'
            assert ext['bom-ref'] == 'ext:ms-python.python'
            assert ext['version'] == '2024.1'
            assert ext['publisher'] == 'ms-python'
            props = {p['name']: p['value'] for p in ext['properties']}
            assert props['ideviewer:risk_level'] == 'high'

    def test_sbom_without_any_scan_report(self, portal_app, portal_db, test_host):
        """A host that has never reported still produces a valid, empty SBOM."""
        from app.sbom import build_cyclonedx
        with portal_app.app_context():
            doc = build_cyclonedx(test_host)
            assert doc['bomFormat'] == 'CycloneDX'
            assert doc['components'] == []

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
