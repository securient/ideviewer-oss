"""Tests for /api/realtime-event — the filesystem-watcher reporting path.

This endpoint had no coverage at all, which is how it shipped broken: it
created a ScanReport, then read ``report.id`` for the package foreign keys
without flushing first, so the id was still None. Every realtime event that
carried dependency data — which is every one the daemon sends — died on a
not-null violation and came back as a 500. The watcher was detecting extension
changes within its 30s debounce and the portal was discarding all of them.
"""
import pytest


def _event(hostname, with_packages=True, ext_id='evil.miner'):
    payload = {
        'hostname': hostname,
        'platform': 'darwin arm64',
        'event_type': 'extension_change',
        'timestamp': '2026-09-04T01:21:28Z',
        'changes': [{
            'path': f'/Users/dev/.vscode/extensions/{ext_id}',
            'event_type': 'CREATE',
            'timestamp': '2026-09-04T01:21:28Z',
        }],
        'scan_data': {
            'timestamp': '2026-09-04T01:21:28Z',
            'platform': 'darwin',
            'ides': [{'name': 'VS Code', 'version': '1.99', 'extensions': [{
                'id': ext_id, 'name': 'Miner', 'version': '0.0.1',
                'publisher': 'evil', 'permissions': ['shellExecution'],
            }]}],
            'total_ides': 1,
            'total_extensions': 1,
        },
    }
    if with_packages:
        payload['dependencies'] = {
            'timestamp': '2026-09-04T01:21:28Z',
            'packages': [{
                'name': 'rt-pkg', 'version': '9.9.9',
                'package_manager': 'npm', 'source_type': 'project',
            }],
            'package_managers_found': ['npm'],
        }
    return payload


class TestRealtimeEvent:
    def _post(self, portal_client, key, payload):
        return portal_client.post(
            '/api/realtime-event',
            headers={'X-Customer-Key': key},
            json=payload,
        )

    def test_event_with_packages_is_accepted(
        self, portal_app, portal_db, portal_client, test_customer_key, test_host
    ):
        """The regression: dependency data used to make this a 500."""
        resp = self._post(portal_client, test_customer_key.key,
                          _event(test_host.hostname))
        assert resp.status_code == 200, resp.get_data(as_text=True)
        assert resp.get_json()['received'] is True

    def test_event_without_packages_is_accepted(
        self, portal_app, portal_db, portal_client, test_customer_key, test_host
    ):
        resp = self._post(portal_client, test_customer_key.key,
                          _event(test_host.hostname, with_packages=False))
        assert resp.status_code == 200, resp.get_data(as_text=True)

    def test_package_is_linked_to_the_new_report(
        self, portal_app, portal_db, portal_client, test_customer_key, test_host
    ):
        """The package must point at a real report, not NULL and not id 1."""
        from app.models import PackageInfo, ScanReport
        self._post(portal_client, test_customer_key.key, _event(test_host.hostname))

        pkg = PackageInfo.query.filter_by(name='rt-pkg').one()
        assert pkg.scan_report_id is not None
        report = ScanReport.query.get(pkg.scan_report_id)
        assert report is not None, 'scan_report_id must reference a real report'
        assert report.host_id == test_host.id, 'and one belonging to this host'

    def test_event_stamps_last_realtime_event(
        self, portal_app, portal_db, portal_client, test_customer_key, test_host
    ):
        """Without this the host page can never show a live update."""
        from app.models import Host
        assert test_host.last_realtime_event is None
        self._post(portal_client, test_customer_key.key, _event(test_host.hostname))
        host = Host.query.filter_by(hostname=test_host.hostname).first()
        assert host.last_realtime_event is not None

    def test_hostname_is_required(
        self, portal_app, portal_db, portal_client, test_customer_key, test_host
    ):
        payload = _event(test_host.hostname)
        del payload['hostname']
        resp = self._post(portal_client, test_customer_key.key, payload)
        assert resp.status_code == 400
