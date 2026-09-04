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


class TestRealtimeFullInventory:
    """The watcher now covers projects and AI-tool config, not just extensions.

    Those categories arrive on the same endpoint, so it has to persist secrets
    and AI tools / MCP servers rather than ignore them — previously a lockfile
    or MCP change could never be recorded in real time at all.
    """

    def _post(self, portal_client, key, payload):
        return portal_client.post(
            '/api/realtime-event',
            headers={'X-Customer-Key': key},
            json=payload,
        )

    def _base(self, hostname, category):
        return {
            'hostname': hostname,
            'platform': 'darwin arm64',
            'event_type': 'workstation_change',
            'categories': [category],
            'timestamp': '2026-09-04T01:21:28Z',
            'changes': [{
                'path': '/Users/dev/project/.env',
                'event_type': 'created',
                'category': category,
                'timestamp': '2026-09-04T01:21:28Z',
            }],
        }

    def test_secrets_are_recorded(
        self, portal_app, portal_db, portal_client, test_customer_key, test_host, test_scan_report
    ):
        from app.models import SecretFinding
        payload = self._base(test_host.hostname, 'projects')
        payload['secrets'] = {'findings': [{
            'file_path': '/Users/dev/project/.env',
            'variable_name': 'AWS_SECRET_ACCESS_KEY',
            'secret_type': 'aws_key',
            'severity': 'critical',
            'redacted_value': 'AKIA****',
        }]}

        resp = self._post(portal_client, test_customer_key.key, payload)
        assert resp.status_code == 200, resp.get_data(as_text=True)

        finding = SecretFinding.query.filter_by(host_id=test_host.id).one()
        assert finding.variable_name == 'AWS_SECRET_ACCESS_KEY'
        assert finding.severity == 'critical'
        assert finding.scan_report_id is not None

    def test_ai_tools_and_mcp_servers_are_recorded(
        self, portal_app, portal_db, portal_client, test_customer_key, test_host, test_scan_report
    ):
        from app.models import AIToolInfo
        payload = self._base(test_host.hostname, 'aitools')
        payload['ai_tools'] = {'ai_tools': [{
            'name': 'Claude Code',
            'version': '1.0.0',
            'is_running': True,
            'config_path': '/Users/dev/.claude/settings.json',
            'components': [{'name': 'evil-mcp', 'command': 'node evil.js'}],
        }]}

        resp = self._post(portal_client, test_customer_key.key, payload)
        assert resp.status_code == 200, resp.get_data(as_text=True)

        tool = AIToolInfo.query.filter_by(host_id=test_host.id).one()
        assert tool.tool_name == 'Claude Code'
        assert tool.mcp_servers[0]['name'] == 'evil-mcp'

    def test_secrets_without_any_report_do_not_error(
        self, portal_app, portal_db, portal_client, test_customer_key, test_host
    ):
        """A host that has never reported has no row for findings to hang off.

        Skipping beats a 500: the next periodic scan records them anyway.
        """
        payload = self._base(test_host.hostname, 'projects')
        payload['secrets'] = {'findings': [{
            'file_path': '/x/.env', 'variable_name': 'K', 'severity': 'critical',
        }]}
        resp = self._post(portal_client, test_customer_key.key, payload)
        assert resp.status_code == 200, resp.get_data(as_text=True)

    def test_absent_sections_leave_existing_inventory_alone(
        self, portal_app, portal_db, portal_client, test_customer_key, test_host, test_scan_report
    ):
        """An extensions-only event must not retire secrets or AI tools.

        Both helpers delete what is missing from their payload, so they may only
        run for a category the daemon actually rescanned.
        """
        from app.models import SecretFinding
        seeded = self._base(test_host.hostname, 'projects')
        seeded['secrets'] = {'findings': [{
            'file_path': '/Users/dev/project/.env',
            'variable_name': 'TOKEN', 'severity': 'critical',
        }]}
        self._post(portal_client, test_customer_key.key, seeded)
        assert SecretFinding.query.filter_by(host_id=test_host.id, is_resolved=False).count() == 1

        # An extension-only event carries no 'secrets' key at all.
        ext_only = self._base(test_host.hostname, 'extensions')
        resp = self._post(portal_client, test_customer_key.key, ext_only)
        assert resp.status_code == 200

        still_open = SecretFinding.query.filter_by(host_id=test_host.id, is_resolved=False).count()
        assert still_open == 1, 'an unrelated category must not resolve secrets'
