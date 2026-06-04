"""Tests for the extension metadata enrichment worker (T2.3)."""
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def fresh_meta(portal_app, portal_db):
    """Insert one ExtensionMetadata row representing a previously-known
    extension that is still in the marketplace.
    """
    from app.models import ExtensionMetadata
    with portal_app.app_context():
        row = ExtensionMetadata(
            marketplace='vscode',
            extension_id='pub.ext',
            version='1.0.0',
            publisher_display_name='Pub',
            install_count=100,
            average_rating=4.5,
            is_unpublished=False,
            fetched_at=datetime.utcnow(),
            last_fetch_status=200,
            raw_data={'name': 'Ext'},
        )
        portal_db.session.add(row)
        portal_db.session.commit()
        yield ExtensionMetadata.query.first()


class TestEnrichWorker:
    def test_first_fetch_creates_row(self, portal_app, portal_db):
        from app.jobs.extension_enrich import enrich_extension
        from app.models import ExtensionMetadata
        with portal_app.app_context():
            with patch(
                'app.jobs.extension_enrich.fetch_extension_with_status',
                return_value=({'publisher': 'new-pub', 'installs': 500, 'rating': 4.2}, 200),
            ):
                result = enrich_extension('vscode', 'new-pub.thing', '0.1.0')

            row = ExtensionMetadata.query.filter_by(extension_id='new-pub.thing').first()
            assert row is not None
            assert row.publisher_display_name == 'new-pub'
            assert row.install_count == 500
            assert row.is_unpublished is False
            assert result['is_new'] is True

    def test_idempotent_on_repeat(self, portal_app, portal_db):
        from app.jobs.extension_enrich import enrich_extension
        from app.models import ExtensionMetadata
        with portal_app.app_context():
            with patch(
                'app.jobs.extension_enrich.fetch_extension_with_status',
                return_value=({'publisher': 'p', 'installs': 10}, 200),
            ):
                enrich_extension('vscode', 'p.ext', '1.0')
                enrich_extension('vscode', 'p.ext', '1.0')
            assert ExtensionMetadata.query.filter_by(extension_id='p.ext').count() == 1

    def test_404_marks_unpublished_and_fires_event_once(
        self, portal_app, portal_db, fresh_meta, test_host
    ):
        """The False -> True transition must fire exactly one event.
        A second 404 against the same row must NOT re-fire.
        """
        from app.jobs.extension_enrich import enrich_extension
        from app.models import ScanReport
        # Stage a scan_data on the test host that references the
        # extension so the affected_hosts lookup finds someone.
        with portal_app.app_context():
            report = ScanReport(
                host_id=test_host.id,
                scan_data={
                    'ides': [{
                        'name': 'VS Code',
                        'extensions': [{'id': 'pub.ext', 'version': '1.0.0'}],
                    }]
                },
                total_ides=1,
                total_extensions=1,
            )
            portal_db.session.add(report)
            portal_db.session.commit()

            with patch(
                'app.jobs.extension_enrich.fetch_extension_with_status',
                return_value=(None, 404),
            ), patch('app.jobs.extension_enrich.emit_event') as emit:
                enrich_extension('vscode', 'pub.ext', '1.0.0')
                first_call_count = emit.call_count
                # Second poll: same 404, already unpublished — must not fire again.
                enrich_extension('vscode', 'pub.ext', '1.0.0')

            assert first_call_count == 1, "first transition must fire one event"
            assert emit.call_count == 1, "second poll must NOT re-fire"
            args, kwargs = emit.call_args
            assert args[0] == 'extension.unpublished_detected'

    def test_transient_failure_leaves_previous_state(
        self, portal_app, portal_db, fresh_meta
    ):
        from app.jobs.extension_enrich import enrich_extension
        from app.models import ExtensionMetadata
        with portal_app.app_context():
            with patch(
                'app.jobs.extension_enrich.fetch_extension_with_status',
                return_value=(None, None),  # network error
            ):
                enrich_extension('vscode', 'pub.ext', '1.0.0')
            row = ExtensionMetadata.query.first()
            assert row.is_unpublished is False
            assert row.publisher_display_name == 'Pub'  # untouched
            assert row.last_fetch_status is None

    def test_recovery_clears_unpublished_flag(self, portal_app, portal_db):
        """If an extension was marked unpublished and then returns, the
        flag clears and the detected_at timestamp resets.
        """
        from app.jobs.extension_enrich import enrich_extension
        from app.models import ExtensionMetadata
        with portal_app.app_context():
            row = ExtensionMetadata(
                marketplace='vscode',
                extension_id='gone.then.back',
                version='2.0',
                is_unpublished=True,
                unpublished_detected_at=datetime.utcnow() - timedelta(days=2),
                fetched_at=datetime.utcnow() - timedelta(days=2),
            )
            portal_db.session.add(row)
            portal_db.session.commit()

            with patch(
                'app.jobs.extension_enrich.fetch_extension_with_status',
                return_value=({'publisher': 'p', 'installs': 50}, 200),
            ):
                enrich_extension('vscode', 'gone.then.back', '2.0')

            row = ExtensionMetadata.query.first()
            assert row.is_unpublished is False
            assert row.unpublished_detected_at is None


class TestEnqueuePendingEnrichments:
    def test_dedupes_within_scan(self, portal_app, portal_db):
        from app.jobs.extension_enrich import enqueue_pending_enrichments
        scan_data = {
            'ides': [
                {'name': 'VS Code', 'extensions': [
                    {'id': 'a.b', 'version': '1.0'},
                    {'id': 'c.d', 'version': '2.0'},
                ]},
                {'name': 'VS Code', 'extensions': [
                    {'id': 'a.b', 'version': '1.0'},  # duplicate
                ]},
            ]
        }
        with portal_app.app_context():
            with patch('app.jobs.extension_enrich.enqueue') as mock_enqueue:
                mock_enqueue.return_value = MagicMock()
                count = enqueue_pending_enrichments(scan_data)
            assert count == 2  # a.b and c.d, not a.b twice

    def test_skips_fresh_cache_rows(self, portal_app, portal_db, fresh_meta):
        from app.jobs.extension_enrich import enqueue_pending_enrichments
        scan_data = {
            'ides': [{'name': 'VS Code', 'extensions': [
                {'id': 'pub.ext', 'version': '1.0.0'},  # cached row is fresh
                {'id': 'other.ext', 'version': '1.0'},
            ]}]
        }
        with portal_app.app_context():
            with patch('app.jobs.extension_enrich.enqueue') as mock_enqueue:
                mock_enqueue.return_value = MagicMock()
                count = enqueue_pending_enrichments(scan_data)
            assert count == 1  # only other.ext, pub.ext is fresh

    def test_enqueues_stale_cache_rows(self, portal_app, portal_db):
        from app.jobs.extension_enrich import enqueue_pending_enrichments
        from app.models import ExtensionMetadata
        with portal_app.app_context():
            stale = ExtensionMetadata(
                marketplace='vscode',
                extension_id='stale.ext',
                version='1.0',
                fetched_at=datetime.utcnow() - timedelta(hours=25),
            )
            portal_db.session.add(stale)
            portal_db.session.commit()

            scan_data = {'ides': [{'name': 'VS Code', 'extensions': [
                {'id': 'stale.ext', 'version': '1.0'},
            ]}]}
            with patch('app.jobs.extension_enrich.enqueue') as mock_enqueue:
                mock_enqueue.return_value = MagicMock()
                count = enqueue_pending_enrichments(scan_data)
            assert count == 1


class TestRefreshJob:
    def test_enqueues_only_stale_rows(self, portal_app, portal_db):
        from app.jobs.extension_refresh import refresh_stale_extension_metadata
        from app.models import ExtensionMetadata
        with portal_app.app_context():
            fresh = ExtensionMetadata(
                marketplace='vscode', extension_id='f.x', version='1',
                fetched_at=datetime.utcnow() - timedelta(hours=1),
            )
            stale1 = ExtensionMetadata(
                marketplace='vscode', extension_id='s1.x', version='1',
                fetched_at=datetime.utcnow() - timedelta(hours=25),
            )
            stale2 = ExtensionMetadata(
                marketplace='jetbrains', extension_id='s2.x', version='1',
                fetched_at=datetime.utcnow() - timedelta(days=3),
            )
            portal_db.session.add_all([fresh, stale1, stale2])
            portal_db.session.commit()

            with patch('app.jobs.extension_refresh.enqueue') as mock_enqueue:
                mock_enqueue.return_value = MagicMock()
                result = refresh_stale_extension_metadata()

            assert result == {'stale_rows': 2, 'enqueued': 2}
            assert mock_enqueue.call_count == 2


class TestMarketplaceClient:
    def test_detect_marketplace_jetbrains(self):
        from app.marketplace import detect_marketplace
        assert detect_marketplace(ide_name='PyCharm') == 'jetbrains'
        assert detect_marketplace(ide_name='IntelliJ', ide_type='jetbrains-ide') == 'jetbrains'

    def test_detect_marketplace_vscodium(self):
        from app.marketplace import detect_marketplace
        assert detect_marketplace(ide_type='vscodium-editor') == 'vscodium'

    def test_detect_marketplace_cursor(self):
        from app.marketplace import detect_marketplace
        assert detect_marketplace(ide_name='Cursor') == 'cursor'

    def test_detect_marketplace_default_vscode(self):
        from app.marketplace import detect_marketplace
        assert detect_marketplace(ide_name='VS Code') == 'vscode'
        assert detect_marketplace() == 'vscode'

    def test_last_status_code_tracked_on_success(self, portal_app):
        from app.marketplace import MarketplaceClient
        from unittest.mock import patch, MagicMock
        with portal_app.app_context():
            c = MarketplaceClient()
            mock_resp = MagicMock()
            mock_resp.read.return_value = b'{"ok": true}'
            mock_resp.status = 200
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = lambda s, *a: None
            with patch('app.marketplace.urlopen', return_value=mock_resp):
                c._make_request('https://example.test/')
            assert c.last_status_code == 200

    def test_last_status_code_tracked_on_http_error(self, portal_app):
        from app.marketplace import MarketplaceClient
        from urllib.error import HTTPError
        from unittest.mock import patch
        with portal_app.app_context():
            c = MarketplaceClient()
            err = HTTPError('url', 404, 'Not Found', {}, None)
            with patch('app.marketplace.urlopen', side_effect=err):
                c._make_request('https://example.test/')
            assert c.last_status_code == 404
