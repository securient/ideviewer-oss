"""Timestamps rendered for the browser must be parseable by ``new Date()``.

Every DateTime column is ``timestamptz``, so SQLAlchemy hands back aware
datetimes and ``isoformat()`` already carries a ``+00:00`` offset. Templates
used to append a literal 'Z' on top of that, producing ``...+00:00Z`` -- two
timezone designators, which ``new Date()`` rejects. The host page then showed
"Last seen: Invalid Date" and "Token: Issued - Invalid Date".
"""
import re
from datetime import datetime, timezone, timedelta

import pytest


# Mirrors what the browser accepts: an ISO-8601 instant with exactly one
# timezone designator -- either 'Z' or a numeric offset, never both.
_VALID_INSTANT = re.compile(
    r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$'
)


class TestUtcIsoFilter:
    def _render(self, portal_app, value):
        with portal_app.app_context():
            return portal_app.jinja_env.from_string(
                '{{ v | utc_iso }}'
            ).render(v=value)

    def test_aware_utc_emits_single_designator(self, portal_app):
        out = self._render(portal_app, datetime(2026, 9, 3, 22, 12, 48, tzinfo=timezone.utc))
        assert out == '2026-09-03T22:12:48Z'
        assert _VALID_INSTANT.match(out)
        assert '+00:00Z' not in out

    def test_naive_is_treated_as_utc(self, portal_app):
        out = self._render(portal_app, datetime(2026, 9, 3, 22, 12, 48))
        assert out == '2026-09-03T22:12:48Z'

    def test_non_utc_offset_is_converted_not_relabelled(self, portal_app):
        """A -07:00 value must shift to UTC, not just get stamped with 'Z'."""
        aware = datetime(2026, 9, 3, 15, 12, 48, tzinfo=timezone(timedelta(hours=-7)))
        assert self._render(portal_app, aware) == '2026-09-03T22:12:48Z'

    def test_none_renders_empty(self, portal_app):
        # The template JS guards on a falsy data-utc, so None must stay empty
        # rather than becoming the string 'None'.
        assert self._render(portal_app, None) == ''


class TestRenderedPages:
    """The real templates must not emit a double-suffixed timestamp."""

    LAST_SEEN = datetime(2026, 9, 3, 22, 12, 48, tzinfo=timezone.utc)

    @staticmethod
    def _prepare(portal_db, hostname, last_seen, with_token=False):
        """Stamp the host and return its public_id.

        Deliberately no nested ``app_context``: the ``portal_app`` fixture keeps
        one pushed for the whole test and the test client's request reuses it,
        so the session here is the same one the view will read from. Mutating
        inside a nested context would commit to a *different* session, leaving
        the view to re-render its own stale copy from the identity map.
        """
        from app.models import Host
        host = Host.query.filter_by(hostname=hostname).first()
        host.last_seen_at = last_seen
        if with_token:
            host.issue_token()  # sets token_hash + token_issued_at
        portal_db.session.commit()
        return host.public_id

    @pytest.mark.parametrize('path', ['/dashboard', '/hosts', '/audit'])
    def test_listing_pages_emit_parseable_timestamps(
        self, portal_app, portal_db, logged_in_client, test_host, path
    ):
        self._prepare(portal_db, test_host.hostname, self.LAST_SEEN)
        html = logged_in_client.get(path).get_data(as_text=True)
        self._assert_all_parseable(html)

    def test_host_detail_heartbeat_and_token_issued(
        self, portal_app, portal_db, logged_in_client, test_host
    ):
        """The header renders last_heartbeat_at and the token stamp.

        It deliberately no longer shows last_seen_at: liveness now comes from
        the heartbeat and the scan time from the report, so last_seen_at is not
        displayed at all.
        """
        from app.models import Host
        host = Host.query.filter_by(hostname=test_host.hostname).first()
        host.last_heartbeat_at = self.LAST_SEEN
        host.issue_token()  # sets token_hash + token_issued_at
        portal_db.session.commit()

        html = logged_in_client.get(f'/host/{host.public_id}').get_data(as_text=True)

        stamps = self._assert_all_parseable(html)
        assert '2026-09-03T22:12:48Z' in stamps, f'heartbeat missing from {stamps}'
        # The "Token: Issued" stamp is the other one.
        assert len(stamps) >= 2, f'expected heartbeat and token_issued, got {stamps}'

    @staticmethod
    def _assert_all_parseable(html):
        stamps = [s for s in re.findall(r'data-utc="([^"]*)"', html) if s]
        for s in stamps:
            assert '+00:00Z' not in s, f'double timezone designator: {s!r}'
            assert _VALID_INSTANT.match(s), f'unparseable by new Date(): {s!r}'
        return stamps


class TestHostDetailLiveness:
    """The host header must separate daemon liveness from last scan.

    These were conflated under a single "Last seen" label reading
    ``last_seen_at``. Heartbeats write ``last_heartbeat_at`` and deliberately
    leave ``last_seen_at`` alone, so a live daemon with nothing new to report
    looked stale and was indistinguishable from a dead one.
    """

    @staticmethod
    def _host(portal_db, hostname):
        from app.models import Host
        return Host.query.filter_by(hostname=hostname).first()

    def _render(self, portal_db, logged_in_client, host):
        portal_db.session.commit()
        return logged_in_client.get(f'/host/{host.public_id}').get_data(as_text=True)

    @pytest.mark.parametrize('minutes,expected', [
        (1, 'Online'),
        (10, 'Idle'),
        (120, 'Offline'),
    ])
    def test_liveness_follows_heartbeat(
        self, portal_app, portal_db, logged_in_client, test_host, minutes, expected
    ):
        from app.models import utcnow
        host = self._host(portal_db, test_host.hostname)
        host.last_heartbeat_at = utcnow() - timedelta(minutes=minutes)
        html = self._render(portal_db, logged_in_client, host)
        # Assert on the dot's title attribute specifically -- a bare substring
        # check would pass on the word appearing anywhere on the page.
        assert f'title="{expected}"' in html, f'expected the {expected} dot'

    def test_stale_last_seen_does_not_mark_a_live_host_offline(
        self, portal_app, portal_db, logged_in_client, test_host
    ):
        """The regression: heartbeat current, last_seen_at hours old."""
        from app.models import utcnow
        host = self._host(portal_db, test_host.hostname)
        host.last_heartbeat_at = utcnow() - timedelta(seconds=30)
        host.last_seen_at = utcnow() - timedelta(hours=3)
        html = self._render(portal_db, logged_in_client, host)
        assert 'Online' in html
        assert 'Offline' not in html

    def test_last_scan_comes_from_the_report_not_last_seen(
        self, portal_app, portal_db, logged_in_client, test_host
    ):
        """"Last scan" must be the report's own timestamp.

        ``last_seen_at`` is bumped by registration and realtime events too, so
        it is not a truthful stand-in for when the scan actually landed.
        """
        from app.models import ScanReport
        host = self._host(portal_db, test_host.hostname)
        scanned_at = datetime(2026, 9, 3, 22, 12, 48, tzinfo=timezone.utc)
        report = ScanReport(
            host_id=host.id,
            customer_key_id=host.customer_key_id,
            scan_data={'ides': []},
            total_ides=0,
            total_extensions=0,
        )
        portal_db.session.add(report)
        portal_db.session.commit()
        report.created_at = scanned_at          # server_default fires on insert
        host.last_seen_at = datetime(2026, 9, 3, 23, 59, 59, tzinfo=timezone.utc)
        html = self._render(portal_db, logged_in_client, host)

        assert 'Last scan' in html
        assert '2026-09-03T22:12:48Z' in html, 'Last scan should be the report timestamp'
        assert '2026-09-03T23:59:59Z' not in html, 'last_seen_at must not be shown as the scan time'

    def test_host_with_no_report_renders_never(
        self, portal_app, portal_db, logged_in_client, test_host
    ):
        host = self._host(portal_db, test_host.hostname)
        html = self._render(portal_db, logged_in_client, host)
        assert 'Last scan:' in html
        assert 'Never' in html
