"""Tests for the observability thin slice (T4.3): JSON logging + /metrics."""
import json
import logging
from io import StringIO

import pytest


class TestMetricsEndpoint:
    def test_metrics_responds_with_prometheus_content_type(self, portal_client):
        resp = portal_client.get('/metrics')
        assert resp.status_code == 200
        assert resp.content_type.startswith('text/plain')

    def test_metrics_exposes_all_four_counters(self, portal_client):
        resp = portal_client.get('/metrics')
        body = resp.data.decode('utf-8')
        # Counter names use the prefix declared in observability.py.
        assert 'ideviewer_webhook_deliveries_total' in body
        assert 'ideviewer_policy_violations_total' in body
        assert 'ideviewer_rq_jobs_total' in body
        assert 'ideviewer_extension_enrichments_total' in body

    def test_counter_increment_reflected_in_metrics(self, portal_client):
        from app.observability import WEBHOOK_DELIVERIES

        WEBHOOK_DELIVERIES.labels(status='succeeded').inc()
        resp = portal_client.get('/metrics')
        body = resp.data.decode('utf-8')
        # Find any non-zero "succeeded" line.
        succeeded_lines = [
            line for line in body.splitlines()
            if 'ideviewer_webhook_deliveries_total' in line
            and 'status="succeeded"' in line
            and not line.startswith('#')
        ]
        assert succeeded_lines, "no succeeded label found"
        # The value is the last whitespace-separated token.
        values = [float(line.rsplit(' ', 1)[-1]) for line in succeeded_lines]
        assert max(values) >= 1.0

    def test_metrics_requires_bearer_when_METRICS_TOKEN_set(
        self, portal_client, monkeypatch
    ):
        monkeypatch.setenv('METRICS_TOKEN', 'secret-scrape-token')
        # No header -> 401.
        resp = portal_client.get('/metrics')
        assert resp.status_code == 401
        # Wrong token -> 401.
        resp = portal_client.get('/metrics', headers={'Authorization': 'Bearer nope'})
        assert resp.status_code == 401
        # Correct token -> 200.
        resp = portal_client.get(
            '/metrics',
            headers={'Authorization': 'Bearer secret-scrape-token'},
        )
        assert resp.status_code == 200


class TestJSONLogging:
    def test_init_skipped_when_not_production(self, portal_app):
        from app.observability import init_json_logging

        # portal_app fixture uses 'testing' config — must NOT install JSON formatter.
        root = logging.getLogger()
        before = list(root.handlers)
        init_json_logging(portal_app)
        assert list(root.handlers) == before

    def test_init_installs_json_formatter_when_production(self):
        """Verify the JSON formatter shape against a Flask app set to production.

        We don't go through create_app to avoid side effects (DB init,
        OAuth, etc.); we just synthesize the minimum app surface
        init_json_logging needs.
        """
        from flask import Flask
        from app.observability import init_json_logging

        app = Flask(__name__)
        app.config['FLASK_CONFIG'] = 'production'

        try:
            init_json_logging(app)
            # Capture output by attaching our own StringIO StreamHandler
            # using the same JSON formatter installed on root.
            root = logging.getLogger()
            assert root.handlers, "init_json_logging should have added a handler"
            installed_formatter = root.handlers[0].formatter

            buf = StringIO()
            test_handler = logging.StreamHandler(buf)
            test_handler.setFormatter(installed_formatter)
            test_logger = logging.getLogger('test.observability.shape')
            test_logger.addHandler(test_handler)
            test_logger.setLevel(logging.INFO)
            try:
                test_logger.info('hello world', extra={'event_id': 'evt_abc'})
                line = buf.getvalue().strip()
                parsed = json.loads(line)
                assert parsed['level'] == 'INFO'
                assert parsed['message'] == 'hello world'
                assert parsed['event_id'] == 'evt_abc'
                assert 'timestamp' in parsed
            finally:
                test_logger.removeHandler(test_handler)
        finally:
            # Restore plain logging so subsequent tests aren't affected.
            for h in list(logging.getLogger().handlers):
                logging.getLogger().removeHandler(h)
            logging.basicConfig(level=logging.WARNING)
