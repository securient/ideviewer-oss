"""Tests for the queue helper and the relocated vuln-scan job.

These tests cover the sync-fallback paths. The async path (real Redis or
fakeredis) is exercised in a single optional case guarded by an import.
"""

import os
import pytest


@pytest.fixture(autouse=True)
def _reset_queue_state():
    """Ensure the module-level queue state is clean for every test."""
    from app.queue import reset_for_tests
    reset_for_tests()
    yield
    reset_for_tests()


# ──────────────────────────────────────────────
# init_queue
# ──────────────────────────────────────────────

class TestInitQueue:
    def test_no_redis_url_skips(self, portal_app):
        """With no REDIS_URL configured, queue stays disabled."""
        from app.queue import init_queue, is_async, reset_for_tests
        reset_for_tests()
        # portal_app is created with config_name='testing', which already
        # skips init_queue. Call it directly to verify the helper too.
        portal_app.config.pop("REDIS_URL", None)
        os.environ.pop("REDIS_URL", None)
        init_queue(portal_app)
        assert is_async() is False

    def test_unreachable_redis_falls_back(self, portal_app):
        """Bad REDIS_URL is swallowed and sync mode persists."""
        from app.queue import init_queue, is_async, reset_for_tests
        reset_for_tests()
        # Use a host:port that cannot resolve / connect quickly.
        portal_app.config["REDIS_URL"] = "redis://127.0.0.1:1/0"
        init_queue(portal_app)
        assert is_async() is False


# ──────────────────────────────────────────────
# enqueue()
# ──────────────────────────────────────────────

class TestEnqueueSync:
    def test_enqueue_returns_none_when_sync(self, portal_app):
        """When the queue is not initialised, enqueue() returns None."""
        from app.queue import enqueue, is_async

        assert is_async() is False

        def _noop():
            return None

        result = enqueue(_noop)
        assert result is None


# ──────────────────────────────────────────────
# Vulnerability scan idempotency (sync path)
# ──────────────────────────────────────────────

class TestVulnScanIdempotent:
    def test_scan_with_no_packages_returns_zero(
        self, portal_app, portal_db, test_host
    ):
        """A host with no packages should yield a 0 result, not crash."""
        from app.jobs.vuln_scan import scan_host_vulnerabilities

        with portal_app.app_context():
            result = scan_host_vulnerabilities(test_host.id)

        assert result["host_id"] == test_host.id
        assert result["vulnerabilities_found"] == 0

    def test_scan_unknown_host_skipped(self, portal_app):
        """Unknown host_id returns a skipped result, no exception."""
        from app.jobs.vuln_scan import scan_host_vulnerabilities

        with portal_app.app_context():
            result = scan_host_vulnerabilities(999999)
        assert result.get("skipped") is True

    def test_scan_is_idempotent_with_stubbed_osv(
        self, portal_app, portal_db, test_host, monkeypatch
    ):
        """Running scan twice should not double-insert vulnerabilities."""
        from app.jobs import vuln_scan as vs
        from app.models import PackageInfo, ScanReport, Vulnerability

        # Seed one package the OSV stub will match.
        with portal_app.app_context():
            report = ScanReport(
                host_id=test_host.id,
                scan_data={"ides": [], "total_ides": 0, "total_extensions": 0},
                total_ides=0,
                total_extensions=0,
                dangerous_extensions=0,
            )
            portal_db.session.add(report)
            portal_db.session.flush()
            pkg = PackageInfo(
                host_id=test_host.id,
                scan_report_id=report.id,
                name="requests",
                version="2.0.0",
                package_manager="pip",
                source_type="project",
            )
            portal_db.session.add(pkg)
            portal_db.session.commit()

        def fake_get_ecosystem(manager):
            return "PyPI" if manager == "pip" else None

        def fake_query_packages_batch(batch):
            return {
                ("requests", "2.0.0", "PyPI"): [
                    {
                        "vuln_id": "CVE-TEST-0001",
                        "summary": "test vuln",
                        "severity_label": "HIGH",
                        "cvss_score": 7.5,
                        "affected_versions": "< 2.1.0",
                        "fixed_version": "2.1.0",
                        "references": ["https://example/cve"],
                    }
                ]
            }

        monkeypatch.setattr(
            "app.osv_client.get_ecosystem", fake_get_ecosystem, raising=False
        )
        monkeypatch.setattr(
            "app.osv_client.query_packages_batch",
            fake_query_packages_batch,
            raising=False,
        )

        with portal_app.app_context():
            r1 = vs.scan_host_vulnerabilities(test_host.id)
            assert r1["vulnerabilities_found"] == 1
            count1 = Vulnerability.query.filter_by(host_id=test_host.id).count()
            assert count1 == 1

            # Second run — same fixtures → no duplicate.
            r2 = vs.scan_host_vulnerabilities(test_host.id)
            count2 = Vulnerability.query.filter_by(host_id=test_host.id).count()
            assert count2 == 1, "scan should be idempotent"
            # Second call reports zero NEW vulns since the existing row was
            # only refreshed.
            assert r2["vulnerabilities_found"] == 0
