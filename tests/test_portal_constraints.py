"""The database must reject what the application considers impossible.

Every constraint class introduced by the 0001_baseline squash gets a test that
tries to violate it. Before Phase 1 none of these were enforced: the VALID_*
tuples were advisory Python constants, 33 of 34 foreign keys had no ON DELETE
action, and the suite ran on SQLite, which ignores foreign keys entirely.

These tests exist so a future schema change cannot quietly relax a guarantee —
a constraint that stops being enforced fails here rather than in production.
"""

import uuid

import pytest
from sqlalchemy.exc import IntegrityError, InternalError

from app.models import (
    AuditLog, CustomerKey, EnforcementAction, Host, PackageInfo, ScanReport,
    User, Vulnerability, prune_host_scan_data,
)


@pytest.fixture
def two_tenants(portal_app, portal_db):
    """Two customer keys, one host each, plus a scan report for the first."""
    with portal_app.app_context():
        users, keys, hosts = [], [], []
        for i in (1, 2):
            u = User(email=f"t{i}@example.com", username=f"t{i}")
            u.set_password("x")
            portal_db.session.add(u)
            users.append(u)
        portal_db.session.flush()
        for i, u in enumerate(users, start=1):
            k = CustomerKey(key=str(uuid.uuid4()), name=f"K{i}", user_id=u.id)
            portal_db.session.add(k)
            keys.append(k)
        portal_db.session.flush()
        for i, k in enumerate(keys, start=1):
            h = Host(hostname=f"host{i}", customer_key_id=k.id)
            portal_db.session.add(h)
            hosts.append(h)
        portal_db.session.flush()
        report = ScanReport(host_id=hosts[0].id, scan_data={"a": 1})
        portal_db.session.add(report)
        portal_db.session.commit()
        yield {"users": users, "keys": keys, "hosts": hosts, "report": report}


def _rejects(db, obj):
    """Adding obj must fail; leave the session usable afterwards."""
    db.session.add(obj)
    with pytest.raises((IntegrityError, InternalError)):
        db.session.commit()
    db.session.rollback()


# ── vocabularies ───────────────────────────────────────────────────

class TestCheckConstraints:
    def test_rejects_role_outside_vocabulary(self, portal_db):
        u = User(email="bad@example.com", username="bad", role="superadmin")
        u.set_password("x")
        _rejects(portal_db, u)

    def test_rejects_misspelled_enforcement_status(self, portal_db, two_tenants):
        # 'aplied' would silently mean an extension was never quarantined.
        _rejects(portal_db, EnforcementAction(
            host_id=two_tenants["hosts"][0].id, extension_id="e",
            action="quarantine", status="aplied",
        ))

    def test_rejects_risk_score_out_of_range(self, portal_db, two_tenants):
        host = two_tenants["hosts"][0]
        host.risk_score = 250
        with pytest.raises((IntegrityError, InternalError)):
            portal_db.session.commit()
        portal_db.session.rollback()

    def test_accepts_valid_vocabulary(self, portal_db, two_tenants):
        portal_db.session.add(EnforcementAction(
            host_id=two_tenants["hosts"][0].id, extension_id="e",
            action="quarantine", status="pending",
        ))
        portal_db.session.commit()  # must not raise


# ── referential integrity ──────────────────────────────────────────

class TestForeignKeys:
    def test_rejects_orphan_scan_report(self, portal_db, two_tenants):
        _rejects(portal_db, ScanReport(
            host_id=two_tenants["hosts"][0].id + 10_000,
            customer_key_id=two_tenants["keys"][0].id,
            scan_data={},
        ))

    def test_host_delete_cascades(self, portal_app, portal_db, two_tenants):
        """Deleting a host used to fail outright with NotNullViolation."""
        host, other = two_tenants["hosts"][0], two_tenants["hosts"][1]
        portal_db.session.add(PackageInfo(
            host_id=host.id, scan_report_id=two_tenants["report"].id,
            name="left-pad", package_manager="npm",
        ))
        portal_db.session.commit()
        assert PackageInfo.query.count() == 1

        portal_db.session.delete(host)
        portal_db.session.commit()

        assert ScanReport.query.count() == 0
        assert PackageInfo.query.count() == 0
        assert Host.query.filter_by(id=other.id).count() == 1  # other tenant intact

    def test_deleting_user_with_keys_is_refused(self, portal_db, two_tenants):
        """RESTRICT: reassign or revoke the keys first, don't cascade a fleet away."""
        portal_db.session.delete(two_tenants["users"][1])
        with pytest.raises((IntegrityError, InternalError)):
            portal_db.session.commit()
        portal_db.session.rollback()


# ── tenant isolation ───────────────────────────────────────────────

class TestTenantIsolation:
    def test_rejects_row_whose_tenant_disagrees_with_its_host(self, portal_db, two_tenants):
        """The composite FK makes a cross-tenant row impossible, not merely unlikely."""
        _rejects(portal_db, PackageInfo(
            host_id=two_tenants["hosts"][0].id,               # tenant 1's host
            customer_key_id=two_tenants["keys"][1].id,        # tenant 2's key
            scan_report_id=two_tenants["report"].id,
            name="x", package_manager="npm",
        ))

    def test_tenant_is_backfilled_from_host(self, portal_db, two_tenants):
        """Callers may omit customer_key_id; it is derived on insert."""
        pkg = PackageInfo(
            host_id=two_tenants["hosts"][0].id,
            scan_report_id=two_tenants["report"].id,
            name="derived", package_manager="npm",
        )
        portal_db.session.add(pkg)
        portal_db.session.commit()
        assert pkg.customer_key_id == two_tenants["keys"][0].id


# ── idempotent ingestion ───────────────────────────────────────────

class TestUniqueness:
    def test_rejects_duplicate_package_for_host(self, portal_db, two_tenants):
        for _ in range(1):
            portal_db.session.add(PackageInfo(
                host_id=two_tenants["hosts"][0].id,
                scan_report_id=two_tenants["report"].id,
                name="left-pad", package_manager="npm", source_type="project",
            ))
        portal_db.session.commit()
        _rejects(portal_db, PackageInfo(
            host_id=two_tenants["hosts"][0].id,
            scan_report_id=two_tenants["report"].id,
            name="left-pad", package_manager="npm", source_type="project",
        ))

    def test_rejects_same_cve_twice_on_one_package(self, portal_db, two_tenants):
        common = dict(
            host_id=two_tenants["hosts"][0].id, package_name="left-pad",
            package_version="1.0", package_manager="npm", ecosystem="npm",
            vuln_id="CVE-2026-0001",
        )
        portal_db.session.add(Vulnerability(**common, severity_label="high"))
        portal_db.session.commit()
        _rejects(portal_db, Vulnerability(**common, severity_label="high"))


# ── append-only audit trail ────────────────────────────────────────

class TestAuditLogIsAppendOnly:
    def test_update_is_refused(self, portal_db):
        entry = AuditLog(actor="system", action="policy.create")
        portal_db.session.add(entry)
        portal_db.session.commit()

        entry.action = "tampered"
        with pytest.raises((IntegrityError, InternalError)):
            portal_db.session.commit()
        portal_db.session.rollback()

    def test_delete_is_refused(self, portal_db):
        entry = AuditLog(actor="system", action="policy.delete")
        portal_db.session.add(entry)
        portal_db.session.commit()

        portal_db.session.delete(entry)
        with pytest.raises((IntegrityError, InternalError)):
            portal_db.session.commit()
        portal_db.session.rollback()


# ── database-side defaults ─────────────────────────────────────────

class TestServerDefaults:
    def test_insert_bypassing_the_orm_gets_defaults(self, portal_db, two_tenants):
        """Migrations, bulk loads and psql don't run Python-side defaults."""
        from sqlalchemy import text

        key_id = two_tenants["keys"][0].id
        portal_db.session.execute(text(
            "INSERT INTO hosts (public_id, hostname, customer_key_id) "
            "VALUES (:p, :h, :k)"
        ), {"p": str(uuid.uuid4()), "h": "raw-insert", "k": key_id})
        portal_db.session.commit()

        host = Host.query.filter_by(hostname="raw-insert").one()
        assert host.heartbeat_alarm_state == "ok"
        assert host.is_active is True
        assert host.first_seen_at is not None
        assert host.first_seen_at.tzinfo is not None  # timestamptz, not naive


# ── retention ──────────────────────────────────────────────────────

class TestScanDataRetention:
    def test_only_the_newest_report_keeps_its_payload(self, portal_db, two_tenants):
        host = two_tenants["hosts"][0]
        older = two_tenants["report"]
        newer = ScanReport(host_id=host.id, scan_data={"b": 2}, total_extensions=7)
        portal_db.session.add(newer)
        portal_db.session.flush()

        pruned = prune_host_scan_data(host.id, newer.id)
        portal_db.session.commit()

        assert pruned == 1
        portal_db.session.refresh(older)
        assert older.scan_data is None            # blob dropped
        assert older.total_extensions is not None  # summary retained
        assert newer.scan_data == {"b": 2}

    def test_other_hosts_are_untouched(self, portal_db, two_tenants):
        other_host = two_tenants["hosts"][1]
        theirs = ScanReport(host_id=other_host.id, scan_data={"keep": True})
        portal_db.session.add(theirs)
        portal_db.session.commit()

        mine = ScanReport(host_id=two_tenants["hosts"][0].id, scan_data={"c": 3})
        portal_db.session.add(mine)
        portal_db.session.flush()
        prune_host_scan_data(two_tenants["hosts"][0].id, mine.id)
        portal_db.session.commit()

        portal_db.session.refresh(theirs)
        assert theirs.scan_data == {"keep": True}
