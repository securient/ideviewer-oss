"""
Shared test fixtures for IDEViewer portal tests.

The suite runs against a real PostgreSQL server — the engine the portal ships
on. It used to run on in-memory SQLite, which meant two things went untested:
the production engine (SQLite silently disables foreign-key enforcement, so no
FK in the schema was ever checked) and the migration chain itself, because the
fixture built its schema with ``create_all()`` instead of ``upgrade()``.

Point the suite at a server with ``TEST_DATABASE_URL``, or let it derive a
throwaway database from ``DATABASE_URL`` — see ``_resolve_test_url``.
"""

import os
import sys
import uuid
import pytest
from datetime import datetime
from pathlib import Path

PORTAL_DIR = Path(__file__).resolve().parent.parent / "portal"

# Ensure the portal package is importable
sys.path.insert(0, str(PORTAL_DIR))


# ──────────────────────────────────────────────
# Test database plumbing
# ──────────────────────────────────────────────

def _resolve_test_url():
    """Return the SQLAlchemy URL of the database the suite may destroy.

    ``TEST_DATABASE_URL`` is taken at face value. Otherwise a database name is
    derived from ``DATABASE_URL`` by appending ``_test``, so a developer whose
    DATABASE_URL points at their real portal database gets a separate scratch
    database rather than a truncated one.
    """
    from sqlalchemy.engine import make_url
    from config import normalize_database_url

    explicit = os.environ.get("TEST_DATABASE_URL")
    if explicit:
        return make_url(normalize_database_url(explicit))

    base = os.environ.get("DATABASE_URL")
    if not base:
        pytest.exit(
            "The portal test suite needs PostgreSQL. Set TEST_DATABASE_URL "
            "(or DATABASE_URL, from which a '<name>_test' database is "
            "derived), e.g. "
            "TEST_DATABASE_URL=postgresql://ideviewer:PASSWORD@localhost:5432/ideviewer_test",
            returncode=1,
        )

    url = make_url(normalize_database_url(base))
    return url.set(database=f"{url.database}_test")


def _ensure_database(url):
    """Create the test database if it does not exist yet."""
    import psycopg2
    from psycopg2 import sql

    admin_dsn = url.set(database="postgres").render_as_string(hide_password=False)
    try:
        conn = psycopg2.connect(admin_dsn)
    except psycopg2.OperationalError as exc:
        pytest.exit(
            f"Could not reach PostgreSQL at {url.host}:{url.port or 5432} — {exc}\n"
            "Start one with ./start.sh, or `docker run -d --name ideviewer-postgres "
            "-e POSTGRES_USER=ideviewer -e POSTGRES_PASSWORD=ideviewer_dev_password "
            "-e POSTGRES_DB=ideviewer -p 5432:5432 postgres:15-alpine`.",
            returncode=1,
        )

    conn.autocommit = True
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_database WHERE datname = %s", (url.database,))
            if cur.fetchone() is None:
                cur.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(url.database)))
    finally:
        conn.close()


def pytest_configure(config):
    """Provision the test database before anything imports the app package.

    ``config.py`` binds SQLALCHEMY_DATABASE_URI at class-definition time, so
    TEST_DATABASE_URL has to be in the environment before the app pulls config
    in. Doing this in a hook rather than a fixture guarantees the ordering
    regardless of what a test module imports at module scope.
    """
    import importlib

    url = _resolve_test_url()
    _ensure_database(url)

    os.environ["TEST_DATABASE_URL"] = url.render_as_string(hide_password=False)
    os.environ.pop("FLASK_CONFIG", None)
    os.environ.setdefault("SECRET_KEY", "test-secret-key")
    # The app factory must not migrate or seed: portal_schema owns schema
    # setup, and per-test truncation would otherwise fight the default-user
    # insert on every single test.
    os.environ["SKIP_DB_INIT"] = "1"

    # _resolve_test_url imported config to normalise the URL, which bound the
    # URIs against an incomplete environment. Rebind now that it's complete.
    import config as config_module
    importlib.reload(config_module)


@pytest.fixture(scope="session")
def portal_schema():
    """Drop and rebuild the test schema by running the real Alembic chain.

    Running ``upgrade()`` rather than ``create_all()`` is the point: a broken
    or missing migration fails the suite here instead of passing CI and then
    failing on a real deployment.
    """
    from sqlalchemy import text
    from flask_migrate import upgrade
    from app import create_app, db as _db, _migrations_directory

    app = create_app("testing")
    with app.app_context():
        _db.session.execute(text("DROP SCHEMA public CASCADE; CREATE SCHEMA public"))
        _db.session.commit()
        upgrade(directory=_migrations_directory())
        _db.session.remove()

    yield os.environ["TEST_DATABASE_URL"]


def _truncate_all(database):
    """Empty every model table, leaving the migrated schema in place."""
    from sqlalchemy import text

    tables = [f'"{t.name}"' for t in database.metadata.sorted_tables]
    if not tables:
        return
    # alembic_version is not in the model metadata, so the recorded revision
    # survives — the schema stays migrated across the whole session.
    database.session.execute(
        text(f"TRUNCATE TABLE {', '.join(tables)} RESTART IDENTITY CASCADE")
    )
    database.session.commit()


# ──────────────────────────────────────────────
# Flask portal fixtures
# ──────────────────────────────────────────────

@pytest.fixture
def portal_app(portal_schema):
    """A Flask test application bound to the migrated test database."""
    from app import create_app, db as _db

    app = create_app("testing")

    with app.app_context():
        _truncate_all(_db)
        try:
            yield app
        finally:
            _db.session.rollback()
            _truncate_all(_db)
            _db.session.remove()


@pytest.fixture
def portal_db(portal_app):
    """Provide the SQLAlchemy db instance bound to the test app context."""
    from app import db as _db
    with portal_app.app_context():
        yield _db


@pytest.fixture
def portal_client(portal_app):
    """Flask test client for the portal."""
    return portal_app.test_client()


@pytest.fixture
def test_user(portal_app, portal_db):
    """Create a test user."""
    from app.models import User
    with portal_app.app_context():
        user = User(email="test@example.com", username="testuser")
        user.set_password("password123")
        portal_db.session.add(user)
        portal_db.session.commit()
        # Re-query to ensure it's attached to the session
        user = User.query.filter_by(email="test@example.com").first()
        yield user


@pytest.fixture
def test_customer_key(portal_app, portal_db, test_user):
    """Create a test customer key."""
    from app.models import CustomerKey
    with portal_app.app_context():
        key = CustomerKey(
            key=str(uuid.uuid4()),
            name="Test Key",
            user_id=test_user.id,
        )
        portal_db.session.add(key)
        portal_db.session.commit()
        key = CustomerKey.query.filter_by(name="Test Key").first()
        yield key


@pytest.fixture
def test_host(portal_app, portal_db, test_customer_key):
    """Create a test host."""
    from app.models import Host
    with portal_app.app_context():
        host = Host(
            hostname="test-machine",
            ip_address="192.168.1.100",
            platform="Darwin 23.0",
            customer_key_id=test_customer_key.id,
        )
        portal_db.session.add(host)
        portal_db.session.commit()
        host = Host.query.filter_by(hostname="test-machine").first()
        yield host


@pytest.fixture
def test_scan_report(portal_app, portal_db, test_host):
    """Create a test scan report."""
    from app.models import ScanReport
    with portal_app.app_context():
        report = ScanReport(
            host_id=test_host.id,
            scan_data={
                "ides": [
                    {
                        "name": "VS Code",
                        "version": "1.85.0",
                        "extensions": [
                            {
                                "id": "pub.test-ext",
                                "name": "Test Extension",
                                "version": "1.0.0",
                                "publisher": "test-pub",
                                "permissions": [
                                    {"name": "fileSystem", "is_dangerous": True}
                                ],
                            }
                        ],
                    }
                ],
                "total_ides": 1,
                "total_extensions": 1,
            },
            total_ides=1,
            total_extensions=1,
            dangerous_extensions=1,
        )
        portal_db.session.add(report)
        portal_db.session.commit()
        report = ScanReport.query.first()
        yield report


@pytest.fixture
def logged_in_client(portal_app, portal_client, test_user):
    """A test client that is already logged in."""
    with portal_app.app_context():
        with portal_client.session_transaction() as sess:
            sess["_user_id"] = str(test_user.id)
        yield portal_client


@pytest.fixture
def test_host_with_token(portal_app, portal_db, test_host):
    """Yield (host, plaintext_token) — a host with an issued enrollment token."""
    with portal_app.app_context():
        from app.models import Host
        host = Host.query.filter_by(id=test_host.id).first()
        plaintext = host.issue_token()
        portal_db.session.commit()
        host = Host.query.filter_by(id=test_host.id).first()
        yield host, plaintext
