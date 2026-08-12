"""First-run bootstrap: an empty database must come up fully on its own.

This covers the path no other test exercised — the app factory migrating a
brand-new database and seeding the admin account in the same process. It caught
a real bug: ``migrations/env.py`` sets ``SKIP_DB_INIT=1`` in ``os.environ`` so
Alembic doesn't recurse into schema setup, and because ``_init_database``
imports that module via ``upgrade()``, the factory's *second* read of the
variable saw Alembic's value instead of the operator's. The result was that no
default admin user was created on any fresh database the app migrated itself.

Docker hid it: ``entrypoint.sh`` runs ``flask db upgrade`` in a separate process
and sets ``MIGRATIONS_DONE``, so the factory never imports ``env.py`` at all.
"""

import os

import pytest
from sqlalchemy.engine import make_url


@pytest.fixture
def scratch_dsn(portal_schema):
    """A dedicated empty database, dropped when the test finishes."""
    import psycopg2
    from psycopg2 import sql

    url = make_url(os.environ["TEST_DATABASE_URL"])
    name = f"{url.database}_bootstrap"
    admin_dsn = url.set(database="postgres").render_as_string(hide_password=False)

    def _run(statement):
        conn = psycopg2.connect(admin_dsn)
        conn.autocommit = True
        try:
            with conn.cursor() as cur:
                cur.execute(statement)
        finally:
            conn.close()

    drop = sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(name))
    _run(drop)
    _run(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    try:
        yield url.set(database=name).render_as_string(hide_password=False)
    finally:
        _run(drop)


def test_fresh_database_bootstraps_schema_and_admin(scratch_dsn, monkeypatch):
    """create_app on an empty database migrates it and seeds exactly one admin."""
    from sqlalchemy import text
    import app as app_module

    # Let the factory do the work it skips under the normal test fixture.
    monkeypatch.delenv("SKIP_DB_INIT", raising=False)
    monkeypatch.delenv("MIGRATIONS_DONE", raising=False)
    monkeypatch.setenv("IDEVIEWER_ADMIN_PASSWORD", "bootstrap-test-password")
    # create_app reads the class out of app's own config dict, so patch that
    # object rather than reloading the config module.
    monkeypatch.setattr(
        app_module.config["testing"], "SQLALCHEMY_DATABASE_URI", scratch_dsn
    )

    app = app_module.create_app("testing")

    with app.app_context():
        from app.models import User

        database = app_module.db

        revision = database.session.execute(
            text("SELECT version_num FROM alembic_version")
        ).scalar()
        assert revision, "the factory did not run migrations on the empty database"

        tables = database.session.execute(
            text(
                "SELECT count(*) FROM information_schema.tables "
                "WHERE table_schema = 'public'"
            )
        ).scalar()
        # 23 model tables plus alembic_version.
        assert tables == len(database.metadata.sorted_tables) + 1

        admins = User.query.all()
        assert len(admins) == 1, (
            "expected exactly one seeded admin user, got "
            f"{[u.username for u in admins]}"
        )
        assert admins[0].must_change_password is True

        database.session.remove()
        for engine in database.engines.values():
            engine.dispose()


def test_alembic_env_sets_skip_db_init(portal_app):
    """Pin the surprising side effect the bootstrap bug relied on.

    If this ever stops being true the snapshot in create_app becomes dead
    weight and can go — but it must not be removed on the assumption that
    reading os.environ twice is safe.
    """
    from app import _migrations_directory

    env_py = os.path.join(_migrations_directory(), "env.py")
    with open(env_py) as fh:
        source = fh.read()

    assert "SKIP_DB_INIT" in source, (
        "migrations/env.py no longer sets SKIP_DB_INIT; re-check whether "
        "create_app still needs to snapshot it before running migrations"
    )
