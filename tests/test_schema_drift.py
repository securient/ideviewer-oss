"""The models and the migration head must agree.

Nothing previously connected ``models.py`` to ``migrations/``: the test suite
built its schema with ``create_all()``, so a model change that never got a
migration passed CI and then failed on a real deployment. This test closes that
gap by asking Alembic to autogenerate against the migrated database and
asserting it finds nothing to do.

When this fails, the fix is almost always to generate the missing revision:

    cd portal && flask db migrate -m "describe the change"
"""

import pytest


# Autogenerate reports some differences that are artefacts of comparison rather
# than real drift — most commonly indexes and constraints that Alembic cannot
# reflect identically across dialects. Nothing is ignored today; entries added
# here must name the specific object and say why it can't be represented.
IGNORED_OBJECTS: set[tuple[str, str]] = set()


def _describe(diff):
    """Render one autogenerate diff tuple as a readable line."""
    kind = diff[0]
    if kind in ("add_table", "remove_table"):
        return f"{kind}: {diff[1].name}"
    if kind in ("add_column", "remove_column"):
        return f"{kind}: {diff[2]}.{diff[3].name}"
    if kind in ("add_index", "remove_index", "add_constraint", "remove_constraint"):
        obj = diff[1]
        return f"{kind}: {getattr(obj, 'name', obj)}"
    if kind == "modify_nullable":
        return f"{kind}: {diff[2]}.{diff[3]} {diff[5]} -> {diff[6]}"
    if kind == "modify_type":
        return f"{kind}: {diff[2]}.{diff[3]} {diff[5]!r} -> {diff[6]!r}"
    return str(diff)


def _relevant(diff):
    kind = diff[0]
    if kind in ("add_table", "remove_table"):
        return (kind, diff[1].name) not in IGNORED_OBJECTS
    if kind in ("add_column", "remove_column"):
        return (kind, f"{diff[2]}.{diff[3].name}") not in IGNORED_OBJECTS
    return True


def test_models_match_migration_head(portal_app, portal_db):
    """Autogenerate against the migrated database must produce no operations."""
    from alembic.autogenerate import compare_metadata
    from alembic.migration import MigrationContext

    with portal_db.engine.connect() as conn:
        context = MigrationContext.configure(conn)
        diffs = compare_metadata(context, portal_db.metadata)

    # compare_metadata nests grouped diffs (e.g. per-column modifications) one
    # level deep; flatten so each operation is reported individually.
    flat = []
    for diff in diffs:
        if isinstance(diff, list):
            flat.extend(diff)
        else:
            flat.append(diff)

    drift = [d for d in flat if _relevant(d)]

    assert not drift, (
        "models.py and the Alembic migration head disagree:\n  "
        + "\n  ".join(_describe(d) for d in drift)
        + "\n\nGenerate the missing revision with:\n"
        "  cd portal && flask db migrate -m \"describe the change\""
    )


def test_migration_head_is_recorded(portal_app, portal_db):
    """The test database must be stamped, proving upgrade() ran (not create_all)."""
    from sqlalchemy import text

    revision = portal_db.session.execute(
        text("SELECT version_num FROM alembic_version")
    ).scalar()
    assert revision, "alembic_version is empty — the schema was not built by migrations"


def test_foreign_keys_are_enforced(portal_app, portal_db, test_host):
    """A dangling foreign key must be rejected by the database.

    This is the guarantee SQLite never provided: it disables FK enforcement by
    default and nothing in the repo turned it on, so for most of this project's
    life every foreign key was decorative. On PostgreSQL the constraint is real,
    and this test fails loudly if the suite ever drifts back to an engine or a
    configuration where it isn't.
    """
    from sqlalchemy.exc import IntegrityError
    from app.models import ScanReport

    orphan = ScanReport(host_id=test_host.id + 10_000, scan_data={})
    portal_db.session.add(orphan)
    with pytest.raises(IntegrityError):
        portal_db.session.commit()
    portal_db.session.rollback()
