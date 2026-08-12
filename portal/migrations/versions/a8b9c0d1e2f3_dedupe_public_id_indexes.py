"""Remove redundant public_id unique constraints and make the indexes unique

Three tables ended up enforcing uniqueness on ``public_id`` twice. The models
declare ``unique=True, index=True``, which SQLAlchemy renders as a single
unique index named ``ix_<table>_<column>``; the migrations that created these
tables additionally issued an explicit unique constraint. On PostgreSQL that
left two btree indexes on the same column — duplicated writes, duplicated
storage — and in two cases the ``ix_`` index was created non-unique, so the
column's uniqueness rested entirely on the constraint the models don't know
about.

This was invisible until the test suite moved off SQLite: nothing compared the
models against the migration head, so the divergence never surfaced.

Revision ID: a8b9c0d1e2f3
Revises: f5a6b7c8d9e0
Create Date: 2026-08-11

"""
from alembic import op


revision = 'a8b9c0d1e2f3'
down_revision = 'f5a6b7c8d9e0'
branch_labels = None
depends_on = None


# (table, redundant unique constraint, index that should be unique)
_TABLES = (
    ('extension_policies', 'uq_extension_policies_public_id', True),
    ('webhook_subscriptions', 'uq_webhook_subscriptions_public_id', True),
    # remediation_playbooks already has a unique ix_ index; only the
    # auto-named constraint from unique=True is redundant here.
    ('remediation_playbooks', 'remediation_playbooks_public_id_key', False),
)


def upgrade():
    for table, constraint, reindex in _TABLES:
        index_name = f'ix_{table}_public_id'
        # Drop the non-unique index first so uniqueness is never unenforced:
        # the constraint still covers the column at this point.
        if reindex:
            op.drop_index(index_name, table_name=table)
            op.create_index(index_name, table, ['public_id'], unique=True)
        op.drop_constraint(constraint, table, type_='unique')


def downgrade():
    for table, constraint, reindex in _TABLES:
        index_name = f'ix_{table}_public_id'
        op.create_unique_constraint(constraint, table, ['public_id'])
        if reindex:
            op.drop_index(index_name, table_name=table)
            op.create_index(index_name, table, ['public_id'], unique=False)
