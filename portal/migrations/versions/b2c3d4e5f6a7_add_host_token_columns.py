"""Add host token columns

Adds per-host enrollment-token columns (token_hash, token_issued_at,
token_revoked_at) plus an index on token_hash for fast auth lookups.

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-05-22 09:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b2c3d4e5f6a7'
down_revision = 'a1b2c3d4e5f6'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('hosts', schema=None) as batch_op:
        batch_op.add_column(sa.Column('token_hash', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('token_issued_at', sa.DateTime(), nullable=True))
        batch_op.add_column(sa.Column('token_revoked_at', sa.DateTime(), nullable=True))
        batch_op.create_index('ix_hosts_token_hash', ['token_hash'])


def downgrade():
    with op.batch_alter_table('hosts', schema=None) as batch_op:
        batch_op.drop_index('ix_hosts_token_hash')
        batch_op.drop_column('token_revoked_at')
        batch_op.drop_column('token_issued_at')
        batch_op.drop_column('token_hash')
