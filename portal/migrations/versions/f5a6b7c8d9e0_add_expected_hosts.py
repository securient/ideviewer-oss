"""Add expected_hosts table for fleet coverage (Phase 1 B12)

Revision ID: f5a6b7c8d9e0
Revises: e4f5a6b7c8d9
Create Date: 2026-06-14
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f5a6b7c8d9e0'
down_revision = 'e4f5a6b7c8d9'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'expected_hosts',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('customer_key_id', sa.Integer(), nullable=False),
        sa.Column('hostname', sa.String(length=255), nullable=False),
        sa.Column('source', sa.String(length=20), nullable=True, server_default='manual'),
        sa.Column('added_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['customer_key_id'], ['customer_keys.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('customer_key_id', 'hostname', name='uq_expected_key_host'),
    )


def downgrade():
    op.drop_table('expected_hosts')
