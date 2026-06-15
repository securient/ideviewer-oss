"""Add extension_prevalence table for fleet drift/anomaly detection (Phase 1 B7)

Revision ID: c2d3e4f5a6b7
Revises: b1c2d3e4f5a6
Create Date: 2026-06-14
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c2d3e4f5a6b7'
down_revision = 'b1c2d3e4f5a6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'extension_prevalence',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('customer_key_id', sa.Integer(), nullable=False),
        sa.Column('extension_id', sa.String(length=200), nullable=False),
        sa.Column('host_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('prev_host_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('max_risk_level', sa.String(length=20), nullable=True),
        sa.Column('first_seen_at', sa.DateTime(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['customer_key_id'], ['customer_keys.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('customer_key_id', 'extension_id', name='uq_prevalence_key_ext'),
    )
    op.create_index('idx_prevalence_key', 'extension_prevalence', ['customer_key_id'])


def downgrade():
    op.drop_index('idx_prevalence_key', table_name='extension_prevalence')
    op.drop_table('extension_prevalence')
