"""Add remediation_playbooks table (Phase 1 B10 SOAR)

Revision ID: e4f5a6b7c8d9
Revises: d3e4f5a6b7c8
Create Date: 2026-06-14
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e4f5a6b7c8d9'
down_revision = 'd3e4f5a6b7c8'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'remediation_playbooks',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('public_id', sa.String(length=36), nullable=False),
        sa.Column('customer_key_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('trigger_event', sa.String(length=80), nullable=False),
        sa.Column('action', sa.String(length=40), nullable=False, server_default='notify_only'),
        sa.Column('mode', sa.String(length=20), nullable=False, server_default='dry_run'),
        sa.Column('min_severity', sa.String(length=20), nullable=True, server_default='high'),
        sa.Column('max_actions_per_hour', sa.Integer(), nullable=True, server_default='5'),
        sa.Column('is_active', sa.Boolean(), nullable=True, server_default=sa.true()),
        sa.Column('created_by_user_id', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['customer_key_id'], ['customer_keys.id']),
        sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('public_id'),
    )
    op.create_index(op.f('ix_remediation_playbooks_public_id'),
                    'remediation_playbooks', ['public_id'], unique=True)


def downgrade():
    op.drop_index(op.f('ix_remediation_playbooks_public_id'), table_name='remediation_playbooks')
    op.drop_table('remediation_playbooks')
