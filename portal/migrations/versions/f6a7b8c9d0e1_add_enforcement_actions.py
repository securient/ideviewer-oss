"""Add enforcement_actions table

Enforcement plane v1. One row per requested action on an extension on a
host (quarantine / restore), polled and executed by the daemon. Created by
a 'quarantine' policy match or manually by an admin. Reversible — nothing
is deleted.

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-06-12 10:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f6a7b8c9d0e1'
down_revision = 'e5f6a7b8c9d0'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'enforcement_actions',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('hosts.id'), nullable=False),
        sa.Column('violation_id', sa.Integer(), sa.ForeignKey('policy_violations.id'), nullable=True),
        sa.Column('action', sa.String(length=20), nullable=False, server_default='quarantine'),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='pending'),
        sa.Column('extension_id', sa.String(length=200), nullable=False),
        sa.Column('extension_name', sa.String(length=200), nullable=True),
        sa.Column('extension_version', sa.String(length=50), nullable=True),
        sa.Column('ide_type', sa.String(length=50), nullable=True),
        sa.Column('original_path', sa.String(length=1000), nullable=True),
        sa.Column('quarantine_path', sa.String(length=1000), nullable=True),
        sa.Column('result_detail', sa.Text(), nullable=True),
        sa.Column('created_by_user_id', sa.Integer(), sa.ForeignKey('users.id'), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('dispatched_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
    )
    op.create_index('idx_enforcement_host_status', 'enforcement_actions', ['host_id', 'status'])
    op.create_index('idx_enforcement_violation', 'enforcement_actions', ['violation_id'])


def downgrade():
    op.drop_index('idx_enforcement_violation', table_name='enforcement_actions')
    op.drop_index('idx_enforcement_host_status', table_name='enforcement_actions')
    op.drop_table('enforcement_actions')
