"""Add extension policies and policy violations

Policy engine (T2.2). extension_policies stores per-customer match
criteria + action; policy_violations records one (host, policy,
extension, version) match, upserted on rescan.

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-05-29 14:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd4e5f6a7b8c9'
down_revision = 'c3d4e5f6a7b8'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'extension_policies',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('public_id', sa.String(length=36), nullable=False),
        sa.Column('customer_key_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('priority', sa.Integer(), nullable=False, server_default='100'),
        sa.Column('action', sa.String(length=20), nullable=False),
        sa.Column('match_publisher', sa.String(length=200), nullable=True),
        sa.Column('match_extension_id', sa.String(length=200), nullable=True),
        sa.Column('match_permission_glob', sa.String(length=200), nullable=True),
        sa.Column('match_risk_level', sa.String(length=20), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('created_by_user_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['customer_key_id'], ['customer_keys.id']),
        sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id']),
        sa.UniqueConstraint('public_id', name='uq_extension_policies_public_id'),
    )
    op.create_index('ix_extension_policies_public_id', 'extension_policies', ['public_id'])
    op.create_index('ix_extension_policies_customer_key_id', 'extension_policies', ['customer_key_id'])
    op.create_index('idx_policy_customer_active', 'extension_policies', ['customer_key_id', 'is_active'])

    op.create_table(
        'policy_violations',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('host_id', sa.Integer(), nullable=False),
        sa.Column('policy_id', sa.Integer(), nullable=False),
        sa.Column('extension_id', sa.String(length=200), nullable=False),
        sa.Column('extension_name', sa.String(length=200), nullable=True),
        sa.Column('extension_version', sa.String(length=50), nullable=True),
        sa.Column('publisher', sa.String(length=200), nullable=True),
        sa.Column('risk_level', sa.String(length=20), nullable=True),
        sa.Column('action_taken', sa.String(length=20), nullable=False),
        sa.Column('first_detected_at', sa.DateTime(), nullable=False),
        sa.Column('last_seen_at', sa.DateTime(), nullable=False),
        sa.Column('is_resolved', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('resolved_at', sa.DateTime(), nullable=True),
        sa.Column('resolved_by_user_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['host_id'], ['hosts.id']),
        sa.ForeignKeyConstraint(['policy_id'], ['extension_policies.id']),
        sa.ForeignKeyConstraint(['resolved_by_user_id'], ['users.id']),
        sa.UniqueConstraint(
            'host_id', 'policy_id', 'extension_id', 'extension_version',
            name='uq_policy_violation_per_ext_version',
        ),
    )
    op.create_index('idx_violation_host_resolved', 'policy_violations', ['host_id', 'is_resolved'])
    op.create_index('idx_violation_policy', 'policy_violations', ['policy_id'])


def downgrade():
    op.drop_index('idx_violation_policy', table_name='policy_violations')
    op.drop_index('idx_violation_host_resolved', table_name='policy_violations')
    op.drop_table('policy_violations')

    op.drop_index('idx_policy_customer_active', table_name='extension_policies')
    op.drop_index('ix_extension_policies_customer_key_id', table_name='extension_policies')
    op.drop_index('ix_extension_policies_public_id', table_name='extension_policies')
    op.drop_table('extension_policies')
