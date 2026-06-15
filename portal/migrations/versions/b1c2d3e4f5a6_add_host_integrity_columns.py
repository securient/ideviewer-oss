"""Add server-side integrity + composite-risk columns to hosts (Phase 1 B2/B8)

Revision ID: b1c2d3e4f5a6
Revises: a7b8c9d0e1f2
Create Date: 2026-06-13

Adds heartbeat-gap alarm state (B2) so the portal can detect a host whose
daemon has gone silent, plus the denormalized composite risk score (B8).
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b1c2d3e4f5a6'
down_revision = 'a7b8c9d0e1f2'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('hosts', schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            'heartbeat_alarm_state', sa.String(length=16),
            nullable=False, server_default='ok',
        ))
        batch_op.add_column(sa.Column(
            'silent_since', sa.DateTime(), nullable=True,
        ))
        batch_op.add_column(sa.Column(
            'risk_score', sa.Integer(), nullable=True,
        ))
        batch_op.add_column(sa.Column(
            'risk_level_composite', sa.String(length=16), nullable=True,
        ))


def downgrade():
    with op.batch_alter_table('hosts', schema=None) as batch_op:
        batch_op.drop_column('risk_level_composite')
        batch_op.drop_column('risk_score')
        batch_op.drop_column('silent_since')
        batch_op.drop_column('heartbeat_alarm_state')
