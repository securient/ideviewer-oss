"""Add webhook subscriptions and deliveries

Outbound webhook framework (T2.1). webhook_subscriptions stores
per-customer endpoints (URL + event filter + HMAC secret + health
counters); webhook_deliveries records every dispatch attempt for
observability and replay.

Revision ID: c3d4e5f6a7b8
Revises: b2c3d4e5f6a7
Create Date: 2026-05-29 12:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c3d4e5f6a7b8'
down_revision = 'b2c3d4e5f6a7'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'webhook_subscriptions',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('public_id', sa.String(length=36), nullable=False),
        sa.Column('customer_key_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('url', sa.String(length=500), nullable=False),
        sa.Column('event_types', sa.JSON(), nullable=False),
        sa.Column('secret', sa.String(length=64), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('consecutive_failures', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_success_at', sa.DateTime(), nullable=True),
        sa.Column('last_failure_at', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('created_by_user_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['customer_key_id'], ['customer_keys.id']),
        sa.ForeignKeyConstraint(['created_by_user_id'], ['users.id']),
        sa.UniqueConstraint('public_id', name='uq_webhook_subscriptions_public_id'),
    )
    op.create_index(
        'ix_webhook_subscriptions_public_id',
        'webhook_subscriptions',
        ['public_id'],
    )
    op.create_index(
        'ix_webhook_subscriptions_customer_key_id',
        'webhook_subscriptions',
        ['customer_key_id'],
    )

    op.create_table(
        'webhook_deliveries',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('subscription_id', sa.Integer(), nullable=False),
        sa.Column('event_id', sa.String(length=36), nullable=False),
        sa.Column('event_type', sa.String(length=100), nullable=False),
        sa.Column('payload', sa.JSON(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='pending'),
        sa.Column('attempt_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_attempt_at', sa.DateTime(), nullable=True),
        sa.Column('response_code', sa.Integer(), nullable=True),
        sa.Column('response_body', sa.Text(), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(
            ['subscription_id'], ['webhook_subscriptions.id'], ondelete='CASCADE',
        ),
    )
    op.create_index(
        'ix_webhook_deliveries_subscription_id',
        'webhook_deliveries',
        ['subscription_id'],
    )
    op.create_index('ix_webhook_deliveries_event_id', 'webhook_deliveries', ['event_id'])
    op.create_index('ix_webhook_deliveries_event_type', 'webhook_deliveries', ['event_type'])
    op.create_index('ix_webhook_deliveries_created_at', 'webhook_deliveries', ['created_at'])
    op.create_index(
        'idx_delivery_sub_status',
        'webhook_deliveries',
        ['subscription_id', 'status'],
    )


def downgrade():
    op.drop_index('idx_delivery_sub_status', table_name='webhook_deliveries')
    op.drop_index('ix_webhook_deliveries_created_at', table_name='webhook_deliveries')
    op.drop_index('ix_webhook_deliveries_event_type', table_name='webhook_deliveries')
    op.drop_index('ix_webhook_deliveries_event_id', table_name='webhook_deliveries')
    op.drop_index('ix_webhook_deliveries_subscription_id', table_name='webhook_deliveries')
    op.drop_table('webhook_deliveries')

    op.drop_index('ix_webhook_subscriptions_customer_key_id', table_name='webhook_subscriptions')
    op.drop_index('ix_webhook_subscriptions_public_id', table_name='webhook_subscriptions')
    op.drop_table('webhook_subscriptions')
