"""Add type column to webhook_subscriptions

Lets a subscription declare its delivery format (slack / pagerduty / generic)
instead of sniffing the URL. Backfills existing Slack-URL subscriptions to
type='slack' so they keep formatting correctly.

Revision ID: a7b8c9d0e1f2
Revises: f6a7b8c9d0e1
Create Date: 2026-06-12 16:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = 'a7b8c9d0e1f2'
down_revision = 'f6a7b8c9d0e1'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'webhook_subscriptions',
        sa.Column('type', sa.String(length=20), nullable=False, server_default='generic'),
    )
    # Backfill: existing Slack incoming-webhook URLs become type='slack'.
    op.execute(
        "UPDATE webhook_subscriptions SET type = 'slack' "
        "WHERE url LIKE '%hooks.slack.com%'"
    )


def downgrade():
    op.drop_column('webhook_subscriptions', 'type')
