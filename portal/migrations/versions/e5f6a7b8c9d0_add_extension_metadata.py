"""Add extension_metadata cache table

T2.3 enrichment cache. One row per (marketplace, extension_id, version)
with marketplace stats and the critical is_unpublished signal that
drives the extension.unpublished_detected webhook event.

Revision ID: e5f6a7b8c9d0
Revises: d4e5f6a7b8c9
Create Date: 2026-06-01 19:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e5f6a7b8c9d0'
down_revision = 'd4e5f6a7b8c9'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'extension_metadata',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('marketplace', sa.String(length=50), nullable=False),
        sa.Column('extension_id', sa.String(length=200), nullable=False),
        sa.Column('version', sa.String(length=50), nullable=False),
        sa.Column('publisher_display_name', sa.String(length=200), nullable=True),
        sa.Column('install_count', sa.BigInteger(), nullable=True),
        sa.Column('average_rating', sa.Float(), nullable=True),
        sa.Column('last_updated_at', sa.DateTime(), nullable=True),
        sa.Column('is_unpublished', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('unpublished_detected_at', sa.DateTime(), nullable=True),
        sa.Column('raw_data', sa.JSON(), nullable=True),
        sa.Column('fetched_at', sa.DateTime(), nullable=False),
        sa.Column('last_fetch_status', sa.Integer(), nullable=True),
        sa.UniqueConstraint('marketplace', 'extension_id', 'version', name='uq_ext_meta'),
    )
    op.create_index('idx_ext_meta_lookup', 'extension_metadata',
                    ['marketplace', 'extension_id', 'version'])
    op.create_index('idx_ext_meta_unpublished', 'extension_metadata', ['is_unpublished'])
    op.create_index('idx_ext_meta_fetched_at', 'extension_metadata', ['fetched_at'])


def downgrade():
    op.drop_index('idx_ext_meta_fetched_at', table_name='extension_metadata')
    op.drop_index('idx_ext_meta_unpublished', table_name='extension_metadata')
    op.drop_index('idx_ext_meta_lookup', table_name='extension_metadata')
    op.drop_table('extension_metadata')
