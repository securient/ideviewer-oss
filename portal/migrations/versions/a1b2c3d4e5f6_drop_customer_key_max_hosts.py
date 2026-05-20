"""Drop max_hosts from customer_keys

Removes the host-cap column. Hosts per customer key are unlimited.

Revision ID: a1b2c3d4e5f6
Revises: 3b55959a4b71
Create Date: 2026-05-20 10:45:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a1b2c3d4e5f6'
down_revision = '3b55959a4b71'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('customer_keys', schema=None) as batch_op:
        batch_op.drop_column('max_hosts')


def downgrade():
    with op.batch_alter_table('customer_keys', schema=None) as batch_op:
        batch_op.add_column(sa.Column('max_hosts', sa.Integer(), nullable=True))
