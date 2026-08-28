"""allow 'cancelled' scan requests and record scan-report provenance

Two fixes reported from Windows field testing:

  * ``/host/<id>/cancel-scan`` has always written ``status='cancelled'``, but
    ``cancelled`` was absent from ``ScanRequest.VALID_STATUSES`` and therefore
    from ``ck_scan_requests_status``. Every Stop click raised a CheckViolation,
    the request stayed at 'pending', and — because trigger-scan refuses to
    queue while one is active — the Trigger Scan button wedged permanently.

  * ``scan_reports.source`` distinguishes a report the daemon produced on its
    own schedule from one a human pushed with ``ideviewer scan --push``.
    Reports are append-only, so a manual push never overwrites daemon data, but
    an operator reading a host page needs to see which is which. Existing rows
    predate the CLI push path and are backfilled to 'daemon'.

Revision ID: 0002_cancellable_scans
Revises: 0001_baseline

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0002_cancellable_scans'
down_revision = '0001_baseline'
branch_labels = None
depends_on = None


SCAN_REQUEST_STATUSES_OLD = (
    'pending', 'connecting', 'scanning_ides', 'scanning_secrets',
    'scanning_packages', 'completed', 'failed', 'timeout',
)
SCAN_REQUEST_STATUSES_NEW = SCAN_REQUEST_STATUSES_OLD + ('cancelled',)


def _status_check(values):
    rendered = ', '.join(f"'{v}'" for v in values)
    return f'status IS NULL OR status IN ({rendered})'


def upgrade():
    op.drop_constraint('ck_scan_requests_status', 'scan_requests', type_='check')
    op.create_check_constraint(
        'ck_scan_requests_status', 'scan_requests',
        _status_check(SCAN_REQUEST_STATUSES_NEW),
    )

    op.add_column(
        'scan_reports',
        sa.Column('source', sa.String(length=16), nullable=False,
                  server_default='daemon'),
    )
    op.create_check_constraint(
        'ck_scan_reports_source', 'scan_reports',
        "source IS NULL OR source IN ('daemon', 'cli')",
    )


def downgrade():
    # Requests already cancelled have no pre-'cancelled' equivalent; 'failed'
    # is the closest terminal state and keeps the CHECK satisfiable.
    op.execute(
        "UPDATE scan_requests SET status = 'failed' WHERE status = 'cancelled'"
    )
    op.drop_constraint('ck_scan_requests_status', 'scan_requests', type_='check')
    op.create_check_constraint(
        'ck_scan_requests_status', 'scan_requests',
        _status_check(SCAN_REQUEST_STATUSES_OLD),
    )

    op.drop_constraint('ck_scan_reports_source', 'scan_reports', type_='check')
    op.drop_column('scan_reports', 'source')
