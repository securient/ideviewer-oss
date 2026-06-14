"""Entry point for the rq-scheduler process.

Run as: ``python -m portal.run_scheduler`` or directly via the
``rqscheduler`` CLI. The container/service that runs this is what
ticks the daily extension-metadata refresh.

Idempotent on startup: the schedule is registered with a stable job
id, so restarting the scheduler doesn't double-schedule.
"""
import logging
import os
import sys
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("ideviewer.scheduler")

DAILY_REFRESH_JOB_ID = "extension-metadata-daily-refresh"
DAILY_REFRESH_INTERVAL_SECONDS = 24 * 60 * 60

INTEGRITY_SWEEP_JOB_ID = "host-integrity-sweep"
INTEGRITY_SWEEP_INTERVAL_SECONDS = 60


def _reschedule(scheduler, job_id, func, interval, first_delay, timeout):
    """(Re)register a recurring job under a stable id, removing any duplicate."""
    for existing in scheduler.get_jobs():
        if existing.id == job_id:
            log.info("removing existing scheduled job %s", existing.id)
            scheduler.cancel(existing)
    scheduler.schedule(
        scheduled_time=datetime.utcnow() + timedelta(seconds=first_delay),
        func=func,
        interval=interval,
        repeat=None,  # forever
        id=job_id,
        timeout=timeout,
    )
    log.info("scheduled %s every %ds (first run in %ds)", job_id, interval, first_delay)


def main() -> int:
    redis_url = os.environ.get("REDIS_URL")
    if not redis_url:
        log.error("REDIS_URL is required; refusing to run scheduler without it.")
        return 1

    import redis
    from rq import Queue
    from rq_scheduler import Scheduler

    from app.jobs.extension_refresh import refresh_stale_extension_metadata
    from app.jobs.integrity_monitor import sweep_host_integrity

    conn = redis.from_url(redis_url)
    queue = Queue("default", connection=conn)
    scheduler = Scheduler(queue=queue, connection=conn)

    _reschedule(scheduler, DAILY_REFRESH_JOB_ID, refresh_stale_extension_metadata,
                DAILY_REFRESH_INTERVAL_SECONDS, first_delay=60, timeout=600)
    _reschedule(scheduler, INTEGRITY_SWEEP_JOB_ID, sweep_host_integrity,
                INTEGRITY_SWEEP_INTERVAL_SECONDS, first_delay=30, timeout=120)

    scheduler.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
