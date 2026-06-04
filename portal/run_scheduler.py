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


def main() -> int:
    redis_url = os.environ.get("REDIS_URL")
    if not redis_url:
        log.error("REDIS_URL is required; refusing to run scheduler without it.")
        return 1

    import redis
    from rq import Queue
    from rq_scheduler import Scheduler

    from app.jobs.extension_refresh import refresh_stale_extension_metadata

    conn = redis.from_url(redis_url)
    queue = Queue("default", connection=conn)
    scheduler = Scheduler(queue=queue, connection=conn)

    # Wipe any previously-scheduled instance of this job so restarts
    # don't accumulate copies.
    for existing in scheduler.get_jobs():
        if existing.id == DAILY_REFRESH_JOB_ID:
            log.info("removing existing scheduled job %s", existing.id)
            scheduler.cancel(existing)

    scheduler.schedule(
        scheduled_time=datetime.utcnow() + timedelta(seconds=60),
        func=refresh_stale_extension_metadata,
        interval=DAILY_REFRESH_INTERVAL_SECONDS,
        repeat=None,  # forever
        id=DAILY_REFRESH_JOB_ID,
        timeout=600,
    )
    log.info(
        "scheduled %s every %ds (first run in 60s)",
        DAILY_REFRESH_JOB_ID, DAILY_REFRESH_INTERVAL_SECONDS,
    )

    scheduler.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
