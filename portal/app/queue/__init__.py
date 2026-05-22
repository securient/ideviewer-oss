"""Redis Queue helper with sync fallback.

When REDIS_URL is set and reachable, queueable jobs run on an RQ
worker. When not, they run inline so first-run UX is preserved.

IMPORTANT: jobs enqueued via ``enqueue()`` MUST be module-level
functions because RQ serialises them by import path. Lambdas, nested
functions, and bound methods will not survive the round-trip.
"""
import logging
import os
from typing import Callable, Optional

import redis
from rq import Queue, Retry
from rq.job import Job

logger = logging.getLogger(__name__)

_redis: Optional[redis.Redis] = None
_queue: Optional[Queue] = None


def init_queue(app) -> None:
    """Initialise Redis + queue from REDIS_URL. Falls back silently."""
    global _redis, _queue
    url = app.config.get("REDIS_URL") or os.environ.get("REDIS_URL")
    if not url:
        app.logger.info("REDIS_URL not set; queue disabled (sync mode)")
        return
    try:
        conn = redis.from_url(url, socket_connect_timeout=2)
        conn.ping()
    except Exception as e:
        app.logger.warning("Redis unreachable (%s); queue disabled", e)
        return
    _redis = conn
    _queue = Queue("default", connection=conn, default_timeout=600)
    app.logger.info("RQ queue initialised: %s", url)


def is_async() -> bool:
    """Return True iff jobs will be enqueued for async execution."""
    return _queue is not None


def enqueue(func: Callable, *args, retry_max: int = 3, **kwargs) -> Optional[Job]:
    """Enqueue a job. Returns the Job, or None if running sync.

    ``func`` must be a module-level function — RQ pickles it by
    fully-qualified import path.
    """
    if _queue is None:
        return None
    return _queue.enqueue(
        func,
        *args,
        retry=Retry(max=retry_max, interval=[10, 60, 300]),
        **kwargs,
    )


def reset_for_tests() -> None:
    """Test hook to reset module-level state."""
    global _redis, _queue
    _redis = None
    _queue = None
