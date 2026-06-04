"""Outbound webhook delivery (T2.1).

One enqueued job = one delivery attempt. On HTTP failure (or non-2xx),
the job schedules its own next attempt via ``enqueue_in`` with the
configured backoff. State (attempt_count, last_error, etc.) lives in
the WebhookDelivery row, so worker restarts don't lose attempt state.

Signature scheme: Stripe-style ``X-IDEViewer-Signature: t=<unix>,v1=<hex>``
where the signed payload is ``f"{t}.{raw_body}"``. Receivers reject if
``now - t > REPLAY_WINDOW_SECONDS`` to defeat replay.
"""
import hashlib
import hmac
import json
import logging
import os
import time
from datetime import datetime
from typing import Tuple

import requests

from app.observability import WEBHOOK_DELIVERIES

logger = logging.getLogger("ideviewer.webhook")

# Backoff schedule applied AFTER attempt N (i.e. RETRY_DELAYS[0] is the
# wait before attempt 2). Total: 5 attempts spanning ~7.5 hours.
RETRY_DELAYS_SECONDS = [30, 120, 600, 3600, 21600]
MAX_ATTEMPTS = len(RETRY_DELAYS_SECONDS) + 1  # 6 — one initial + 5 retries

HTTP_TIMEOUT_SECONDS = 10
RESPONSE_BODY_TRUNCATE = 1000


def deliver_webhook(delivery_id: int) -> None:
    """Single delivery attempt for ``delivery_id``.

    Builds Flask app context if needed (worker entry point) and delegates
    to ``_attempt_delivery``. Designed to be enqueued via app.queue.
    """
    from flask import has_app_context

    if has_app_context():
        _attempt_delivery(delivery_id)
        return

    from app import create_app
    app = create_app(os.environ.get("FLASK_CONFIG", "production"))
    with app.app_context():
        _attempt_delivery(delivery_id)


def _attempt_delivery(delivery_id: int) -> None:
    from app import db
    from app.models import WebhookDelivery

    delivery = WebhookDelivery.query.get(delivery_id)
    if delivery is None:
        logger.warning("webhook delivery %s not found", delivery_id)
        return

    if delivery.status == WebhookDelivery.STATUS_SUCCEEDED:
        return  # idempotent re-run guard
    if delivery.status == WebhookDelivery.STATUS_FAILED:
        return

    sub = delivery.subscription
    if sub is None or not sub.is_active:
        delivery.status = WebhookDelivery.STATUS_FAILED
        delivery.last_error = "subscription inactive or deleted"
        delivery.completed_at = datetime.utcnow()
        db.session.commit()
        return

    delivery.attempt_count = (delivery.attempt_count or 0) + 1
    delivery.last_attempt_at = datetime.utcnow()
    if delivery.attempt_count > 1:
        delivery.status = WebhookDelivery.STATUS_RETRYING
    db.session.commit()

    try:
        status_code, response_body = _send(sub.url, sub.secret, delivery.payload, delivery.event_type, delivery.event_id)
        delivery.response_code = status_code
        delivery.response_body = (response_body or '')[:RESPONSE_BODY_TRUNCATE]
        if 200 <= status_code < 300:
            delivery.status = WebhookDelivery.STATUS_SUCCEEDED
            delivery.completed_at = datetime.utcnow()
            delivery.last_error = None
            sub.record_success()
            db.session.commit()
            WEBHOOK_DELIVERIES.labels(status='succeeded').inc()
            return
        delivery.last_error = f"HTTP {status_code}"
    except requests.RequestException as e:
        delivery.last_error = f"{type(e).__name__}: {e}"[:500]
    except Exception as e:
        delivery.last_error = f"{type(e).__name__}: {e}"[:500]
        logger.exception("unexpected error delivering webhook %s", delivery_id)

    if delivery.attempt_count >= MAX_ATTEMPTS:
        delivery.status = WebhookDelivery.STATUS_FAILED
        delivery.completed_at = datetime.utcnow()
        sub.record_failure()
        db.session.commit()
        WEBHOOK_DELIVERIES.labels(status='failed').inc()
        return

    delivery.status = WebhookDelivery.STATUS_RETRYING
    sub.record_failure()
    db.session.commit()
    WEBHOOK_DELIVERIES.labels(status='retrying').inc()

    delay = RETRY_DELAYS_SECONDS[delivery.attempt_count - 1]
    from app.queue import enqueue_in
    enqueue_in(delay, deliver_webhook, delivery.id)


def _send(
    url: str,
    secret: str,
    payload: dict,
    event_type: str,
    event_id: str,
) -> Tuple[int, str]:
    body = json.dumps(payload, separators=(',', ':'), sort_keys=True)
    timestamp = int(time.time())
    signed = f"{timestamp}.{body}".encode('utf-8')
    sig = hmac.new(secret.encode('utf-8'), signed, hashlib.sha256).hexdigest()
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'IDEViewer-Webhook/1.0',
        'X-IDEViewer-Signature': f"t={timestamp},v1={sig}",
        'X-IDEViewer-Event-Type': event_type,
        'X-IDEViewer-Event-Id': event_id,
    }
    response = requests.post(
        url,
        data=body,
        headers=headers,
        timeout=HTTP_TIMEOUT_SECONDS,
    )
    return response.status_code, response.text
