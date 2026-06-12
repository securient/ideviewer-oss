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
    # Slack Incoming Webhooks reject anything that isn't a Slack-shaped body
    # (HTTP 400 "no_text"). Detect them and send a formatted text message
    # instead of our generic signed envelope. Slack ignores extra headers and
    # doesn't verify the HMAC, so we send a plain JSON message.
    if 'hooks.slack.com' in url:
        body = json.dumps(_slack_payload(event_type, payload))
        response = requests.post(
            url,
            data=body,
            headers={'Content-Type': 'application/json',
                     'User-Agent': 'IDEViewer-Webhook/1.0'},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        return response.status_code, response.text

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


def _slack_payload(event_type: str, p: dict) -> dict:
    """Render an event as a Slack Incoming-Webhook message (``{"text": ...}``).

    Defensive: every field is optional, with a JSON fallback for event types
    we don't have a bespoke template for.
    """
    host = p.get('host') or {}
    hostname = host.get('hostname', 'unknown host')
    ext = p.get('extension') or {}
    ext_id = ext.get('extension_id') or ext.get('id') or ext.get('name') or 'unknown'
    ver = ext.get('version')
    ext_label = f"`{ext_id}`" + (f"@{ver}" if ver else "")

    if event_type == 'policy.violation':
        pol = p.get('policy') or {}
        text = (f":rotating_light: *Policy violation* — {ext_label} on *{hostname}* "
                f"matched policy *{pol.get('name', '?')}* (action: {pol.get('action', '?')})")
    elif event_type == 'extension.high_risk_detected':
        text = (f":warning: *High-risk extension* — {ext_label} "
                f"({ext.get('risk_level', '?')}) on *{hostname}*")
    elif event_type == 'extension.unpublished_detected':
        text = (f":package: *Extension removed from marketplace* — {ext_label} "
                f"(host *{hostname}*)")
    elif event_type == 'tamper_alert.created':
        text = (f":rotating_light: *Tamper alert* [{p.get('severity', '?')}] on "
                f"*{hostname}*: {p.get('details', '')}")
    elif event_type == 'hook_bypass.detected':
        text = (f":no_entry: *Git hook bypass* on *{hostname}* — commit "
                f"`{(p.get('commit_hash') or '')[:10]}` by {p.get('commit_author', '?')}")
    elif event_type in ('enforcement.action_created', 'enforcement.completed'):
        action = p.get('action', 'enforcement')
        verb = 'requested' if event_type.endswith('created') else (p.get('status') or 'updated')
        detail = p.get('result_detail') or ''
        text = (f":lock: *Enforcement {action} {verb}* for {ext_label} on *{hostname}*"
                + (f" — {detail}" if detail else ""))
    else:
        text = f"*{event_type}*\n```{json.dumps(p, indent=2)[:1500]}```"

    return {"text": "IDEViewer — " + text}
