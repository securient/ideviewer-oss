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
        status_code, response_body = _send(sub.url, sub.secret, delivery.payload, delivery.event_type, delivery.event_id, getattr(sub, 'type', 'generic'))
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


PAGERDUTY_ENQUEUE_URL = 'https://events.pagerduty.com/v2/enqueue'


def _send(
    url: str,
    secret: str,
    payload: dict,
    event_type: str,
    event_id: str,
    wtype: str = 'generic',
) -> Tuple[int, str]:
    # Slack: send a Slack-shaped message. Explicit type wins; we also keep the
    # hooks.slack.com sniff as a fallback for older subs with no type set.
    if wtype == 'slack' or (wtype != 'pagerduty' and 'hooks.slack.com' in url):
        body = json.dumps(_slack_payload(event_type, payload))
        response = requests.post(
            url,
            data=body,
            headers={'Content-Type': 'application/json',
                     'User-Agent': 'IDEViewer-Webhook/1.0'},
            timeout=HTTP_TIMEOUT_SECONDS,
        )
        return response.status_code, response.text

    # PagerDuty Events API v2: `url` holds the routing (integration) key; we
    # POST a v2 event to the fixed enqueue endpoint.
    if wtype == 'pagerduty':
        body = json.dumps(_pagerduty_payload(event_type, payload, url))
        response = requests.post(
            PAGERDUTY_ENQUEUE_URL,
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


def _slack_payload(event_type: str, payload: dict) -> dict:
    """Render an event as a Slack Incoming-Webhook message (``{"text": ...}``).

    Reads the event envelope's ``data`` block (falling back to the raw dict),
    so all the host/extension/policy fields are available. Defensive: every
    field is optional, with a JSON fallback for unknown event types.
    """
    d = payload.get('data') if isinstance(payload.get('data'), dict) else payload
    host = d.get('host') or {}
    hostname = host.get('hostname', 'unknown host')
    ext = d.get('extension') or {}
    ext_id = ext.get('extension_id') or ext.get('id') or ext.get('name') or 'unknown'
    ver = ext.get('version')
    ext_label = f"`{ext_id}`" + (f"@{ver}" if ver else "")
    ide = ext.get('ide') or ext.get('ide_type')
    risk = ext.get('risk_level')
    publisher = ext.get('publisher')

    def vuln_line():
        vd = ext.get('vulnerable_dependencies') or {}
        crit, high = vd.get('critical', 0), vd.get('high', 0)
        if not (crit or high):
            return ''
        line = f"\n• :biohazard_sign: Vulnerable bundled deps: *{crit} critical, {high} high*"
        examples = vd.get('examples') or []
        if examples:
            line += " — " + ", ".join(
                f"{e.get('vuln_id')} ({e.get('package')})" for e in examples[:3]
            )
        return line

    if event_type == 'policy.violation':
        pol = d.get('policy') or {}
        lines = [
            f":rotating_light: *Policy violation* on *{hostname}*",
            f"• Extension: {ext_label}" + (f"  _{ide}_" if ide else ""),
            f"• Publisher: {publisher or '?'}   •   Risk: *{risk or '?'}*",
            f"• Policy: *{pol.get('name', '?')}* → {pol.get('action', '?')}",
        ]
        text = "\n".join(lines) + vuln_line()
    elif event_type == 'extension.high_risk_detected':
        text = (
            f":warning: *High-risk extension* on *{hostname}*\n"
            f"• {ext_label}" + (f"  _{ide}_" if ide else "") +
            f"\n• Publisher: {publisher or '?'}   •   Risk: *{risk or '?'}*"
        ) + vuln_line()
    elif event_type == 'extension.installed':
        text = (f":new: *Extension installed* on *{hostname}*\n"
                f"• {ext_label}" + (f"  _{ide}_" if ide else "") +
                (f"\n• Publisher: {publisher}" if publisher else "")) + vuln_line()
    elif event_type == 'extension.updated':
        prev = ext.get('previous_version')
        text = (f":arrows_counterclockwise: *Extension updated* on *{hostname}*\n"
                f"• {ext_label}" + (f" (from {prev})" if prev else "") + (f"  _{ide}_" if ide else "")) + vuln_line()
    elif event_type == 'extension.removed':
        text = (f":wastebasket: *Extension removed* on *{hostname}*\n• {ext_label}" + (f"  _{ide}_" if ide else ""))
    elif event_type == 'secret.detected':
        sec = d.get('secret') or {}
        text = (f":key: *Plaintext secret detected* on *{hostname}*\n"
                f"• Type: *{sec.get('secret_type', '?')}*   •   Source: {sec.get('source', '?')}\n"
                f"• Location: `{sec.get('file_path', '?')}`"
                + (f" ({sec.get('variable_name')})" if sec.get('variable_name') else ""))
    elif event_type == 'extension.threat_matched':
        ind = ext.get('indicator_type', 'threat')
        detail = ext.get('detail', '')
        text = (f":no_entry_sign: *Threat-intel match* ({ind}) on *{hostname}*\n"
                f"• {ext_label}" + (f"  _{ide}_" if ide else "") +
                (f"\n• {detail}" if detail else ""))
    elif event_type == 'extension.unpublished_detected':
        text = f":package: *Extension removed from marketplace* — {ext_label} (host *{hostname}*)"
    elif event_type == 'tamper_alert.created':
        text = (f":rotating_light: *Tamper alert* [{d.get('severity', '?')}] on "
                f"*{hostname}*: {d.get('details', '')}")
    elif event_type in ('anomaly.new_risky_extension', 'anomaly.rapid_propagation'):
        emoji = ':globe_with_meridians:' if event_type.endswith('propagation') else ':warning:'
        text = (f"{emoji} *Fleet anomaly* — {d.get('details', event_type)}"
                + (f"  (`{d.get('extension_id')}`)" if d.get('extension_id') else ""))
    elif event_type == 'hook_bypass.detected':
        text = (f":no_entry: *Git hook bypass* on *{hostname}* — commit "
                f"`{(d.get('commit_hash') or '')[:10]}` by {d.get('commit_author', '?')}")
    elif event_type in ('enforcement.action_created', 'enforcement.completed'):
        action = d.get('action', 'enforcement')
        verb = 'requested' if event_type.endswith('created') else (d.get('status') or 'updated')
        detail = d.get('result_detail') or ''
        text = (f":lock: *Enforcement {action} {verb}* for {ext_label} on *{hostname}*"
                + (f" — {detail}" if detail else ""))
    else:
        text = f"*{event_type}*\n```{json.dumps(d, indent=2)[:1500]}```"

    return {"text": "IDEViewer — " + text}


def _pagerduty_payload(event_type: str, payload: dict, routing_key: str) -> dict:
    """Render an event as a PagerDuty Events API v2 'trigger' (with routing_key)."""
    d = payload.get('data') if isinstance(payload.get('data'), dict) else payload
    host = d.get('host') or {}
    hostname = host.get('hostname', 'unknown host')
    ext = d.get('extension') or {}
    ext_id = ext.get('extension_id') or ext.get('id') or ext.get('name') or ''

    summary = f"IDEViewer: {event_type} on {hostname}"
    if ext_id:
        summary += f" — {ext_id}"

    # PagerDuty severity must be one of critical|error|warning|info.
    risk = (ext.get('risk_level') or d.get('severity') or '').lower()
    severity = {'critical': 'critical', 'high': 'error',
                'medium': 'warning', 'low': 'info'}.get(risk, 'warning')

    return {
        'routing_key': routing_key,
        'event_action': 'trigger',
        'payload': {
            'summary': summary[:1024],
            'source': hostname,
            'severity': severity,
            'component': ext_id or 'ideviewer',
            'group': event_type.split('.')[0],
            'class': event_type,
            'custom_details': d,
        },
    }
