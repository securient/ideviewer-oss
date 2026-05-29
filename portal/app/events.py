"""Event dispatch for outbound webhooks (T2.1).

emit_event() is the only entry point callers should use. It resolves
matching subscriptions for the host's customer, persists a
WebhookDelivery row per subscription, and enqueues the first delivery
attempt. The actual HTTP send and retry scheduling live in
app.jobs.webhook_delivery.

Synchronous fallback: when Redis is unavailable, the delivery is
attempted inline (single attempt, no retries). This matches the rest of
the queue subsystem's degradation pattern.
"""
import logging
import uuid
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

logger = logging.getLogger(__name__)


def emit_event(
    event_type: str,
    customer_key_id: int,
    data: Dict[str, Any],
) -> List[int]:
    """Fan out an event to every matching active subscription.

    Returns the list of WebhookDelivery IDs created (empty if no
    subscription matched). Safe to call from request handlers; never
    raises on subscription/queue problems.
    """
    from app import db
    from app.models import WebhookSubscription, WebhookDelivery
    from app import queue as queue_module
    from app.jobs.webhook_delivery import deliver_webhook

    subscriptions = (
        WebhookSubscription.query
        .filter_by(customer_key_id=customer_key_id, is_active=True)
        .all()
    )
    matched = [s for s in subscriptions if s.matches_event(event_type)]
    if not matched:
        return []

    envelope = _build_envelope(event_type, data)
    delivery_ids: List[int] = []

    for sub in matched:
        delivery = WebhookDelivery(
            subscription_id=sub.id,
            event_id=envelope['id'],
            event_type=event_type,
            payload=envelope,
            status=WebhookDelivery.STATUS_PENDING,
        )
        db.session.add(delivery)
        db.session.flush()  # need delivery.id before enqueueing
        delivery_ids.append(delivery.id)

    db.session.commit()

    for did in delivery_ids:
        job = queue_module.enqueue(deliver_webhook, did, retry_max=0)
        if job is None:
            # Sync mode — best-effort inline delivery, single attempt.
            try:
                deliver_webhook(did)
            except Exception:
                logger.exception("inline webhook delivery failed (delivery_id=%s)", did)

    return delivery_ids


def _build_envelope(event_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
    return {
        'id': f'evt_{uuid.uuid4().hex}',
        'type': event_type,
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'data': data,
    }
