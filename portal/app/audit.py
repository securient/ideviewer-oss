"""Audit logging + role-based access control helpers (Phase 1 B9).

``record_audit`` writes one append-only ``AuditLog`` row for a mutating action;
it is defensive and never raises, so audit failures can't break the action
being audited. ``require_role`` is a view decorator that enforces the RBAC tiers
on top of Flask-Login's ``login_required``.
"""
import functools
import logging

from flask import abort, request
from flask_login import current_user

logger = logging.getLogger("ideviewer.audit")


def record_audit(action, target_type=None, target_id=None, detail=None, commit=True):
    """Append an audit-log entry for the current user/request. Best-effort."""
    try:
        from app import db
        from app.models import AuditLog

        actor = "system"
        user_id = None
        if getattr(current_user, "is_authenticated", False):
            user_id = current_user.id
            actor = current_user.username or current_user.email

        entry = AuditLog(
            user_id=user_id,
            actor=actor,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            detail=detail,
            ip_address=request.remote_addr if request else None,
        )
        db.session.add(entry)
        if commit:
            db.session.commit()
        return entry
    except Exception as e:  # auditing must never break the audited action
        logger.error("failed to record audit entry for %s: %s", action, e)
        try:
            from app import db
            db.session.rollback()
        except Exception:
            pass
        return None


def require_role(*roles):
    """Decorator: 403 unless the logged-in user holds one of ``roles``.

    Use ``@login_required`` first, then ``@require_role('admin')``. Layers on
    top of the existing per-object ownership checks — it gates by capability,
    ownership still gates by tenant.
    """
    def decorator(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if not getattr(current_user, "is_authenticated", False):
                abort(401)
            if not current_user.has_role(*roles):
                logger.warning("RBAC denied: %s (role=%s) needs one of %s",
                               getattr(current_user, "username", "?"),
                               getattr(current_user, "role", "?"), roles)
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator
