import hashlib
import json
import logging

from .throttling import get_client_ip

audit_logger = logging.getLogger("igihozo.audit")


def hash_identifier(value):
    normalized = (value or "").strip().lower()
    if not normalized:
        return ""
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:12]


def log_security_event(
    event,
    *,
    request=None,
    actor=None,
    actor_username=None,
    target_user=None,
    target_username=None,
    outcome="success",
    details=None,
):
    payload = {
        "event": event,
        "outcome": outcome,
        "actor_username": actor_username or getattr(actor, "username", None),
        "target_username": target_username or getattr(target_user, "username", None),
        "client_ip": get_client_ip(request) if request else None,
        "path": request.path if request else None,
        "method": request.method if request else None,
        "details": details or {},
    }
    audit_logger.info(json.dumps(payload, sort_keys=True))
