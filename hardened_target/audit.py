from datetime import datetime, timezone
import re
from threading import Lock
from typing import Any
from uuid import uuid4


_AUDIT_EVENTS: list[dict[str, Any]] = []
_AUDIT_LOCK = Lock()
_MAX_EVENTS = 500
_SENSITIVE_KEY_RE = re.compile(r"(?i)(password|secret|token|api[_-]?key|private[_-]?key|credential|authorization)")
_SECRET_VALUE_RE = re.compile(
    r"(?is)("
    r"\b[A-Z0-9_]*(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)[A-Z0-9_]*\s*=\s*[^\s]+"
    r"|\bsk-[A-Za-z0-9_-]{16,}\b"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----"
    r")"
)


def new_request_id() -> str:
    """Create a short correlation id for one chat request."""

    return uuid4().hex[:12]


def redact_audit_value(value: Any) -> Any:
    """Redact secret-like values before storing audit evidence."""

    if isinstance(value, dict):
        redacted = {}
        for key, item in value.items():
            key_text = str(key)
            redacted[key_text] = "[REDACTED_SECRET]" if _SENSITIVE_KEY_RE.search(key_text) else redact_audit_value(item)
        return redacted
    if isinstance(value, list):
        return [redact_audit_value(item) for item in value]
    if isinstance(value, str):
        return _SECRET_VALUE_RE.sub("[REDACTED_SECRET]", value)
    return value


def record_tool_decision(
    *,
    request_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    decision: str,
    reason: str,
    result: str = "",
) -> dict[str, Any]:
    """Store ALLOW/BLOCK tool gateway decisions without leaking full tool output."""

    event = {
        "id": uuid4().hex,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "event_type": "tool_gateway_decision",
        "decision": decision.upper(),
        "attempted_tool": tool_name,
        "arguments": redact_audit_value(arguments),
        "reason": reason,
        "result_preview": " ".join(result.split())[:300],
        "result_length": len(result),
    }

    with _AUDIT_LOCK:
        _AUDIT_EVENTS.append(event)
        del _AUDIT_EVENTS[:-_MAX_EVENTS]

    return event


def list_events(request_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
    """Return recent audit events, optionally filtered by request id."""

    with _AUDIT_LOCK:
        events = list(_AUDIT_EVENTS)

    if request_id:
        events = [event for event in events if event.get("request_id") == request_id]

    return events[-limit:]


def clear_events() -> int:
    """Clear audit events and return how many were removed."""

    with _AUDIT_LOCK:
        count = len(_AUDIT_EVENTS)
        _AUDIT_EVENTS.clear()

    return count
