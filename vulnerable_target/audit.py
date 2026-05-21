from datetime import datetime, timezone
from threading import Lock
from typing import Any
from uuid import uuid4


_AUDIT_EVENTS: list[dict[str, Any]] = []
_AUDIT_LOCK = Lock()
_MAX_EVENTS = 500


def new_request_id() -> str:
    """Create a short correlation id for one chat request."""

    return uuid4().hex[:12]


def record_tool_call(
    *,
    request_id: str,
    tool_name: str,
    arguments: dict[str, Any],
    result: str,
) -> dict[str, Any]:
    """Store a compact audit event for an agent tool invocation."""

    event = {
        "id": uuid4().hex,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id,
        "event_type": "tool_call",
        "tool_name": tool_name,
        "arguments": arguments,
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
