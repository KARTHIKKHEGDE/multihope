"""In-memory structured event store for API polling."""

from __future__ import annotations

from datetime import datetime, timezone
from threading import Lock
from typing import Any

_events: list[dict[str, Any]] = []
_lock = Lock()


def emit_event(source: str, message: str, status: str = "info", **extra: Any) -> dict[str, Any]:
    event = {
        "time": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "message": message,
        "status": status,
        **extra,
    }
    with _lock:
        _events.append(event)
    return event


def get_events() -> list[dict[str, Any]]:
    with _lock:
        return list(_events)


def clear_events() -> None:
    with _lock:
        _events.clear()

