"""In-memory inbox for received messages and security alerts."""

from __future__ import annotations

import threading
import time
from typing import Any

_messages: list[dict[str, Any]] = []
_lock = threading.Lock()


def add_message(
    plaintext: str,
    sender_name: str,
    sender_ip: str,
    error_rate: float,
    attack_detected: bool = False,
    attack_type: str = "",
    relay_name: str = "",
    relay_ip: str = "",
    bb84_details: dict | None = None,
    route_steps: list[dict[str, Any]] | None = None,
    crypto_details: dict | None = None,
) -> dict[str, Any]:
    """Store a received message with its security metadata."""
    msg = {
        "id": len(_messages) + 1,
        "plaintext": plaintext,
        "senderName": sender_name,
        "senderIp": sender_ip,
        "errorRate": error_rate,
        "attackDetected": attack_detected,
        "attackType": attack_type,
        "relayName": relay_name,
        "relayIp": relay_ip,
        "bb84Details": bb84_details or {},
        "routeSteps": route_steps or [],
        "cryptoDetails": crypto_details or {},
        "receivedAt": time.time(),
        "receivedAtISO": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    with _lock:
        _messages.append(msg)
    return msg


def get_messages() -> list[dict[str, Any]]:
    """Return all received messages."""
    with _lock:
        return list(_messages)


def clear() -> None:
    """Clear all messages."""
    with _lock:
        _messages.clear()
