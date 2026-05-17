"""Attack mode, target node selection, and packet inspection logic."""

from __future__ import annotations

import time
from dataclasses import dataclass

from . import config

_attack_mode = "normal"
_target_node = "node1"
_seen_nonces: dict[str, float] = {}
_last_intercepted: dict[str, object] | None = None


@dataclass(frozen=True)
class DetectionResult:
    ok: bool
    status: str
    reason: str


def set_attack_mode(mode: str) -> str:
    if mode not in config.VALID_ATTACK_MODES:
        raise ValueError(f"unknown attack mode: {mode}")
    global _attack_mode
    _attack_mode = mode
    return _attack_mode


def get_attack_mode() -> str:
    return _attack_mode


def set_target_node(node: str) -> str:
    if node not in config.VALID_TARGET_NODES:
        raise ValueError(f"invalid target node: {node}")
    global _target_node
    _target_node = node
    return _target_node


def get_target_node() -> str:
    return _target_node


def is_target_node(node_name: str) -> bool:
    """Return True if this node is the one the attacker is targeting."""
    return _attack_mode != "normal" and node_name == _target_node


def store_intercepted(data: dict[str, object]) -> None:
    global _last_intercepted
    _last_intercepted = data


def get_intercepted() -> dict[str, object] | None:
    return _last_intercepted


def clear_intercepted() -> None:
    global _last_intercepted
    _last_intercepted = None


def reset_detector() -> None:
    global _attack_mode, _target_node, _last_intercepted
    _attack_mode = "normal"
    _target_node = "node1"
    _last_intercepted = None
    _seen_nonces.clear()


def is_error_rate_attack(error_rate: float, threshold: float = config.ERROR_THRESHOLD) -> bool:
    return error_rate > threshold


def _prune_nonces(now: float) -> None:
    expired = [nonce for nonce, seen_at in _seen_nonces.items() if now - seen_at > config.NONCE_TTL_SECONDS]
    for nonce in expired:
        del _seen_nonces[nonce]


def register_nonce(nonce: str, timestamp: float | None = None) -> DetectionResult:
    now = time.time() if timestamp is None else timestamp
    _prune_nonces(now)
    if nonce in _seen_nonces:
        return DetectionResult(False, "attack", "replay nonce detected")
    _seen_nonces[nonce] = now
    return DetectionResult(True, "ok", "nonce accepted")


def inspect_packet(nonce: str, error_rate: float) -> DetectionResult:
    nonce_result = register_nonce(nonce)
    if not nonce_result.ok:
        return nonce_result
    if is_error_rate_attack(error_rate):
        return DetectionResult(False, "attack", "BB84 error rate exceeded threshold")
    return DetectionResult(True, "ok", "packet accepted")
