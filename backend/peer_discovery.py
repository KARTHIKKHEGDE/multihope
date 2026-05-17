"""UDP broadcast-based peer discovery for LAN."""

from __future__ import annotations

import json
import socket
import threading
import time

from . import config

_peers: dict[str, dict] = {}
_lock = threading.Lock()
_running = False


def get_peers() -> list[dict]:
    """Get list of currently online peers (excluding self)."""
    now = time.time()
    with _lock:
        stale = [ip for ip, p in _peers.items() if now - p["last_seen"] > config.PEER_TIMEOUT]
        for ip in stale:
            del _peers[ip]
        return [
            {
                "name": p["name"],
                "ip": p["ip"],
                "port": p["port"],
                "socketPort": p.get("socketPort", config.PEER_SOCKET_PORT),
                "relay": p.get("relay", False)
            }
            for p in _peers.values()
            if p["ip"] != config.LOCAL_IP
        ]


def _broadcast_loop():
    """Periodically broadcast our presence on the LAN."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while _running:
        try:
            message = json.dumps({
                "name": config.MACHINE_NAME,
                "ip": config.LOCAL_IP,
                "port": config.API_PORT,
                "socketPort": config.PEER_SOCKET_PORT,
            }).encode("utf-8")
            sock.sendto(message, ("<broadcast>", config.DISCOVERY_PORT))
        except Exception:
            pass
        time.sleep(config.DISCOVERY_INTERVAL)
    sock.close()


def _listen_loop():
    """Listen for peer broadcasts."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(2.0)
    try:
        sock.bind(("", config.DISCOVERY_PORT))
    except OSError:
        return
    while _running:
        try:
            data, addr = sock.recvfrom(1024)
            peer = json.loads(data.decode("utf-8"))
            peer["last_seen"] = time.time()
            if peer["ip"] != config.LOCAL_IP:
                with _lock:
                    _peers[peer["ip"]] = peer
        except socket.timeout:
            continue
        except Exception:
            pass
    sock.close()


def start_discovery():
    """Start broadcast and listen threads."""
    global _running
    if _running:
        return
    _running = True
    threading.Thread(target=_broadcast_loop, daemon=True, name="peer-broadcast").start()
    threading.Thread(target=_listen_loop, daemon=True, name="peer-listen").start()


def stop_discovery():
    """Stop discovery threads."""
    global _running
    _running = False
