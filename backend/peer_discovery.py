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


def remember_peer(
    name: str,
    ip: str,
    port: int = config.API_PORT,
    socket_port: int = config.PEER_SOCKET_PORT,
) -> None:
    """Add or refresh a peer learned from discovery or an incoming socket message."""
    if not ip or ip == config.LOCAL_IP:
        return
    with _lock:
        _peers[ip] = {
            "name": name or ip,
            "ip": ip,
            "port": port,
            "socketPort": socket_port,
            "last_seen": time.time(),
        }


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
    broadcast_targets = [
        ("255.255.255.255", config.DISCOVERY_PORT),
        ("<broadcast>", config.DISCOVERY_PORT),
    ]
    if config.LOCAL_IP.count(".") == 3 and not config.LOCAL_IP.startswith("127."):
        parts = config.LOCAL_IP.split(".")
        broadcast_targets.append((".".join(parts[:3] + ["255"]), config.DISCOVERY_PORT))
    while _running:
        try:
            message = json.dumps({
                "name": config.MACHINE_NAME,
                "ip": config.LOCAL_IP,
                "port": config.API_PORT,
                "socketPort": config.PEER_SOCKET_PORT,
            }).encode("utf-8")
            for target in broadcast_targets:
                try:
                    sock.sendto(message, target)
                except Exception:
                    pass
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
            remember_peer(
                peer.get("name", addr[0]),
                peer.get("ip", addr[0]),
                int(peer.get("port", config.API_PORT)),
                int(peer.get("socketPort", config.PEER_SOCKET_PORT)),
            )
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
