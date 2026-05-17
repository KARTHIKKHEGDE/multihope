"""Central configuration for ports, hosts, thresholds, and demo defaults."""

import os
import socket

# Network settings - bind to all interfaces for LAN communication
HOST = "0.0.0.0"
API_PORT = 5000
PEER_SOCKET_PORT = 5010     # raw TCP socket used for laptop-to-laptop P2P messages


def get_local_ip():
    """Get the local IP address of this machine on the LAN."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


LOCAL_IP = get_local_ip()
MACHINE_NAME = os.environ.get("QH_NAME", socket.gethostname())

# Peer discovery via UDP broadcast
DISCOVERY_PORT = 5555
DISCOVERY_INTERVAL = 3  # seconds between broadcasts
PEER_TIMEOUT = 12  # seconds before considering a peer offline

# Node ports (kept for backward compat with local simulation)
NODE_PORTS = {
    "node1": 5001,
    "node2": 5002,
    "node3": 5003,
    "receiver": 5004,
}

SOCKET_BACKLOG = 5
SOCKET_BUFFER_SIZE = 65536
SOCKET_TIMEOUT_SECONDS = 5

# BB84 / crypto thresholds
ERROR_THRESHOLD = 0.15
NONCE_TTL_SECONDS = 60
BB84_SAMPLE_SIZE = 16
BB84_KEY_BITS = 256
EAVESDROP_BIT_FLIP_RATE = 1.0
RECEIVER_IP = HOST

VALID_ATTACK_MODES = {"normal", "mitm", "eavesdrop", "replay"}
VALID_TARGET_NODES = {"node1", "node2", "node3"}
