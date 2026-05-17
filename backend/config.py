"""Central configuration for ports, hosts, thresholds, and demo defaults."""

HOST = "127.0.0.1"
RECEIVER_IP = HOST
API_PORT = 5000

NODE_PORTS = {
    "node1": 5001,
    "node2": 5002,
    "node3": 5003,
    "receiver": 5004,
}

SOCKET_BACKLOG = 5
SOCKET_BUFFER_SIZE = 65536
SOCKET_TIMEOUT_SECONDS = 5
ERROR_THRESHOLD = 0.15
NONCE_TTL_SECONDS = 60
BB84_SAMPLE_SIZE = 16
BB84_KEY_BITS = 256
EAVESDROP_BIT_FLIP_RATE = 1.0

VALID_ATTACK_MODES = {"normal", "mitm", "eavesdrop", "replay"}
VALID_TARGET_NODES = {"node1", "node2", "node3"}
