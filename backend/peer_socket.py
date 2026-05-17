"""
Raw TCP socket server for peer-to-peer encrypted message delivery.

Architecture:
  - Each laptop runs this server on PEER_SOCKET_PORT (5010).
  - Sender machine opens a TCP socket to receiver's port 5010 and sends a JSON envelope.
  - Receiver runs BB84, detects attacks, decrypts, stores in inbox.
  - MITM: sender sends to attacker's port 5010; attacker logs the intercept, then
    opens a NEW socket to the real receiver — demonstrating the man-in-the-middle.
  - Replay: attacker resends a captured envelope; receiver detects duplicate nonce.
  - Eavesdrop: sender marks envelope with attackMode=eavesdrop; receiver runs BB84
    with eavesdropping simulation, causing high error rate.

Envelope JSON schema (sent over raw TCP):
  {
    "type": "message" | "relay",
    "packet": {                        # BB84-encrypted packet
      "payload": {"iv": "...", "ciphertext": "..."},
      "key":     "<hex AES key>",
      "nonce":   "<hex 32-char>",
      "timestamp": <float>,
      "route": ["SenderName", ...]
    },
    "senderName": "...",
    "senderIp":   "...",
    "attackMode": "normal|mitm|eavesdrop|replay",
    # Only for relay (MITM) envelopes:
    "targetIp":   "...",
    "targetPort": 5010,
  }

Response JSON schema:
  {
    "ok": true | false,
    "plaintext": "...",   # only on successful receive
    "attackDetected": false,
    "attackType": "",
    "errorRate": 0.04,
    "error": "..."         # only on failure
  }
"""

from __future__ import annotations

import json
import socket
import threading
import time
from secrets import token_hex

from . import attack_detector, bb84, config, crypto_utils, inbox, logger

# ─── Outbound: send a JSON envelope over a raw TCP socket ─────────────────────

def _send_envelope(host: str, port: int, envelope: dict) -> dict:
    """Open a TCP socket, send an envelope JSON, return the response JSON."""
    with socket.create_connection((host, port), timeout=config.SOCKET_TIMEOUT_SECONDS) as sock:
        data = json.dumps(envelope).encode("utf-8")
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)          # signal end-of-send
        chunks = []
        while True:
            chunk = sock.recv(config.SOCKET_BUFFER_SIZE)
            if not chunk:
                break
            chunks.append(chunk)
    return json.loads(b"".join(chunks).decode("utf-8"))


def send_message_to_peer(
    message: str,
    target_ip: str,
    target_port: int,
    attack_mode: str = "normal",
    relay_ip: str = "",
    relay_port: int = 0,
) -> dict:
    """
    Public API called by Flask when user clicks "Send Securely".
    Builds the BB84 packet, picks the routing strategy, delivers via raw TCP.
    """
    # BB84 key exchange + AES encrypt
    key_result = bb84.establish_key()
    payload = crypto_utils.encrypt_message(message, key_result.key)

    packet = {
        "payload": payload,
        "key": key_result.key.hex(),
        "nonce": token_hex(16),
        "timestamp": time.time(),
        "route": [config.MACHINE_NAME],
        "errorRate": key_result.error_rate,
    }

    logger.emit_event(
        "sender",
        f"[SEND] -> {target_ip}:{target_port}  mode={attack_mode}  key={key_result.key.hex()[:12]}",
        "info",
        phase="aes-encrypt",
        errorRate=key_result.error_rate,
        keyFingerprint=key_result.key.hex()[:12],
        plaintextLength=len(message),
        ivPreview=payload["iv"][:12],
        ciphertextPreview=payload["ciphertext"][:16],
    )

    # Route via MITM relay if attacker machine is specified
    if attack_mode in ("mitm", "eavesdrop", "replay") and relay_ip:
        envelope = {
            "type": "relay",
            "packet": packet,
            "senderName": config.MACHINE_NAME,
            "senderIp": config.LOCAL_IP,
            "attackMode": attack_mode,
            "targetIp": target_ip,
            "targetPort": target_port,
        }
        try:
            resp = _send_envelope(relay_ip, relay_port or config.PEER_SOCKET_PORT, envelope)
            return {"ok": True, "relay": True, "relayIp": relay_ip, "result": resp}
        except Exception as exc:
            logger.emit_event("sender", f"[ERR] Relay socket failed: {exc}", "error")
            return {"ok": False, "error": f"Relay socket failed: {exc}"}

    # Direct delivery
    envelope = {
        "type": "message",
        "packet": packet,
        "senderName": config.MACHINE_NAME,
        "senderIp": config.LOCAL_IP,
        "attackMode": attack_mode,
    }
    try:
        resp = _send_envelope(target_ip, target_port, envelope)
        return {"ok": True, "relay": False, "result": resp}
    except Exception as exc:
        logger.emit_event("sender", f"[ERR] Direct socket failed: {exc}", "error")
        return {"ok": False, "error": f"Direct socket failed: {exc}"}


# ─── Inbound handlers ─────────────────────────────────────────────────────────

def _handle_message(envelope: dict, peer_addr: str) -> dict:
    """Process a direct 'message' envelope — receiver side."""
    packet      = envelope.get("packet", {})
    sender_name = envelope.get("senderName", peer_addr)
    sender_ip   = envelope.get("senderIp", peer_addr)
    attack_mode = envelope.get("attackMode", "normal")

    # BB84 key exchange for this hop (simulates quantum channel)
    is_eavesdrop = attack_mode == "eavesdrop"
    is_mitm      = attack_mode == "mitm"

    key_result = bb84.establish_key(
        eavesdrop=is_eavesdrop,
        bit_flip_rate=config.EAVESDROP_BIT_FLIP_RATE if is_eavesdrop else 0.0,
    )
    error_rate = key_result.error_rate

    bb84_details = {
        "errorRate":      error_rate,
        "errorThreshold": config.ERROR_THRESHOLD,
        "matchingBases":  key_result.matching_bases,
        "siftedBits":     len(key_result.sifted_bits),
        "keyFingerprint": key_result.key.hex()[:12],
        "aliceBasisPreview": key_result.alice_basis_preview,
        "bobBasisPreview":   key_result.bob_basis_preview,
        "keepPreview":       key_result.keep_preview,
    }

    # ── Attack detection ───────────────────────────────────────────────────
    nonce  = str(packet.get("nonce", ""))
    nonce_result = attack_detector.register_nonce(nonce)

    attack_detected = False
    attack_type     = ""

    if not nonce_result.ok:
        attack_detected = True
        attack_type = "Replay Attack - duplicate nonce detected"
    elif is_mitm:
        attack_detected = True
        attack_type = "Man-in-the-Middle - packet was relayed through an attacker machine"
    elif attack_detector.is_error_rate_attack(error_rate):
        attack_detected = True
        attack_type = (
            f"Eavesdropping - BB84 error rate "
            f"{round(error_rate * 100)}% exceeded "
            f"{round(config.ERROR_THRESHOLD * 100)}% threshold"
        )

    if attack_detected:
        logger.emit_event(
            "receiver",
            f"[ATTACK] {attack_type}  from={sender_name}",
            "attack",
            phase="attack-detected",
            detectionReason=attack_type,
            errorRate=error_rate,
            errorThreshold=config.ERROR_THRESHOLD,
            senderName=sender_name,
            senderIp=sender_ip,
            aliceBasisPreview=key_result.alice_basis_preview,
            bobBasisPreview=key_result.bob_basis_preview,
            keepPreview=key_result.keep_preview,
            matchingBases=key_result.matching_bases,
            siftedBits=len(key_result.sifted_bits),
            comparedBits=key_result.compared_bits,
            generatedBits=key_result.generated_bits,
            keyFingerprint=key_result.key.hex()[:12],
        )
        inbox.add_message(
            plaintext="[MESSAGE BLOCKED - attack detected]",
            sender_name=sender_name,
            sender_ip=sender_ip,
            error_rate=error_rate,
            attack_detected=True,
            attack_type=attack_type,
            bb84_details=bb84_details,
        )
        return {
            "ok": False,
            "attackDetected": True,
            "attackType": attack_type,
            "errorRate": error_rate,
        }

    # Decrypt — packet["key"] is already a sha256-derived 32-byte key in hex;
    # pass raw bytes to avoid double-hashing inside derive_aes_key.
    try:
        key_bytes = bytes.fromhex(packet["key"])
        plaintext = crypto_utils.decrypt_message(packet["payload"], key_bytes)
    except Exception as exc:
        return {"ok": False, "error": f"Decryption failed: {exc}"}

    logger.emit_event(
        "receiver",
        f"[OK] Received from {sender_name}: {plaintext[:80]}",
        "success",
        phase="aes-decrypt",
        plaintextLength=len(plaintext),
        senderName=sender_name,
        senderIp=sender_ip,
        bb84Details=bb84_details,
    )

    inbox.add_message(
        plaintext=plaintext,
        sender_name=sender_name,
        sender_ip=sender_ip,
        error_rate=error_rate,
        attack_detected=False,
        bb84_details=bb84_details,
    )

    return {"ok": True, "plaintext": plaintext, "errorRate": error_rate}


def _handle_relay(envelope: dict, peer_addr: str) -> dict:
    """
    MITM relay handler — this machine is the attacker.
    Log the interception, then forward to the real target.
    """
    packet      = envelope.get("packet", {})
    sender_name = envelope.get("senderName", peer_addr)
    sender_ip   = envelope.get("senderIp", peer_addr)
    target_ip   = envelope.get("targetIp", "")
    target_port = int(envelope.get("targetPort", config.PEER_SOCKET_PORT))
    attack_mode = envelope.get("attackMode", "mitm")

    logger.emit_event(
        "node1",
        f"[MITM] Intercepted from {sender_name} -> forwarding to {target_ip}:{target_port}",
        "attack",
        phase="attack-detected",
        detectionReason="Packet routed through MITM relay machine",
        senderName=sender_name,
        senderIp=sender_ip,
        targetIp=target_ip,
        ciphertextPreview=packet.get("payload", {}).get("ciphertext", "")[:24],
        nonce=str(packet.get("nonce", ""))[:16],
    )

    if not target_ip:
        return {"ok": False, "error": "Relay has no target IP"}

    # Forward to the real receiver with relay metadata attached
    forward_envelope = {
        "type": "message",
        "packet": packet,
        "senderName": sender_name,
        "senderIp": sender_ip,
        "attackMode": attack_mode,       # "mitm" — receiver will detect it
        "relayName": config.MACHINE_NAME,
        "relayIp":   config.LOCAL_IP,
    }
    try:
        resp = _send_envelope(target_ip, target_port, forward_envelope)
        return {"ok": True, "relayed": True, "result": resp}
    except Exception as exc:
        logger.emit_event("node1", f"[ERR] Relay forward failed: {exc}", "error")
        return {"ok": False, "error": f"Relay forward failed: {exc}"}


def _handle_client(conn: socket.socket, peer_addr: tuple) -> None:
    """Handle one incoming TCP connection in its own thread."""
    addr_str = f"{peer_addr[0]}:{peer_addr[1]}"
    with conn:
        try:
            chunks = []
            while True:
                chunk = conn.recv(config.SOCKET_BUFFER_SIZE)
                if not chunk:
                    break
                chunks.append(chunk)
            raw = b"".join(chunks)
            if not raw:
                return
            envelope = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            err = json.dumps({"ok": False, "error": f"Bad envelope: {exc}"}).encode()
            conn.sendall(err)
            return

        msg_type = envelope.get("type", "message")
        try:
            if msg_type == "relay":
                response = _handle_relay(envelope, peer_addr[0])
            else:
                response = _handle_message(envelope, peer_addr[0])
        except Exception as exc:
            import traceback
            traceback.print_exc()
            response = {"ok": False, "error": f"Handler error: {exc}"}

        conn.sendall(json.dumps(response).encode("utf-8"))


# ─── Server ───────────────────────────────────────────────────────────────────

_server_thread: threading.Thread | None = None


def run_peer_server() -> None:
    """Blocking TCP server loop — call from a daemon thread."""
    port = config.PEER_SOCKET_PORT
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(config.SOCKET_BACKLOG)
        logger.emit_event("peer-server", f"Peer socket server listening on port {port}", "info")
        while True:
            conn, addr = srv.accept()
            t = threading.Thread(
                target=_handle_client, args=(conn, addr), daemon=True,
                name=f"peer-conn-{addr[0]}"
            )
            t.start()


def start_peer_server() -> None:
    """Start the peer socket server in a background daemon thread."""
    global _server_thread
    if _server_thread and _server_thread.is_alive():
        return
    _server_thread = threading.Thread(
        target=run_peer_server, daemon=True, name="peer-socket-server"
    )
    _server_thread.start()
