"""
Raw TCP socket server for peer-to-peer encrypted message delivery.

Architecture:
  - Each laptop runs this server on PEER_SOCKET_PORT (5010).
  - Sender machine opens a TCP socket to receiver's port 5010 and sends a JSON envelope.
  - Receiver runs BB84, detects attacks, decrypts, stores in inbox.
  - MITM: an in-path attacker tampers with ciphertext; receiver catches the
    modified bytes through AES/HMAC integrity verification.
  - Replay: attacker resends a captured envelope; receiver detects duplicate nonce.
  - Eavesdrop: BB84 measurements are disturbed, producing a high error rate.

Envelope JSON schema (sent over raw TCP):
  {
    "type": "message" | "relay",
    "packet": {                        # BB84-encrypted packet
      "payload": {"iv": "...", "ciphertext": "...", "tag": "..."},
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

import base64
import json
import socket
import threading
import time
from secrets import randbelow, token_hex

from . import attack_detector, bb84, config, crypto_utils, inbox, logger, peer_discovery


def _tamper_payload(payload: dict) -> dict:
    """Flip one ciphertext bit so AES/HMAC verification fails downstream."""
    tampered = dict(payload)
    ciphertext = bytearray(base64.b64decode(str(tampered.get("ciphertext", ""))))
    if ciphertext:
        ciphertext[0] ^= 0x01
    tampered["ciphertext"] = base64.b64encode(bytes(ciphertext)).decode("ascii")
    return tampered


def _build_route_steps(
    *,
    attack_mode: str,
    sender_name: str,
    sender_ip: str,
    target_name: str,
    target_ip: str,
    virtual_hops: list[dict],
    attack_hop: int | None,
    nonce: str,
    nonce_ok: bool,
    error_rate: float,
    attack_detected: bool,
    attack_type: str,
    bb84_details: dict,
) -> list[dict]:
    """Create a compact receiver-side explanation for the inbox timeline."""
    error_pct = round(error_rate * 100)
    threshold_pct = round(config.ERROR_THRESHOLD * 100)
    nonce_preview = nonce[:12] or "missing"
    steps = [{
        "node": "Sender laptop",
        "name": sender_name,
        "ip": sender_ip,
        "status": "success",
        "title": "Message encrypted",
        "detail": (
            f"Plain text was encrypted with AES. Packet nonce {nonce_preview}... and "
            f"mode={attack_mode} were added before sending."
        ),
    }]

    for hop in virtual_hops:
        hop_number = int(hop.get("number", 0))
        hop_attacked = attack_mode == "mitm" and hop_number == attack_hop
        if hop_attacked:
            title = "MITM tampered with ciphertext"
            detail = (
                "A man-in-the-middle modified the encrypted bytes in transit. "
                "The attacker cannot recompute the AES HMAC tag without the hop key."
            )
            status = "attack"
        elif attack_mode == "eavesdrop":
            title = "Quantum channel checked at this hop"
            detail = "Eavesdrop mode disturbs BB84 qubits while the packet crosses the route."
            status = "warning"
        elif attack_mode == "replay":
            title = "Packet forwarded"
            detail = "This hop forwards the same encrypted packet; the receiver will catch replay using the nonce."
            status = "warning"
        else:
            title = "Packet forwarded safely"
            detail = "No attack detected at this hop. The encrypted packet continues to the next hop."
            status = "success"

        steps.append({
            "node": f"Hop {hop_number}",
            "name": hop.get("name", f"Network hop {hop_number}"),
            "ip": hop.get("ip", ""),
            "status": status,
            "title": title,
            "detail": detail,
        })

    steps.append({
        "node": "Receiver check",
        "name": config.MACHINE_NAME,
        "ip": config.LOCAL_IP,
        "status": "success" if nonce_ok else "attack",
        "title": "Nonce replay check",
        "detail": (
            f"Nonce {nonce_preview}... was {'fresh' if nonce_ok else 'already seen in the replay cache'}."
        ),
    })

    if attack_detected:
        if attack_mode == "mitm":
            detail = (
                f"Blocked because ciphertext tampering from Hop {attack_hop} made the AES HMAC tag fail. "
                "The receiver did not trust attack metadata; it verified cryptographic integrity."
            )
        elif attack_mode == "replay":
            detail = f"Blocked because nonce {nonce_preview}... matched a recently received packet."
        else:
            detail = (
                f"Blocked because BB84 error rate was {error_pct}%, above the {threshold_pct}% threshold. "
                f"Matching bases: {bb84_details.get('matchingBases')}, sifted bits: {bb84_details.get('siftedBits')}."
            )
        steps.append({
            "node": "Receiver",
            "name": target_name or config.MACHINE_NAME,
            "ip": target_ip or config.LOCAL_IP,
            "status": "attack",
            "title": "Attack detected and message blocked",
        "detail": detail,
        "crypto": {
            "action": "blocked",
            "blockedReason": attack_type,
            "bb84": bb84_details,
            "note": "Receiver blocks only after nonce, BB84, or AES integrity verification fails.",
        },
    })
    else:
        steps.append({
            "node": "Receiver",
            "name": target_name or config.MACHINE_NAME,
            "ip": target_ip or config.LOCAL_IP,
            "status": "success",
            "title": "Packet verified and decrypted",
            "detail": (
                f"Nonce was fresh, BB84 error rate was {error_pct}% within the {threshold_pct}% threshold, "
                "and AES decryption succeeded."
            ),
        })

    return steps

# ─── Outbound: send a JSON envelope over a raw TCP socket ─────────────────────

def _bb84_details(result: bb84.BB84Result) -> dict:
    return {
        "errorRate": result.error_rate,
        "errorThreshold": config.ERROR_THRESHOLD,
        "matchingBases": result.matching_bases,
        "siftedBits": len(result.sifted_bits),
        "comparedBits": result.compared_bits,
        "generatedBits": result.generated_bits,
        "keyFingerprint": result.key.hex()[:12],
        "aliceBasisPreview": result.alice_basis_preview,
        "bobBasisPreview": result.bob_basis_preview,
        "aliceBitPreview": result.alice_bit_preview,
        "bobBitPreview": result.bob_bit_preview,
        "keepPreview": result.keep_preview,
        "siftedPreview": result.sifted_preview,
    }


def _crypto_details(
    *,
    packet: dict,
    receiver_bb84: dict,
    plaintext: str = "",
    decrypted: bool = False,
    blocked_reason: str = "",
) -> dict:
    payload = packet.get("payload", {})
    sender_bb84 = packet.get("routeMeta", {}).get("senderBb84", {})
    key_hex = str(packet.get("key", ""))
    return {
        "nonce": str(packet.get("nonce", "")),
        "attackMode": packet.get("routeMeta", {}).get("attackMode", ""),
        "aesKeyFingerprint": key_hex[:12],
        "aesKeyLengthBits": len(key_hex) * 4 if key_hex else 0,
        "ivPreview": str(payload.get("iv", ""))[:24],
        "ciphertextPreview": str(payload.get("ciphertext", ""))[:40],
        "tagPreview": str(payload.get("tag", ""))[:24],
        "senderPlaintextPreview": packet.get("routeMeta", {}).get("senderPlaintextPreview", ""),
        "plaintextPreview": plaintext[:80] if decrypted else "",
        "decrypted": decrypted,
        "blockedReason": blocked_reason,
        "senderBB84": sender_bb84,
        "receiverBB84": receiver_bb84,
        "nodeRouteSteps": packet.get("routeMeta", {}).get("nodeRouteSteps", []),
    }


def _packet_crypto(
    *,
    action: str,
    plaintext: str,
    payload: dict,
    key: bytes,
    bb84_result: bb84.BB84Result,
    decrypted_plaintext: str = "",
    note: str = "",
) -> dict:
    return {
        "action": action,
        "plaintextPreview": plaintext[:80],
        "decryptedPreview": decrypted_plaintext[:80],
        "aesKeyFingerprint": key.hex()[:12],
        "aesKeyLengthBits": len(key) * 8,
        "ivPreview": str(payload.get("iv", ""))[:24],
        "ciphertextPreview": str(payload.get("ciphertext", ""))[:40],
        "tagPreview": str(payload.get("tag", ""))[:24],
        "bb84": _bb84_details(bb84_result),
        "note": note,
    }


def _simulate_multihop_packet(message: str, attack_mode: str, nonce: str) -> tuple[dict, list[dict], int | None]:
    virtual_hops = [
        {"number": 1, "name": "Hop 1", "ip": "virtual-hop-1"},
        {"number": 2, "name": "Hop 2", "ip": "virtual-hop-2"},
        {"number": 3, "name": "Hop 3", "ip": "virtual-hop-3"},
    ]
    attack_hop = randbelow(3) + 1 if attack_mode == "mitm" else None
    steps: list[dict] = []

    current_plaintext = message
    current_key_result = bb84.establish_key()
    current_payload = crypto_utils.encrypt_message(current_plaintext, current_key_result.key)
    current_key = current_key_result.key
    blocked = False

    steps.append({
        "node": "Sender laptop",
        "name": config.MACHINE_NAME,
        "ip": config.LOCAL_IP,
        "status": "success",
        "title": "Encrypt for Hop 1",
        "detail": "Sender runs BB84, derives a fresh AES key, and encrypts the plaintext for the first hop.",
        "crypto": _packet_crypto(
            action="encrypt",
            plaintext=current_plaintext,
            payload=current_payload,
            key=current_key,
            bb84_result=current_key_result,
            note="Outbound packet: Sender -> Hop 1",
        ),
    })

    for hop in virtual_hops:
        hop_number = int(hop["number"])
        hop_attacked = attack_mode == "mitm" and hop_number == attack_hop

        if hop_attacked:
            tampered_payload = _tamper_payload(current_payload)
            steps.append({
                "node": f"Hop {hop_number}",
                "name": hop["name"],
                "ip": hop["ip"],
                "status": "attack",
                "title": "MITM modifies ciphertext",
                "detail": (
                    f"An attacker at Hop {hop_number} flips a ciphertext bit while forwarding the packet. "
                    "The AES HMAC tag is not updated because the attacker does not know the hop key."
                ),
                "crypto": _packet_crypto(
                    action="tamper",
                    plaintext=current_plaintext,
                    payload=tampered_payload,
                    key=current_key,
                    bb84_result=current_key_result,
                    note="Ciphertext was modified in transit; receiver should catch this by verifying HMAC before decrypting.",
                ),
            })
            current_payload = tampered_payload
            blocked = True
            break

        decrypted = crypto_utils.decrypt_message(current_payload, current_key)
        next_name = "Receiver" if hop_number == 3 else f"Hop {hop_number + 1}"
        next_key_result = bb84.establish_key(
            eavesdrop=attack_mode == "eavesdrop",
            bit_flip_rate=config.EAVESDROP_BIT_FLIP_RATE if attack_mode == "eavesdrop" else 0.0,
        )
        next_payload = crypto_utils.encrypt_message(decrypted, next_key_result.key)
        steps.append({
            "node": f"Hop {hop_number}",
            "name": hop["name"],
            "ip": hop["ip"],
            "status": "warning" if attack_mode in ("eavesdrop", "replay") else "success",
            "title": f"Decrypt and re-encrypt for {next_name}",
            "detail": (
                f"Hop {hop_number} decrypts the packet with the previous AES key, then runs BB84 again "
                f"and re-encrypts the same plaintext for {next_name}."
            ),
            "crypto": _packet_crypto(
                action="decrypt-reencrypt",
                plaintext=decrypted,
                payload=next_payload,
                key=next_key_result.key,
                bb84_result=next_key_result,
                decrypted_plaintext=decrypted,
                note=f"Outbound packet: Hop {hop_number} -> {next_name}",
            ),
        })
        current_plaintext = decrypted
        current_payload = next_payload
        current_key = next_key_result.key
        current_key_result = next_key_result

    route_meta = {
        "attackMode": attack_mode,
        "senderPlaintextPreview": message[:80],
        "virtualHops": virtual_hops,
        "attackHop": attack_hop,
        "nodeRouteSteps": steps,
        "finalBlockedInRoute": blocked,
        "ciphertextTampered": blocked,
        "finalBb84": _bb84_details(current_key_result),
    }
    packet = {
        "payload": current_payload,
        "key": current_key.hex(),
        "nonce": nonce,
        "timestamp": time.time(),
        "route": [config.MACHINE_NAME, "Hop 1", "Hop 2", "Hop 3"],
        "errorRate": current_key_result.error_rate,
        "routeMeta": route_meta,
    }
    return packet, steps, attack_hop


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


def _usable_sender_ip(sender_ip: str, peer_addr: str) -> str:
    """Prefer the real socket address when packet metadata is missing or loopback."""
    if not sender_ip or sender_ip.startswith("127.") or sender_ip == "0.0.0.0":
        return peer_addr
    return sender_ip


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
    nonce = token_hex(16)
    packet, route_steps, attack_hop = _simulate_multihop_packet(message, attack_mode, nonce)
    key_fingerprint = str(packet.get("key", ""))[:12]
    payload = packet.get("payload", {})

    logger.emit_event(
        "sender",
        f"[SEND] -> {target_ip}:{target_port}  mode={attack_mode}  key={key_fingerprint}",
        "info",
        phase="aes-encrypt",
        errorRate=packet.get("errorRate", 0),
        keyFingerprint=key_fingerprint,
        plaintextLength=len(message),
        ivPreview=str(payload.get("iv", ""))[:12],
        ciphertextPreview=str(payload.get("ciphertext", ""))[:16],
        virtualHops=packet.get("routeMeta", {}).get("virtualHops", []),
        attackHop=attack_hop,
        routeSteps=route_steps,
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
            if attack_mode == "replay":
                first_resp = _send_envelope(relay_ip, relay_port or config.PEER_SOCKET_PORT, envelope)
                second_resp = _send_envelope(relay_ip, relay_port or config.PEER_SOCKET_PORT, envelope)
                return {
                    "ok": True,
                    "relay": True,
                    "replayed": True,
                    "relayIp": relay_ip,
                    "firstResult": first_resp,
                    "result": second_resp,
                }
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
        if attack_mode == "replay":
            first_resp = _send_envelope(target_ip, target_port, envelope)
            second_resp = _send_envelope(target_ip, target_port, envelope)
            return {
                "ok": True,
                "relay": False,
                "replayed": True,
                "firstResult": first_resp,
                "result": second_resp,
            }
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
    sender_ip   = _usable_sender_ip(envelope.get("senderIp", ""), peer_addr)
    attack_mode = envelope.get("attackMode", "normal")
    relay_name  = envelope.get("relayName", "")
    relay_ip    = envelope.get("relayIp", "")
    route_meta  = packet.get("routeMeta", {})
    virtual_hops = route_meta.get("virtualHops") or [
        {"number": 1, "name": "Network hop 1", "ip": "virtual-hop-1"},
        {"number": 2, "name": "Network hop 2", "ip": "virtual-hop-2"},
        {"number": 3, "name": "Network hop 3", "ip": "virtual-hop-3"},
    ]
    attack_hop = route_meta.get("attackHop")
    peer_discovery.remember_peer(sender_name, sender_ip)

    # BB84 key exchange for this hop (simulates quantum channel)
    is_eavesdrop = attack_mode == "eavesdrop"
    key_result = bb84.establish_key(
        eavesdrop=is_eavesdrop,
        bit_flip_rate=config.EAVESDROP_BIT_FLIP_RATE if is_eavesdrop else 0.0,
    )
    error_rate = key_result.error_rate

    bb84_details = _bb84_details(key_result)

    # ── Attack detection ───────────────────────────────────────────────────
    nonce  = str(packet.get("nonce", ""))
    nonce_result = attack_detector.register_nonce(nonce)

    attack_detected = False
    attack_type     = ""

    if not nonce_result.ok:
        attack_detected = True
        attack_type = "Replay Attack - duplicate nonce detected"
    elif attack_detector.is_error_rate_attack(error_rate):
        attack_detected = True
        attack_type = (
            f"Eavesdropping - BB84 error rate "
            f"{round(error_rate * 100)}% exceeded "
            f"{round(config.ERROR_THRESHOLD * 100)}% threshold"
        )

    route_steps = list(route_meta.get("nodeRouteSteps") or [])
    if not route_steps:
        route_steps = _build_route_steps(
            attack_mode=attack_mode,
            sender_name=sender_name,
            sender_ip=sender_ip,
            target_name=config.MACHINE_NAME,
            target_ip=config.LOCAL_IP,
            virtual_hops=virtual_hops,
            attack_hop=attack_hop,
            nonce=nonce,
            nonce_ok=nonce_result.ok,
            error_rate=error_rate,
            attack_detected=attack_detected,
            attack_type=attack_type,
            bb84_details=bb84_details,
        )
    route_steps.append({
        "node": "Receiver check",
        "name": config.MACHINE_NAME,
        "ip": config.LOCAL_IP,
        "status": "success" if nonce_result.ok else "attack",
        "title": "Nonce and mode check",
        "detail": (
            f"Receiver checks nonce {nonce[:12]}... before decryption. "
            f"Nonce is {'fresh' if nonce_result.ok else 'a duplicate'}. Mode is shown only for the demo trace, not trusted as proof."
        ),
        "crypto": {
            "action": "inspect",
            "nonce": nonce,
            "mode": attack_mode,
            "note": "Replay detection happens before final decryption; attack mode metadata is not used as MITM proof.",
        },
    })

    if attack_detected:
        route_steps.append({
            "node": "Receiver laptop",
            "name": config.MACHINE_NAME,
            "ip": config.LOCAL_IP,
            "status": "attack",
            "title": "Blocked before final decryption",
            "detail": f"Receiver refuses to decrypt because: {attack_type}.",
            "crypto": {
                "action": "blocked",
                "blockedReason": attack_type,
                "bb84": bb84_details,
                "note": "No plaintext is released at receiver.",
            },
        })
        crypto_details = _crypto_details(
            packet=packet,
            receiver_bb84=bb84_details,
            decrypted=False,
            blocked_reason=attack_type,
        )
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
            routeSteps=route_steps,
            cryptoDetails=crypto_details,
        )
        inbox.add_message(
            plaintext="[MESSAGE BLOCKED - attack detected]",
            sender_name=sender_name,
            sender_ip=sender_ip,
            error_rate=error_rate,
            attack_detected=True,
            attack_type=attack_type,
            relay_name=relay_name,
            relay_ip=relay_ip,
            bb84_details=bb84_details,
            route_steps=route_steps,
            crypto_details=crypto_details,
        )
        return {
            "ok": False,
            "attackDetected": True,
            "attackType": attack_type,
            "errorRate": error_rate,
            "routeSteps": route_steps,
            "bb84Details": bb84_details,
            "cryptoDetails": crypto_details,
        }

    # Decrypt — packet["key"] is already a sha256-derived 32-byte key in hex;
    # pass raw bytes to avoid double-hashing inside derive_aes_key.
    try:
        key_bytes = bytes.fromhex(packet["key"])
        plaintext = crypto_utils.decrypt_message(packet["payload"], key_bytes)
    except Exception as exc:
        attack_type = (
            "Man-in-the-Middle - AES integrity check failed"
            if attack_mode == "mitm"
            else f"Decryption failed: {exc}"
        )
        route_steps.append({
            "node": "Receiver laptop",
            "name": config.MACHINE_NAME,
            "ip": config.LOCAL_IP,
            "status": "attack",
            "title": "AES integrity check failed",
            "detail": (
                "Receiver recalculated the AES HMAC over IV + ciphertext before releasing plaintext. "
                f"The check failed: {exc}. This means the encrypted bytes were modified or the wrong key was used."
            ),
            "crypto": {
                "action": "blocked",
                "blockedReason": attack_type,
                "payload": packet.get("payload", {}),
                "aesKeyFingerprint": str(packet.get("key", ""))[:12],
                "aesKeyLengthBits": len(str(packet.get("key", ""))) * 4,
                "bb84": packet.get("routeMeta", {}).get("finalBb84", bb84_details),
                "note": "No plaintext is released when AES HMAC verification fails.",
            },
        })
        crypto_details = _crypto_details(
            packet=packet,
            receiver_bb84=bb84_details,
            decrypted=False,
            blocked_reason=attack_type,
        )
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
            routeSteps=route_steps,
            cryptoDetails=crypto_details,
            ciphertextTampered=attack_mode == "mitm",
            integrityTagPresent=bool(packet.get("payload", {}).get("tag")),
        )
        inbox.add_message(
            plaintext="[MESSAGE BLOCKED - attack detected]",
            sender_name=sender_name,
            sender_ip=sender_ip,
            error_rate=error_rate,
            attack_detected=True,
            attack_type=attack_type,
            relay_name=relay_name,
            relay_ip=relay_ip,
            bb84_details=bb84_details,
            route_steps=route_steps,
            crypto_details=crypto_details,
        )
        return {
            "ok": False,
            "attackDetected": True,
            "attackType": attack_type,
            "errorRate": error_rate,
            "routeSteps": route_steps,
            "bb84Details": bb84_details,
            "cryptoDetails": crypto_details,
        }

    route_steps.append({
        "node": "Receiver laptop",
        "name": config.MACHINE_NAME,
        "ip": config.LOCAL_IP,
        "status": "success",
        "title": "Final decrypt",
        "detail": "Receiver decrypts the final Hop 3 -> Receiver packet and recovers the original plaintext.",
        "crypto": {
            "action": "decrypt-final",
            "decryptedPreview": plaintext[:80],
            "payload": packet.get("payload", {}),
            "aesKeyFingerprint": str(packet.get("key", ""))[:12],
            "aesKeyLengthBits": len(str(packet.get("key", ""))) * 4,
            "bb84": packet.get("routeMeta", {}).get("finalBb84", bb84_details),
            "note": "Inbound packet: Hop 3 -> Receiver",
        },
    })

    crypto_details = _crypto_details(
        packet=packet,
        receiver_bb84=bb84_details,
        plaintext=plaintext,
        decrypted=True,
    )

    logger.emit_event(
        "receiver",
        f"[OK] Received from {sender_name}: {plaintext[:80]}",
        "success",
        phase="aes-decrypt",
        plaintextLength=len(plaintext),
        senderName=sender_name,
        senderIp=sender_ip,
        bb84Details=bb84_details,
        routeSteps=route_steps,
        cryptoDetails=crypto_details,
    )

    inbox.add_message(
        plaintext=plaintext,
        sender_name=sender_name,
        sender_ip=sender_ip,
        error_rate=error_rate,
        attack_detected=False,
        relay_name=relay_name,
        relay_ip=relay_ip,
        bb84_details=bb84_details,
        route_steps=route_steps,
        crypto_details=crypto_details,
    )

    return {
        "ok": True,
        "plaintext": plaintext,
        "errorRate": error_rate,
        "routeSteps": route_steps,
        "bb84Details": bb84_details,
        "cryptoDetails": crypto_details,
    }


def _handle_relay(envelope: dict, peer_addr: str) -> dict:
    """
    MITM relay handler — this machine is the attacker.
    Log the interception, then forward to the real target.
    """
    packet      = envelope.get("packet", {})
    sender_name = envelope.get("senderName", peer_addr)
    sender_ip   = _usable_sender_ip(envelope.get("senderIp", ""), peer_addr)
    peer_discovery.remember_peer(sender_name, sender_ip)
    target_ip   = envelope.get("targetIp", "")
    target_port = int(envelope.get("targetPort", config.PEER_SOCKET_PORT))
    attack_mode = envelope.get("attackMode", "mitm")

    logger.emit_event(
        "node1",
        f"[MITM] Intercepted from {sender_name} -> forwarding to {target_ip}:{target_port}",
        "attack",
        phase="attack-detected",
        detectionReason="Relay intercepted the encrypted packet and may tamper with ciphertext",
        senderName=sender_name,
        senderIp=sender_ip,
        targetIp=target_ip,
        ciphertextPreview=packet.get("payload", {}).get("ciphertext", "")[:24],
        nonce=str(packet.get("nonce", ""))[:16],
    )

    if not target_ip:
        return {"ok": False, "error": "Relay has no target IP"}

    forwarded_packet = dict(packet)
    route_meta = dict(forwarded_packet.get("routeMeta", {}))
    if attack_mode == "mitm" and not route_meta.get("ciphertextTampered"):
        forwarded_packet["payload"] = _tamper_payload(forwarded_packet.get("payload", {}))
        route_meta["ciphertextTampered"] = True
        route_meta["relayTamperedBy"] = config.MACHINE_NAME
        forwarded_packet["routeMeta"] = route_meta

    # Forward to the real receiver with relay identity attached for display only.
    forward_envelope = {
        "type": "message",
        "packet": forwarded_packet,
        "senderName": sender_name,
        "senderIp": sender_ip,
        "attackMode": attack_mode,
        "relayName": config.MACHINE_NAME,
        "relayIp": config.LOCAL_IP,
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
