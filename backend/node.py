"""Generic hop: receive, decrypt, rekey, encrypt, and forward."""

from __future__ import annotations

import json
import socket
import time
from secrets import token_hex
from typing import Callable

from . import attack_detector, bb84, config, crypto_utils, logger, receiver, router

Transport = Callable[[str, dict[str, object]], str | None]


def _key_fingerprint(key: bytes | str) -> str:
    if isinstance(key, bytes):
        return key.hex()[:12]
    return key[:12]


def _log_bb84(node_name: str, result: bb84.BB84Result) -> None:
    logger.emit_event(
        node_name,
        "BB84 rekey completed for next hop",
        "info",
        phase="bb84",
        generatedBits=result.generated_bits,
        matchingBases=result.matching_bases,
        siftedBits=len(result.sifted_bits),
        comparedBits=result.compared_bits,
        errorRate=result.error_rate,
        errorThreshold=config.ERROR_THRESHOLD,
        aliceBasisPreview=result.alice_basis_preview,
        bobBasisPreview=result.bob_basis_preview,
        aliceBitPreview=result.alice_bit_preview,
        bobBitPreview=result.bob_bit_preview,
        keepPreview=result.keep_preview,
        siftedPreview=result.sifted_preview,
        keyFingerprint=_key_fingerprint(result.key),
    )


def process_packet(node_name: str, packet: dict[str, object]) -> dict[str, object] | None:
    mode = attack_detector.get_attack_mode()
    is_target = attack_detector.is_target_node(node_name)

    # Only apply eavesdrop distortion on the targeted node
    eavesdrop_here = mode == "eavesdrop" and is_target
    key_result = bb84.establish_key(
        eavesdrop=eavesdrop_here,
        bit_flip_rate=config.EAVESDROP_BIT_FLIP_RATE if eavesdrop_here else 0.0,
    )
    _log_bb84(node_name, key_result)

    # Only inspect for MITM flag if this is the target node
    mitm_flag = bool(packet.get("mitm")) and is_target
    detection = attack_detector.inspect_packet(
        str(packet["nonce"]),
        key_result.error_rate,
        mitm_flag=mitm_flag,
    )

    if not detection.ok:
        router.block_node(node_name)
        # Store the intercepted data for the MITM challenge panel
        attack_detector.store_intercepted({
            "node": node_name,
            "ciphertextPreview": packet["payload"].get("ciphertext", "")[:32],
            "ivPreview": packet["payload"].get("iv", "")[:16],
            "realKeyFingerprint": _key_fingerprint(packet["key"]),
            "errorRate": key_result.error_rate,
            "reason": detection.reason,
        })
        logger.emit_event(
            node_name,
            detection.reason,
            "attack",
            phase="attack-detected",
            detectionReason=detection.reason,
            errorRate=key_result.error_rate,
            errorThreshold=config.ERROR_THRESHOLD,
            noncePreview=str(packet["nonce"])[:12],
            blockedNode=node_name,
        )
        return None

    plaintext = crypto_utils.decrypt_message(packet["payload"], packet["key"])
    logger.emit_event(
        node_name,
        "AES-CBC decrypted packet from previous hop",
        "info",
        phase="aes-decrypt",
        plaintextLength=len(plaintext),
        ivPreview=packet["payload"]["iv"][:12],
        ciphertextPreview=packet["payload"]["ciphertext"][:16],
        keyFingerprint=_key_fingerprint(packet["key"]),
    )

    # If MITM mode and this is the target, store intercepted data for the challenge
    if mode == "mitm" and is_target:
        attack_detector.store_intercepted({
            "node": node_name,
            "ciphertextPreview": packet["payload"].get("ciphertext", "")[:32],
            "ivPreview": packet["payload"].get("iv", "")[:16],
            "realKeyFingerprint": _key_fingerprint(packet["key"]),
            "plaintextLength": len(plaintext),
            "errorRate": key_result.error_rate,
        })

    next_key = key_result.key
    next_payload = crypto_utils.encrypt_message(plaintext, next_key)
    logger.emit_event(
        node_name,
        "AES-CBC encrypted packet for next hop",
        "info",
        phase="aes-encrypt",
        plaintextLength=len(plaintext),
        ivPreview=next_payload["iv"][:12],
        ciphertextPreview=next_payload["ciphertext"][:16],
        keyFingerprint=_key_fingerprint(next_key),
    )
    logger.emit_event(node_name, "Forwarded encrypted packet", "success", errorRate=key_result.error_rate)
    return {
        **packet,
        "payload": next_payload,
        "key": next_key.hex(),
        "nonce": token_hex(16),
        "timestamp": time.time(),
        "route": [*packet.get("route", []), node_name],
        "errorRate": key_result.error_rate,
    }


def send_packet_to_receiver(packet: dict[str, object]) -> str | None:
    address = (config.RECEIVER_IP, config.NODE_PORTS["receiver"])
    try:
        with socket.create_connection(address, timeout=config.SOCKET_TIMEOUT_SECONDS) as client:
            client.sendall(json.dumps(packet).encode("utf-8"))
            raw = client.recv(config.SOCKET_BUFFER_SIZE)
        response = json.loads(raw.decode("utf-8"))
        if response.get("ok"):
            for event in response.get("receiverEvents", []):
                metadata = {
                    key: value
                    for key, value in event.items()
                    if key not in {"time", "source", "message", "status"}
                }
                logger.emit_event(
                    event.get("source", "receiver"),
                    event.get("message", "Receiver processed packet"),
                    event.get("status", "info"),
                    **metadata,
                )
            logger.emit_event("node3", "Delivered packet to remote receiver", "success")
            return response.get("plaintext")
        logger.emit_event("node3", f"Remote receiver rejected packet: {response.get('error')}", "error")
    except Exception as exc:
        logger.emit_event("node3", f"Remote receiver delivery failed: {exc}", "error")
    return None


def forward_packet(source: str, packet: dict[str, object], transport: Transport | None = None) -> str | None:
    next_hop = router.get_next_hop(source)
    if next_hop is None:
        return None
    if next_hop == "receiver":
        if transport:
            return transport(next_hop, packet)
        return send_packet_to_receiver(packet)
    processed = process_packet(next_hop, packet)
    if processed is None:
        return None
    return forward_packet(next_hop, processed, transport)


def handle_client(client: socket.socket, node_name: str) -> None:
    with client:
        raw = client.recv(config.SOCKET_BUFFER_SIZE)
        if not raw:
            return
        try:
            packet = json.loads(raw.decode("utf-8"))
            processed = process_packet(node_name, packet)
            response = {"ok": bool(processed), "packet": processed}
        except Exception as exc:
            logger.emit_event(node_name, f"Socket packet failed: {exc}", "error")
            response = {"ok": False, "error": str(exc)}
        client.sendall(json.dumps(response).encode("utf-8"))


def run_node_server(node_name: str) -> None:
    port = config.NODE_PORTS[node_name]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((config.HOST, port))
        server.listen(config.SOCKET_BACKLOG)
        logger.emit_event(node_name, f"Listening on port {port}", "info")
        while True:
            client, _address = server.accept()
            handle_client(client, node_name)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Run a generic multihop node")
    parser.add_argument("node_name", choices=("node1", "node2", "node3"))
    args = parser.parse_args()
    run_node_server(args.node_name)
