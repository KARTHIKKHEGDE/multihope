"""Final endpoint for decrypted messages."""

from __future__ import annotations

import json
import socket

from . import config, crypto_utils, logger


def receive_packet(packet: dict[str, object]) -> str:
    plaintext = crypto_utils.decrypt_message(packet["payload"], packet["key"])
    print(f"Received plaintext: {plaintext}", flush=True)
    logger.emit_event(
        "receiver",
        "AES-CBC decrypted final packet",
        "info",
        phase="aes-decrypt",
        plaintextLength=len(plaintext),
        ivPreview=packet["payload"]["iv"][:12],
        ciphertextPreview=packet["payload"]["ciphertext"][:16],
        keyFingerprint=str(packet["key"])[:12],
    )
    logger.emit_event("receiver", f"Received plaintext: {plaintext}", "success", plaintext=plaintext)
    return plaintext


def handle_client(client: socket.socket) -> None:
    with client:
        try:
            raw = client.recv(config.SOCKET_BUFFER_SIZE)
            if not raw:
                return
            packet = json.loads(raw.decode("utf-8"))
            event_start = len(logger.get_events())
            plaintext = receive_packet(packet)
            receiver_events = logger.get_events()[event_start:]
            response = {"ok": True, "plaintext": plaintext, "receiverEvents": receiver_events}
        except Exception as exc:
            logger.emit_event("receiver", f"Receiver socket packet failed: {exc}", "error")
            response = {"ok": False, "error": str(exc)}
        client.sendall(json.dumps(response).encode("utf-8"))


def run_receiver_server() -> None:
    port = config.NODE_PORTS["receiver"]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((config.HOST, port))
        server.listen(config.SOCKET_BACKLOG)
        logger.emit_event("receiver", f"Listening on port {port}", "info")
        while True:
            client, _address = server.accept()
            handle_client(client)


if __name__ == "__main__":
    run_receiver_server()
