"""Entry point for sending plaintext into the multihop chain."""

from __future__ import annotations

import time
from secrets import token_hex

from . import attack_detector, bb84, config, crypto_utils, logger, node


def _key_fingerprint(key: bytes) -> str:
    return key.hex()[:12]


def _log_bb84(source: str, result: bb84.BB84Result) -> None:
    logger.emit_event(
        source,
        "BB84 generated matching bases and sifted a shared key",
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


def build_initial_packet(message: str) -> dict[str, object]:
    key_result = bb84.establish_key(
        eavesdrop=False,
        bit_flip_rate=0.0,
    )
    _log_bb84("sender", key_result)
    payload = crypto_utils.encrypt_message(message, key_result.key)
    logger.emit_event(
        "sender",
        "AES-CBC encrypted plaintext for first hop",
        "info",
        phase="aes-encrypt",
        plaintextLength=len(message),
        ivPreview=payload["iv"][:12],
        ciphertextPreview=payload["ciphertext"][:16],
        keyFingerprint=_key_fingerprint(key_result.key),
    )
    nonce = token_hex(16)
    packet = {
        "payload": payload,
        "key": key_result.key.hex(),
        "nonce": nonce,
        "timestamp": time.time(),
        "route": ["sender"],
        "errorRate": key_result.error_rate,
    }
    logger.emit_event("sender", "Sent encrypted packet", "success", errorRate=key_result.error_rate)
    return packet


def send_message(message: str, transport: node.Transport | None = None) -> str | None:
    packet = build_initial_packet(message)
    if attack_detector.get_attack_mode() == "replay":
        node.forward_packet("sender", packet, transport)
    return node.forward_packet("sender", packet, transport)
