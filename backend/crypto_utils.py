"""AES-256-CBC encryption helpers."""

from __future__ import annotations

import base64
import hmac
import hashlib
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE_BITS = 128
IV_SIZE_BYTES = 16


def derive_aes_key(key_material: bytes | str) -> bytes:
    if isinstance(key_material, str):
        try:
            key_material = bytes.fromhex(key_material)
        except ValueError:
            key_material = key_material.encode("utf-8")
    return hashlib.sha256(key_material).digest()


def encrypt_message(message: str, key_material: bytes | str) -> dict[str, str]:
    key = derive_aes_key(key_material)
    iv = os.urandom(IV_SIZE_BYTES)
    padder = padding.PKCS7(BLOCK_SIZE_BITS).padder()
    padded = padder.update(message.encode("utf-8")) + padder.finalize()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    tag = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
    return {
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }


def decrypt_message(payload: dict[str, str], key_material: bytes | str) -> str:
    key = derive_aes_key(key_material)
    iv = base64.b64decode(payload["iv"])
    ciphertext = base64.b64decode(payload["ciphertext"])
    if payload.get("tag"):
        expected_tag = hmac.new(key, iv + ciphertext, hashlib.sha256).digest()
        received_tag = base64.b64decode(payload["tag"])
        if not hmac.compare_digest(received_tag, expected_tag):
            raise ValueError("AES integrity check failed: ciphertext/tag mismatch")
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(BLOCK_SIZE_BITS).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode("utf-8")
