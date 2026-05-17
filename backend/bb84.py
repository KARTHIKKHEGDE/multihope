"""BB84 quantum key exchange simulation."""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass

from . import config

BASES = ("+", "x")


@dataclass(frozen=True)
class BB84Result:
    key: bytes
    error_rate: float
    accepted: bool
    sifted_bits: list[int]
    compared_bits: int
    generated_bits: int
    matching_bases: int
    alice_basis_preview: str
    bob_basis_preview: str
    alice_bit_preview: str
    bob_bit_preview: str
    keep_preview: str
    sifted_preview: str


def generate_bits(count: int) -> list[int]:
    return [random.randint(0, 1) for _ in range(count)]


def generate_bases(count: int) -> list[str]:
    return [random.choice(BASES) for _ in range(count)]


def measure_bits(
    alice_bits: list[int],
    alice_bases: list[str],
    bob_bases: list[str],
    eavesdrop: bool = False,
    bit_flip_rate: float = 0.0,
) -> list[int]:
    if not (len(alice_bits) == len(alice_bases) == len(bob_bases)):
        raise ValueError("bit and basis lists must be the same length")

    eve_bases = generate_bases(len(alice_bits)) if eavesdrop else alice_bases
    measured: list[int] = []
    for bit, alice_basis, eve_basis, bob_basis in zip(alice_bits, alice_bases, eve_bases, bob_bases):
        transmitted = bit if alice_basis == eve_basis else random.randint(0, 1)
        measured_bit = transmitted if eve_basis == bob_basis else random.randint(0, 1)
        if bit_flip_rate and random.random() < bit_flip_rate:
            measured_bit = 1 - measured_bit
        measured.append(measured_bit)
    return measured


def sift_key(alice_bits: list[int], bob_bits: list[int], alice_bases: list[str], bob_bases: list[str]) -> tuple[list[int], list[int]]:
    if not (len(alice_bits) == len(bob_bits) == len(alice_bases) == len(bob_bases)):
        raise ValueError("bit and basis lists must be the same length")
    alice_sifted: list[int] = []
    bob_sifted: list[int] = []
    for alice_bit, bob_bit, alice_basis, bob_basis in zip(alice_bits, bob_bits, alice_bases, bob_bases):
        if alice_basis == bob_basis:
            alice_sifted.append(alice_bit)
            bob_sifted.append(bob_bit)
    return alice_sifted, bob_sifted


def calculate_error_rate(alice_sifted: list[int], bob_sifted: list[int], sample_size: int | None = None) -> float:
    if len(alice_sifted) != len(bob_sifted):
        raise ValueError("sifted key lists must be the same length")
    if not alice_sifted:
        return 1.0
    comparisons = min(sample_size or len(alice_sifted), len(alice_sifted))
    errors = sum(1 for left, right in zip(alice_sifted[:comparisons], bob_sifted[:comparisons]) if left != right)
    return errors / comparisons


def derive_key(bits: list[int]) -> bytes:
    if not bits:
        raise ValueError("cannot derive a key from no bits")
    bit_string = "".join(str(bit) for bit in bits)
    return hashlib.sha256(bit_string.encode("ascii")).digest()


def _preview(values: list[int] | list[str], limit: int = 16) -> str:
    return "".join(str(value) for value in values[:limit])


def _keep_preview(alice_bases: list[str], bob_bases: list[str], limit: int = 16) -> str:
    return "".join("Y" if alice == bob else "N" for alice, bob in zip(alice_bases[:limit], bob_bases[:limit]))


def establish_key(
    requested_key_bits: int = config.BB84_KEY_BITS,
    threshold: float = config.ERROR_THRESHOLD,
    eavesdrop: bool = False,
    bit_flip_rate: float = 0.0,
) -> BB84Result:
    rounds = max(requested_key_bits * 4, config.BB84_SAMPLE_SIZE * 4)
    alice_bits = generate_bits(rounds)
    alice_bases = generate_bases(rounds)
    bob_bases = generate_bases(rounds)
    bob_bits = measure_bits(alice_bits, alice_bases, bob_bases, eavesdrop=eavesdrop, bit_flip_rate=bit_flip_rate)
    alice_sifted, bob_sifted = sift_key(alice_bits, bob_bits, alice_bases, bob_bases)
    compared_bits = min(config.BB84_SAMPLE_SIZE, len(alice_sifted))
    error_rate = calculate_error_rate(alice_sifted, bob_sifted, compared_bits)
    key_material = bob_sifted[compared_bits:] or bob_sifted
    return BB84Result(
        key=derive_key(key_material),
        error_rate=error_rate,
        accepted=error_rate <= threshold,
        sifted_bits=bob_sifted,
        compared_bits=compared_bits,
        generated_bits=rounds,
        matching_bases=len(bob_sifted),
        alice_basis_preview=_preview(alice_bases),
        bob_basis_preview=_preview(bob_bases),
        alice_bit_preview=_preview(alice_bits),
        bob_bit_preview=_preview(bob_bits),
        keep_preview=_keep_preview(alice_bases, bob_bases),
        sifted_preview=_preview(bob_sifted),
    )
