"""Shamir's Secret Sharing for master key recovery.

Implements a threshold scheme on GF(2^8) using AES-compatible field arithmetic.
No external dependencies beyond the Python standard library.
"""

import base64
import json
import os
import secrets
from dataclasses import dataclass
from typing import Iterable

from cryptodb.exceptions import KeyManagementError


# GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1 (0x11b)
_IRREDUCIBLE = 0x11B


def _gf_add(a: int, b: int) -> int:
    return a ^ b


def _gf_mul(a: int, b: int) -> int:
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= _IRREDUCIBLE
        b >>= 1
    return result & 0xFF


def _gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("GF(2^8) inversion of zero")
    # Extended Euclidean algorithm in GF(2^8)
    old_r, r = a, _IRREDUCIBLE
    old_s, s = 1, 0
    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r ^ _gf_mul(quotient, r)
        old_s, s = s, old_s ^ _gf_mul(quotient, s)
    return old_s & 0xFF


def _eval_poly(coeffs: list[int], x: int) -> int:
    """Evaluate a polynomial at point x in GF(2^8)."""
    result = 0
    for coeff in reversed(coeffs):
        result = _gf_add(_gf_mul(result, x), coeff)
    return result


def _lagrange_interpolate(points: list[tuple[int, int]], x: int = 0) -> int:
    """Lagrange interpolation at point x in GF(2^8)."""
    result = 0
    for i, (xi, yi) in enumerate(points):
        numerator = 1
        denominator = 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            numerator = _gf_mul(numerator, _gf_add(x, xj))
            denominator = _gf_mul(denominator, _gf_add(xi, xj))
        result ^= _gf_mul(yi, _gf_mul(numerator, _gf_inv(denominator)))
    return result


@dataclass(frozen=True, slots=True)
class Share:
    """A single Shamir share."""

    index: int  # x-coordinate (1-based, non-zero)
    value: bytes  # y-coordinate bytes

    def to_b64(self) -> str:
        payload = json.dumps({"i": self.index, "v": base64.b64encode(self.value).decode()})
        return base64.b64encode(payload.encode()).decode()

    @classmethod
    def from_b64(cls, b64: str) -> "Share":
        payload = json.loads(base64.b64decode(b64).decode())
        return cls(index=payload["i"], value=base64.b64decode(payload["v"]))


def split_secret(secret: bytes, threshold: int, total_shares: int) -> list[Share]:
    """Split *secret* into *total_shares* shares with *threshold* required to reconstruct.

    Raises:
        KeyManagementError: if threshold or total_shares are invalid.
    """
    if not (2 <= threshold <= total_shares <= 255):
        raise KeyManagementError("threshold must be >= 2, total_shares <= 255, and threshold <= total_shares")

    shares: list[Share] = []
    for byte_offset in range(len(secret)):
        # Generate random polynomial for each byte
        coeffs = [secret[byte_offset]] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        for x in range(1, total_shares + 1):
            y = _eval_poly(coeffs, x)
            if byte_offset == 0:
                shares.append(Share(index=x, value=bytes([y])))
            else:
                shares[x - 1] = Share(
                    index=x,
                    value=shares[x - 1].value + bytes([y]),
                )
    return shares


def recover_secret(shares: Iterable[Share]) -> bytes:
    """Reconstruct the secret from a sufficient set of shares.

    Raises:
        KeyManagementError: if shares are empty or inconsistent lengths.
    """
    share_list = list(shares)
    if not share_list:
        raise KeyManagementError("At least one share required")

    length = len(share_list[0].value)
    points_by_byte: list[list[tuple[int, int]]] = [[] for _ in range(length)]
    for sh in share_list:
        if len(sh.value) != length:
            raise KeyManagementError("All shares must have the same length")
        for byte_idx, b in enumerate(sh.value):
            points_by_byte[byte_idx].append((sh.index, b))

    secret = bytearray()
    for points in points_by_byte:
        secret.append(_lagrange_interpolate(points, x=0))
    return bytes(secret)
