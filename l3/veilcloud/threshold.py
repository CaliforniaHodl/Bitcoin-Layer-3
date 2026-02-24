"""
Shamir's Secret Sharing over GF(256).

Uses the Rijndael polynomial (0x11B) — same field as AES.
Pure Python, zero external dependencies.

Shares are 1-indexed (index 0 would expose the secret directly).
Maximum 255 shares (GF(256) field limit minus the zero element).

Usage:
    shares = split_secret(secret_bytes, threshold=3, total_shares=5)
    recovered = combine_shares(shares[:3])
    assert recovered == secret_bytes
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from l3 import VEILCLOUD_MAX_SHARES

# GF(256) arithmetic using the Rijndael (AES) irreducible polynomial: x^8 + x^4 + x^3 + x + 1
# Polynomial value: 0x11B (bit 8 is implicit in the modular reduction)

# Precomputed lookup tables for GF(256) multiplication
_EXP = [0] * 512
_LOG = [0] * 256


def _init_tables() -> None:
    """Initialize GF(256) exp/log tables using generator 3."""
    x = 1
    for i in range(255):
        _EXP[i] = x
        _LOG[x] = i
        x = _gf_mul_slow(x, 3)
    # Extend exp table for overflow-safe multiplication
    for i in range(255, 512):
        _EXP[i] = _EXP[i - 255]


def _gf_mul_slow(a: int, b: int) -> int:
    """GF(256) multiplication without tables (used only for table init)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B  # Rijndael reduction
        b >>= 1
    return p


_init_tables()


def _gf_mul(a: int, b: int) -> int:
    """GF(256) multiplication using precomputed tables."""
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def _gf_inv(a: int) -> int:
    """GF(256) multiplicative inverse."""
    if a == 0:
        raise ZeroDivisionError("No inverse for 0 in GF(256)")
    return _EXP[255 - _LOG[a]]


def _gf_div(a: int, b: int) -> int:
    """GF(256) division: a / b."""
    if b == 0:
        raise ZeroDivisionError("Division by zero in GF(256)")
    if a == 0:
        return 0
    return _EXP[(_LOG[a] + 255 - _LOG[b]) % 255]


@dataclass(frozen=True)
class Share:
    """A single share from Shamir's Secret Sharing.

    Attributes:
        index: The x-coordinate (1-based, 1..255).
        data: The share data (same length as the original secret).
    """

    index: int
    data: bytes

    def to_hex(self) -> str:
        """Encode as hex: index_byte + data_bytes."""
        return bytes([self.index]) .hex() + self.data.hex()

    @classmethod
    def from_hex(cls, hex_str: str) -> Share:
        """Decode from hex."""
        raw = bytes.fromhex(hex_str)
        if len(raw) < 2:
            raise ValueError("Share hex too short")
        return cls(index=raw[0], data=raw[1:])


def split_secret(
    secret: bytes,
    threshold: int,
    total_shares: int,
) -> list[Share]:
    """Split a secret into shares using Shamir's Secret Sharing over GF(256).

    Args:
        secret: The secret bytes to split.
        threshold: Minimum number of shares needed to reconstruct (t).
        total_shares: Total number of shares to create (n).

    Returns:
        A list of `total_shares` Share objects. Any `threshold` of them
        can reconstruct the secret.

    Raises:
        ValueError: If parameters are invalid.
    """
    if not secret:
        raise ValueError("Secret must not be empty")
    if threshold < 2:
        raise ValueError("Threshold must be at least 2")
    if total_shares < threshold:
        raise ValueError(
            f"Total shares ({total_shares}) must be >= threshold ({threshold})"
        )
    if total_shares > VEILCLOUD_MAX_SHARES:
        raise ValueError(
            f"Total shares ({total_shares}) exceeds GF(256) limit ({VEILCLOUD_MAX_SHARES})"
        )

    shares_data: list[bytearray] = [bytearray() for _ in range(total_shares)]

    for byte_val in secret:
        # Build a random polynomial of degree (threshold - 1)
        # where coefficients[0] = the secret byte
        coeffs = [byte_val]
        for _ in range(threshold - 1):
            coeffs.append(secrets.randbelow(256))

        # Evaluate at x = 1, 2, ..., total_shares
        for i in range(total_shares):
            x = i + 1  # 1-based indices
            y = _eval_polynomial(coeffs, x)
            shares_data[i].append(y)

    return [
        Share(index=i + 1, data=bytes(shares_data[i]))
        for i in range(total_shares)
    ]


def combine_shares(shares: list[Share]) -> bytes:
    """Reconstruct a secret from shares using Lagrange interpolation at x=0.

    Args:
        shares: A list of Share objects (at least `threshold` shares).

    Returns:
        The reconstructed secret bytes.

    Raises:
        ValueError: If shares are invalid or inconsistent.
    """
    if not shares:
        raise ValueError("No shares provided")

    # Validate shares
    indices = [s.index for s in shares]
    if len(set(indices)) != len(indices):
        raise ValueError("Duplicate share indices")
    if any(i < 1 or i > VEILCLOUD_MAX_SHARES for i in indices):
        raise ValueError("Share index out of range [1, 255]")

    secret_len = len(shares[0].data)
    if any(len(s.data) != secret_len for s in shares):
        raise ValueError("All shares must have the same data length")

    # Lagrange interpolation at x=0 for each byte position
    result = bytearray(secret_len)
    xs = [s.index for s in shares]

    for byte_idx in range(secret_len):
        ys = [s.data[byte_idx] for s in shares]
        result[byte_idx] = _lagrange_interpolate_at_zero(xs, ys)

    return bytes(result)


def _eval_polynomial(coeffs: list[int], x: int) -> int:
    """Evaluate a polynomial in GF(256) using Horner's method.

    coeffs[0] is the constant term, coeffs[1] is the x coefficient, etc.
    """
    # Horner's method: start from the highest degree
    result = 0
    for i in range(len(coeffs) - 1, -1, -1):
        result = _gf_mul(result, x) ^ coeffs[i]
    return result


def _lagrange_interpolate_at_zero(xs: list[int], ys: list[int]) -> int:
    """Lagrange interpolation at x=0 in GF(256)."""
    k = len(xs)
    result = 0

    for i in range(k):
        # Compute Lagrange basis polynomial L_i(0)
        numerator = 1
        denominator = 1

        for j in range(k):
            if i == j:
                continue
            # L_i(0) = product of (0 - x_j) / (x_i - x_j)
            # In GF(256), subtraction is XOR, and (0 - x_j) = x_j
            numerator = _gf_mul(numerator, xs[j])
            denominator = _gf_mul(denominator, xs[i] ^ xs[j])

        lagrange_coeff = _gf_mul(numerator, _gf_inv(denominator))
        result ^= _gf_mul(ys[i], lagrange_coeff)

    return result
