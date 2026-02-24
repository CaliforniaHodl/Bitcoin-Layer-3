"""
Client-side encryption for VeilCloud.

- Key derivation: PBKDF2-HMAC-SHA256 (stdlib, 600K iterations)
- Encryption: AES-256-GCM (requires `cryptography` package)

The `cryptography` package is lazily imported — missing dependency produces
a clear error message, same pattern as P2P handles missing `secp256k1`.

Install with: pip install bitcoin-l3[veilcloud]
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from l3 import (
    VEILCLOUD_KDF_ITERATIONS,
    VEILCLOUD_KEY_SIZE,
    VEILCLOUD_SALT_SIZE,
    VEILCLOUD_NONCE_SIZE,
)


def _import_cryptography():
    """Lazily import the cryptography package.

    Raises ImportError with a helpful message if not installed.
    """
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        return AESGCM
    except ImportError:
        raise ImportError(
            "cryptography is required for VeilCloud encryption. "
            "Install with: pip install bitcoin-l3[veilcloud]"
        )


@dataclass(frozen=True)
class EncryptedPayload:
    """Container for an AES-256-GCM encrypted payload.

    Attributes:
        ciphertext: The encrypted data including GCM auth tag.
        nonce: The 12-byte nonce used for encryption.
        salt: The 16-byte salt used for key derivation (empty if key was provided directly).
    """

    ciphertext: bytes
    nonce: bytes
    salt: bytes

    def to_bytes(self) -> bytes:
        """Serialize to bytes: salt(16) + nonce(12) + ciphertext."""
        return self.salt + self.nonce + self.ciphertext

    @classmethod
    def from_bytes(cls, data: bytes) -> EncryptedPayload:
        """Deserialize from bytes."""
        if len(data) < VEILCLOUD_SALT_SIZE + VEILCLOUD_NONCE_SIZE + 16:
            raise ValueError("Encrypted payload too short")
        salt = data[:VEILCLOUD_SALT_SIZE]
        nonce = data[VEILCLOUD_SALT_SIZE : VEILCLOUD_SALT_SIZE + VEILCLOUD_NONCE_SIZE]
        ciphertext = data[VEILCLOUD_SALT_SIZE + VEILCLOUD_NONCE_SIZE :]
        return cls(ciphertext=ciphertext, nonce=nonce, salt=salt)


def derive_key(
    password: str,
    salt: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Derive an AES-256 key from a password using PBKDF2-HMAC-SHA256.

    Uses stdlib hashlib — no external dependencies.

    Args:
        password: The password to derive from.
        salt: Optional 16-byte salt. Generated if not provided.

    Returns:
        (key, salt) tuple. The salt should be stored alongside the ciphertext.
    """
    if salt is None:
        salt = os.urandom(VEILCLOUD_SALT_SIZE)
    if len(salt) != VEILCLOUD_SALT_SIZE:
        raise ValueError(f"Salt must be {VEILCLOUD_SALT_SIZE} bytes")

    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        VEILCLOUD_KDF_ITERATIONS,
        dklen=VEILCLOUD_KEY_SIZE,
    )
    return key, salt


def encrypt(plaintext: bytes, password: str) -> EncryptedPayload:
    """Encrypt data with a password using AES-256-GCM.

    Derives a key via PBKDF2, then encrypts with AES-256-GCM.
    Requires the `cryptography` package.

    Args:
        plaintext: Data to encrypt.
        password: Password for key derivation.

    Returns:
        EncryptedPayload containing ciphertext, nonce, and salt.
    """
    AESGCM = _import_cryptography()

    key, salt = derive_key(password)
    nonce = os.urandom(VEILCLOUD_NONCE_SIZE)

    try:
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    finally:
        # Best-effort key zeroing
        key_ba = bytearray(key)
        for i in range(len(key_ba)):
            key_ba[i] = 0

    return EncryptedPayload(ciphertext=ciphertext, nonce=nonce, salt=salt)


def decrypt(payload: EncryptedPayload, password: str) -> bytes:
    """Decrypt data with a password.

    Derives the key from the password and salt, then decrypts with AES-256-GCM.

    Args:
        payload: The encrypted payload.
        password: The password used for encryption.

    Returns:
        The decrypted plaintext.

    Raises:
        ValueError: If decryption fails (wrong password or tampered data).
    """
    AESGCM = _import_cryptography()

    key, _ = derive_key(password, payload.salt)

    try:
        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(payload.nonce, payload.ciphertext, None)
        except Exception:
            raise ValueError("Decryption failed — wrong password or tampered ciphertext")
    finally:
        key_ba = bytearray(key)
        for i in range(len(key_ba)):
            key_ba[i] = 0

    return plaintext


def encrypt_with_key(plaintext: bytes, key: bytes) -> EncryptedPayload:
    """Encrypt data with a raw key (e.g. from Shamir reconstruction).

    Args:
        plaintext: Data to encrypt.
        key: 32-byte AES-256 key.

    Returns:
        EncryptedPayload with empty salt (key was provided directly).
    """
    AESGCM = _import_cryptography()

    if len(key) != VEILCLOUD_KEY_SIZE:
        raise ValueError(f"Key must be {VEILCLOUD_KEY_SIZE} bytes")

    nonce = os.urandom(VEILCLOUD_NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return EncryptedPayload(
        ciphertext=ciphertext,
        nonce=nonce,
        salt=b"\x00" * VEILCLOUD_SALT_SIZE,
    )


def decrypt_with_key(payload: EncryptedPayload, key: bytes) -> bytes:
    """Decrypt data with a raw key.

    Args:
        payload: The encrypted payload.
        key: 32-byte AES-256 key.

    Returns:
        The decrypted plaintext.

    Raises:
        ValueError: If decryption fails.
    """
    AESGCM = _import_cryptography()

    if len(key) != VEILCLOUD_KEY_SIZE:
        raise ValueError(f"Key must be {VEILCLOUD_KEY_SIZE} bytes")

    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(payload.nonce, payload.ciphertext, None)
    except Exception:
        raise ValueError("Decryption failed — wrong key or tampered ciphertext")
