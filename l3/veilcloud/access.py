"""
HMAC-signed credentials with permissions, expiry, and revocation.

Permission bitfield:
    READ   = 0x01
    WRITE  = 0x02
    DELETE = 0x04
    SHARE  = 0x08
    ADMIN  = 0x10

Credentials are HMAC-SHA256 signed. Verification is fail-closed:
any error (expired, revoked, tampered, invalid) returns False.

Revocation set is persisted atomically, thread-safe.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import tempfile
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from enum import IntFlag
from pathlib import Path


class Permission(IntFlag):
    """Permission bitfield for VeilCloud credentials."""

    READ = 0x01
    WRITE = 0x02
    DELETE = 0x04
    SHARE = 0x08
    ADMIN = 0x10


@dataclass(frozen=True)
class Credential:
    """An HMAC-signed credential.

    Attributes:
        credential_id: Unique identifier for this credential.
        user_id: The user this credential was issued to.
        permissions: Permission bitfield.
        issued_at: ISO 8601 timestamp.
        expires_at: ISO 8601 timestamp (empty string = no expiry).
        signature: HMAC-SHA256 signature (hex).
    """

    credential_id: str
    user_id: str
    permissions: int
    issued_at: str
    expires_at: str
    signature: str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> Credential:
        return cls(**d)

    def has_permission(self, perm: Permission) -> bool:
        """Check if this credential has a specific permission."""
        return bool(self.permissions & perm)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)

    @classmethod
    def from_json(cls, s: str) -> Credential:
        return cls.from_dict(json.loads(s))


class CredentialManager:
    """Issue, verify, and revoke HMAC-signed credentials.

    Thread-safe. Revocation set persisted to disk.

    Usage:
        manager = CredentialManager(signing_key=os.urandom(32))
        cred = manager.issue_credential("user123", Permission.READ | Permission.WRITE)
        assert manager.verify_credential(cred)
        manager.revoke_credential(cred.credential_id)
        assert not manager.verify_credential(cred)
    """

    def __init__(
        self,
        signing_key: bytes,
        revocation_path: Path | None = None,
    ) -> None:
        if len(signing_key) < 32:
            raise ValueError("Signing key must be at least 32 bytes")

        self._key = signing_key
        self._lock = threading.Lock()

        if revocation_path is None:
            revocation_path = (
                Path.home() / ".pfm" / "l3" / "veilcloud" / "revocations.json"
            )
        self._revocation_path = revocation_path
        self._revoked: set[str] = set()
        self._load_revocations()

    def _load_revocations(self) -> None:
        """Load revocation set from disk."""
        if not self._revocation_path.is_file():
            return
        try:
            data = json.loads(self._revocation_path.read_text(encoding="utf-8"))
            self._revoked = set(data)
        except (json.JSONDecodeError, TypeError):
            self._revoked = set()

    def _save_revocations(self) -> None:
        """Atomically persist revocation set."""
        self._revocation_path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(sorted(self._revoked))
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self._revocation_path.parent), suffix=".tmp"
        )
        try:
            os.write(fd, data.encode("utf-8"))
            os.close(fd)
            os.replace(tmp_path, str(self._revocation_path))
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def _compute_signature(
        self,
        credential_id: str,
        user_id: str,
        permissions: int,
        issued_at: str,
        expires_at: str,
    ) -> str:
        """Compute HMAC-SHA256 signature over credential fields."""
        payload = (
            f"{credential_id}|{user_id}|{permissions}|{issued_at}|{expires_at}"
        )
        return hmac.new(
            self._key,
            payload.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def issue_credential(
        self,
        user_id: str,
        permissions: int | Permission,
        expires_at: str = "",
    ) -> Credential:
        """Issue a new credential.

        Args:
            user_id: The user to issue the credential to.
            permissions: Permission bitfield.
            expires_at: Optional ISO 8601 expiry timestamp.

        Returns:
            A signed Credential.
        """
        credential_id = secrets.token_hex(16)
        issued_at = datetime.now(timezone.utc).isoformat()
        permissions_int = int(permissions)

        signature = self._compute_signature(
            credential_id, user_id, permissions_int, issued_at, expires_at
        )

        return Credential(
            credential_id=credential_id,
            user_id=user_id,
            permissions=permissions_int,
            issued_at=issued_at,
            expires_at=expires_at,
            signature=signature,
        )

    def verify_credential(self, credential: Credential) -> bool:
        """Verify a credential.

        Fail-closed: returns False if:
            - Signature doesn't match (tampered)
            - Credential is expired
            - Credential is revoked
            - Any error occurs

        Uses hmac.compare_digest for constant-time comparison.
        """
        try:
            # Check revocation first (fast path)
            with self._lock:
                if credential.credential_id in self._revoked:
                    return False

            # Check expiry
            if credential.expires_at:
                try:
                    expiry = datetime.fromisoformat(credential.expires_at)
                    if expiry.tzinfo is None:
                        expiry = expiry.replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) > expiry:
                        return False
                except (ValueError, TypeError):
                    return False

            # Verify HMAC signature (constant-time comparison)
            expected = self._compute_signature(
                credential.credential_id,
                credential.user_id,
                credential.permissions,
                credential.issued_at,
                credential.expires_at,
            )
            return hmac.compare_digest(credential.signature, expected)

        except Exception:
            return False

    def revoke_credential(self, credential_id: str) -> None:
        """Revoke a credential by ID.

        Revoked credentials will fail verification immediately.
        """
        with self._lock:
            self._revoked.add(credential_id)
            self._save_revocations()

    def is_revoked(self, credential_id: str) -> bool:
        """Check if a credential has been revoked."""
        with self._lock:
            return credential_id in self._revoked
