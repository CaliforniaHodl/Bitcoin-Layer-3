"""
Invoice state machine and persistence for the Anchor API.

States:
    pending_payment → paid → anchoring → confirmed
           │                     │
           ▼                     ▼
        expired                failed → anchoring (retry)

Thread-safe via threading.Lock. Persisted to JSON with atomic writes.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class InvoiceError(Exception):
    """Invalid invoice operation."""


# Valid state transitions
_TRANSITIONS: dict[str, set[str]] = {
    "pending_payment": {"paid", "expired"},
    "paid": {"anchoring"},
    "anchoring": {"confirmed", "failed"},
    "failed": {"anchoring"},  # retry
    # Terminal states: expired, confirmed — no outgoing transitions
    "expired": set(),
    "confirmed": set(),
}

_VALID_STATES = set(_TRANSITIONS.keys())

_DEFAULT_DIR = Path.home() / ".pfm" / "l3" / "api"


class Invoice:
    """A single anchor invoice."""

    def __init__(
        self,
        anchor_id: str,
        checksum: str,
        address: str,
        amount_sats: int,
        expires_at: str,
        status: str = "pending_payment",
        created_at: str = "",
        l1_txid: str = "",
        content_type: str = "",
    ) -> None:
        if status not in _VALID_STATES:
            raise InvoiceError(f"Invalid status: {status!r}")
        self.anchor_id = anchor_id
        self.checksum = checksum
        self.address = address
        self.amount_sats = amount_sats
        self.expires_at = expires_at
        self.status = status
        self.created_at = created_at or datetime.now(timezone.utc).isoformat()
        self.l1_txid = l1_txid
        self.content_type = content_type

    def transition(self, new_status: str) -> None:
        """Advance the state machine. Raises InvoiceError on invalid transition."""
        allowed = _TRANSITIONS.get(self.status, set())
        if new_status not in allowed:
            raise InvoiceError(
                f"Cannot transition from {self.status!r} to {new_status!r}"
            )
        self.status = new_status

    @property
    def is_terminal(self) -> bool:
        return self.status in ("expired", "confirmed")

    def to_dict(self) -> dict[str, Any]:
        return {
            "anchor_id": self.anchor_id,
            "checksum": self.checksum,
            "address": self.address,
            "amount_sats": self.amount_sats,
            "expires_at": self.expires_at,
            "status": self.status,
            "created_at": self.created_at,
            "l1_txid": self.l1_txid,
            "content_type": self.content_type,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Invoice:
        return cls(
            anchor_id=data["anchor_id"],
            checksum=data["checksum"],
            address=data["address"],
            amount_sats=data["amount_sats"],
            expires_at=data["expires_at"],
            status=data.get("status", "pending_payment"),
            created_at=data.get("created_at", ""),
            l1_txid=data.get("l1_txid", ""),
            content_type=data.get("content_type", ""),
        )


class InvoiceManager:
    """Thread-safe invoice store with JSON persistence.

    Usage:
        mgr = InvoiceManager()
        inv = mgr.create(checksum="abc...", address="bc1q...", amount_sats=2200)
        mgr.transition(inv.anchor_id, "paid")
    """

    def __init__(self, data_dir: str | Path | None = None) -> None:
        self._dir = Path(data_dir) if data_dir else _DEFAULT_DIR
        self._path = self._dir / "invoices.json"
        self._lock = threading.Lock()
        self._invoices: dict[str, Invoice] = {}
        self._load()

    def _load(self) -> None:
        """Load invoices from disk."""
        if not self._path.is_file():
            return
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                return
            for aid, inv_data in data.items():
                try:
                    self._invoices[aid] = Invoice.from_dict(inv_data)
                except (KeyError, InvoiceError):
                    continue  # skip corrupt entries
        except (json.JSONDecodeError, OSError):
            pass

    def _persist(self) -> None:
        """Atomically write invoices to disk (temp + os.replace)."""
        self._dir.mkdir(parents=True, exist_ok=True)
        data = {aid: inv.to_dict() for aid, inv in self._invoices.items()}
        content = json.dumps(data, indent=2, sort_keys=True)
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self._dir), suffix=".tmp", prefix=".inv_"
        )
        try:
            os.write(fd, content.encode("utf-8"))
            os.fsync(fd)
            os.close(fd)
            os.replace(tmp_path, str(self._path))
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

    def create(
        self,
        checksum: str,
        address: str,
        amount_sats: int,
        expires_at: str,
        content_type: str = "",
    ) -> Invoice:
        """Create a new invoice. Returns it in pending_payment state."""
        anchor_id = uuid.uuid4().hex[:16]
        inv = Invoice(
            anchor_id=anchor_id,
            checksum=checksum,
            address=address,
            amount_sats=amount_sats,
            expires_at=expires_at,
            content_type=content_type,
        )
        with self._lock:
            self._invoices[anchor_id] = inv
            self._persist()
        return inv

    def get(self, anchor_id: str) -> Invoice | None:
        """Get an invoice by ID. Returns None if not found."""
        with self._lock:
            return self._invoices.get(anchor_id)

    def transition(self, anchor_id: str, new_status: str) -> Invoice:
        """Transition an invoice's state. Raises InvoiceError on failure."""
        with self._lock:
            inv = self._invoices.get(anchor_id)
            if inv is None:
                raise InvoiceError(f"Invoice not found: {anchor_id!r}")
            inv.transition(new_status)
            self._persist()
            return inv

    def set_l1_txid(self, anchor_id: str, txid: str) -> None:
        """Record the L1 transaction ID on an invoice."""
        with self._lock:
            inv = self._invoices.get(anchor_id)
            if inv is None:
                raise InvoiceError(f"Invoice not found: {anchor_id!r}")
            inv.l1_txid = txid
            self._persist()

    def list_by_status(self, status: str) -> list[Invoice]:
        """Return all invoices with the given status."""
        with self._lock:
            return [inv for inv in self._invoices.values() if inv.status == status]

    def all(self) -> list[Invoice]:
        """Return all invoices."""
        with self._lock:
            return list(self._invoices.values())
