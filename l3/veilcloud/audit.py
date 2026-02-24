"""
Append-only audit log with hash chain and Merkle proofs.

Each entry includes:
    - event_type, actor, data, timestamp
    - prev_hash: hash of the previous entry (chain linkage)
    - entry_hash: SHA-256(prev_hash + event_type + actor + data + timestamp)

Logs are persisted to ~/.pfm/l3/audit/<name>.json with atomic writes
(temp file + os.replace) and thread-safe access (threading.Lock).

Merkle proofs are generated on demand over entry hashes.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import threading
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path

from l3 import VEILCLOUD_AUDIT_DIR
from l3.veilcloud.merkle import MerkleTree, MerkleProof


_GENESIS_HASH = "0" * 64  # Hash chain starts with zeros


@dataclass
class AuditEntry:
    """A single entry in an audit log."""

    sequence: int
    event_type: str
    actor: str
    data: dict
    timestamp: str
    prev_hash: str
    entry_hash: str

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> AuditEntry:
        return cls(**d)


def _compute_entry_hash(
    prev_hash: str,
    event_type: str,
    actor: str,
    data: dict,
    timestamp: str,
) -> str:
    """Compute the hash of an audit entry."""
    payload = (
        prev_hash
        + "|"
        + event_type
        + "|"
        + actor
        + "|"
        + json.dumps(data, sort_keys=True, separators=(",", ":"))
        + "|"
        + timestamp
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only audit log with hash chain linkage.

    Persisted to ~/.pfm/l3/audit/<name>.json.
    Thread-safe for concurrent appends.

    Usage:
        log = AuditLog("my-audit")
        entry = log.log("STORE", "user@example", {"checksum": "aabb..."})
        assert log.verify_chain()
        proof = log.get_proof(0)
    """

    def __init__(self, name: str, base_dir: Path | None = None) -> None:
        if not name or not name.replace("-", "").replace("_", "").isalnum():
            raise ValueError(
                f"Invalid audit log name: {name!r} (alphanumeric, hyphens, underscores only)"
            )

        if base_dir is None:
            base_dir = Path.home() / ".pfm" / "l3" / VEILCLOUD_AUDIT_DIR
        self._path = base_dir / f"{name}.json"
        self._lock = threading.Lock()
        self._entries: list[AuditEntry] = []
        self._load()

    def _load(self) -> None:
        """Load entries from disk."""
        if not self._path.is_file():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            self._entries = [AuditEntry.from_dict(e) for e in raw]
        except (json.JSONDecodeError, KeyError, TypeError):
            self._entries = []

    def _save(self) -> None:
        """Atomically persist entries to disk."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        data = json.dumps(
            [e.to_dict() for e in self._entries],
            indent=2,
            sort_keys=True,
        )
        # Atomic write: write to temp file, then os.replace
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self._path.parent), suffix=".tmp"
        )
        try:
            os.write(fd, data.encode("utf-8"))
            os.close(fd)
            os.replace(tmp_path, str(self._path))
        except Exception:
            os.close(fd) if not os.get_inheritable(fd) else None
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def log(
        self,
        event_type: str,
        actor: str,
        data: dict | None = None,
    ) -> AuditEntry:
        """Append a new entry to the audit log.

        Args:
            event_type: Type of event (e.g. "STORE", "ANCHOR", "ACCESS").
            actor: Who performed the action.
            data: Additional event data.

        Returns:
            The new AuditEntry.
        """
        if data is None:
            data = {}

        with self._lock:
            prev_hash = (
                self._entries[-1].entry_hash if self._entries else _GENESIS_HASH
            )
            sequence = len(self._entries)
            timestamp = datetime.now(timezone.utc).isoformat()

            entry_hash = _compute_entry_hash(
                prev_hash, event_type, actor, data, timestamp
            )

            entry = AuditEntry(
                sequence=sequence,
                event_type=event_type,
                actor=actor,
                data=data,
                timestamp=timestamp,
                prev_hash=prev_hash,
                entry_hash=entry_hash,
            )

            self._entries.append(entry)
            self._save()
            return entry

    def verify_chain(self) -> bool:
        """Verify the entire hash chain.

        Fail-closed: returns False on any error.
        """
        try:
            with self._lock:
                if not self._entries:
                    return True

                for i, entry in enumerate(self._entries):
                    expected_prev = (
                        self._entries[i - 1].entry_hash
                        if i > 0
                        else _GENESIS_HASH
                    )

                    if entry.prev_hash != expected_prev:
                        return False

                    expected_hash = _compute_entry_hash(
                        entry.prev_hash,
                        entry.event_type,
                        entry.actor,
                        entry.data,
                        entry.timestamp,
                    )

                    if entry.entry_hash != expected_hash:
                        return False

                return True
        except Exception:
            return False

    def get_proof(self, sequence: int) -> MerkleProof:
        """Generate a Merkle inclusion proof for an entry.

        Builds a MerkleTree over all entry hashes and returns the proof
        for the specified sequence number.

        Args:
            sequence: The 0-based sequence number.

        Returns:
            A MerkleProof.

        Raises:
            IndexError: If sequence is out of range.
            ValueError: If the log is empty.
        """
        with self._lock:
            if not self._entries:
                raise ValueError("Audit log is empty")
            if sequence < 0 or sequence >= len(self._entries):
                raise IndexError(
                    f"Sequence {sequence} out of range [0, {len(self._entries)})"
                )

            leaf_data = [e.entry_hash.encode("ascii") for e in self._entries]
            tree = MerkleTree.from_leaves(leaf_data)
            return tree.get_proof(sequence)

    @property
    def entries(self) -> list[AuditEntry]:
        """Return a copy of all entries."""
        with self._lock:
            return list(self._entries)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)
