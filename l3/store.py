"""
L3 Store — local content-addressed storage for anchored PFM documents.

Storage layout:
    ~/.pfm/l3/store/<checksum>.pfm   — PFM document files
    ~/.pfm/l3/index.json             — metadata index (checksum -> txid, network, ts)

All writes are atomic (temp file + os.replace) for crash safety.
Content-addressed by SHA-256 checksum — storing the same content twice is a no-op.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Strict hex pattern for SHA-256 checksums
_CHECKSUM_RE = re.compile(r"^[0-9a-f]{64}$")

# Default L3 store root
_DEFAULT_ROOT = Path.home() / ".pfm" / "l3"


class L3StoreError(Exception):
    """Error in L3 store operations."""


class L3Store:
    """File-based, content-addressed PFM document store.

    Documents are stored by their SHA-256 checksum, which is the same
    checksum PFM already computes via ``doc.compute_checksum()``.

    Usage:
        store = L3Store()
        checksum = store.store(doc)
        doc = store.retrieve(checksum)
    """

    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root) if root else _DEFAULT_ROOT
        self.store_dir = self.root / "store"
        self.index_path = self.root / "index.json"

    def _ensure_dirs(self) -> None:
        """Create store directories if they don't exist."""
        self.store_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _validate_checksum(checksum: str) -> None:
        """Validate checksum format. Prevents path traversal via checksum."""
        if not isinstance(checksum, str) or not _CHECKSUM_RE.match(checksum):
            raise ValueError(
                f"Invalid checksum: must be 64 lowercase hex chars, got {checksum!r}"
            )

    def _read_index(self) -> dict[str, dict[str, str]]:
        """Read the JSON index. Returns empty dict if missing or corrupt."""
        if not self.index_path.is_file():
            return {}
        try:
            data = self.index_path.read_text(encoding="utf-8")
            index = json.loads(data)
            if not isinstance(index, dict):
                return {}
            return index
        except (json.JSONDecodeError, OSError):
            return {}

    def _write_index(self, index: dict[str, dict[str, str]]) -> None:
        """Atomically write the JSON index (temp + rename)."""
        self._ensure_dirs()
        data = json.dumps(index, indent=2, sort_keys=True)
        # Write to temp file in same directory, then atomic rename
        fd, tmp_path = tempfile.mkstemp(
            dir=str(self.root), suffix=".tmp", prefix=".index_"
        )
        try:
            os.write(fd, data.encode("utf-8"))
            os.fsync(fd)
            os.close(fd)
            os.replace(tmp_path, str(self.index_path))
        except Exception:
            os.close(fd) if not os.get_inheritable(fd) else None
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    def store(self, doc: Any) -> str:
        """Store a PFM document. Returns its checksum.

        Content-addressed: if a document with the same checksum already
        exists, this is a no-op (deduplication).

        Uses atomic writes (temp + os.replace) for crash safety.
        """
        checksum = doc.compute_checksum()
        self._validate_checksum(checksum)
        self._ensure_dirs()

        dest = self.store_dir / f"{checksum}.pfm"

        # Deduplicate — if file already exists, just update index
        if not dest.is_file():
            # Atomic write: serialize to temp, then rename
            content = doc.to_bytes()
            fd, tmp_path = tempfile.mkstemp(
                dir=str(self.store_dir), suffix=".tmp", prefix=".pfm_"
            )
            try:
                os.write(fd, content)
                os.fsync(fd)
                os.close(fd)
                os.chmod(tmp_path, 0o644)
                os.replace(tmp_path, str(dest))
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

        # Update index
        index = self._read_index()
        if checksum not in index:
            index[checksum] = {
                "stored_at": datetime.now(timezone.utc).isoformat(),
            }
            # Carry over meta from the document
            if doc.id:
                index[checksum]["doc_id"] = doc.id
            if doc.agent:
                index[checksum]["agent"] = doc.agent
            self._write_index(index)

        return checksum

    def retrieve(self, checksum: str) -> Any:
        """Retrieve a PFM document by checksum.

        Raises L3StoreError if not found.
        """
        self._validate_checksum(checksum)
        path = self.store_dir / f"{checksum}.pfm"

        if not path.is_file():
            raise L3StoreError(f"Document not found: {checksum}")

        from l3._format.reader import PFMReader
        return PFMReader.read(str(path))

    def contains(self, checksum: str) -> bool:
        """Check if a document with this checksum is stored."""
        self._validate_checksum(checksum)
        return (self.store_dir / f"{checksum}.pfm").is_file()

    def list(self) -> list[dict[str, str]]:
        """List all stored documents with their index metadata.

        Returns a list of dicts with at least 'checksum' key.
        """
        index = self._read_index()
        result = []
        for checksum, meta in sorted(index.items()):
            entry = {"checksum": checksum}
            entry.update(meta)
            result.append(entry)
        return result

    def lookup_by_txid(self, txid: str) -> str | None:
        """Reverse lookup: find checksum by anchor transaction ID.

        Returns the checksum or None if not found.
        """
        if not txid:
            return None
        index = self._read_index()
        for checksum, meta in index.items():
            if meta.get("anchor_txid") == txid:
                return checksum
        return None

    def update_txid(
        self, checksum: str, txid: str, network: str, *, force: bool = False,
    ) -> None:
        """Record an anchor transaction for a stored document.

        Call this after a successful anchor to link the on-chain txid
        back to the local store entry.

        Raises L3StoreError if an anchor_txid already exists unless force=True.
        This prevents silent anchor overwrite attacks (C-NEW-005).
        """
        self._validate_checksum(checksum)
        index = self._read_index()
        if checksum not in index:
            raise L3StoreError(f"Document not in index: {checksum}")
        existing_txid = index[checksum].get("anchor_txid")
        if existing_txid and existing_txid != txid and not force:
            raise L3StoreError(
                f"Document {checksum[:12]} already anchored to tx {existing_txid[:12]}. "
                f"Use force=True to overwrite."
            )
        index[checksum]["anchor_txid"] = txid
        index[checksum]["anchor_network"] = network
        index[checksum]["anchor_ts"] = datetime.now(timezone.utc).isoformat()
        self._write_index(index)
