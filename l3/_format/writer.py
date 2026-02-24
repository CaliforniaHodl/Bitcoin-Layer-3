"""
Writer — serializes documents to container format.

Two-pass strategy:
  1. Serialize all sections to bytes (calculate sizes)
  2. Build index with real byte offsets (iterative convergence)
  3. Assemble final output: magic + meta + index + sections + EOF

Forked from PFM (getpfm.io) — MIT License.
"""

from __future__ import annotations

import io
from typing import TYPE_CHECKING

from l3._format.spec import MAGIC, EOF_MARKER, SECTION_PREFIX, FORMAT_VERSION, escape_content

if TYPE_CHECKING:
    from l3._format.document import PFMDocument


class PFMWriter:

    @staticmethod
    def serialize(doc: PFMDocument) -> bytes:
        """Serialize a document to bytes. Pure — does not mutate the input."""

        checksum = doc.compute_checksum()

        # --- Pass 1: Pre-serialize sections (with content escaping) ---
        section_blobs: list[tuple[str, bytes]] = []
        for section in doc.sections:
            header_line = f"{SECTION_PREFIX}{section.name}\n".encode("utf-8")
            escaped = escape_content(section.content)
            content_bytes = escaped.encode("utf-8")
            content_bytes += b"\n"
            section_blobs.append((section.name, header_line + content_bytes))

        # --- Build header (magic + meta) ---
        header = io.BytesIO()

        header.write(f"{MAGIC}/{doc.format_version}\n".encode("utf-8"))

        header.write(f"{SECTION_PREFIX}meta\n".encode("utf-8"))
        meta = doc.get_meta_dict()
        meta["checksum"] = checksum
        for key, val in meta.items():
            safe_key = "".join(c for c in key if c >= " " and c != "\x7f")
            safe_val = "".join(c for c in val if c >= " " and c != "\x7f")
            header.write(f"{safe_key}: {safe_val}\n".encode("utf-8"))

        # --- Pass 2: Calculate offsets and build index ---
        index_header = f"{SECTION_PREFIX}index\n".encode("utf-8")

        header_bytes = header.getvalue()

        entry_info: list[tuple[str, int, int]] = []
        for name, blob in section_blobs:
            section_header_len = len(f"{SECTION_PREFIX}{name}\n".encode("utf-8"))
            content_len = len(blob) - section_header_len
            entry_info.append((name, content_len, len(blob)))

        prev_index_bytes = index_header

        for _attempt in range(5):  # Converges in 2-3 iterations
            base_offset = len(header_bytes) + len(prev_index_bytes)
            index_buf = io.BytesIO()
            index_buf.write(index_header)
            running = base_offset
            for name, content_len, blob_len in entry_info:
                section_header_len = len(f"{SECTION_PREFIX}{name}\n".encode("utf-8"))
                content_offset = running + section_header_len
                index_buf.write(f"{name} {content_offset} {content_len}\n".encode("utf-8"))
                running += blob_len

            index_bytes = index_buf.getvalue()

            if len(index_bytes) == len(prev_index_bytes):
                break
            prev_index_bytes = index_bytes

        # --- Assemble final output ---
        out = io.BytesIO()
        out.write(header_bytes)
        out.write(index_bytes)
        for _, blob in section_blobs:
            out.write(blob)
        out.write(f"{EOF_MARKER}\n".encode("utf-8"))

        return out.getvalue()

    @staticmethod
    def write(doc: PFMDocument, path: str, mode: int = 0o644) -> int:
        """Write a document to file atomically. Returns bytes written."""
        import os
        import tempfile
        data = PFMWriter.serialize(doc)
        dir_name = os.path.dirname(os.path.abspath(path)) or "."
        fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".pfm.tmp")
        try:
            with os.fdopen(fd, 'wb') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            if os.path.exists(path):
                os.replace(tmp_path, path)
            else:
                os.rename(tmp_path, path)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        return len(data)
