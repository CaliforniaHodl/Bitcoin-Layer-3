"""
Reader — fast parser for container files.

Speed features:
  - Magic byte check in first 64 bytes (instant file identification)
  - Index-based O(1) section access via file seek (true lazy reading)
  - Only the header (magic + meta + index) is read on open
  - Section content is read on demand

Security features:
  - Content unescaping (reverses writer escaping of #@/#! markers)
  - Strict allowlist for meta field parsing (no arbitrary setattr)
  - File size limits (prevents OOM from crafted files)
  - Index bounds validation (prevents out-of-bounds reads)

Forked from PFM (getpfm.io) — MIT License.
"""

from __future__ import annotations

import builtins
import hashlib
import hmac as _hmac
from pathlib import Path
from typing import BinaryIO

from l3._format.spec import (
    MAGIC, EOF_MARKER, SECTION_PREFIX, MAX_MAGIC_SCAN_BYTES,
    META_ALLOWLIST, MAX_FILE_SIZE, MAX_META_FIELDS, SUPPORTED_FORMAT_VERSIONS,
    unescape_content,
)
from l3._format.document import PFMDocument, PFMSection


class PFMIndex:
    """Parsed index for O(1) section access."""

    def __init__(self) -> None:
        self.entries: dict[str, list[tuple[int, int]]] = {}

    def add(self, name: str, offset: int, length: int) -> None:
        if name not in self.entries:
            self.entries[name] = []
        self.entries[name].append((offset, length))

    def get(self, name: str) -> tuple[int, int] | None:
        entries = self.entries.get(name)
        if entries:
            return entries[0]
        return None

    def get_all(self, name: str) -> list[tuple[int, int]]:
        return self.entries.get(name, [])

    @property
    def section_names(self) -> list[str]:
        return list(self.entries.keys())


class PFMReader:
    """
    Fast container file reader.

    Usage:
        # Full parse (loads entire file)
        doc = PFMReader.read("file.pfm")

        # Indexed access (lazy)
        with PFMReader.open("file.pfm") as reader:
            content = reader.get_section("content")
    """

    def __init__(self, handle: BinaryIO, raw: bytes | None = None) -> None:
        self._handle = handle
        self._raw = raw
        self.meta: dict[str, str] = {}
        self.index: PFMIndex = PFMIndex()
        self.format_version: str = ""
        self._parsed_header = False

    @staticmethod
    def is_pfm(path: str | Path) -> bool:
        """Fast check if a file is PFM format. Reads only first 64 bytes."""
        with open(path, "rb") as f:
            head = f.read(MAX_MAGIC_SCAN_BYTES)
        return head.startswith(MAGIC.encode("utf-8"))

    @staticmethod
    def is_pfm_bytes(data: bytes) -> bool:
        """Fast check if bytes are PFM format."""
        return data[:len(MAGIC)].startswith(MAGIC.encode("utf-8"))

    @classmethod
    def read(cls, path: str | Path, max_size: int = MAX_FILE_SIZE) -> PFMDocument:
        """Fully parse a file into a PFMDocument."""
        path = Path(path)
        file_size = path.stat().st_size
        if file_size > max_size:
            raise ValueError(
                f"File size {file_size} exceeds maximum {max_size} bytes. "
                f"Pass max_size= to override."
            )
        with open(path, "rb") as f:
            data = f.read()
        return cls.parse(data)

    @classmethod
    def parse(cls, data: bytes, max_size: int = MAX_FILE_SIZE) -> PFMDocument:
        """Parse bytes into a PFMDocument."""
        if len(data) > max_size:
            raise ValueError(
                f"Input size {len(data)} exceeds maximum {max_size} bytes. "
                f"Pass max_size= to override."
            )
        text = data.decode("utf-8")
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        lines = text.split("\n")

        doc = PFMDocument()
        current_section: str | None = None
        section_lines: list[str] = []
        in_meta = False
        in_index = False
        hit_eof = False

        i = 0
        while i < len(lines):
            line = lines[i]

            if line.startswith(MAGIC):
                version_part = line.split("/", 1)[1] if "/" in line else "1.0"
                parsed_version = version_part.split(":")[0]
                if parsed_version not in SUPPORTED_FORMAT_VERSIONS:
                    raise ValueError(
                        f"Unsupported format version: {parsed_version!r}. "
                        f"Supported: {', '.join(sorted(SUPPORTED_FORMAT_VERSIONS))}"
                    )
                doc.format_version = parsed_version
                i += 1
                continue

            if line.startswith(EOF_MARKER):
                hit_eof = True
                break

            if line.startswith(SECTION_PREFIX):
                skip_sections = ("meta", "index", "index-trailing")
                if current_section and current_section not in skip_sections:
                    content = "\n".join(section_lines)
                    content = unescape_content(content)
                    doc.add_section(current_section, content)

                section_name = line[len(SECTION_PREFIX):]
                current_section = section_name
                section_lines = []
                in_meta = section_name == "meta"
                in_index = section_name in ("index", "index-trailing")
                i += 1
                continue

            if in_meta:
                if ": " in line:
                    key, val = line.split(": ", 1)
                    key = key.strip()
                    val = val.strip()
                    if key in META_ALLOWLIST:
                        if not getattr(doc, key, ""):
                            doc.__dict__[key] = val
                    else:
                        if key not in doc.custom_meta:
                            if len(doc.custom_meta) >= MAX_META_FIELDS:
                                raise ValueError(
                                    f"Maximum custom meta fields exceeded: {MAX_META_FIELDS}"
                                )
                            doc.custom_meta[key] = val
                i += 1
                continue

            if in_index:
                i += 1
                continue

            if current_section:
                section_lines.append(line)

            i += 1

        if current_section and current_section not in ("meta", "index", "index-trailing"):
            content = "\n".join(section_lines)
            if not hit_eof and content.endswith("\n"):
                content = content[:-1]
            content = unescape_content(content)
            doc.add_section(current_section, content)

        return doc

    @classmethod
    def open(cls, path: str | Path, max_size: int = MAX_FILE_SIZE) -> PFMReaderHandle:
        """Open a file for indexed, lazy reading."""
        path = Path(path)
        file_size = path.stat().st_size
        if file_size > max_size:
            raise ValueError(
                f"File size {file_size} exceeds maximum {max_size} bytes. "
                f"Pass max_size= to override."
            )

        f = builtins_open(path, "rb")
        head = f.read(min(file_size, 4096))
        has_crlf = b"\r\n" in head

        if has_crlf:
            f.seek(0)
            raw = f.read()
            f.close()
            normalized = raw.replace(b"\r\n", b"\n")
            import io as _io
            f = _io.BytesIO(normalized)
            file_size = len(normalized)
        else:
            f.seek(0)

        reader = PFMReaderHandle(f, file_size)
        reader._parse_header()
        return reader


builtins_open = builtins.open


class PFMReaderHandle:
    """Handle for indexed, lazy access to a container file."""

    def __init__(self, handle: BinaryIO, file_size: int) -> None:
        self._handle = handle
        self._file_size = file_size
        self.meta: dict[str, str] = {}
        self.index: PFMIndex = PFMIndex()
        self.format_version: str = ""

    def _parse_header(self) -> None:
        """Parse only magic, meta, and index."""
        self._handle.seek(0)
        current_section: str | None = None
        is_stream = False

        while True:
            line_bytes = self._handle.readline()
            if not line_bytes:
                break
            line = line_bytes.decode("utf-8").rstrip("\n").rstrip("\r")

            if line.startswith(MAGIC):
                version_part = line.split("/", 1)[1] if "/" in line else "1.0"
                parsed_version = version_part.split(":")[0]
                if parsed_version not in SUPPORTED_FORMAT_VERSIONS:
                    raise ValueError(
                        f"Unsupported format version: {parsed_version!r}. "
                        f"Supported: {', '.join(sorted(SUPPORTED_FORMAT_VERSIONS))}"
                    )
                self.format_version = parsed_version
                is_stream = ":STREAM" in line
                continue

            if line.startswith(SECTION_PREFIX):
                section_name = line[len(SECTION_PREFIX):]
                current_section = section_name
                if current_section not in ("meta", "index", "index-trailing"):
                    break
                continue

            if current_section == "meta" and ": " in line:
                key, val = line.split(": ", 1)
                key = key.strip()
                if key in self.meta:
                    continue
                if len(self.meta) >= MAX_META_FIELDS:
                    continue
                self.meta[key] = val.strip()

            if current_section in ("index", "index-trailing"):
                parts = line.strip().split()
                if len(parts) == 3 and parts[0] != "checksum":
                    try:
                        name, offset, length = parts
                        off = int(offset)
                        ln = int(length)
                    except ValueError:
                        continue
                    if 0 <= off and off + ln <= self._file_size:
                        self.index.add(name, off, ln)

        if is_stream and not self.index.entries:
            self._parse_trailing_index()

    def _parse_trailing_index(self) -> None:
        """Parse trailing index from the end of a stream-mode file."""
        tail_size = min(self._file_size, 64 * 1024)
        self._handle.seek(self._file_size - tail_size)
        tail = self._handle.read(tail_size).decode("utf-8")
        lines = tail.split("\n")

        for line in reversed(lines):
            if line.startswith(EOF_MARKER):
                continue
            if line.startswith(f"{SECTION_PREFIX}index-trailing"):
                break
            if line.strip() == "":
                continue
            parts = line.strip().split()
            if len(parts) == 3 and parts[0] != "checksum":
                try:
                    name, offset, length = parts[0], int(parts[1]), int(parts[2])
                    if 0 <= offset and offset + length <= self._file_size:
                        self.index.add(name, offset, length)
                except ValueError:
                    continue
            elif len(parts) == 2 and parts[0] == "checksum":
                self.meta["checksum"] = parts[1]

    def _read_raw(self, offset: int, length: int) -> bytes:
        self._handle.seek(offset)
        return self._handle.read(length)

    def get_section(self, name: str) -> str | None:
        """O(1) indexed access to a section's content."""
        entry = self.index.get(name)
        if entry is None:
            return None
        offset, length = entry
        raw = self._read_raw(offset, length).decode("utf-8")
        if raw.endswith("\n"):
            raw = raw[:-1]
        return unescape_content(raw)

    def get_sections(self, name: str) -> list[str]:
        results = []
        for offset, length in self.index.get_all(name):
            raw = self._read_raw(offset, length).decode("utf-8")
            if raw.endswith("\n"):
                raw = raw[:-1]
            results.append(unescape_content(raw))
        return results

    @property
    def section_names(self) -> list[str]:
        return self.index.section_names

    def to_document(self) -> PFMDocument:
        self._handle.seek(0)
        data = self._handle.read()
        return PFMReader.parse(data)

    def validate_checksum(self) -> bool:
        """Validate the checksum in meta against actual content."""
        expected = self.meta.get("checksum", "")
        if not expected:
            return False

        all_entries = []
        for name in self.index.section_names:
            for offset, length in self.index.get_all(name):
                all_entries.append((offset, length))
        all_entries.sort()

        h = hashlib.sha256()
        for offset, length in all_entries:
            chunk = self._read_raw(offset, length)
            if chunk.endswith(b"\n"):
                chunk = chunk[:-1]
            unescaped = unescape_content(chunk.decode("utf-8")).encode("utf-8")
            h.update(unescaped)
        return _hmac.compare_digest(h.hexdigest(), expected)

    def close(self) -> None:
        self._handle.close()

    def __enter__(self) -> PFMReaderHandle:
        return self

    def __exit__(self, *args) -> None:
        self.close()
