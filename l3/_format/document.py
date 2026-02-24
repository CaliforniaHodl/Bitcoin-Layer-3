"""
Document model — in-memory representation of a container file.

Forked from PFM (getpfm.io) — MIT License.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field

from l3._format.spec import (
    MAX_SECTIONS,
    MAX_SECTION_NAME_LENGTH,
    ALLOWED_SECTION_NAME_CHARS,
)


@dataclass
class PFMSection:
    """A single section in a document."""
    name: str
    content: str
    offset: int = 0   # byte offset from file start (populated on read/write)
    length: int = 0    # byte length of content (populated on read/write)


@dataclass
class PFMDocument:
    """
    In-memory representation of a .pfm container file.

    Usage:
        doc = PFMDocument.create(agent="l3-node")
        doc.add_section("content", "Hello from L3!")
        doc.write("output.pfm")
    """

    # Metadata
    id: str = ""
    agent: str = ""
    model: str = ""
    created: str = ""
    checksum: str = ""
    parent: str = ""
    tags: str = ""
    version: str = ""

    # Custom meta fields (beyond the standard ones)
    custom_meta: dict[str, str] = field(default_factory=dict)

    # Ordered sections
    sections: list[PFMSection] = field(default_factory=list)

    # Format version
    format_version: str = "1.0"

    @classmethod
    def create(
        cls,
        agent: str = "",
        model: str = "",
        parent: str = "",
        tags: str = "",
        version: str = "",
        **custom_meta: str,
    ) -> PFMDocument:
        """Create a new document with auto-generated id and timestamp."""
        return cls(
            id=str(uuid.uuid4()),
            agent=agent,
            model=model,
            created=datetime.now(timezone.utc).isoformat(),
            parent=parent,
            tags=tags,
            version=version,
            custom_meta=custom_meta,
        )

    # Reserved names that cannot be used as content section names
    _RESERVED_SECTION_NAMES = frozenset({"meta", "index", "index-trailing"})

    def add_section(self, name: str, content: str) -> PFMSection:
        """Add a named section. Returns the section for chaining."""
        if not name:
            raise ValueError("Section name cannot be empty")
        if len(name) > MAX_SECTION_NAME_LENGTH:
            raise ValueError(
                f"Section name too long: {len(name)} chars "
                f"(max {MAX_SECTION_NAME_LENGTH})"
            )
        if not all(c in ALLOWED_SECTION_NAME_CHARS for c in name):
            raise ValueError(
                f"Invalid section name: {name!r}. "
                f"Only lowercase alphanumeric, hyphens, and underscores allowed."
            )
        if name in self._RESERVED_SECTION_NAMES:
            raise ValueError(f"Reserved section name: {name!r}")

        if len(self.sections) >= MAX_SECTIONS:
            raise ValueError(
                f"Maximum section count exceeded: {MAX_SECTIONS}"
            )

        section = PFMSection(name=name, content=content)
        self.sections.append(section)
        return section

    def get_section(self, name: str) -> PFMSection | None:
        """Get first section by name."""
        for s in self.sections:
            if s.name == name:
                return s
        return None

    def get_sections(self, name: str) -> list[PFMSection]:
        """Get all sections with a given name."""
        return [s for s in self.sections if s.name == name]

    def compute_checksum(self) -> str:
        """Compute SHA-256 checksum of all section contents combined."""
        h = hashlib.sha256()
        for section in self.sections:
            h.update(section.content.encode("utf-8"))
        return h.hexdigest()

    def get_meta_dict(self) -> dict[str, str]:
        """Return all metadata as a flat dict."""
        meta = {}
        for key in ("id", "agent", "model", "created", "checksum", "parent", "tags", "version"):
            val = getattr(self, key, "")
            if val:
                meta[key] = val
        meta.update(self.custom_meta)
        return meta

    @property
    def content(self) -> str | None:
        """Shortcut to get the primary content section."""
        s = self.get_section("content")
        return s.content if s else None

    def validate_checksum(self) -> bool:
        """Validate document integrity by recomputing and comparing checksum."""
        import hmac
        if not self.checksum:
            return False
        return hmac.compare_digest(self.checksum, self.compute_checksum())

    def write(self, path: str, mode: int = 0o644) -> int:
        """Write this document to a file. Returns bytes written."""
        from pathlib import Path as _Path
        if ".." in _Path(path).parts:
            raise ValueError("Output path must not contain '..' (path traversal)")
        from l3._format.writer import PFMWriter
        return PFMWriter.write(self, path, mode)

    def to_bytes(self) -> bytes:
        """Serialize this document to bytes."""
        from l3._format.writer import PFMWriter
        return PFMWriter.serialize(self)

    def __repr__(self) -> str:
        sec_names = [s.name for s in self.sections]
        return f"PFMDocument(id={self.id[:8]}..., sections={sec_names})"
