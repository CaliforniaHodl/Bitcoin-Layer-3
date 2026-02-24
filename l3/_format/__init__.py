"""
Internal container format engine — forked from PFM (getpfm.io).

The container format (section-based, byte-indexed, SHA-256 checksummed)
is used by Bitcoin L3 for document storage and anchoring. This is an
internal dependency — not a public API.

Format: #!PFM/1.0 (compatible with PFM spec v1.0)
Protocol: PFM3 OP_RETURN prefix (4 bytes + 32 byte SHA-256)

Origin: PFM (MIT License)
"""

from l3._format.spec import MAGIC, FORMAT_VERSION, SECTION_TYPES
from l3._format.writer import PFMWriter
from l3._format.reader import PFMReader
from l3._format.document import PFMDocument, PFMSection
