"""
Container Format Specification v1.0 — forked from PFM (getpfm.io).

Layout:
    #!PFM/1.0                    <- Magic line (file identification, instant)
    #@meta                       <- Metadata section header
    id: <uuid>                   <- Unique document ID
    created: <iso-8601>          <- Timestamp
    checksum: <sha256>           <- SHA-256 of all content sections combined
    #@index                      <- Index section (byte offsets for O(1) jumps)
    <name> <offset> <length>     <- Section name, byte offset from file start, byte length
    #@<section_name>             <- Content sections
    <content>
    #!END                        <- EOF marker

Content Escaping:
    - Lines starting with #@ or #! inside section content are escaped on write
    - Escape prefix: \\# (backslash-hash) replaces the leading #
    - Writer: "#@fake" -> "\\#@fake",  "#!END" -> "\\#!END"
    - Reader: "\\#@fake" -> "#@fake",  "\\#!END" -> "#!END"

Checksum Protocol:
    - The checksum covers UNESCAPED section content (original text)
    - Each section's content is UTF-8 encoded and fed into SHA-256 in document order
    - Trailing newlines added by the writer for format correctness are stripped before hashing

Origin: PFM (MIT License)
"""

# Magic bytes - first line of every container file
MAGIC = "#!PFM"
EOF_MARKER = "#!END"
SECTION_PREFIX = "#@"
ESCAPE_PREFIX = "\\#"  # Escape for content lines that look like markers

# Format version
FORMAT_VERSION = "1.0"

# Supported format versions (reject unknown versions to prevent downgrade attacks)
SUPPORTED_FORMAT_VERSIONS = frozenset({"1.0"})

# Strict allowlist for meta fields settable via parser
META_ALLOWLIST = frozenset({
    "id", "agent", "model", "created", "checksum",
    "parent", "tags", "version",
})
# L3-specific fields are stored in custom_meta (not standard attributes):
# anchor_txid, anchor_network, anchor_hash, anchor_ts,
# block_height, content_type

# Safety limits
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB max file size for reader
MAX_SECTIONS = 10_000              # Max sections per document
MAX_META_FIELDS = 100              # Max custom meta fields
MAX_SECTION_NAME_LENGTH = 64       # Max length for section names
ALLOWED_SECTION_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789_-")

# Section types relevant to L3 operations
SECTION_TYPES = {
    "meta": "File metadata (id, timestamps, anchor info)",
    "index": "Byte offset index for O(1) section access",
    "content": "Primary content",
    "data": "Raw data payload",
    "proof": "Merkle proof or verification data",
    "anchor": "Bitcoin L1 anchor metadata",
}

# Meta field names
META_FIELDS = {
    "id": "Unique document identifier (UUID v4)",
    "agent": "Name/identifier of the generating agent",
    "model": "Model ID used for generation",
    "created": "ISO-8601 creation timestamp",
    "checksum": "SHA-256 hash of all content sections",
    "parent": "ID of parent document (for chains)",
    "tags": "Comma-separated tags",
    "version": "Document version (user-defined)",
    "content_type": "MIME type of primary content",
    "anchor_txid": "Bitcoin transaction ID of L1 anchor",
    "anchor_network": "Bitcoin network (mainnet/testnet/signet/regtest)",
    "anchor_hash": "SHA-256 hash anchored on-chain",
    "anchor_ts": "ISO-8601 timestamp of anchor transaction",
    "block_height": "Bitcoin block height containing anchor",
}

# File extension
EXTENSION = ".pfm"

# Max magic line scan (for fast identification - don't read more than this)
MAX_MAGIC_SCAN_BYTES = 64


def _has_marker_after_backslashes(line: str) -> bool:
    """Check if line starts with zero or more backslashes followed by a PFM marker."""
    i = 0
    while i < len(line) and line[i] == "\\":
        i += 1
    rest = line[i:]
    return rest.startswith(SECTION_PREFIX) or rest.startswith(MAGIC) or rest.startswith(EOF_MARKER)


def escape_content_line(line: str) -> str:
    """Escape a content line that starts with a PFM marker prefix."""
    if _has_marker_after_backslashes(line):
        return "\\" + line
    return line


def unescape_content_line(line: str) -> str:
    """Unescape a previously escaped content line."""
    if line.startswith("\\") and _has_marker_after_backslashes(line[1:]):
        return line[1:]
    return line


def escape_content(content: str) -> str:
    """Escape all lines in a content string."""
    return "\n".join(escape_content_line(line) for line in content.split("\n"))


def unescape_content(content: str) -> str:
    """Unescape all lines in a content string."""
    return "\n".join(unescape_content_line(line) for line in content.split("\n"))
