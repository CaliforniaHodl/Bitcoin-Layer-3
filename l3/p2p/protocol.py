"""
Wire protocol — message types, binary framing, serialization, and validation.

Frame format (over TCP):
    [4 bytes: "PFM3"]  [4 bytes: payload length, big-endian uint32]  [payload: JSON UTF-8]

All messages are JSON objects with required fields:
    type     — message type string
    version  — protocol version ("1.0")
    payload  — type-specific dict
    ts       — ISO-8601 timestamp
    nonce    — random hex string (replay deduplication)
"""

from __future__ import annotations

import json
import os
import struct
from datetime import datetime, timezone
from typing import Any

from l3 import P2P_MAGIC, P2P_MAX_PAYLOAD, P2P_PROTOCOL_VERSION

# Frame header: 4-byte magic + 4-byte length
HEADER_SIZE = 8
HEADER_STRUCT = struct.Struct(">4sI")  # big-endian: 4-char magic, uint32 length

# Valid message types
HANDSHAKE = "HANDSHAKE"
PING = "PING"
PONG = "PONG"
INV = "INV"
WANT = "WANT"
DATA = "DATA"
ANCHOR_ANN = "ANCHOR_ANN"
PEERS_REQ = "PEERS_REQ"
PEERS_RES = "PEERS_RES"
NOT_FOUND = "NOT_FOUND"

HANDSHAKE_ACK = "HANDSHAKE_ACK"

VALID_TYPES = frozenset({
    HANDSHAKE, HANDSHAKE_ACK, PING, PONG, INV, WANT, DATA,
    ANCHOR_ANN, PEERS_REQ, PEERS_RES, NOT_FOUND,
})

# Required payload fields per message type
_PAYLOAD_SCHEMA: dict[str, set[str]] = {
    HANDSHAKE: {"node_pubkey", "version", "store_size", "challenge"},
    HANDSHAKE_ACK: {"challenge_sig"},
    PING: set(),
    PONG: set(),
    INV: {"checksums"},
    WANT: {"checksum"},
    DATA: {"checksum", "document"},
    ANCHOR_ANN: {"checksum", "txid", "network"},
    PEERS_REQ: set(),
    PEERS_RES: {"peers"},
    NOT_FOUND: {"checksum"},
}


class ProtocolError(Exception):
    """Invalid message or framing error."""


def make_message(msg_type: str, payload: dict[str, Any] | None = None) -> dict:
    """Build a protocol message dict with required envelope fields."""
    if msg_type not in VALID_TYPES:
        raise ProtocolError(f"Unknown message type: {msg_type!r}")
    return {
        "type": msg_type,
        "version": P2P_PROTOCOL_VERSION,
        "payload": payload or {},
        "ts": datetime.now(timezone.utc).isoformat(),
        "nonce": os.urandom(8).hex(),
    }


def validate_message(msg: dict) -> None:
    """Validate a deserialized message. Raises ProtocolError on failure."""
    if not isinstance(msg, dict):
        raise ProtocolError("Message must be a JSON object")

    for field in ("type", "version", "payload", "ts", "nonce"):
        if field not in msg:
            raise ProtocolError(f"Missing required field: {field!r}")

    msg_type = msg["type"]
    if msg_type not in VALID_TYPES:
        raise ProtocolError(f"Unknown message type: {msg_type!r}")

    if not isinstance(msg["payload"], dict):
        raise ProtocolError("payload must be a JSON object")

    if not isinstance(msg["nonce"], str) or len(msg["nonce"]) < 4:
        raise ProtocolError("nonce must be a hex string of at least 4 chars")

    # Check required payload fields
    required = _PAYLOAD_SCHEMA.get(msg_type, set())
    missing = required - set(msg["payload"].keys())
    if missing:
        raise ProtocolError(
            f"{msg_type} missing payload fields: {', '.join(sorted(missing))}"
        )


def encode(msg: dict) -> bytes:
    """Serialize a message dict to a framed binary blob.

    Returns: magic (4B) + length (4B) + JSON payload (variable).
    """
    validate_message(msg)
    payload_bytes = json.dumps(msg, separators=(",", ":")).encode("utf-8")
    if len(payload_bytes) > P2P_MAX_PAYLOAD:
        raise ProtocolError(
            f"Payload too large: {len(payload_bytes)} bytes (max {P2P_MAX_PAYLOAD})"
        )
    header = HEADER_STRUCT.pack(P2P_MAGIC, len(payload_bytes))
    return header + payload_bytes


def decode_header(data: bytes) -> int:
    """Decode a frame header. Returns payload length.

    Expects exactly HEADER_SIZE (8) bytes.
    Raises ProtocolError on bad magic or oversized payload.
    """
    if len(data) < HEADER_SIZE:
        raise ProtocolError(f"Header too short: {len(data)} bytes")

    magic, length = HEADER_STRUCT.unpack(data[:HEADER_SIZE])
    if magic != P2P_MAGIC:
        raise ProtocolError(f"Bad magic: expected {P2P_MAGIC!r}, got {magic!r}")
    if length > P2P_MAX_PAYLOAD:
        raise ProtocolError(f"Payload length {length} exceeds max {P2P_MAX_PAYLOAD}")
    return length


def decode_payload(data: bytes) -> dict:
    """Decode and validate a JSON payload (after header is stripped).

    Returns the validated message dict.
    """
    try:
        msg = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ProtocolError(f"Invalid JSON payload: {e}") from e

    validate_message(msg)
    return msg


def decode(data: bytes) -> dict:
    """Decode a full framed message (header + payload).

    Convenience function for testing. In production, use decode_header +
    decode_payload separately for streaming reads.
    """
    length = decode_header(data)
    payload_data = data[HEADER_SIZE:HEADER_SIZE + length]
    if len(payload_data) < length:
        raise ProtocolError(
            f"Incomplete payload: expected {length} bytes, got {len(payload_data)}"
        )
    return decode_payload(payload_data)
