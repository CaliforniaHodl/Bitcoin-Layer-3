"""
Bitcoin L3 — anchor PFM document checksums to Bitcoin via OP_RETURN.

Architecture:
    L1 (Bitcoin):  OP_RETURN = "PFM3" (4 bytes) + SHA-256 checksum (32 bytes) = 36 bytes
    L3 (Local):    ~/.pfm/l3/store/<checksum>.pfm + index.json
    Bridge:        l3 anchor / l3 verify-anchor CLI commands
"""

__version__ = "0.1.0"

ANCHOR_PROTOCOL_PREFIX = "PFM3"
ANCHOR_PREFIX_BYTES = b"PFM3"
ANCHOR_PREFIX_HEX = "50464d33"
ANCHOR_PAYLOAD_SIZE = 36  # 4 (prefix) + 32 (SHA-256)

# P2P network constants
P2P_PROTOCOL_VERSION = "1.0"
P2P_DEFAULT_PORT = 9735
P2P_MAGIC = b"PFM3"
P2P_MAX_PAYLOAD = 2 * 1024 * 1024  # 2MB — hardened from 100MB to prevent OOM
P2P_DEFAULT_RELAYS = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
]

# Anchor API constants
API_DEFAULT_PORT = 8080
API_DEFAULT_HOST = "127.0.0.1"
API_MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
API_DEFAULT_EXPIRY_SECS = 3600  # 1 hour
API_POLL_INTERVAL_SECS = 30

# VeilCloud constants
VEILCLOUD_KDF_ITERATIONS = 600_000  # OWASP 2023 minimum for PBKDF2-HMAC-SHA256
VEILCLOUD_KEY_SIZE = 32  # AES-256
VEILCLOUD_SALT_SIZE = 16  # 128-bit salt
VEILCLOUD_NONCE_SIZE = 12  # AES-GCM standard nonce
VEILCLOUD_MAX_SHARES = 255  # GF(256) field limit
VEILCLOUD_AUDIT_DIR = "audit"  # subdirectory under ~/.pfm/l3/
