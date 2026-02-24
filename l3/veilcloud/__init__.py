"""
VeilCloud — zero-knowledge storage primitives for Bitcoin L3.

Provides:
    - MerkleTree / MerkleProof — Merkle tree construction and proof generation
    - encrypt / decrypt — AES-256-GCM client-side encryption (requires `cryptography`)
    - split_secret / combine_shares — Shamir's Secret Sharing over GF(256)
    - AuditLog / AuditEntry — append-only hash-chained audit trail
    - CredentialManager / Credential — HMAC-signed access credentials

All modules use stdlib only except crypto.py which requires the `cryptography` package.
Install with: pip install bitcoin-l3[veilcloud]
"""

from l3.veilcloud.merkle import MerkleTree, MerkleProof, verify_proof
from l3.veilcloud.threshold import split_secret, combine_shares, Share
from l3.veilcloud.audit import AuditLog, AuditEntry
from l3.veilcloud.access import (
    CredentialManager,
    Credential,
    Permission,
)

__all__ = [
    "MerkleTree",
    "MerkleProof",
    "verify_proof",
    "split_secret",
    "combine_shares",
    "Share",
    "AuditLog",
    "AuditEntry",
    "CredentialManager",
    "Credential",
    "Permission",
]
