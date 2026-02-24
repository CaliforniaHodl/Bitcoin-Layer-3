"""
Merkle tree construction and proof generation/verification.

Domain separation:
    Leaf hash:     SHA-256(0x00 + data)
    Internal hash: SHA-256(0x01 + left + right)

This prevents second-preimage attacks where an internal node could be
confused with a leaf.

Odd leaf count: duplicate last leaf (Bitcoin Merkle convention).
Root is a 64-char hex string that plugs directly into _build_op_return_hex()
for batch anchoring.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass


_LEAF_PREFIX = b"\x00"
_INTERNAL_PREFIX = b"\x01"


def _hash_leaf(data: bytes) -> bytes:
    """Hash a leaf node with domain separation prefix."""
    return hashlib.sha256(_LEAF_PREFIX + data).digest()


def _hash_internal(left: bytes, right: bytes) -> bytes:
    """Hash two child nodes with domain separation prefix."""
    return hashlib.sha256(_INTERNAL_PREFIX + left + right).digest()


@dataclass(frozen=True)
class MerkleProof:
    """Inclusion proof for a leaf in a Merkle tree.

    Attributes:
        leaf: The original leaf data (hex checksum bytes).
        leaf_index: Position of the leaf in the original list.
        siblings: List of (hash_bytes, direction) pairs.
            direction is 'left' if sibling is on the left, 'right' if on the right.
        root: The Merkle root (32 bytes).
    """

    leaf: bytes
    leaf_index: int
    siblings: list[tuple[bytes, str]]
    root: bytes

    @property
    def root_hex(self) -> str:
        return self.root.hex()


def verify_proof(proof: MerkleProof) -> bool:
    """Verify a Merkle inclusion proof.

    Uses constant-time comparison for the root check.
    Fail-closed: returns False on any error.
    """
    try:
        current = _hash_leaf(proof.leaf)

        for sibling_hash, direction in proof.siblings:
            if direction == "left":
                current = _hash_internal(sibling_hash, current)
            else:
                current = _hash_internal(current, sibling_hash)

        return hmac.compare_digest(current, proof.root)
    except Exception:
        return False


class MerkleTree:
    """Balanced Merkle tree built from a list of leaf data.

    Usage:
        tree = MerkleTree.from_leaves([b"aabb...", b"ccdd..."])
        root = tree.root_hex  # 64-char hex string
        proof = tree.get_proof(0)
        assert verify_proof(proof)
    """

    def __init__(self, leaves: list[bytes], layers: list[list[bytes]]) -> None:
        self._leaves = leaves
        self._layers = layers

    @classmethod
    def from_leaves(cls, leaf_data: list[bytes]) -> MerkleTree:
        """Build a Merkle tree from leaf data.

        Args:
            leaf_data: List of raw data for each leaf (e.g. checksum bytes).
                       Must have at least one element.

        Returns:
            A MerkleTree instance.

        Raises:
            ValueError: If leaf_data is empty.
        """
        if not leaf_data:
            raise ValueError("Cannot build Merkle tree from empty leaf list")

        leaves = list(leaf_data)
        layer = [_hash_leaf(d) for d in leaves]
        layers = [layer]

        while len(layer) > 1:
            if len(layer) % 2 == 1:
                layer = layer + [layer[-1]]  # duplicate last (Bitcoin convention)

            next_layer = []
            for i in range(0, len(layer), 2):
                next_layer.append(_hash_internal(layer[i], layer[i + 1]))
            layer = next_layer
            layers.append(layer)

        return cls(leaves, layers)

    @classmethod
    def from_checksums(cls, checksums: list[str]) -> MerkleTree:
        """Build a Merkle tree from hex checksum strings.

        Convenience wrapper that encodes hex checksums to bytes.
        """
        leaf_data = []
        for cs in checksums:
            cs = cs.strip()
            if cs.startswith("sha256:"):
                cs = cs[7:]
            if len(cs) != 64:
                raise ValueError(f"Invalid checksum length: {len(cs)} (expected 64)")
            try:
                bytes.fromhex(cs)
            except ValueError:
                raise ValueError(f"Invalid hex in checksum: {cs!r}")
            leaf_data.append(cs.encode("ascii"))
        return cls.from_leaves(leaf_data)

    @property
    def root(self) -> bytes:
        """The 32-byte Merkle root."""
        return self._layers[-1][0]

    @property
    def root_hex(self) -> str:
        """The Merkle root as a 64-char hex string."""
        return self.root.hex()

    @property
    def leaf_count(self) -> int:
        return len(self._leaves)

    def get_proof(self, index: int) -> MerkleProof:
        """Generate an inclusion proof for the leaf at the given index.

        Args:
            index: 0-based index into the original leaf list.

        Returns:
            A MerkleProof that can be verified with verify_proof().

        Raises:
            IndexError: If index is out of range.
        """
        if index < 0 or index >= len(self._leaves):
            raise IndexError(
                f"Leaf index {index} out of range [0, {len(self._leaves)})"
            )

        siblings: list[tuple[bytes, str]] = []
        idx = index

        for layer in self._layers[:-1]:
            # Pad odd layers the same way we did during construction
            padded = layer
            if len(padded) % 2 == 1:
                padded = padded + [padded[-1]]

            if idx % 2 == 0:
                sibling = padded[idx + 1]
                siblings.append((sibling, "right"))
            else:
                sibling = padded[idx - 1]
                siblings.append((sibling, "left"))

            idx //= 2

        return MerkleProof(
            leaf=self._leaves[index],
            leaf_index=index,
            siblings=siblings,
            root=self.root,
        )
