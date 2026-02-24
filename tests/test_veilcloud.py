"""
Comprehensive tests for VeilCloud modules.

TestMerkleTree          — construction, proofs, domain separation, batch anchoring
TestEncryption          — roundtrip, wrong password, tampered ciphertext
TestShamirSecretSharing — split/combine, any-t-of-n subsets, edge cases
TestAuditLog            — chain integrity, Merkle proofs, persistence, thread safety
TestAccessControl       — issue/verify/revoke, expiry, tampered signatures
TestIntegration         — encrypt-with-shamir-key, audit-anchor flow
"""

from __future__ import annotations

import hashlib
import itertools
import json
import os
import secrets
import tempfile
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest import TestCase

import pytest


# ══════════════════════════════════════════════════════════════════════════
# Merkle Tree Tests
# ══════════════════════════════════════════════════════════════════════════


class TestMerkleTree(TestCase):
    """Tests for l3.veilcloud.merkle."""

    def test_single_leaf(self):
        from l3.veilcloud.merkle import MerkleTree, verify_proof

        tree = MerkleTree.from_leaves([b"hello"])
        assert tree.leaf_count == 1
        assert len(tree.root_hex) == 64

        proof = tree.get_proof(0)
        assert verify_proof(proof)

    def test_two_leaves(self):
        from l3.veilcloud.merkle import MerkleTree, verify_proof

        tree = MerkleTree.from_leaves([b"a", b"b"])
        assert tree.leaf_count == 2

        for i in range(2):
            proof = tree.get_proof(i)
            assert verify_proof(proof)

    def test_power_of_two(self):
        from l3.veilcloud.merkle import MerkleTree, verify_proof

        leaves = [f"leaf-{i}".encode() for i in range(8)]
        tree = MerkleTree.from_leaves(leaves)

        for i in range(8):
            proof = tree.get_proof(i)
            assert verify_proof(proof), f"Proof failed for leaf {i}"

    def test_odd_leaf_count(self):
        from l3.veilcloud.merkle import MerkleTree, verify_proof

        leaves = [f"leaf-{i}".encode() for i in range(5)]
        tree = MerkleTree.from_leaves(leaves)

        for i in range(5):
            proof = tree.get_proof(i)
            assert verify_proof(proof), f"Proof failed for leaf {i}"

    def test_large_tree(self):
        from l3.veilcloud.merkle import MerkleTree, verify_proof

        leaves = [secrets.token_bytes(32) for _ in range(100)]
        tree = MerkleTree.from_leaves(leaves)

        # Spot-check some proofs
        for i in [0, 1, 49, 50, 99]:
            proof = tree.get_proof(i)
            assert verify_proof(proof), f"Proof failed for leaf {i}"

    def test_domain_separation(self):
        """Leaf hashes and internal hashes must differ even with same data."""
        from l3.veilcloud.merkle import _hash_leaf, _hash_internal

        data = b"test"
        leaf_hash = _hash_leaf(data)
        # An internal node with the same data should produce a different hash
        internal_hash = _hash_internal(data, data)
        assert leaf_hash != internal_hash

    def test_from_checksums(self):
        from l3.veilcloud.merkle import MerkleTree, verify_proof

        checksums = [hashlib.sha256(f"doc-{i}".encode()).hexdigest() for i in range(4)]
        tree = MerkleTree.from_checksums(checksums)

        assert tree.leaf_count == 4
        assert len(tree.root_hex) == 64

        for i in range(4):
            proof = tree.get_proof(i)
            assert verify_proof(proof)

    def test_from_checksums_with_prefix(self):
        from l3.veilcloud.merkle import MerkleTree

        cs = hashlib.sha256(b"test").hexdigest()
        tree = MerkleTree.from_checksums([f"sha256:{cs}"])
        assert tree.leaf_count == 1

    def test_invalid_checksum_length(self):
        from l3.veilcloud.merkle import MerkleTree

        with pytest.raises(ValueError, match="Invalid checksum length"):
            MerkleTree.from_checksums(["abc"])

    def test_empty_leaves_raises(self):
        from l3.veilcloud.merkle import MerkleTree

        with pytest.raises(ValueError, match="empty"):
            MerkleTree.from_leaves([])

    def test_index_out_of_range(self):
        from l3.veilcloud.merkle import MerkleTree

        tree = MerkleTree.from_leaves([b"a", b"b"])
        with pytest.raises(IndexError):
            tree.get_proof(2)
        with pytest.raises(IndexError):
            tree.get_proof(-1)

    def test_tampered_proof_fails(self):
        from l3.veilcloud.merkle import MerkleTree, MerkleProof, verify_proof

        tree = MerkleTree.from_leaves([b"a", b"b", b"c", b"d"])
        proof = tree.get_proof(0)

        # Tamper with root
        tampered = MerkleProof(
            leaf=proof.leaf,
            leaf_index=proof.leaf_index,
            siblings=proof.siblings,
            root=b"\x00" * 32,
        )
        assert not verify_proof(tampered)

    def test_root_hex_is_64_chars(self):
        from l3.veilcloud.merkle import MerkleTree

        tree = MerkleTree.from_leaves([b"data"])
        assert len(tree.root_hex) == 64
        bytes.fromhex(tree.root_hex)  # must be valid hex

    def test_integration_with_op_return(self):
        """Merkle root should be a valid checksum for _build_op_return_hex."""
        from l3.veilcloud.merkle import MerkleTree
        from l3.anchor import _build_op_return_hex

        checksums = [hashlib.sha256(f"doc-{i}".encode()).hexdigest() for i in range(3)]
        tree = MerkleTree.from_checksums(checksums)

        # The root should be valid for anchoring
        script_hex = _build_op_return_hex(tree.root_hex)
        assert script_hex.startswith("6a24")

    def test_deterministic(self):
        from l3.veilcloud.merkle import MerkleTree

        leaves = [b"a", b"b", b"c"]
        tree1 = MerkleTree.from_leaves(leaves)
        tree2 = MerkleTree.from_leaves(leaves)
        assert tree1.root_hex == tree2.root_hex


# ══════════════════════════════════════════════════════════════════════════
# Encryption Tests
# ══════════════════════════════════════════════════════════════════════════


# Skip encryption tests if cryptography is not installed
try:
    import cryptography
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

skip_no_crypto = pytest.mark.skipif(
    not HAS_CRYPTO,
    reason="cryptography package not installed",
)


class TestEncryption(TestCase):
    """Tests for l3.veilcloud.crypto."""

    @skip_no_crypto
    def test_roundtrip(self):
        from l3.veilcloud.crypto import encrypt, decrypt

        plaintext = b"Hello, VeilCloud!"
        password = "test-password-123"

        payload = encrypt(plaintext, password)
        recovered = decrypt(payload, password)
        assert recovered == plaintext

    @skip_no_crypto
    def test_large_data(self):
        from l3.veilcloud.crypto import encrypt, decrypt

        plaintext = secrets.token_bytes(1024 * 100)  # 100KB
        password = "large-data-test"

        payload = encrypt(plaintext, password)
        recovered = decrypt(payload, password)
        assert recovered == plaintext

    @skip_no_crypto
    def test_wrong_password(self):
        from l3.veilcloud.crypto import encrypt, decrypt

        payload = encrypt(b"secret", "correct")
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt(payload, "wrong")

    @skip_no_crypto
    def test_tampered_ciphertext(self):
        from l3.veilcloud.crypto import encrypt, decrypt, EncryptedPayload

        payload = encrypt(b"secret", "password")
        tampered = EncryptedPayload(
            ciphertext=b"\x00" + payload.ciphertext[1:],
            nonce=payload.nonce,
            salt=payload.salt,
        )
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt(tampered, "password")

    @skip_no_crypto
    def test_serialize_deserialize(self):
        from l3.veilcloud.crypto import encrypt, decrypt, EncryptedPayload

        payload = encrypt(b"test data", "pass")
        raw = payload.to_bytes()
        restored = EncryptedPayload.from_bytes(raw)

        assert restored.salt == payload.salt
        assert restored.nonce == payload.nonce
        assert restored.ciphertext == payload.ciphertext

        assert decrypt(restored, "pass") == b"test data"

    @skip_no_crypto
    def test_encrypt_with_key(self):
        from l3.veilcloud.crypto import encrypt_with_key, decrypt_with_key

        key = secrets.token_bytes(32)
        plaintext = b"key-based encryption"

        payload = encrypt_with_key(plaintext, key)
        recovered = decrypt_with_key(payload, key)
        assert recovered == plaintext

    @skip_no_crypto
    def test_wrong_key(self):
        from l3.veilcloud.crypto import encrypt_with_key, decrypt_with_key

        key = secrets.token_bytes(32)
        payload = encrypt_with_key(b"secret", key)
        with pytest.raises(ValueError, match="Decryption failed"):
            decrypt_with_key(payload, secrets.token_bytes(32))

    @skip_no_crypto
    def test_invalid_key_size(self):
        from l3.veilcloud.crypto import encrypt_with_key

        with pytest.raises(ValueError, match="32 bytes"):
            encrypt_with_key(b"data", b"short-key")

    def test_derive_key_deterministic(self):
        from l3.veilcloud.crypto import derive_key

        salt = b"\x00" * 16
        key1, _ = derive_key("password", salt)
        key2, _ = derive_key("password", salt)
        assert key1 == key2

    def test_derive_key_different_passwords(self):
        from l3.veilcloud.crypto import derive_key

        salt = b"\x00" * 16
        key1, _ = derive_key("password1", salt)
        key2, _ = derive_key("password2", salt)
        assert key1 != key2

    def test_derive_key_generates_salt(self):
        from l3.veilcloud.crypto import derive_key

        key1, salt1 = derive_key("password")
        key2, salt2 = derive_key("password")
        # Different salts should produce different keys
        assert salt1 != salt2
        assert key1 != key2

    def test_missing_cryptography_message(self):
        """If cryptography is missing, import should give a clear message."""
        # This test just verifies the import mechanism exists
        from l3.veilcloud.crypto import _import_cryptography
        if HAS_CRYPTO:
            _import_cryptography()  # should not raise


# ══════════════════════════════════════════════════════════════════════════
# Shamir's Secret Sharing Tests
# ══════════════════════════════════════════════════════════════════════════


class TestShamirSecretSharing(TestCase):
    """Tests for l3.veilcloud.threshold."""

    def test_basic_split_combine(self):
        from l3.veilcloud.threshold import split_secret, combine_shares

        secret = b"my secret key!!"
        shares = split_secret(secret, threshold=3, total_shares=5)
        assert len(shares) == 5

        recovered = combine_shares(shares[:3])
        assert recovered == secret

    def test_any_t_of_n_subsets(self):
        from l3.veilcloud.threshold import split_secret, combine_shares

        secret = secrets.token_bytes(32)
        shares = split_secret(secret, threshold=3, total_shares=5)

        # Any 3 of 5 should work
        for combo in itertools.combinations(shares, 3):
            recovered = combine_shares(list(combo))
            assert recovered == secret

    def test_insufficient_shares(self):
        """Fewer than threshold shares should NOT recover the secret."""
        from l3.veilcloud.threshold import split_secret, combine_shares

        secret = b"top secret"
        shares = split_secret(secret, threshold=3, total_shares=5)

        # 2 shares should not produce the correct secret
        result = combine_shares(shares[:2])
        assert result != secret

    def test_2_of_2(self):
        from l3.veilcloud.threshold import split_secret, combine_shares

        secret = b"minimal"
        shares = split_secret(secret, threshold=2, total_shares=2)
        recovered = combine_shares(shares)
        assert recovered == secret

    def test_5_of_5(self):
        from l3.veilcloud.threshold import split_secret, combine_shares

        secret = secrets.token_bytes(64)
        shares = split_secret(secret, threshold=5, total_shares=5)
        recovered = combine_shares(shares)
        assert recovered == secret

    def test_single_byte_secret(self):
        from l3.veilcloud.threshold import split_secret, combine_shares

        secret = b"\x42"
        shares = split_secret(secret, threshold=2, total_shares=3)
        recovered = combine_shares(shares[:2])
        assert recovered == secret

    def test_all_zero_secret(self):
        from l3.veilcloud.threshold import split_secret, combine_shares

        secret = b"\x00" * 16
        shares = split_secret(secret, threshold=3, total_shares=5)
        recovered = combine_shares(shares[:3])
        assert recovered == secret

    def test_all_ff_secret(self):
        from l3.veilcloud.threshold import split_secret, combine_shares

        secret = b"\xff" * 16
        shares = split_secret(secret, threshold=3, total_shares=5)
        recovered = combine_shares(shares[:3])
        assert recovered == secret

    def test_share_serialization(self):
        from l3.veilcloud.threshold import split_secret, combine_shares, Share

        secret = b"serialize me"
        shares = split_secret(secret, threshold=2, total_shares=3)

        hex_shares = [s.to_hex() for s in shares]
        restored = [Share.from_hex(h) for h in hex_shares]
        recovered = combine_shares(restored[:2])
        assert recovered == secret

    def test_empty_secret_raises(self):
        from l3.veilcloud.threshold import split_secret

        with pytest.raises(ValueError, match="empty"):
            split_secret(b"", threshold=2, total_shares=3)

    def test_threshold_too_low(self):
        from l3.veilcloud.threshold import split_secret

        with pytest.raises(ValueError, match="at least 2"):
            split_secret(b"secret", threshold=1, total_shares=3)

    def test_total_less_than_threshold(self):
        from l3.veilcloud.threshold import split_secret

        with pytest.raises(ValueError, match="must be >="):
            split_secret(b"secret", threshold=5, total_shares=3)

    def test_max_shares_limit(self):
        from l3.veilcloud.threshold import split_secret

        with pytest.raises(ValueError, match="exceeds"):
            split_secret(b"secret", threshold=2, total_shares=256)

    def test_255_shares(self):
        """Maximum valid share count (GF(256) limit)."""
        from l3.veilcloud.threshold import split_secret, combine_shares

        secret = b"max shares"
        shares = split_secret(secret, threshold=2, total_shares=255)
        assert len(shares) == 255

        recovered = combine_shares([shares[0], shares[254]])
        assert recovered == secret

    def test_duplicate_share_indices(self):
        from l3.veilcloud.threshold import combine_shares, Share

        share = Share(index=1, data=b"\x00")
        with pytest.raises(ValueError, match="Duplicate"):
            combine_shares([share, share])

    def test_no_shares_raises(self):
        from l3.veilcloud.threshold import combine_shares

        with pytest.raises(ValueError, match="No shares"):
            combine_shares([])

    def test_gf256_tables_initialized(self):
        """Verify GF(256) lookup tables are consistent."""
        from l3.veilcloud.threshold import _EXP, _LOG, _gf_mul

        # exp(log(x)) should equal x for all non-zero x
        for x in range(1, 256):
            assert _EXP[_LOG[x]] == x

        # Multiplication by 1 should be identity
        for x in range(256):
            assert _gf_mul(x, 1) == x

        # Multiplication by 0 should be 0
        for x in range(256):
            assert _gf_mul(x, 0) == 0


# ══════════════════════════════════════════════════════════════════════════
# Audit Log Tests
# ══════════════════════════════════════════════════════════════════════════


class TestAuditLog(TestCase):
    """Tests for l3.veilcloud.audit."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.base_dir = Path(self.tmpdir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_log(self, name="test-log"):
        from l3.veilcloud.audit import AuditLog
        return AuditLog(name, base_dir=self.base_dir)

    def test_basic_log(self):
        log = self._make_log()
        entry = log.log("STORE", "user@test", {"checksum": "aabb"})
        assert entry.sequence == 0
        assert entry.event_type == "STORE"
        assert entry.actor == "user@test"
        assert len(entry.entry_hash) == 64

    def test_chain_integrity(self):
        log = self._make_log()
        log.log("STORE", "alice", {"doc": "1"})
        log.log("ANCHOR", "alice", {"txid": "abc"})
        log.log("VERIFY", "bob", {"result": "ok"})
        assert log.verify_chain()

    def test_chain_linkage(self):
        log = self._make_log()
        e0 = log.log("FIRST", "alice")
        e1 = log.log("SECOND", "bob")
        assert e1.prev_hash == e0.entry_hash

    def test_genesis_prev_hash(self):
        log = self._make_log()
        e = log.log("GENESIS", "system")
        assert e.prev_hash == "0" * 64

    def test_persistence(self):
        log1 = self._make_log("persist-test")
        log1.log("STORE", "user1", {"a": 1})
        log1.log("ANCHOR", "user2", {"b": 2})

        # Reload from disk
        log2 = self._make_log("persist-test")
        assert len(log2) == 2
        assert log2.verify_chain()

    def test_empty_log_verifies(self):
        log = self._make_log()
        assert log.verify_chain()

    def test_merkle_proof(self):
        from l3.veilcloud.merkle import verify_proof

        log = self._make_log()
        for i in range(5):
            log.log("EVENT", "actor", {"i": i})

        proof = log.get_proof(2)
        assert verify_proof(proof)

    def test_merkle_proof_all_entries(self):
        from l3.veilcloud.merkle import verify_proof

        log = self._make_log()
        for i in range(10):
            log.log("EVENT", "actor", {"i": i})

        for i in range(10):
            proof = log.get_proof(i)
            assert verify_proof(proof), f"Proof failed for entry {i}"

    def test_proof_empty_log_raises(self):
        log = self._make_log()
        with pytest.raises(ValueError, match="empty"):
            log.get_proof(0)

    def test_proof_out_of_range(self):
        log = self._make_log()
        log.log("EVENT", "actor")
        with pytest.raises(IndexError):
            log.get_proof(1)

    def test_thread_safety(self):
        log = self._make_log("thread-test")
        errors = []

        def writer(thread_id):
            try:
                for i in range(10):
                    log.log("WRITE", f"thread-{thread_id}", {"i": i})
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert len(log) == 40
        assert log.verify_chain()

    def test_invalid_name(self):
        from l3.veilcloud.audit import AuditLog
        with pytest.raises(ValueError, match="Invalid"):
            AuditLog("../../etc/passwd", base_dir=self.base_dir)

    def test_entries_property(self):
        log = self._make_log()
        log.log("A", "user")
        log.log("B", "user")
        entries = log.entries
        assert len(entries) == 2
        assert entries[0].event_type == "A"
        assert entries[1].event_type == "B"


# ══════════════════════════════════════════════════════════════════════════
# Access Control Tests
# ══════════════════════════════════════════════════════════════════════════


class TestAccessControl(TestCase):
    """Tests for l3.veilcloud.access."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.key = secrets.token_bytes(32)
        self.rev_path = Path(self.tmpdir) / "revocations.json"

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _make_manager(self, key=None):
        from l3.veilcloud.access import CredentialManager
        return CredentialManager(
            signing_key=key or self.key,
            revocation_path=self.rev_path,
        )

    def test_issue_and_verify(self):
        from l3.veilcloud.access import Permission

        mgr = self._make_manager()
        cred = mgr.issue_credential("alice", Permission.READ | Permission.WRITE)
        assert mgr.verify_credential(cred)

    def test_permissions_check(self):
        from l3.veilcloud.access import Permission

        mgr = self._make_manager()
        cred = mgr.issue_credential("bob", Permission.READ)
        assert cred.has_permission(Permission.READ)
        assert not cred.has_permission(Permission.WRITE)
        assert not cred.has_permission(Permission.ADMIN)

    def test_admin_has_admin(self):
        from l3.veilcloud.access import Permission

        mgr = self._make_manager()
        cred = mgr.issue_credential("admin", Permission.ADMIN | Permission.READ)
        assert cred.has_permission(Permission.ADMIN)
        assert cred.has_permission(Permission.READ)
        assert not cred.has_permission(Permission.DELETE)

    def test_revocation(self):
        from l3.veilcloud.access import Permission

        mgr = self._make_manager()
        cred = mgr.issue_credential("carol", Permission.READ)
        assert mgr.verify_credential(cred)

        mgr.revoke_credential(cred.credential_id)
        assert not mgr.verify_credential(cred)
        assert mgr.is_revoked(cred.credential_id)

    def test_revocation_persists(self):
        from l3.veilcloud.access import Permission

        mgr1 = self._make_manager()
        cred = mgr1.issue_credential("dave", Permission.READ)
        mgr1.revoke_credential(cred.credential_id)

        # New manager should load revocations from disk
        mgr2 = self._make_manager()
        assert not mgr2.verify_credential(cred)

    def test_expired_credential(self):
        from l3.veilcloud.access import Permission

        mgr = self._make_manager()
        past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        cred = mgr.issue_credential("eve", Permission.READ, expires_at=past)
        assert not mgr.verify_credential(cred)

    def test_not_yet_expired(self):
        from l3.veilcloud.access import Permission

        mgr = self._make_manager()
        future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        cred = mgr.issue_credential("frank", Permission.READ, expires_at=future)
        assert mgr.verify_credential(cred)

    def test_tampered_signature(self):
        from l3.veilcloud.access import Permission, Credential

        mgr = self._make_manager()
        cred = mgr.issue_credential("grace", Permission.READ)

        tampered = Credential(
            credential_id=cred.credential_id,
            user_id=cred.user_id,
            permissions=cred.permissions,
            issued_at=cred.issued_at,
            expires_at=cred.expires_at,
            signature="0" * 64,
        )
        assert not mgr.verify_credential(tampered)

    def test_tampered_permissions(self):
        from l3.veilcloud.access import Permission, Credential

        mgr = self._make_manager()
        cred = mgr.issue_credential("hank", Permission.READ)

        # Escalate permissions
        tampered = Credential(
            credential_id=cred.credential_id,
            user_id=cred.user_id,
            permissions=Permission.ADMIN | Permission.READ,
            issued_at=cred.issued_at,
            expires_at=cred.expires_at,
            signature=cred.signature,
        )
        assert not mgr.verify_credential(tampered)

    def test_wrong_signing_key(self):
        from l3.veilcloud.access import Permission

        mgr1 = self._make_manager(key=secrets.token_bytes(32))
        cred = mgr1.issue_credential("ivan", Permission.READ)

        mgr2 = self._make_manager(key=secrets.token_bytes(32))
        assert not mgr2.verify_credential(cred)

    def test_credential_serialization(self):
        from l3.veilcloud.access import Permission, Credential

        mgr = self._make_manager()
        cred = mgr.issue_credential("jane", Permission.READ | Permission.WRITE)

        json_str = cred.to_json()
        restored = Credential.from_json(json_str)
        assert mgr.verify_credential(restored)

    def test_signing_key_too_short(self):
        from l3.veilcloud.access import CredentialManager
        with pytest.raises(ValueError, match="32 bytes"):
            CredentialManager(signing_key=b"short")

    def test_thread_safe_revocation(self):
        from l3.veilcloud.access import Permission

        mgr = self._make_manager()
        creds = [
            mgr.issue_credential(f"user-{i}", Permission.READ)
            for i in range(20)
        ]
        errors = []

        def revoker(start, end):
            try:
                for c in creds[start:end]:
                    mgr.revoke_credential(c.credential_id)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=revoker, args=(0, 10)),
            threading.Thread(target=revoker, args=(10, 20)),
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        for c in creds:
            assert mgr.is_revoked(c.credential_id)


# ══════════════════════════════════════════════════════════════════════════
# Integration Tests
# ══════════════════════════════════════════════════════════════════════════


class TestIntegration(TestCase):
    """Integration tests combining multiple VeilCloud modules."""

    @skip_no_crypto
    def test_encrypt_with_shamir_key(self):
        """Encrypt data with a key, split the key via Shamir, reconstruct and decrypt."""
        from l3.veilcloud.crypto import encrypt_with_key, decrypt_with_key
        from l3.veilcloud.threshold import split_secret, combine_shares

        # Generate an encryption key
        key = secrets.token_bytes(32)
        plaintext = b"This is a secret document anchored to Bitcoin."

        # Encrypt with the key
        payload = encrypt_with_key(plaintext, key)

        # Split the key into shares
        shares = split_secret(key, threshold=3, total_shares=5)

        # Reconstruct from any 3 shares
        reconstructed_key = combine_shares(shares[1:4])
        assert reconstructed_key == key

        # Decrypt with the reconstructed key
        recovered = decrypt_with_key(payload, reconstructed_key)
        assert recovered == plaintext

    def test_audit_with_merkle_anchor(self):
        """Log events, generate Merkle root suitable for Bitcoin anchoring."""
        from l3.veilcloud.audit import AuditLog
        from l3.veilcloud.merkle import MerkleTree, verify_proof

        tmpdir = tempfile.mkdtemp()
        try:
            log = AuditLog("integration-test", base_dir=Path(tmpdir))
            log.log("STORE", "alice", {"checksum": "aa" * 32})
            log.log("ANCHOR", "alice", {"txid": "bb" * 32})
            log.log("ACCESS", "bob", {"action": "read"})

            # Build Merkle tree from entry hashes
            entry_hashes = [e.entry_hash for e in log.entries]
            tree = MerkleTree.from_checksums(entry_hashes)

            # Root is suitable for anchoring (64-char hex)
            assert len(tree.root_hex) == 64

            # Each entry can be proven to be part of the batch
            for i in range(3):
                proof = log.get_proof(i)
                assert verify_proof(proof)
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_credential_in_audit_trail(self):
        """Issue credential, log it in audit trail, verify both."""
        from l3.veilcloud.access import CredentialManager, Permission
        from l3.veilcloud.audit import AuditLog

        tmpdir = tempfile.mkdtemp()
        try:
            key = secrets.token_bytes(32)
            mgr = CredentialManager(
                signing_key=key,
                revocation_path=Path(tmpdir) / "rev.json",
            )

            cred = mgr.issue_credential("alice", Permission.READ | Permission.WRITE)
            assert mgr.verify_credential(cred)

            log = AuditLog("cred-audit", base_dir=Path(tmpdir))
            log.log("CREDENTIAL_ISSUED", "system", {
                "credential_id": cred.credential_id,
                "user_id": cred.user_id,
                "permissions": cred.permissions,
            })

            assert log.verify_chain()
            assert len(log) == 1
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    @skip_no_crypto
    def test_full_pipeline(self):
        """Full VeilCloud pipeline: encrypt, split key, audit, generate proof."""
        from l3.veilcloud.crypto import encrypt_with_key, decrypt_with_key
        from l3.veilcloud.threshold import split_secret, combine_shares
        from l3.veilcloud.audit import AuditLog
        from l3.veilcloud.merkle import verify_proof

        tmpdir = tempfile.mkdtemp()
        try:
            # 1. Encrypt a document
            key = secrets.token_bytes(32)
            plaintext = b"Confidential document for Bitcoin anchoring"
            payload = encrypt_with_key(plaintext, key)

            # 2. Split the key
            shares = split_secret(key, threshold=2, total_shares=3)

            # 3. Log everything
            log = AuditLog("pipeline-test", base_dir=Path(tmpdir))
            log.log("ENCRYPT", "alice", {
                "checksum": hashlib.sha256(payload.to_bytes()).hexdigest(),
            })
            log.log("KEY_SPLIT", "alice", {
                "threshold": 2,
                "total_shares": 3,
            })

            # 4. Verify audit chain
            assert log.verify_chain()

            # 5. Generate Merkle proof for the first entry
            proof = log.get_proof(0)
            assert verify_proof(proof)

            # 6. Reconstruct key and decrypt
            recovered_key = combine_shares(shares[:2])
            recovered = decrypt_with_key(payload, recovered_key)
            assert recovered == plaintext
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)
