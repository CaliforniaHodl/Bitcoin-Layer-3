"""
Tests for Bitcoin L3 Anchoring — anchor.py + store.py.

All tests use mock RPC — no Bitcoin node required.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from l3.anchor import (
    BitcoinRPC,
    BitcoinRPCError,
    _build_op_return_hex,
    _validate_checksum,
    anchor_document,
    lookup_anchor,
    parse_op_return,
    verify_anchor,
)
from l3.store import L3Store, L3StoreError
from l3 import (
    ANCHOR_PAYLOAD_SIZE,
    ANCHOR_PREFIX_HEX,
    ANCHOR_PROTOCOL_PREFIX,
)
from l3._format.document import PFMDocument


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_doc():
    """Create a minimal PFM document for testing."""
    doc = PFMDocument.create(agent="test-agent", model="test-model")
    doc.add_section("content", "Hello, Bitcoin!")
    return doc


@pytest.fixture
def sample_checksum(sample_doc):
    """The checksum of sample_doc."""
    return sample_doc.compute_checksum()


@pytest.fixture
def tmp_store(tmp_path):
    """L3Store rooted in a temp directory."""
    return L3Store(root=tmp_path / "l3")


@pytest.fixture
def mock_rpc():
    """A mock BitcoinRPC that simulates a testnet node."""
    rpc = MagicMock(spec=BitcoinRPC)
    rpc.url = "http://127.0.0.1:18332"
    rpc.get_network.return_value = "testnet"
    return rpc


# ---------------------------------------------------------------------------
# TestOpReturnEncoding
# ---------------------------------------------------------------------------

class TestOpReturnEncoding:
    """Tests for _build_op_return_hex."""

    def test_valid_checksum(self, sample_checksum):
        script = _build_op_return_hex(sample_checksum)
        # OP_RETURN (6a) + push 36 bytes (24) + data (72 hex) = 76 hex chars
        assert len(script) == 76
        assert script.startswith("6a24")
        assert ANCHOR_PREFIX_HEX in script
        assert sample_checksum in script

    def test_known_values(self):
        """Test with a known checksum to verify exact encoding."""
        checksum = "a" * 64
        script = _build_op_return_hex(checksum)
        expected = "6a24" + ANCHOR_PREFIX_HEX + ("a" * 64)
        assert script == expected

    def test_payload_size(self):
        """The data portion must be exactly ANCHOR_PAYLOAD_SIZE bytes."""
        checksum = "b" * 64
        script = _build_op_return_hex(checksum)
        # Strip OP_RETURN (6a) and push byte (24) — remaining is payload hex
        payload_hex = script[4:]
        assert len(payload_hex) // 2 == ANCHOR_PAYLOAD_SIZE

    def test_reject_short_checksum(self):
        with pytest.raises(ValueError, match="Invalid checksum"):
            _build_op_return_hex("abcd")

    def test_reject_uppercase(self):
        with pytest.raises(ValueError, match="Invalid checksum"):
            _build_op_return_hex("A" * 64)

    def test_reject_non_hex(self):
        with pytest.raises(ValueError, match="Invalid checksum"):
            _build_op_return_hex("g" * 64)

    def test_reject_empty(self):
        with pytest.raises(ValueError, match="Invalid checksum"):
            _build_op_return_hex("")

    def test_reject_none(self):
        with pytest.raises(ValueError, match="Invalid checksum"):
            _build_op_return_hex(None)


# ---------------------------------------------------------------------------
# TestOpReturnParsing
# ---------------------------------------------------------------------------

class TestOpReturnParsing:
    """Tests for parse_op_return."""

    def test_roundtrip(self, sample_checksum):
        """Encode then parse — should get back the original checksum."""
        script = _build_op_return_hex(sample_checksum)
        result = parse_op_return(script)
        assert result is not None
        prefix, checksum = result
        assert prefix == ANCHOR_PROTOCOL_PREFIX
        assert checksum == sample_checksum

    def test_known_script(self):
        """Parse a hand-crafted script."""
        checksum = "0123456789abcdef" * 4
        script = "6a24" + ANCHOR_PREFIX_HEX + checksum
        result = parse_op_return(script)
        assert result == (ANCHOR_PROTOCOL_PREFIX, checksum)

    def test_reject_non_pfm_prefix(self):
        """Non-PFM OP_RETURN data should return None."""
        script = "6a24" + "deadbeef" + ("0" * 64)
        assert parse_op_return(script) is None

    def test_reject_wrong_length(self):
        """Too short / too long data should return None."""
        assert parse_op_return("6a24" + "ff" * 10) is None

    def test_reject_no_op_return(self):
        """Script that isn't OP_RETURN."""
        assert parse_op_return("76a914" + "0" * 40 + "88ac") is None

    def test_reject_empty_string(self):
        assert parse_op_return("") is None

    def test_reject_none(self):
        assert parse_op_return(None) is None

    def test_reject_non_string(self):
        assert parse_op_return(12345) is None

    def test_case_insensitive(self, sample_checksum):
        """Should handle uppercase hex from some node implementations."""
        script = _build_op_return_hex(sample_checksum).upper()
        result = parse_op_return(script)
        assert result is not None
        assert result[1] == sample_checksum


# ---------------------------------------------------------------------------
# TestBitcoinRPC
# ---------------------------------------------------------------------------

class TestBitcoinRPC:
    """Tests for BitcoinRPC configuration and creation."""

    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("BITCOIN_RPC_URL", "http://localhost:18332")
        monkeypatch.setenv("BITCOIN_RPC_USER", "testuser")
        monkeypatch.setenv("BITCOIN_RPC_PASS", "testpass")
        rpc = BitcoinRPC.from_env()
        assert rpc.url == "http://localhost:18332"

    def test_from_env_missing_url(self, monkeypatch):
        monkeypatch.delenv("BITCOIN_RPC_URL", raising=False)
        with pytest.raises(BitcoinRPCError, match="BITCOIN_RPC_URL not set"):
            BitcoinRPC.from_env()

    def test_empty_url_raises(self):
        with pytest.raises(ValueError, match="cannot be empty"):
            BitcoinRPC("", "user", "pass")

    def test_network_detection(self, mock_rpc):
        """Network detection via mocked getblockchaininfo."""
        mock_rpc.get_network = MagicMock(return_value="testnet")
        assert mock_rpc.get_network() == "testnet"


# ---------------------------------------------------------------------------
# TestAnchorDocument
# ---------------------------------------------------------------------------

class TestAnchorDocument:
    """Tests for anchor_document with mock RPC."""

    def test_full_workflow(self, sample_doc, mock_rpc):
        """Mock the full create->fund->sign->broadcast flow."""
        mock_txid = "abc123def456" * 5 + "abcd"
        mock_rpc.call.side_effect = [
            "raw_tx_hex",                                   # createrawtransaction
            {"hex": "funded_tx_hex"},                       # fundrawtransaction
            {"hex": "signed_tx_hex", "complete": True},     # signrawtransactionwithwallet
            mock_txid,                                      # sendrawtransaction
        ]

        txid = anchor_document(sample_doc, mock_rpc)

        assert txid == mock_txid
        assert mock_rpc.call.call_count == 4

        # Verify calls
        calls = mock_rpc.call.call_args_list
        assert calls[0][0][0] == "createrawtransaction"
        assert calls[1][0][0] == "fundrawtransaction"
        assert calls[2][0][0] == "signrawtransactionwithwallet"
        assert calls[3][0][0] == "sendrawtransaction"

    def test_metadata_set(self, sample_doc, mock_rpc):
        """After anchoring, custom_meta should have anchor fields."""
        mock_rpc.call.side_effect = [
            "raw_hex",
            {"hex": "funded_hex"},
            {"hex": "signed_hex", "complete": True},
            "txid_result",
        ]

        anchor_document(sample_doc, mock_rpc)

        assert sample_doc.custom_meta["anchor_txid"] == "txid_result"
        assert sample_doc.custom_meta["anchor_network"] == "testnet"
        assert sample_doc.custom_meta["anchor_hash"] == sample_doc.compute_checksum()
        assert "anchor_ts" in sample_doc.custom_meta

    def test_metadata_survives_write_read(self, sample_doc, mock_rpc, tmp_path):
        """Anchor metadata should persist through write/read cycle."""
        mock_rpc.call.side_effect = [
            "raw", {"hex": "funded"}, {"hex": "signed", "complete": True}, "txid123",
        ]

        anchor_document(sample_doc, mock_rpc)
        path = str(tmp_path / "anchored.pfm")
        sample_doc.write(path)

        from l3._format.reader import PFMReader
        reloaded = PFMReader.read(path)
        assert reloaded.custom_meta["anchor_txid"] == "txid123"
        assert reloaded.custom_meta["anchor_network"] == "testnet"

    def test_signing_incomplete_raises(self, sample_doc, mock_rpc):
        """If signing is incomplete, should raise."""
        mock_rpc.call.side_effect = [
            "raw", {"hex": "funded"}, {"hex": "partial", "complete": False},
        ]
        with pytest.raises(BitcoinRPCError, match="signing incomplete"):
            anchor_document(sample_doc, mock_rpc)


# ---------------------------------------------------------------------------
# TestVerifyAnchor
# ---------------------------------------------------------------------------

class TestVerifyAnchor:
    """Tests for verify_anchor — fail-closed verification."""

    def test_valid_anchor(self, sample_doc, mock_rpc):
        """Matching on-chain hash should verify True."""
        checksum = sample_doc.compute_checksum()
        sample_doc.custom_meta["anchor_txid"] = "valid_txid"
        script = _build_op_return_hex(checksum)

        mock_rpc.call.return_value = {
            "vout": [
                {"scriptPubKey": {"hex": script}}
            ]
        }

        assert verify_anchor(sample_doc, mock_rpc) is True

    def test_no_anchor_metadata(self, sample_doc, mock_rpc):
        """Document with no anchor_txid should fail verification."""
        assert verify_anchor(sample_doc, mock_rpc) is False

    def test_tampered_document(self, sample_doc, mock_rpc):
        """If document is modified after anchoring, verify should fail."""
        original_checksum = sample_doc.compute_checksum()
        sample_doc.custom_meta["anchor_txid"] = "some_txid"
        script = _build_op_return_hex(original_checksum)

        mock_rpc.call.return_value = {
            "vout": [{"scriptPubKey": {"hex": script}}]
        }

        # Tamper with the document
        sample_doc.sections[0].content = "TAMPERED CONTENT"

        assert verify_anchor(sample_doc, mock_rpc) is False

    def test_connection_failure(self, sample_doc, mock_rpc):
        """Connection failures should fail closed (return False)."""
        sample_doc.custom_meta["anchor_txid"] = "some_txid"
        mock_rpc.call.side_effect = BitcoinRPCError("Connection refused")

        assert verify_anchor(sample_doc, mock_rpc) is False

    def test_transaction_not_found(self, sample_doc, mock_rpc):
        """If tx has no PFM OP_RETURN, should return False."""
        sample_doc.custom_meta["anchor_txid"] = "wrong_txid"
        mock_rpc.call.return_value = {
            "vout": [{"scriptPubKey": {"hex": "76a914aabbccdd88ac"}}]
        }

        assert verify_anchor(sample_doc, mock_rpc) is False


# ---------------------------------------------------------------------------
# TestLookupAnchor
# ---------------------------------------------------------------------------

class TestLookupAnchor:
    """Tests for lookup_anchor."""

    def test_found(self, mock_rpc, sample_checksum):
        script = _build_op_return_hex(sample_checksum)
        mock_rpc.call.return_value = {
            "vout": [
                {"scriptPubKey": {"hex": "76a914aabb88ac"}},  # non-PFM output
                {"scriptPubKey": {"hex": script}},             # PFM OP_RETURN
            ]
        }
        result = lookup_anchor("txid", mock_rpc)
        assert result == (ANCHOR_PROTOCOL_PREFIX, sample_checksum)

    def test_not_found(self, mock_rpc):
        mock_rpc.call.return_value = {
            "vout": [{"scriptPubKey": {"hex": "76a914aabb88ac"}}]
        }
        assert lookup_anchor("txid", mock_rpc) is None

    def test_rpc_error(self, mock_rpc):
        mock_rpc.call.side_effect = BitcoinRPCError("not found")
        assert lookup_anchor("txid", mock_rpc) is None


# ---------------------------------------------------------------------------
# TestL3Store
# ---------------------------------------------------------------------------

class TestL3Store:
    """Tests for L3Store — local content-addressed storage."""

    def test_store_and_retrieve(self, sample_doc, tmp_store):
        checksum = tmp_store.store(sample_doc)
        assert len(checksum) == 64

        retrieved = tmp_store.retrieve(checksum)
        assert retrieved.compute_checksum() == checksum

    def test_deduplication(self, sample_doc, tmp_store):
        """Storing the same document twice returns the same checksum."""
        c1 = tmp_store.store(sample_doc)
        c2 = tmp_store.store(sample_doc)
        assert c1 == c2

    def test_contains(self, sample_doc, tmp_store):
        assert not tmp_store.contains(sample_doc.compute_checksum())
        tmp_store.store(sample_doc)
        assert tmp_store.contains(sample_doc.compute_checksum())

    def test_list(self, sample_doc, tmp_store):
        tmp_store.store(sample_doc)
        entries = tmp_store.list()
        assert len(entries) == 1
        assert entries[0]["checksum"] == sample_doc.compute_checksum()
        assert "stored_at" in entries[0]

    def test_list_empty(self, tmp_store):
        assert tmp_store.list() == []

    def test_retrieve_not_found(self, tmp_store):
        fake = "a" * 64
        with pytest.raises(L3StoreError, match="not found"):
            tmp_store.retrieve(fake)

    def test_invalid_checksum_rejected(self, tmp_store):
        """Path traversal via checksum should be rejected."""
        with pytest.raises(ValueError, match="Invalid checksum"):
            tmp_store.retrieve("../../etc/passwd")

        with pytest.raises(ValueError, match="Invalid checksum"):
            tmp_store.contains("not-a-hex-string")

    def test_txid_update(self, sample_doc, tmp_store):
        checksum = tmp_store.store(sample_doc)
        tmp_store.update_txid(checksum, "tx123", "testnet")

        entries = tmp_store.list()
        assert entries[0]["anchor_txid"] == "tx123"
        assert entries[0]["anchor_network"] == "testnet"

    def test_txid_lookup(self, sample_doc, tmp_store):
        checksum = tmp_store.store(sample_doc)
        tmp_store.update_txid(checksum, "tx456", "testnet")

        found = tmp_store.lookup_by_txid("tx456")
        assert found == checksum

    def test_txid_lookup_not_found(self, tmp_store):
        assert tmp_store.lookup_by_txid("nonexistent") is None

    def test_update_txid_unknown_checksum(self, tmp_store):
        with pytest.raises(L3StoreError, match="not in index"):
            tmp_store.update_txid("a" * 64, "tx", "testnet")

    def test_multiple_documents(self, tmp_store):
        """Store multiple different documents."""
        doc1 = PFMDocument.create(agent="a1")
        doc1.add_section("content", "Document one")
        doc2 = PFMDocument.create(agent="a2")
        doc2.add_section("content", "Document two")

        c1 = tmp_store.store(doc1)
        c2 = tmp_store.store(doc2)
        assert c1 != c2

        entries = tmp_store.list()
        assert len(entries) == 2

        r1 = tmp_store.retrieve(c1)
        r2 = tmp_store.retrieve(c2)
        assert r1.content == "Document one"
        assert r2.content == "Document two"


# ---------------------------------------------------------------------------
# TestAnchorL3Wiring
# ---------------------------------------------------------------------------

class TestAnchorL3Wiring:
    """Tests for the anchor->L3 auto-store flow."""

    def test_anchor_stores_in_l3(self, sample_doc, mock_rpc, tmp_path):
        """anchor_document should produce metadata that L3Store can index."""
        mock_rpc.call.side_effect = [
            "raw", {"hex": "funded"}, {"hex": "signed", "complete": True}, "txid_abc",
        ]

        txid = anchor_document(sample_doc, mock_rpc)
        checksum = sample_doc.custom_meta["anchor_hash"]
        network = sample_doc.custom_meta["anchor_network"]

        # Simulate what cmd_anchor does: store + update_txid
        store = L3Store(root=tmp_path / "l3")
        store.store(sample_doc)
        store.update_txid(checksum, txid, network)

        # Verify the L3 entry has the txid linked
        entries = store.list()
        assert len(entries) == 1
        assert entries[0]["checksum"] == checksum
        assert entries[0]["anchor_txid"] == "txid_abc"
        assert entries[0]["anchor_network"] == "testnet"

    def test_anchor_then_retrieve_and_verify(self, sample_doc, mock_rpc, tmp_path):
        """Full round-trip: anchor -> L3 store -> retrieve -> verify checksum."""
        mock_rpc.call.side_effect = [
            "raw", {"hex": "funded"}, {"hex": "signed", "complete": True}, "txid_xyz",
        ]

        anchor_document(sample_doc, mock_rpc)
        checksum = sample_doc.custom_meta["anchor_hash"]

        store = L3Store(root=tmp_path / "l3")
        store.store(sample_doc)
        store.update_txid(checksum, "txid_xyz", "testnet")

        # Retrieve and check integrity
        retrieved = store.retrieve(checksum)
        assert retrieved.compute_checksum() == checksum

    def test_l3_import_found(self, sample_doc, mock_rpc, tmp_path):
        """lookup_anchor + L3Store.contains simulates l3-import when doc exists."""
        checksum = sample_doc.compute_checksum()
        script = _build_op_return_hex(checksum)

        mock_rpc.call.return_value = {
            "vout": [{"scriptPubKey": {"hex": script}}]
        }

        result = lookup_anchor("some_txid", mock_rpc)
        assert result is not None
        _prefix, on_chain_checksum = result

        store = L3Store(root=tmp_path / "l3")
        store.store(sample_doc)

        assert store.contains(on_chain_checksum)

    def test_l3_import_not_found(self, mock_rpc, tmp_path, sample_checksum):
        """l3-import when the document isn't in local store."""
        script = _build_op_return_hex(sample_checksum)
        mock_rpc.call.return_value = {
            "vout": [{"scriptPubKey": {"hex": script}}]
        }

        result = lookup_anchor("some_txid", mock_rpc)
        assert result is not None

        store = L3Store(root=tmp_path / "l3")
        assert not store.contains(result[1])

    def test_l3_import_no_pfm_op_return(self, mock_rpc):
        """l3-import on a non-PFM transaction returns None."""
        mock_rpc.call.return_value = {
            "vout": [{"scriptPubKey": {"hex": "76a914aabb88ac"}}]
        }
        assert lookup_anchor("some_txid", mock_rpc) is None


# ---------------------------------------------------------------------------
# TestConstants
# ---------------------------------------------------------------------------

class TestConstants:
    """Verify the anchor constants are consistent."""

    def test_prefix_hex_matches_bytes(self):
        assert bytes.fromhex(ANCHOR_PREFIX_HEX) == b"PFM3"

    def test_prefix_matches_protocol(self):
        assert ANCHOR_PREFIX_HEX == ANCHOR_PROTOCOL_PREFIX.encode().hex()

    def test_payload_size(self):
        assert ANCHOR_PAYLOAD_SIZE == 36  # 4 prefix + 32 hash
