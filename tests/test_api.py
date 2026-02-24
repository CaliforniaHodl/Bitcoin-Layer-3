"""
Tests for L3 Anchor API — invoice state machine, auth, handlers, server integration.

All tests use mock RPC — no Bitcoin node or live server required.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch
from http.server import HTTPServer

import pytest

from l3._format.document import PFMDocument
from l3.anchor import BitcoinRPC, _build_op_return_hex
from l3.store import L3Store
from l3.api.invoices import Invoice, InvoiceError, InvoiceManager
from l3.api.auth import check_auth, load_api_key
from l3.api.handlers import (
    handle_anchor,
    handle_anchor_pfm,
    handle_anchor_status,
    handle_verify,
    handle_retrieve,
    handle_status,
)
from l3.api.watcher import PaymentWatcher


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_doc():
    """Create a minimal PFM document."""
    doc = PFMDocument.create(agent="test-api")
    doc.add_section("content", "Hello from the API!")
    return doc


@pytest.fixture
def tmp_store(tmp_path):
    """L3Store rooted in a temp directory."""
    return L3Store(root=tmp_path / "l3")


@pytest.fixture
def tmp_invoices(tmp_path):
    """InvoiceManager with temp directory."""
    return InvoiceManager(data_dir=tmp_path / "api")


@pytest.fixture
def mock_rpc():
    """A mock BitcoinRPC."""
    rpc = MagicMock(spec=BitcoinRPC)
    rpc.url = "http://127.0.0.1:18332"
    rpc.get_network.return_value = "testnet"
    return rpc


# ---------------------------------------------------------------------------
# TestInvoiceStateMachine
# ---------------------------------------------------------------------------

class TestInvoiceStateMachine:
    """Tests for the Invoice state machine transitions."""

    def test_create_default_state(self):
        inv = Invoice(
            anchor_id="abc123",
            checksum="a" * 64,
            address="bc1qtest",
            amount_sats=2200,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        assert inv.status == "pending_payment"

    def test_valid_transitions(self):
        """Full happy path: pending → paid → anchoring → confirmed."""
        inv = Invoice(
            anchor_id="abc123",
            checksum="a" * 64,
            address="bc1qtest",
            amount_sats=2200,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        inv.transition("paid")
        assert inv.status == "paid"

        inv.transition("anchoring")
        assert inv.status == "anchoring"

        inv.transition("confirmed")
        assert inv.status == "confirmed"
        assert inv.is_terminal

    def test_pending_to_expired(self):
        inv = Invoice(
            anchor_id="abc123",
            checksum="a" * 64,
            address="bc1qtest",
            amount_sats=2200,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        inv.transition("expired")
        assert inv.status == "expired"
        assert inv.is_terminal

    def test_failed_retry(self):
        """anchoring → failed → anchoring (retry)."""
        inv = Invoice(
            anchor_id="abc123",
            checksum="a" * 64,
            address="bc1qtest",
            amount_sats=2200,
            expires_at="2099-01-01T00:00:00+00:00",
            status="anchoring",
        )
        inv.transition("failed")
        assert inv.status == "failed"

        inv.transition("anchoring")
        assert inv.status == "anchoring"

    def test_invalid_transition_raises(self):
        inv = Invoice(
            anchor_id="abc123",
            checksum="a" * 64,
            address="bc1qtest",
            amount_sats=2200,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        with pytest.raises(InvoiceError, match="Cannot transition"):
            inv.transition("confirmed")  # skip paid + anchoring

    def test_terminal_state_no_transitions(self):
        inv = Invoice(
            anchor_id="abc123",
            checksum="a" * 64,
            address="bc1qtest",
            amount_sats=2200,
            expires_at="2099-01-01T00:00:00+00:00",
            status="confirmed",
        )
        with pytest.raises(InvoiceError, match="Cannot transition"):
            inv.transition("pending_payment")

    def test_invalid_initial_status(self):
        with pytest.raises(InvoiceError, match="Invalid status"):
            Invoice(
                anchor_id="abc123",
                checksum="a" * 64,
                address="bc1qtest",
                amount_sats=2200,
                expires_at="2099-01-01T00:00:00+00:00",
                status="bogus",
            )

    def test_to_dict_from_dict_roundtrip(self):
        inv = Invoice(
            anchor_id="abc123",
            checksum="b" * 64,
            address="bc1qtest",
            amount_sats=3000,
            expires_at="2099-01-01T00:00:00+00:00",
            content_type="text/plain",
        )
        d = inv.to_dict()
        inv2 = Invoice.from_dict(d)
        assert inv2.anchor_id == inv.anchor_id
        assert inv2.checksum == inv.checksum
        assert inv2.amount_sats == inv.amount_sats
        assert inv2.content_type == inv.content_type


# ---------------------------------------------------------------------------
# TestInvoiceManager
# ---------------------------------------------------------------------------

class TestInvoiceManager:
    """Tests for InvoiceManager persistence and thread safety."""

    def test_create_and_get(self, tmp_invoices):
        inv = tmp_invoices.create(
            checksum="c" * 64,
            address="bc1qmgr",
            amount_sats=2200,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        assert len(inv.anchor_id) == 16

        retrieved = tmp_invoices.get(inv.anchor_id)
        assert retrieved is not None
        assert retrieved.checksum == "c" * 64

    def test_persistence(self, tmp_path):
        """Data survives a new InvoiceManager instance."""
        data_dir = tmp_path / "api"
        mgr1 = InvoiceManager(data_dir=data_dir)
        inv = mgr1.create(
            checksum="d" * 64,
            address="bc1qpersist",
            amount_sats=1000,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        aid = inv.anchor_id

        # New manager reads from same directory
        mgr2 = InvoiceManager(data_dir=data_dir)
        retrieved = mgr2.get(aid)
        assert retrieved is not None
        assert retrieved.address == "bc1qpersist"

    def test_transition(self, tmp_invoices):
        inv = tmp_invoices.create(
            checksum="e" * 64,
            address="bc1qtrans",
            amount_sats=500,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        tmp_invoices.transition(inv.anchor_id, "paid")
        assert tmp_invoices.get(inv.anchor_id).status == "paid"

    def test_transition_not_found(self, tmp_invoices):
        with pytest.raises(InvoiceError, match="not found"):
            tmp_invoices.transition("nonexistent", "paid")

    def test_list_by_status(self, tmp_invoices):
        tmp_invoices.create(
            checksum="f" * 64, address="a1", amount_sats=100,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        inv2 = tmp_invoices.create(
            checksum="0" * 64, address="a2", amount_sats=200,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        tmp_invoices.transition(inv2.anchor_id, "paid")

        pending = tmp_invoices.list_by_status("pending_payment")
        paid = tmp_invoices.list_by_status("paid")
        assert len(pending) == 1
        assert len(paid) == 1

    def test_set_l1_txid(self, tmp_invoices):
        inv = tmp_invoices.create(
            checksum="1" * 64, address="a", amount_sats=100,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        tmp_invoices.set_l1_txid(inv.anchor_id, "txid_abc")
        assert tmp_invoices.get(inv.anchor_id).l1_txid == "txid_abc"

    def test_get_not_found(self, tmp_invoices):
        assert tmp_invoices.get("nonexistent") is None


# ---------------------------------------------------------------------------
# TestAuth
# ---------------------------------------------------------------------------

class TestAuth:
    """Tests for API key authentication."""

    def test_valid_bearer(self):
        assert check_auth("Bearer mysecretkey", "mysecretkey") is True

    def test_wrong_key(self):
        assert check_auth("Bearer wrongkey", "mysecretkey") is False

    def test_missing_bearer_prefix(self):
        assert check_auth("mysecretkey", "mysecretkey") is False

    def test_empty_auth_header(self):
        assert check_auth("", "mysecretkey") is False

    def test_empty_api_key_denies_all(self):
        assert check_auth("Bearer anything", "") is False

    def test_bearer_with_extra_spaces(self):
        assert check_auth("Bearer  mysecretkey ", "mysecretkey") is True

    def test_basic_auth_rejected(self):
        assert check_auth("Basic dXNlcjpwYXNz", "dXNlcjpwYXNz") is False

    def test_load_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("L3_API_KEY", "envkey123")
        assert load_api_key() == "envkey123"

    def test_load_api_key_from_file(self, tmp_path, monkeypatch):
        monkeypatch.delenv("L3_API_KEY", raising=False)
        key_file = tmp_path / "api_key"
        key_file.write_text("filekey456")
        with patch("l3.api.auth._KEY_FILE", key_file):
            assert load_api_key() == "filekey456"

    def test_load_api_key_empty(self, monkeypatch):
        monkeypatch.delenv("L3_API_KEY", raising=False)
        with patch("l3.api.auth._KEY_FILE", Path("/nonexistent/api_key")):
            assert load_api_key() == ""


# ---------------------------------------------------------------------------
# TestHandleAnchor
# ---------------------------------------------------------------------------

class TestHandleAnchor:
    """Tests for handle_anchor (POST /anchor)."""

    def test_success(self, mock_rpc, tmp_store, tmp_invoices):
        mock_rpc.call.side_effect = [
            "bc1qnewaddr",                        # getnewaddress
            {"feerate": 0.00010},                  # estimatesmartfee
        ]

        code, data = handle_anchor(
            body=b"Hello world",
            content_type="text/plain",
            rpc=mock_rpc,
            store=tmp_store,
            invoices=tmp_invoices,
        )

        assert code == 200
        assert "anchor_id" in data
        assert data["checksum"].startswith("sha256:")
        assert data["invoice"]["address"] == "bc1qnewaddr"
        assert data["invoice"]["amount_sats"] > 0

    def test_empty_body(self, mock_rpc, tmp_store, tmp_invoices):
        code, data = handle_anchor(
            body=b"",
            content_type="text/plain",
            rpc=mock_rpc,
            store=tmp_store,
            invoices=tmp_invoices,
        )
        assert code == 400
        assert "error" in data

    def test_binary_data_hex_encoded(self, mock_rpc, tmp_store, tmp_invoices):
        mock_rpc.call.side_effect = ["bc1qaddr", {"feerate": 0.00010}]
        code, data = handle_anchor(
            body=b"\xff\xfe\xfd",
            content_type="application/octet-stream",
            rpc=mock_rpc,
            store=tmp_store,
            invoices=tmp_invoices,
        )
        assert code == 200

    def test_fee_estimation_fallback(self, mock_rpc, tmp_store, tmp_invoices):
        """If estimatesmartfee fails, use fallback fee."""
        mock_rpc.call.side_effect = [
            "bc1qaddr",
            Exception("RPC error"),  # estimatesmartfee fails
        ]
        code, data = handle_anchor(
            body=b"test data",
            content_type="text/plain",
            rpc=mock_rpc,
            store=tmp_store,
            invoices=tmp_invoices,
        )
        assert code == 200
        assert data["invoice"]["amount_sats"] == 2200  # fallback


# ---------------------------------------------------------------------------
# TestHandleAnchorPfm
# ---------------------------------------------------------------------------

class TestHandleAnchorPfm:
    """Tests for handle_anchor_pfm (POST /anchor-pfm)."""

    def test_success(self, sample_doc, mock_rpc, tmp_store, tmp_invoices):
        mock_rpc.call.side_effect = ["bc1qpfm", {"feerate": 0.00005}]
        pfm_bytes = sample_doc.to_bytes()

        code, data = handle_anchor_pfm(
            body=pfm_bytes,
            rpc=mock_rpc,
            store=tmp_store,
            invoices=tmp_invoices,
        )
        assert code == 200
        assert "anchor_id" in data

    def test_invalid_pfm(self, mock_rpc, tmp_store, tmp_invoices):
        code, data = handle_anchor_pfm(
            body=b"not a pfm document",
            rpc=mock_rpc,
            store=tmp_store,
            invoices=tmp_invoices,
        )
        assert code == 400
        assert "Not a valid PFM" in data["error"]

    def test_empty_body(self, mock_rpc, tmp_store, tmp_invoices):
        code, data = handle_anchor_pfm(
            body=b"",
            rpc=mock_rpc,
            store=tmp_store,
            invoices=tmp_invoices,
        )
        assert code == 400


# ---------------------------------------------------------------------------
# TestHandleAnchorStatus
# ---------------------------------------------------------------------------

class TestHandleAnchorStatus:
    """Tests for handle_anchor_status (GET /anchor/<id>)."""

    def test_found(self, tmp_invoices):
        inv = tmp_invoices.create(
            checksum="a" * 64,
            address="bc1qstatus",
            amount_sats=1000,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        code, data = handle_anchor_status(inv.anchor_id, tmp_invoices)
        assert code == 200
        assert data["status"] == "pending_payment"
        assert data["anchor_id"] == inv.anchor_id

    def test_confirmed_has_receipt(self, tmp_invoices):
        inv = tmp_invoices.create(
            checksum="b" * 64,
            address="bc1qreceipt",
            amount_sats=1000,
            expires_at="2099-01-01T00:00:00+00:00",
        )
        tmp_invoices.transition(inv.anchor_id, "paid")
        tmp_invoices.transition(inv.anchor_id, "anchoring")
        tmp_invoices.set_l1_txid(inv.anchor_id, "txid_confirmed")
        tmp_invoices.transition(inv.anchor_id, "confirmed")

        code, data = handle_anchor_status(inv.anchor_id, tmp_invoices)
        assert code == 200
        assert data["status"] == "confirmed"
        assert data["receipt"]["l1_txid"] == "txid_confirmed"

    def test_not_found(self, tmp_invoices):
        code, data = handle_anchor_status("nonexistent0000", tmp_invoices)
        assert code == 404

    def test_empty_id(self, tmp_invoices):
        code, data = handle_anchor_status("", tmp_invoices)
        assert code == 400


# ---------------------------------------------------------------------------
# TestHandleVerify
# ---------------------------------------------------------------------------

class TestHandleVerify:
    """Tests for handle_verify (GET /verify/<txid>)."""

    def test_found(self, mock_rpc, tmp_store, sample_doc):
        checksum = tmp_store.store(sample_doc)
        script = _build_op_return_hex(checksum)
        mock_rpc.call.return_value = {
            "vout": [{"scriptPubKey": {"hex": script}}]
        }

        code, data = handle_verify("a" * 64, mock_rpc, tmp_store)
        assert code == 200
        assert data["verified"] is True
        assert data["in_l3_store"] is True

    def test_not_found(self, mock_rpc, tmp_store):
        mock_rpc.call.return_value = {
            "vout": [{"scriptPubKey": {"hex": "76a914aabb88ac"}}]
        }
        code, data = handle_verify("a" * 64, mock_rpc, tmp_store)
        assert code == 404

    def test_invalid_txid(self, mock_rpc, tmp_store):
        code, data = handle_verify("not-a-txid", mock_rpc, tmp_store)
        assert code == 400


# ---------------------------------------------------------------------------
# TestHandleRetrieve
# ---------------------------------------------------------------------------

class TestHandleRetrieve:
    """Tests for handle_retrieve (GET /retrieve/<checksum>)."""

    def test_found(self, sample_doc, tmp_store):
        checksum = tmp_store.store(sample_doc)
        code, result = handle_retrieve(checksum, tmp_store)
        assert code == 200
        assert isinstance(result, bytes)

    def test_with_sha256_prefix(self, sample_doc, tmp_store):
        checksum = tmp_store.store(sample_doc)
        code, result = handle_retrieve(f"sha256:{checksum}", tmp_store)
        assert code == 200
        assert isinstance(result, bytes)

    def test_not_found(self, tmp_store):
        code, result = handle_retrieve("a" * 64, tmp_store)
        assert code == 404
        assert isinstance(result, dict)

    def test_invalid_checksum(self, tmp_store):
        code, result = handle_retrieve("../etc/passwd", tmp_store)
        assert code == 400


# ---------------------------------------------------------------------------
# TestHandleStatus
# ---------------------------------------------------------------------------

class TestHandleStatus:
    """Tests for handle_status (GET /status)."""

    def test_healthy(self, mock_rpc, tmp_store, tmp_invoices):
        mock_rpc.call.side_effect = [
            {"chain": "test", "blocks": 100, "verificationprogress": 1.0},
            0.001,
        ]
        code, data = handle_status(mock_rpc, tmp_store, tmp_invoices)
        assert code == 200
        assert data["healthy"] is True
        assert data["l1"]["connected"] is True
        assert data["l1"]["blocks"] == 100

    def test_l1_disconnected(self, mock_rpc, tmp_store, tmp_invoices):
        mock_rpc.call.side_effect = Exception("Connection refused")
        code, data = handle_status(mock_rpc, tmp_store, tmp_invoices)
        assert code == 200
        assert data["healthy"] is False
        assert data["l1"]["connected"] is False


# ---------------------------------------------------------------------------
# TestPaymentWatcher
# ---------------------------------------------------------------------------

class TestPaymentWatcher:
    """Tests for the PaymentWatcher background thread."""

    def test_expire_invoice(self, mock_rpc, tmp_store, tmp_invoices):
        """Watcher should expire invoices past their expiry time."""
        expired_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        inv = tmp_invoices.create(
            checksum="a" * 64,
            address="bc1qexpired",
            amount_sats=1000,
            expires_at=expired_time,
        )

        watcher = PaymentWatcher(mock_rpc, tmp_store, tmp_invoices, poll_interval=1)
        watcher._check_payments()

        assert tmp_invoices.get(inv.anchor_id).status == "expired"

    def test_detect_payment(self, mock_rpc, tmp_store, tmp_invoices):
        """Watcher should detect payment and transition to paid."""
        inv = tmp_invoices.create(
            checksum="b" * 64,
            address="bc1qpaid",
            amount_sats=2200,
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        )

        # getreceivedbyaddress returns enough BTC
        mock_rpc.call.return_value = 0.000022  # 2200 sats in BTC

        watcher = PaymentWatcher(mock_rpc, tmp_store, tmp_invoices, poll_interval=1)
        watcher._check_payments()

        assert tmp_invoices.get(inv.anchor_id).status == "paid"

    def test_process_paid_anchors(self, sample_doc, mock_rpc, tmp_store, tmp_invoices):
        """Watcher should anchor paid invoices."""
        checksum = tmp_store.store(sample_doc)
        inv = tmp_invoices.create(
            checksum=checksum,
            address="bc1qanchor",
            amount_sats=2200,
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        )
        tmp_invoices.transition(inv.anchor_id, "paid")

        # Mock anchor_document RPC calls
        mock_rpc.call.side_effect = [
            "raw_tx",                                       # createrawtransaction
            {"hex": "funded_hex"},                          # fundrawtransaction
            {"hex": "signed_hex", "complete": True},        # signrawtransactionwithwallet
            "txid_anchored_123",                            # sendrawtransaction
        ]

        watcher = PaymentWatcher(mock_rpc, tmp_store, tmp_invoices, poll_interval=1)
        watcher._process_paid()

        result = tmp_invoices.get(inv.anchor_id)
        assert result.status == "confirmed"
        assert result.l1_txid == "txid_anchored_123"

    def test_anchor_failure_marks_failed(self, sample_doc, mock_rpc, tmp_store, tmp_invoices):
        """If anchoring fails, invoice should transition to failed."""
        checksum = tmp_store.store(sample_doc)
        inv = tmp_invoices.create(
            checksum=checksum,
            address="bc1qfail",
            amount_sats=2200,
            expires_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        )
        tmp_invoices.transition(inv.anchor_id, "paid")

        # createrawtransaction fails
        mock_rpc.call.side_effect = Exception("Wallet locked")

        watcher = PaymentWatcher(mock_rpc, tmp_store, tmp_invoices, poll_interval=1)
        watcher._process_paid()

        assert tmp_invoices.get(inv.anchor_id).status == "failed"

    def test_start_stop(self, mock_rpc, tmp_store, tmp_invoices):
        """Watcher thread starts and stops cleanly."""
        watcher = PaymentWatcher(mock_rpc, tmp_store, tmp_invoices, poll_interval=1)
        watcher.start()
        assert watcher.is_running
        watcher.stop()
        assert not watcher.is_running


# ---------------------------------------------------------------------------
# TestServerIntegration
# ---------------------------------------------------------------------------

class TestServerIntegration:
    """Integration tests using a real HTTP server on localhost."""

    @pytest.fixture
    def api_server(self, mock_rpc, tmp_store, tmp_invoices):
        """Start a real API server on a random port."""
        from l3.api.server import AnchorAPIServer

        # Use port 0 to let OS pick an available port
        server = AnchorAPIServer(
            ("127.0.0.1", 0), mock_rpc, tmp_store, tmp_invoices, "testkey123"
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        yield server
        server.shutdown()
        server.server_close()

    def _url(self, server, path):
        host, port = server.server_address
        return f"http://{host}:{port}{path}"

    def _get(self, server, path):
        import urllib.request
        url = self._url(server, path)
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode())

    def _post(self, server, path, body, headers=None):
        import urllib.request
        import urllib.error
        url = self._url(server, path)
        req = urllib.request.Request(url, data=body, method="POST")
        if headers:
            for k, v in headers.items():
                req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def test_status_endpoint(self, api_server, mock_rpc):
        mock_rpc.call.side_effect = [
            {"chain": "test", "blocks": 50, "verificationprogress": 0.99},
            0.01,
        ]
        code, data = self._get(api_server, "/status")
        assert code == 200
        assert data["service"] == "l3-anchor-api"

    def test_post_anchor_no_auth(self, api_server):
        """POST /anchor without auth should return 401."""
        code, data = self._post(api_server, "/anchor", b"test data")
        assert code == 401

    def test_post_anchor_with_auth(self, api_server, mock_rpc):
        """POST /anchor with valid auth should return an invoice."""
        mock_rpc.call.side_effect = ["bc1qtest", {"feerate": 0.0001}]
        code, data = self._post(
            api_server,
            "/anchor",
            b"hello world",
            {"Authorization": "Bearer testkey123", "Content-Type": "text/plain"},
        )
        assert code == 200
        assert "anchor_id" in data
        assert "invoice" in data

    def test_anchor_status_after_creation(self, api_server, mock_rpc):
        """Create an invoice then check its status."""
        mock_rpc.call.side_effect = ["bc1qcheck", {"feerate": 0.0001}]
        code, data = self._post(
            api_server,
            "/anchor",
            b"status check",
            {"Authorization": "Bearer testkey123"},
        )
        assert code == 200
        anchor_id = data["anchor_id"]

        code2, data2 = self._get(api_server, f"/anchor/{anchor_id}")
        assert code2 == 200
        assert data2["status"] == "pending_payment"

    def test_404_on_unknown_path(self, api_server):
        import urllib.request
        import urllib.error
        url = self._url(api_server, "/nonexistent")
        req = urllib.request.Request(url, method="GET")
        try:
            urllib.request.urlopen(req, timeout=5)
            assert False, "Expected 404"
        except urllib.error.HTTPError as e:
            assert e.code == 404
