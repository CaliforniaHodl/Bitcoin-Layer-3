"""
Request handlers for the Anchor API.

Each handler is a pure function: (request_data, dependencies) → (status_code, response_dict).
No HTTP plumbing — that lives in server.py.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone, timedelta
from typing import Any

from l3 import API_DEFAULT_EXPIRY_SECS, API_MAX_UPLOAD_BYTES

_CHECKSUM_RE = re.compile(r"^[0-9a-f]{64}$")
_TXID_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_ANCHOR_ID_RE = re.compile(r"^[0-9a-f]{16}$")


def handle_anchor(
    body: bytes,
    content_type: str,
    rpc: Any,
    store: Any,
    invoices: Any,
) -> tuple[int, dict]:
    """POST /anchor — submit raw data, wrap in PFM, return invoice.

    Args:
        body: Raw request body (the data to anchor)
        content_type: Content-Type header value
        rpc: BitcoinRPC instance
        store: L3Store instance
        invoices: InvoiceManager instance
    """
    if not body:
        return 400, {"error": "Empty request body"}
    if len(body) > API_MAX_UPLOAD_BYTES:
        return 413, {"error": f"Payload too large (max {API_MAX_UPLOAD_BYTES} bytes)"}

    from l3._format.document import PFMDocument

    doc = PFMDocument.create(agent="l3-api")
    # Store raw data as content section (decode as utf-8 if possible, else hex)
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        text = body.hex()
        doc.custom_meta["encoding"] = "hex"

    if content_type:
        doc.custom_meta["content_type"] = content_type

    doc.add_section("content", text)

    return _create_invoice(doc, content_type, rpc, store, invoices)


def handle_anchor_pfm(
    body: bytes,
    rpc: Any,
    store: Any,
    invoices: Any,
) -> tuple[int, dict]:
    """POST /anchor-pfm — submit a PFM document, return invoice."""
    if not body:
        return 400, {"error": "Empty request body"}
    if len(body) > API_MAX_UPLOAD_BYTES:
        return 413, {"error": f"Payload too large (max {API_MAX_UPLOAD_BYTES} bytes)"}

    from l3._format.reader import PFMReader

    if not PFMReader.is_pfm_bytes(body):
        return 400, {"error": "Not a valid PFM document"}

    try:
        doc = PFMReader.parse(body)
    except Exception as e:
        return 400, {"error": f"Failed to parse PFM document: {e}"}

    return _create_invoice(doc, "application/x-pfm", rpc, store, invoices)


def _create_invoice(
    doc: Any,
    content_type: str,
    rpc: Any,
    store: Any,
    invoices: Any,
) -> tuple[int, dict]:
    """Shared logic: store doc, get address + fee estimate, create invoice."""
    try:
        checksum = store.store(doc)
    except Exception as e:
        return 500, {"error": f"Failed to store document: {e}"}

    try:
        address = rpc.call("getnewaddress", "l3-api", "bech32")
    except Exception as e:
        return 502, {"error": f"Bitcoin RPC error (getnewaddress): {e}"}

    try:
        fee_info = rpc.call("estimatesmartfee", 6)
        fee_rate = fee_info.get("feerate", 0.00001)
        # Estimate tx size ~250 vbytes for OP_RETURN tx, convert BTC/kB to sats
        estimated_sats = max(int(fee_rate * 100_000_000 * 250 / 1000), 546)
    except Exception:
        estimated_sats = 2200  # fallback: reasonable default

    expires_at = (
        datetime.now(timezone.utc) + timedelta(seconds=API_DEFAULT_EXPIRY_SECS)
    ).isoformat()

    inv = invoices.create(
        checksum=checksum,
        address=address,
        amount_sats=estimated_sats,
        expires_at=expires_at,
        content_type=content_type,
    )

    return 200, {
        "anchor_id": inv.anchor_id,
        "checksum": f"sha256:{checksum}",
        "invoice": {
            "address": address,
            "amount_sats": estimated_sats,
            "expires_at": expires_at,
        },
    }


def handle_anchor_status(
    anchor_id: str,
    invoices: Any,
) -> tuple[int, dict]:
    """GET /anchor/<id> — check invoice status and receipt."""
    if not anchor_id:
        return 400, {"error": "Missing anchor_id"}

    inv = invoices.get(anchor_id)
    if inv is None:
        return 404, {"error": "Invoice not found"}

    result: dict[str, Any] = {
        "anchor_id": inv.anchor_id,
        "status": inv.status,
        "checksum": f"sha256:{inv.checksum}",
        "invoice": {
            "address": inv.address,
            "amount_sats": inv.amount_sats,
            "expires_at": inv.expires_at,
        },
    }

    if inv.status == "confirmed" and inv.l1_txid:
        result["receipt"] = {
            "l1_txid": inv.l1_txid,
            "l3_ref": inv.checksum,
            "checksum": f"sha256:{inv.checksum}",
        }

    return 200, result


def handle_verify(
    txid: str,
    rpc: Any,
    store: Any,
) -> tuple[int, dict]:
    """GET /verify/<txid> — verify an anchor on L1."""
    if not txid or not _TXID_RE.match(txid):
        return 400, {"error": "Invalid transaction ID (must be 64 hex chars)"}

    from l3.anchor import lookup_anchor

    result = lookup_anchor(txid, rpc)
    if result is None:
        return 404, {"error": "No PFM anchor found in transaction"}

    prefix, checksum = result
    in_store = store.contains(checksum)

    return 200, {
        "txid": txid,
        "prefix": prefix,
        "checksum": f"sha256:{checksum}",
        "in_l3_store": in_store,
        "verified": True,
    }


def handle_retrieve(
    checksum: str,
    store: Any,
) -> tuple[int, dict | bytes]:
    """GET /retrieve/<checksum> — download data from L3.

    Returns the raw PFM bytes on success (as bytes, not dict).
    Returns (status, dict) on error.
    """
    # Accept with or without sha256: prefix
    if checksum.startswith("sha256:"):
        checksum = checksum[7:]

    if not _CHECKSUM_RE.match(checksum):
        return 400, {"error": "Invalid checksum (must be 64 lowercase hex chars)"}

    if not store.contains(checksum):
        return 404, {"error": "Document not found in L3 store"}

    try:
        doc = store.retrieve(checksum)
        return 200, doc.to_bytes()
    except Exception as e:
        return 500, {"error": f"Failed to retrieve document: {e}"}


def handle_status(
    rpc: Any,
    store: Any,
    invoices: Any,
) -> tuple[int, dict]:
    """GET /status — service health check."""
    result: dict[str, Any] = {"service": "l3-anchor-api", "healthy": True}

    # L1 connection
    try:
        info = rpc.call("getblockchaininfo")
        result["l1"] = {
            "connected": True,
            "chain": info.get("chain", "unknown"),
            "blocks": info.get("blocks", 0),
            "verification_progress": info.get("verificationprogress", 0),
        }
    except Exception:
        result["l1"] = {"connected": False}
        result["healthy"] = False

    # Wallet balance
    try:
        balance = rpc.call("getbalance")
        result["wallet"] = {"balance_btc": balance}
    except Exception:
        result["wallet"] = {"balance_btc": "unavailable"}

    # L3 store stats
    try:
        entries = store.list()
        result["l3_store"] = {"documents": len(entries)}
    except Exception:
        result["l3_store"] = {"documents": "unavailable"}

    # Invoice stats
    try:
        all_inv = invoices.all()
        by_status: dict[str, int] = {}
        for inv in all_inv:
            by_status[inv.status] = by_status.get(inv.status, 0) + 1
        result["invoices"] = by_status
    except Exception:
        result["invoices"] = {}

    return 200, result


def handle_batch_anchor(
    body: bytes,
    rpc: Any,
    store: Any,
    invoices: Any,
) -> tuple[int, dict]:
    """POST /batch-anchor — submit multiple checksums, anchor Merkle root.

    Body: JSON with {"checksums": ["aabb...", "ccdd...", ...]}
    Returns a single invoice for the Merkle root anchor.
    """
    if not body:
        return 400, {"error": "Empty request body"}

    import json as json_mod
    try:
        data = json_mod.loads(body)
    except (json_mod.JSONDecodeError, ValueError):
        return 400, {"error": "Invalid JSON"}

    checksums = data.get("checksums")
    if not checksums or not isinstance(checksums, list):
        return 400, {"error": "Missing or empty 'checksums' array"}

    if len(checksums) > 10000:
        return 400, {"error": "Too many checksums (max 10,000)"}

    # Validate all checksums
    for cs in checksums:
        if not isinstance(cs, str):
            return 400, {"error": f"Checksum must be a string, got {type(cs).__name__}"}
        clean = cs[7:] if cs.startswith("sha256:") else cs
        if not _CHECKSUM_RE.match(clean):
            return 400, {"error": f"Invalid checksum: {cs!r}"}

    # Build Merkle tree
    from l3.veilcloud.merkle import MerkleTree
    clean_checksums = [
        (cs[7:] if cs.startswith("sha256:") else cs) for cs in checksums
    ]
    tree = MerkleTree.from_checksums(clean_checksums)
    merkle_root = tree.root_hex

    # Create a PFM document containing the batch metadata
    from l3._format.document import PFMDocument
    doc = PFMDocument.create(agent="l3-api-batch")
    doc.custom_meta["batch_type"] = "merkle-root"
    doc.custom_meta["merkle_root"] = merkle_root
    doc.custom_meta["batch_size"] = len(checksums)
    doc.add_section("content", json_mod.dumps({
        "merkle_root": merkle_root,
        "checksums": clean_checksums,
    }, indent=2))

    return _create_invoice(doc, "application/json", rpc, store, invoices)


def handle_merkle_proof(
    checksum: str,
    anchor_id: str,
    store: Any,
    invoices: Any,
) -> tuple[int, dict]:
    """GET /merkle-proof/<checksum>/<anchor_id> — retrieve inclusion proof.

    Returns the Merkle proof showing that `checksum` was included in the
    batch anchor identified by `anchor_id`.
    """
    # Validate inputs
    clean_cs = checksum[7:] if checksum.startswith("sha256:") else checksum
    if not _CHECKSUM_RE.match(clean_cs):
        return 400, {"error": "Invalid checksum (must be 64 lowercase hex chars)"}

    if not anchor_id or not _ANCHOR_ID_RE.match(anchor_id):
        return 400, {"error": "Invalid anchor_id (must be 16 hex chars)"}

    # Look up the invoice to get batch metadata
    inv = invoices.get(anchor_id)
    if inv is None:
        return 404, {"error": "Anchor not found"}

    # Retrieve the batch document from L3 store
    if not store.contains(inv.checksum):
        return 404, {"error": "Batch document not found in L3 store"}

    import json as json_mod
    try:
        doc = store.retrieve(inv.checksum)
        content = doc.get_section_content("content")
        batch_data = json_mod.loads(content)
        batch_checksums = batch_data["checksums"]
    except Exception:
        return 500, {"error": "Failed to read batch data"}

    if clean_cs not in batch_checksums:
        return 404, {"error": "Checksum not found in this batch"}

    # Build tree and generate proof
    from l3.veilcloud.merkle import MerkleTree, verify_proof
    tree = MerkleTree.from_checksums(batch_checksums)
    idx = batch_checksums.index(clean_cs)
    proof = tree.get_proof(idx)

    return 200, {
        "checksum": f"sha256:{clean_cs}",
        "anchor_id": anchor_id,
        "merkle_root": proof.root_hex,
        "leaf_index": proof.leaf_index,
        "siblings": [
            {"hash": s[0].hex(), "direction": s[1]}
            for s in proof.siblings
        ],
        "verified": verify_proof(proof),
    }
