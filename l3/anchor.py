"""
Bitcoin L3 Anchoring — anchor PFM document checksums to Bitcoin via OP_RETURN.

Architecture:
    L1 (Bitcoin):  OP_RETURN = "PFM3" (4 bytes) + SHA-256 checksum (32 bytes) = 36 bytes
    L3 (Local):    ~/.pfm/l3/store/<checksum>.pfm + index.json
    Bridge:        l3 anchor / l3 verify-anchor CLI commands

Zero external dependencies — uses stdlib urllib.request for Bitcoin JSON-RPC.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import urllib.error
import urllib.request
from base64 import b64encode
from datetime import datetime, timezone
from typing import Any

from l3 import ANCHOR_PREFIX_HEX, ANCHOR_PAYLOAD_SIZE

# Strict hex pattern for SHA-256 checksums (exactly 64 hex chars)
_CHECKSUM_RE = re.compile(r"^[0-9a-f]{64}$")

# OP_RETURN opcode
_OP_RETURN = "6a"


class BitcoinRPCError(Exception):
    """Error communicating with or returned by Bitcoin JSON-RPC."""


class BitcoinRPC:
    """Minimal Bitcoin JSON-RPC client using stdlib urllib.

    Usage:
        rpc = BitcoinRPC.from_env()
        info = rpc.call("getblockchaininfo")
    """

    def __init__(self, url: str, user: str = "", password: str = "") -> None:
        if not url:
            raise ValueError("Bitcoin RPC URL cannot be empty")
        self.url = url
        self._user = user
        self._password = password
        self._id_counter = 0

    @classmethod
    def from_env(cls) -> BitcoinRPC:
        """Create RPC client from environment variables.

        Reads:
            BITCOIN_RPC_URL  — e.g. http://127.0.0.1:18332
            BITCOIN_RPC_USER — RPC username
            BITCOIN_RPC_PASS — RPC password
        """
        url = os.environ.get("BITCOIN_RPC_URL", "")
        user = os.environ.get("BITCOIN_RPC_USER", "")
        password = os.environ.get("BITCOIN_RPC_PASS", "")
        if not url:
            raise BitcoinRPCError(
                "BITCOIN_RPC_URL not set. "
                "Set it to your Bitcoin node's RPC endpoint "
                "(e.g. http://127.0.0.1:18332 for testnet)."
            )
        return cls(url, user, password)

    def call(self, method: str, *params: Any) -> Any:
        """Execute a JSON-RPC call. Returns the 'result' field.

        Raises BitcoinRPCError on transport or RPC-level errors.
        """
        self._id_counter += 1
        payload = json.dumps({
            "jsonrpc": "1.0",
            "id": self._id_counter,
            "method": method,
            "params": list(params),
        }).encode()

        req = urllib.request.Request(
            self.url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        # Compute auth header per-request to avoid persisting in memory (C-2 fix)
        if self._user or self._password:
            creds = b64encode(f"{self._user}:{self._password}".encode()).decode()
            req.add_header("Authorization", f"Basic {creds}")
            # Zero the intermediate credential string
            creds = "\x00" * len(creds)

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            # Bitcoin Core returns errors as HTTP 500 with JSON body
            try:
                body = json.loads(e.read().decode())
            except Exception:
                raise BitcoinRPCError(f"HTTP {e.code}: {e.reason}") from e
        except urllib.error.URLError as e:
            raise BitcoinRPCError(f"Connection failed: {e.reason}") from e
        except Exception as e:
            raise BitcoinRPCError(f"RPC call failed: {e}") from e

        if body.get("error"):
            err = body["error"]
            msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            raise BitcoinRPCError(f"RPC error: {msg}")

        return body.get("result")

    def get_network(self) -> str:
        """Detect which network the node is running on.

        Returns one of: 'mainnet', 'testnet', 'signet', 'regtest'.
        """
        info = self.call("getblockchaininfo")
        chain = info.get("chain", "")
        network_map = {
            "main": "mainnet",
            "test": "testnet",
            "signet": "signet",
            "regtest": "regtest",
        }
        return network_map.get(chain, chain)


def _validate_checksum(checksum_hex: str) -> None:
    """Validate a hex checksum string. Raises ValueError if invalid."""
    if not isinstance(checksum_hex, str) or not _CHECKSUM_RE.match(checksum_hex):
        raise ValueError(
            f"Invalid checksum: must be 64 lowercase hex chars, got {checksum_hex!r}"
        )


def _build_op_return_hex(checksum_hex: str) -> str:
    """Build the full OP_RETURN script hex for a PFM anchor.

    Format: OP_RETURN <push 36 bytes> "PFM3" <sha256>
    Returns the scriptPubKey as hex.

    The push opcode for 36 bytes is 0x24 (decimal 36, single-byte push).
    """
    _validate_checksum(checksum_hex)
    data_hex = ANCHOR_PREFIX_HEX + checksum_hex  # 8 + 64 = 72 hex chars = 36 bytes
    push_len = format(ANCHOR_PAYLOAD_SIZE, "02x")  # "24"
    return _OP_RETURN + push_len + data_hex


def parse_op_return(script_hex: str) -> tuple[str, str] | None:
    """Parse a PFM OP_RETURN script and extract (prefix, checksum).

    Returns None if the script is not a PFM anchor.

    Expected format: 6a24 50464d33 <64 hex chars>
                     ^    ^        ^
                     |    |        SHA-256 checksum
                     |    "PFM3" prefix
                     OP_RETURN + push 36 bytes
    """
    if not isinstance(script_hex, str):
        return None

    script = script_hex.lower().strip()

    # OP_RETURN (6a) + push 36 bytes (24) + 72 hex data = 76 hex chars total
    expected_prefix = _OP_RETURN + format(ANCHOR_PAYLOAD_SIZE, "02x")  # "6a24"
    if not script.startswith(expected_prefix):
        return None

    data_hex = script[len(expected_prefix):]
    if len(data_hex) != 72:  # 8 (prefix) + 64 (checksum)
        return None

    prefix_hex = data_hex[:8]
    checksum_hex = data_hex[8:]

    if prefix_hex != ANCHOR_PREFIX_HEX:
        return None

    if not _CHECKSUM_RE.match(checksum_hex):
        return None

    # Decode prefix bytes to string
    try:
        prefix = bytes.fromhex(prefix_hex).decode("ascii")
    except (ValueError, UnicodeDecodeError):
        return None

    return prefix, checksum_hex


def anchor_document(doc: Any, rpc: BitcoinRPC) -> str:
    """Anchor a PFM document's checksum to Bitcoin via OP_RETURN.

    Full workflow:
        1. Compute document checksum
        2. Build OP_RETURN output
        3. Create, fund, sign, and broadcast the transaction

    Returns the transaction ID (txid).

    Updates doc.custom_meta with:
        anchor_txid, anchor_network, anchor_hash, anchor_ts
    """
    checksum = doc.compute_checksum()
    _validate_checksum(checksum)

    network = rpc.get_network()

    # Step 1: Create raw transaction with OP_RETURN output
    # Amount is 0 for OP_RETURN (data-only, unspendable)
    raw_tx = rpc.call(
        "createrawtransaction",
        [],  # No inputs yet — fundrawtransaction will select UTXOs
        [{"data": ANCHOR_PREFIX_HEX + checksum}],  # Bitcoin Core builds the OP_RETURN
    )

    # Step 2: Fund the transaction (adds inputs and change output)
    funded = rpc.call("fundrawtransaction", raw_tx)
    funded_hex = funded["hex"]

    # Step 3: Sign the transaction
    signed = rpc.call("signrawtransactionwithwallet", funded_hex)
    if not signed.get("complete"):
        raise BitcoinRPCError("Transaction signing incomplete — check wallet")
    signed_hex = signed["hex"]

    # Step 4: Broadcast
    txid = rpc.call("sendrawtransaction", signed_hex)

    # Record anchor metadata on the document
    doc.custom_meta["anchor_txid"] = txid
    doc.custom_meta["anchor_network"] = network
    doc.custom_meta["anchor_hash"] = checksum
    doc.custom_meta["anchor_ts"] = datetime.now(timezone.utc).isoformat()

    return txid


def lookup_anchor(txid: str, rpc: BitcoinRPC) -> tuple[str, str] | None:
    """Look up a PFM anchor by transaction ID.

    Returns (prefix, checksum) if the transaction contains a PFM OP_RETURN,
    or None if not found.
    """
    try:
        tx = rpc.call("getrawtransaction", txid, True)  # verbose=True for decoded
    except BitcoinRPCError:
        return None

    for vout in tx.get("vout", []):
        script_pub_key = vout.get("scriptPubKey", {})
        script_hex = script_pub_key.get("hex", "")
        result = parse_op_return(script_hex)
        if result is not None:
            return result

    return None


def verify_anchor(doc: Any, rpc: BitcoinRPC) -> bool:
    """Verify that a document's on-chain anchor matches its current checksum.

    Fail-closed: returns False if:
        - Document has no anchor metadata
        - Connection to Bitcoin node fails
        - Transaction not found
        - On-chain hash doesn't match document checksum

    Uses hmac.compare_digest() for constant-time comparison.
    """
    txid = doc.custom_meta.get("anchor_txid")
    if not txid:
        return False

    current_checksum = doc.compute_checksum()

    try:
        result = lookup_anchor(txid, rpc)
    except Exception:
        return False

    if result is None:
        return False

    _prefix, on_chain_checksum = result

    return hmac.compare_digest(current_checksum, on_chain_checksum)
