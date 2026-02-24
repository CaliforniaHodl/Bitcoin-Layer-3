"""
HTTP server for the Anchor API.

Uses stdlib http.server — zero external dependencies.
Routes requests to handler functions in handlers.py.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

from l3 import API_DEFAULT_PORT, API_DEFAULT_HOST, API_MAX_UPLOAD_BYTES
from l3.api.auth import load_api_key, check_auth
from l3.api.handlers import (
    handle_anchor,
    handle_anchor_pfm,
    handle_anchor_status,
    handle_batch_anchor,
    handle_merkle_proof,
    handle_verify,
    handle_retrieve,
    handle_status,
)
from l3.api.invoices import InvoiceManager
from l3.api.watcher import PaymentWatcher

logger = logging.getLogger(__name__)

# Route patterns
_ANCHOR_STATUS_RE = re.compile(r"^/anchor/([a-f0-9]{16})$")
_VERIFY_RE = re.compile(r"^/verify/([0-9a-fA-F]{64})$")
_RETRIEVE_RE = re.compile(r"^/retrieve/(?:sha256:)?([0-9a-f]{64})$")
_MERKLE_PROOF_RE = re.compile(
    r"^/merkle-proof/(?:sha256:)?([0-9a-f]{64})/([0-9a-f]{16})$"
)


class AnchorAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for the Anchor API.

    Server-level dependencies (rpc, store, invoices, api_key) are attached
    to the server instance and accessed via self.server.
    """

    # Suppress default stderr logging — we use the logging module
    def log_message(self, format: str, *args: Any) -> None:
        logger.debug(format, *args)

    def _send_json(self, status: int, data: dict) -> None:
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, status: int, data: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        if length > API_MAX_UPLOAD_BYTES:
            return b""  # handler will check body length
        if length <= 0:
            return b""
        return self.rfile.read(length)

    def _require_auth(self) -> bool:
        """Check Bearer auth. Returns True if authorized, sends 401 if not."""
        api_key = self.server.api_key  # type: ignore[attr-defined]
        auth_header = self.headers.get("Authorization", "")
        if not check_auth(auth_header, api_key):
            self._send_json(401, {"error": "Unauthorized — provide Authorization: Bearer <key>"})
            return False
        return True

    def do_GET(self) -> None:
        path = self.path.split("?")[0]  # strip query string
        server = self.server  # type: ignore[attr-defined]

        # GET /status
        if path == "/status":
            code, data = handle_status(server.rpc, server.store, server.invoices)
            self._send_json(code, data)
            return

        # GET /anchor/<id>
        m = _ANCHOR_STATUS_RE.match(path)
        if m:
            code, data = handle_anchor_status(m.group(1), server.invoices)
            self._send_json(code, data)
            return

        # GET /verify/<txid>
        m = _VERIFY_RE.match(path)
        if m:
            code, data = handle_verify(m.group(1), server.rpc, server.store)
            self._send_json(code, data)
            return

        # GET /retrieve/<checksum>
        m = _RETRIEVE_RE.match(path)
        if m:
            code, result = handle_retrieve(m.group(1), server.store)
            if isinstance(result, bytes):
                self._send_bytes(code, result, "application/x-pfm")
            else:
                self._send_json(code, result)
            return

        # GET /merkle-proof/<checksum>/<anchor_id>
        m = _MERKLE_PROOF_RE.match(path)
        if m:
            code, data = handle_merkle_proof(
                m.group(1), m.group(2), server.store, server.invoices
            )
            self._send_json(code, data)
            return

        self._send_json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        server = self.server  # type: ignore[attr-defined]

        # Always read the body first to avoid connection resets
        body = self._read_body()

        # POST /anchor
        if path == "/anchor":
            if not self._require_auth():
                return
            content_type = self.headers.get("Content-Type", "")
            code, data = handle_anchor(
                body, content_type, server.rpc, server.store, server.invoices
            )
            self._send_json(code, data)
            return

        # POST /anchor-pfm
        if path == "/anchor-pfm":
            if not self._require_auth():
                return
            code, data = handle_anchor_pfm(
                body, server.rpc, server.store, server.invoices
            )
            self._send_json(code, data)
            return

        # POST /batch-anchor
        if path == "/batch-anchor":
            if not self._require_auth():
                return
            code, data = handle_batch_anchor(
                body, server.rpc, server.store, server.invoices
            )
            self._send_json(code, data)
            return

        self._send_json(404, {"error": "Not found"})


class AnchorAPIServer(HTTPServer):
    """HTTPServer subclass that carries API dependencies."""

    def __init__(
        self,
        address: tuple[str, int],
        rpc: Any,
        store: Any,
        invoices: InvoiceManager,
        api_key: str,
    ) -> None:
        super().__init__(address, AnchorAPIHandler)
        self.rpc = rpc
        self.store = store
        self.invoices = invoices
        self.api_key = api_key


def run_api(
    rpc: Any,
    host: str = API_DEFAULT_HOST,
    port: int = API_DEFAULT_PORT,
    store: Any = None,
    invoices: InvoiceManager | None = None,
    poll_interval: int | None = None,
) -> None:
    """Start the Anchor API server (blocking).

    Args:
        rpc: BitcoinRPC instance
        host: Bind address (default 127.0.0.1)
        port: Listen port (default 8080)
        store: L3Store instance (created if not provided)
        invoices: InvoiceManager instance (created if not provided)
        poll_interval: Payment watcher poll interval in seconds
    """
    from l3.store import L3Store

    if store is None:
        store = L3Store()
    if invoices is None:
        invoices = InvoiceManager()

    api_key = load_api_key()
    if not api_key:
        print(
            "WARNING: No API key configured. POST endpoints will reject all requests.\n"
            "Set L3_API_KEY env var or create ~/.pfm/l3/api/api_key",
            file=sys.stderr,
        )

    server = AnchorAPIServer((host, port), rpc, store, invoices, api_key)

    # Start payment watcher
    watcher_kwargs = {}
    if poll_interval is not None:
        watcher_kwargs["poll_interval"] = poll_interval
    watcher = PaymentWatcher(rpc, store, invoices, **watcher_kwargs)
    watcher.start()

    print(f"L3 Anchor API listening on http://{host}:{port}")
    print(f"  POST /anchor              — submit data (auth required)")
    print(f"  POST /anchor-pfm          — submit PFM doc (auth required)")
    print(f"  POST /batch-anchor        — batch anchor via Merkle root (auth required)")
    print(f"  GET  /anchor/<id>         — check invoice status")
    print(f"  GET  /verify/<txid>       — verify on-chain anchor")
    print(f"  GET  /retrieve/<cs>       — download from L3")
    print(f"  GET  /merkle-proof/<cs>/<id> — get Merkle inclusion proof")
    print(f"  GET  /status              — service health")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down...")
    finally:
        watcher.stop()
        server.server_close()
