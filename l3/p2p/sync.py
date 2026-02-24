"""
Document sync engine — connects the P2P layer to L3Store.

Handles the INV/WANT/DATA cycle for document exchange between peers.
Validates checksums on every received document (fail-closed).

Security hardening:
  - _handle_data only stores documents that were in _pending_wants (no unsolicited)
  - _handle_anchor_ann queues unverified anchors (requires on-chain verification)
  - _pending_wants capped at MAX_PENDING_WANTS to prevent memory exhaustion
  - INV messages capped at INV_CHUNK_SIZE checksums
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
from typing import Any, Callable

from l3.store import L3Store
from l3.p2p.connection import PeerConnection, ConnectionError as PeerConnError
from l3.p2p.protocol import (
    INV, WANT, DATA, ANCHOR_ANN, NOT_FOUND, PEERS_RES,
    make_message,
)

log = logging.getLogger(__name__)

# Max checksums per INV message (chunking for large inventories)
INV_CHUNK_SIZE = 500

# Max pending wants to prevent memory exhaustion (B-4.1)
MAX_PENDING_WANTS = 10_000

# Per-peer pending wants cap — prevents single peer from saturating (B-NEW-002)
MAX_PENDING_WANTS_PER_PEER = 1_000

# Timeout for pending wants — auto-expire after this many seconds
PENDING_WANTS_TIMEOUT = 300.0  # 5 minutes

# Max pending anchors waiting for verification (MBK-NEW-003)
MAX_PENDING_ANCHORS = 1_000

# Timeout for pending anchors — auto-expire after this many seconds
PENDING_ANCHORS_TIMEOUT = 3600.0  # 1 hour

# Per-peer WANT serving rate limit — prevents amplification (B-R2-005, S-R2-005)
MAX_WANT_SERVES_PER_PEER = 10  # per second
_WANT_RATE_WINDOW = 1.0  # seconds

# Per-peer outbound bandwidth cap (bytes/sec) — prevents amplification
MAX_OUTBOUND_BYTES_PER_PEER = 2_000_000  # 2 MB/sec
_BANDWIDTH_WINDOW = 10.0  # rolling window in seconds

# Peer score progression deltas (BT-R3-003)
SCORE_SUCCESSFUL_DATA = 0.5    # peer delivered a valid document
SCORE_VALID_RESPONSE = 0.1     # peer sent any valid useful response


class SyncEngine:
    """Sync documents between peers via the P2P network.

    Connects PeerManager message dispatch to L3Store for
    retrieving and storing documents.

    Usage:
        engine = SyncEngine(store)
        # Wire up to PeerManager as the on_message handler
        pm = PeerManager(..., on_message=engine.handle_message)
    """

    def __init__(self, store: L3Store, anchor_verifier: Any = None) -> None:
        self.store = store
        # anchor_verifier: optional callable(txid, checksum) -> bool for on-chain checks
        self._anchor_verifier = anchor_verifier
        # Track pending wants to avoid duplicate requests
        # Maps checksum -> (timestamp, peer_pubkey) for per-peer tracking
        self._pending_wants: dict[str, tuple[float, str]] = {}
        self._pending_lock = asyncio.Lock()
        # Per-peer want counts for saturation DoS prevention (B-NEW-002)
        self._peer_want_counts: dict[str, int] = {}
        # Queue of unverified anchors, keyed by checksum (MBK-NEW-003)
        # Supports multiple entries per checksum to prevent attacker replacement (C-R2-006)
        self._pending_anchors: dict[str, list[dict]] = {}
        # In-memory checksum cache — pre-loaded at construction to avoid
        # blocking event loop on first INV (B-R2-004, BT-R3-007)
        self._checksum_cache: set[str] = {e["checksum"] for e in store.list()}
        self._cache_loaded = True
        # Per-peer WANT serving rate tracking (B-R2-005)
        self._want_serve_timestamps: dict[str, list[float]] = {}
        # Per-peer outbound bandwidth tracking (B-R2-005)
        self._outbound_bytes: dict[str, list[tuple[float, int]]] = {}
        # Peer score callback — wired by server to PeerManager.score_peer (BT-R3-003)
        self._score_callback: Callable[[str, float], Any] | None = None

    def _ensure_cache(self) -> None:
        """Load checksum cache from store on first use (B-R2-004)."""
        if not self._cache_loaded:
            self._checksum_cache = {e["checksum"] for e in self.store.list()}
            self._cache_loaded = True

    def _cached_contains(self, checksum: str) -> bool:
        """Check store membership using in-memory cache (B-R2-004).

        Cache-positive: if in cache, definitely stored (no stat() needed).
        Cache-negative: if not in cache, do a stat() and update cache.
        """
        self._ensure_cache()
        if checksum in self._checksum_cache:
            return True
        # Cache miss — check disk and update
        if self.store.contains(checksum):
            self._checksum_cache.add(checksum)
            return True
        return False

    async def handle_peer_disconnect(self, peer_pubkey: str) -> None:
        """Clean up pending wants for a disconnected peer (MBK-R2-004, B-R2-010).

        Called by PeerManager via on_peer_disconnect callback.
        Immediately frees want slots instead of waiting for 5-minute expiry.
        """
        async with self._pending_lock:
            # Remove all pending wants attributed to this peer
            to_remove = [
                k for k, (ts, peer) in self._pending_wants.items()
                if peer == peer_pubkey
            ]
            for k in to_remove:
                del self._pending_wants[k]
            # Clear the per-peer counter
            self._peer_want_counts.pop(peer_pubkey, None)
            if to_remove:
                log.info(
                    "Cleaned up %d pending wants for disconnected peer %s",
                    len(to_remove), peer_pubkey[:12],
                )
        # Clean up rate tracking
        self._want_serve_timestamps.pop(peer_pubkey, None)
        self._outbound_bytes.pop(peer_pubkey, None)

    async def handle_message(self, msg: dict, conn: PeerConnection) -> None:
        """Dispatch a received message to the appropriate handler."""
        handlers = {
            INV: self._handle_inv,
            WANT: self._handle_want,
            DATA: self._handle_data,
            ANCHOR_ANN: self._handle_anchor_ann,
            NOT_FOUND: self._handle_not_found,
            PEERS_RES: self._handle_peers_res,
        }
        handler = handlers.get(msg["type"])
        if handler:
            await handler(msg["payload"], conn)

    async def _handle_inv(self, payload: dict, conn: PeerConnection) -> None:
        """Handle an INV message — request any documents we're missing.

        Caps inbound checksums to INV_CHUNK_SIZE (MBK-007 fix).
        Batch lock acquisition — single lock hold per INV (B-R2-003 fix).
        """
        checksums = payload.get("checksums", [])
        if not isinstance(checksums, list):
            return

        # Cap inbound INV to prevent filesystem stat() flood (MBK-007)
        checksums = checksums[:INV_CHUNK_SIZE]

        # Pre-filter using in-memory cache — avoids stat() flood (B-R2-004)
        missing = []
        for checksum in checksums:
            if not isinstance(checksum, str) or len(checksum) != 64:
                continue
            if not self._cached_contains(checksum):
                missing.append(checksum)

        # Batch lock — acquire ONCE per INV, not per checksum (B-R2-003)
        wanted = []
        now = time.monotonic()
        peer_pubkey = conn.peer_pubkey
        async with self._pending_lock:
            peer_count = self._peer_want_counts.get(peer_pubkey, 0)
            for checksum in missing:
                # Per-peer cap (B-NEW-002)
                if peer_count >= MAX_PENDING_WANTS_PER_PEER:
                    log.warning(
                        "Per-peer pending_wants cap reached for %s (%d)",
                        peer_pubkey[:12], peer_count,
                    )
                    break
                # Global cap (B-4.1)
                if len(self._pending_wants) >= MAX_PENDING_WANTS:
                    self._expire_pending_wants()
                    if len(self._pending_wants) >= MAX_PENDING_WANTS:
                        break
                if checksum not in self._pending_wants:
                    self._pending_wants[checksum] = (now, peer_pubkey)
                    peer_count += 1
                    wanted.append(checksum)
            self._peer_want_counts[peer_pubkey] = peer_count

        for checksum in wanted:
            try:
                want_msg = make_message(WANT, {"checksum": checksum})
                await conn.send(want_msg)
                log.info("Requested %s from %s", checksum[:12], conn.peer_pubkey[:12])
            except PeerConnError:
                async with self._pending_lock:
                    entry = self._pending_wants.pop(checksum, None)
                    if entry:
                        _ts, peer = entry
                        if peer in self._peer_want_counts:
                            self._peer_want_counts[peer] = max(0, self._peer_want_counts[peer] - 1)
                            if self._peer_want_counts[peer] == 0:
                                del self._peer_want_counts[peer]

    def _expire_pending_wants(self) -> None:
        """Remove timed-out entries from _pending_wants and update per-peer counts.

        Also sweeps stale entries from rate tracking dicts (BT-R3-006 fix).
        """
        now = time.monotonic()
        expired = [
            k for k, (ts, _peer) in self._pending_wants.items()
            if now - ts > PENDING_WANTS_TIMEOUT
        ]
        for k in expired:
            _ts, peer = self._pending_wants.pop(k)
            if peer in self._peer_want_counts:
                self._peer_want_counts[peer] = max(0, self._peer_want_counts[peer] - 1)
                if self._peer_want_counts[peer] == 0:
                    del self._peer_want_counts[peer]

        # Sweep stale rate tracking entries for peers with no pending wants (BT-R3-006)
        active_peers = {peer for _ts, peer in self._pending_wants.values()}
        for peer_key in list(self._want_serve_timestamps):
            if peer_key not in active_peers:
                # Prune timestamps; if all expired, remove the key
                cutoff = now - _WANT_RATE_WINDOW
                self._want_serve_timestamps[peer_key] = [
                    t for t in self._want_serve_timestamps[peer_key] if t > cutoff
                ]
                if not self._want_serve_timestamps[peer_key]:
                    del self._want_serve_timestamps[peer_key]
        for peer_key in list(self._outbound_bytes):
            if peer_key not in active_peers:
                cutoff = now - _BANDWIDTH_WINDOW
                self._outbound_bytes[peer_key] = [
                    (t, b) for t, b in self._outbound_bytes[peer_key] if t > cutoff
                ]
                if not self._outbound_bytes[peer_key]:
                    del self._outbound_bytes[peer_key]

    def _check_want_rate(self, peer_pubkey: str) -> bool:
        """Check per-peer WANT serving rate limit. Returns True if allowed."""
        now = time.monotonic()
        timestamps = self._want_serve_timestamps.get(peer_pubkey, [])
        cutoff = now - _WANT_RATE_WINDOW
        timestamps = [t for t in timestamps if t > cutoff]
        if len(timestamps) >= MAX_WANT_SERVES_PER_PEER:
            self._want_serve_timestamps[peer_pubkey] = timestamps
            return False
        timestamps.append(now)
        self._want_serve_timestamps[peer_pubkey] = timestamps
        return True

    def _check_outbound_bandwidth(self, peer_pubkey: str, nbytes: int) -> bool:
        """Check per-peer outbound bandwidth cap. Returns True if allowed."""
        now = time.monotonic()
        entries = self._outbound_bytes.get(peer_pubkey, [])
        cutoff = now - _BANDWIDTH_WINDOW
        entries = [(t, b) for t, b in entries if t > cutoff]
        total = sum(b for _, b in entries)
        if total + nbytes > MAX_OUTBOUND_BYTES_PER_PEER * _BANDWIDTH_WINDOW:
            self._outbound_bytes[peer_pubkey] = entries
            return False
        entries.append((now, nbytes))
        self._outbound_bytes[peer_pubkey] = entries
        return True

    async def _handle_want(self, payload: dict, conn: PeerConnection) -> None:
        """Handle a WANT message — send the requested document if we have it.

        Rate-limited per peer (B-R2-005): max MAX_WANT_SERVES_PER_PEER/sec.
        Bandwidth-capped per peer: max MAX_OUTBOUND_BYTES_PER_PEER bytes/sec.
        """
        checksum = payload.get("checksum", "")
        if not isinstance(checksum, str) or len(checksum) != 64:
            return

        # Per-peer WANT rate limit (B-R2-005)
        if not self._check_want_rate(conn.peer_pubkey):
            log.warning("WANT rate limit hit for %s, dropping", conn.peer_pubkey[:12])
            return

        if not self._cached_contains(checksum):
            not_found = make_message(NOT_FOUND, {"checksum": checksum})
            try:
                await conn.send(not_found)
            except PeerConnError:
                pass
            return

        try:
            doc = self.store.retrieve(checksum)
            doc_bytes = doc.to_bytes()

            # Per-peer outbound bandwidth cap (B-R2-005)
            if not self._check_outbound_bandwidth(conn.peer_pubkey, len(doc_bytes)):
                log.warning(
                    "Outbound bandwidth cap hit for %s, dropping WANT %s",
                    conn.peer_pubkey[:12], checksum[:12],
                )
                return

            # Encode document as base64 for JSON transport
            doc_b64 = base64.b64encode(doc_bytes).decode("ascii")

            data_msg = make_message(DATA, {
                "checksum": checksum,
                "document": doc_b64,
            })
            await conn.send(data_msg)
            # Score peer for generating a valid WANT (BT-R3-003)
            if self._score_callback:
                self._score_callback(conn.peer_pubkey, SCORE_VALID_RESPONSE)
            log.info("Sent %s to %s (%d bytes)", checksum[:12], conn.peer_pubkey[:12], len(doc_bytes))
        except Exception as e:
            log.error("Failed to send document %s: %s", checksum[:12], e)

    async def _handle_data(self, payload: dict, conn: PeerConnection) -> None:
        """Handle a DATA message — validate checksum and store the document.

        CRITICAL-5 fix: Only stores documents that are in _pending_wants.
        Drops unsolicited DATA messages.
        """
        checksum = payload.get("checksum", "")
        doc_b64 = payload.get("document", "")

        if not isinstance(checksum, str) or len(checksum) != 64:
            return

        # CRITICAL-5: Only store if we actually requested this document
        async with self._pending_lock:
            if checksum not in self._pending_wants:
                log.warning(
                    "Dropped unsolicited DATA %s from %s",
                    checksum[:12], conn.peer_pubkey[:12],
                )
                return
            _ts, peer = self._pending_wants[checksum]
            # Validate DATA source matches WANT target (C-R2-003 fix)
            if peer != conn.peer_pubkey:
                log.warning(
                    "Cross-peer DATA injection: %s sent DATA for %s's WANT %s — REJECTED",
                    conn.peer_pubkey[:12], peer[:12], checksum[:12],
                )
                return
            del self._pending_wants[checksum]
            # Decrement per-peer counter
            if peer in self._peer_want_counts:
                self._peer_want_counts[peer] = max(0, self._peer_want_counts[peer] - 1)
                if self._peer_want_counts[peer] == 0:
                    del self._peer_want_counts[peer]

        try:
            doc_bytes = base64.b64decode(doc_b64)
        except Exception as e:
            log.warning("Invalid base64 in DATA from %s: %s", conn.peer_pubkey[:12], e)
            return

        # Parse and validate
        from l3._format.reader import PFMReader
        try:
            doc = PFMReader.parse(doc_bytes)
        except Exception as e:
            log.warning("Invalid document from %s: %s", conn.peer_pubkey[:12], e)
            return

        # Fail-closed checksum validation
        computed = doc.compute_checksum()
        if computed != checksum:
            log.warning(
                "Checksum mismatch from %s: expected %s, got %s — REJECTED",
                conn.peer_pubkey[:12], checksum[:12], computed[:12],
            )
            return

        # Store it
        try:
            stored_checksum = self.store.store(doc)
            # Update cache (B-R2-004)
            self._checksum_cache.add(stored_checksum)
            # Score peer for successful delivery (BT-R3-003)
            if self._score_callback:
                self._score_callback(conn.peer_pubkey, SCORE_SUCCESSFUL_DATA)
            log.info("Stored document %s from peer %s", stored_checksum[:12], conn.peer_pubkey[:12])
        except Exception as e:
            log.error("Failed to store document %s: %s", checksum[:12], e)

    async def _handle_anchor_ann(self, payload: dict, conn: PeerConnection) -> None:
        """Handle an ANCHOR_ANN — verify before updating our index.

        CRITICAL-3 fix: Does NOT blindly trust peer-announced anchors.
        If an anchor_verifier is available, verifies against on-chain data.
        Otherwise, queues the anchor for later verification.
        """
        checksum = payload.get("checksum", "")
        txid = payload.get("txid", "")
        network = payload.get("network", "")

        if not checksum or not txid:
            return

        # Basic txid format validation (64 hex chars)
        if not isinstance(txid, str) or len(txid) != 64:
            log.warning("Rejected ANCHOR_ANN with invalid txid format from %s", conn.peer_pubkey[:12])
            return
        try:
            int(txid, 16)
        except ValueError:
            log.warning("Rejected ANCHOR_ANN with non-hex txid from %s", conn.peer_pubkey[:12])
            return

        if not self._cached_contains(checksum):
            return

        # Try to verify against on-chain data
        if self._anchor_verifier:
            try:
                verified = self._anchor_verifier(txid, checksum)
                if not verified:
                    log.warning(
                        "ANCHOR_ANN rejected: txid %s does not match checksum %s (on-chain verification failed)",
                        txid[:12], checksum[:12],
                    )
                    return
                # Verified — update index
                self.store.update_txid(checksum, txid, network)
                # Score peer for valid anchor (BT-R3-003)
                if self._score_callback:
                    self._score_callback(conn.peer_pubkey, SCORE_VALID_RESPONSE)
                log.info("Anchor verified and updated: %s -> tx %s", checksum[:12], txid[:12])
            except Exception as e:
                log.debug("Anchor verification failed, queuing: %s", e)
                self._queue_pending_anchor(checksum, txid, network, conn.peer_pubkey)
        else:
            # No verifier available — queue for later verification, do NOT trust blindly
            self._queue_pending_anchor(checksum, txid, network, conn.peer_pubkey)
            log.info(
                "Anchor queued for verification: %s -> tx %s (no verifier available)",
                checksum[:12], txid[:12],
            )

    def _queue_pending_anchor(
        self, checksum: str, txid: str, network: str, from_peer: str,
    ) -> None:
        """Queue an unverified anchor with cap and expiry.

        Queues BOTH entries for same checksum instead of replacing (C-R2-006 fix).
        This prevents attacker from overwriting legitimate anchor with fake txid.
        Dedup by (checksum, txid) pair to avoid truly redundant entries.
        """
        # Expire old entries first
        now = time.time()
        for k in list(self._pending_anchors):
            self._pending_anchors[k] = [
                a for a in self._pending_anchors[k]
                if now - a["received_at"] <= PENDING_ANCHORS_TIMEOUT
            ]
            if not self._pending_anchors[k]:
                del self._pending_anchors[k]

        entry = {
            "checksum": checksum, "txid": txid, "network": network,
            "from_peer": from_peer, "received_at": now,
        }

        # Dedup by (checksum, txid) — don't add identical announcements
        existing = self._pending_anchors.get(checksum, [])
        for a in existing:
            if a["txid"] == txid:
                return  # Already queued this exact (checksum, txid)

        # Cap check (count total entries across all checksums)
        total = sum(len(v) for v in self._pending_anchors.values())
        if total >= MAX_PENDING_ANCHORS:
            log.warning("Pending anchors cap reached (%d), dropping oldest", MAX_PENDING_ANCHORS)
            # Find and drop oldest entry across all checksums
            oldest_key = None
            oldest_time = float("inf")
            for k, entries in self._pending_anchors.items():
                for a in entries:
                    if a["received_at"] < oldest_time:
                        oldest_time = a["received_at"]
                        oldest_key = k
            if oldest_key:
                self._pending_anchors[oldest_key] = [
                    a for a in self._pending_anchors[oldest_key]
                    if a["received_at"] != oldest_time
                ]
                if not self._pending_anchors[oldest_key]:
                    del self._pending_anchors[oldest_key]

        # Max 2 entries per checksum to limit memory
        if len(existing) >= 2:
            return

        existing.append(entry)
        self._pending_anchors[checksum] = existing

    async def _handle_not_found(self, payload: dict, conn: PeerConnection) -> None:
        """Handle a NOT_FOUND — remove from pending wants only if from correct peer.

        Validates source peer matches the peer we sent the WANT to (BT-R3-001 fix).
        Without this, Peer B could send NOT_FOUND to cancel Peer A's legitimate WANTs.
        """
        checksum = payload.get("checksum", "")
        async with self._pending_lock:
            entry = self._pending_wants.get(checksum)
            if entry:
                _ts, peer = entry
                # Validate NOT_FOUND source matches WANT target (BT-R3-001)
                if peer != conn.peer_pubkey:
                    log.warning(
                        "Cross-peer NOT_FOUND injection: %s sent NOT_FOUND for %s's WANT %s — REJECTED",
                        conn.peer_pubkey[:12], peer[:12], checksum[:12],
                    )
                    return
                del self._pending_wants[checksum]
                if peer in self._peer_want_counts:
                    self._peer_want_counts[peer] = max(0, self._peer_want_counts[peer] - 1)
                    if self._peer_want_counts[peer] == 0:
                        del self._peer_want_counts[peer]
        log.debug("Peer %s does not have %s", conn.peer_pubkey[:12], checksum[:12])

    async def _handle_peers_res(self, payload: dict, conn: PeerConnection) -> None:
        """Handle a PEERS_RES — log discovered peers (connection handled by PeerManager)."""
        peers = payload.get("peers", [])
        log.debug("Received %d peers from %s", len(peers), conn.peer_pubkey[:12])

    async def register_want(self, checksum: str, peer_pubkey: str) -> None:
        """Register a pending want for a checksum from a specific peer.

        Public API for external callers (e.g. cmd_fetch) to register wants
        without accessing internal state directly (BT-R3-005 fix).
        """
        async with self._pending_lock:
            self._pending_wants[checksum] = (time.monotonic(), peer_pubkey)
            peer_count = self._peer_want_counts.get(peer_pubkey, 0)
            self._peer_want_counts[peer_pubkey] = peer_count + 1

    # --- Proactive sync ---

    # Progressive inventory disclosure limits (S-R2-004, B-R2-012)
    _INV_DISCLOSURE_NEW = 10       # new peer (score <= 1.0)
    _INV_DISCLOSURE_KNOWN = 100    # known peer (score 1.0-5.0)
    # score > 5.0: full inventory

    async def send_inventory(
        self, conn: PeerConnection, peer_score: float = 1.0,
    ) -> None:
        """Send inventory to a peer, progressively disclosed by trust score.

        New peers (score <= 1.0): max 10 checksums
        Known peers (1.0 < score <= 5.0): max 100 checksums
        Trusted peers (score > 5.0): full inventory

        Prevents full store exfiltration by throwaway Sybil peers (S-R2-004).
        """
        entries = self.store.list()
        checksums = [e["checksum"] for e in entries]

        # Progressive disclosure based on trust
        if peer_score <= 1.0:
            max_disclosure = self._INV_DISCLOSURE_NEW
        elif peer_score <= 5.0:
            max_disclosure = self._INV_DISCLOSURE_KNOWN
        else:
            max_disclosure = len(checksums)  # full

        checksums = checksums[:max_disclosure]

        # Chunk if inventory is large
        for i in range(0, len(checksums), INV_CHUNK_SIZE):
            chunk = checksums[i:i + INV_CHUNK_SIZE]
            inv_msg = make_message(INV, {"checksums": chunk})
            try:
                await conn.send(inv_msg)
            except PeerConnError:
                break

        log.info(
            "Sent inventory (%d/%d checksums, score=%.1f) to %s",
            len(checksums), len(entries), peer_score, conn.peer_pubkey[:12],
        )

    async def send_full_inventory(self, conn: PeerConnection) -> None:
        """Send our full inventory to a peer (legacy — use send_inventory for trust-gated).

        Kept for backward compatibility with tests; delegates to send_inventory
        with maximum disclosure.
        """
        await self.send_inventory(conn, peer_score=10.0)

    def get_local_checksums(self) -> list[str]:
        """Return all checksums in local store."""
        return [e["checksum"] for e in self.store.list()]

    def get_pending_anchors(self) -> list[dict]:
        """Return the flat list of all unverified pending anchors."""
        result = []
        for entries in self._pending_anchors.values():
            result.extend(entries)
        return result

    def verify_pending_anchors(self, verifier: Any) -> int:
        """Verify queued anchors against on-chain data. Returns count of verified.

        Catches L3StoreError on overwrite conflicts and discards the entry (MBK-R2-003).
        """
        from l3.store import L3StoreError
        verified_count = 0
        remaining: dict[str, list[dict]] = {}
        for checksum, entries in self._pending_anchors.items():
            keep = []
            for anchor in entries:
                try:
                    if verifier(anchor["txid"], anchor["checksum"]):
                        try:
                            self.store.update_txid(
                                anchor["checksum"], anchor["txid"], anchor["network"]
                            )
                            verified_count += 1
                            log.info("Pending anchor verified: %s -> tx %s",
                                     anchor["checksum"][:12], anchor["txid"][:12])
                        except L3StoreError:
                            # Overwrite conflict — discard, will never succeed (MBK-R2-003)
                            log.warning("Anchor overwrite conflict, discarding: %s -> tx %s",
                                        anchor["checksum"][:12], anchor["txid"][:12])
                    else:
                        log.warning("Pending anchor rejected: %s -> tx %s",
                                    anchor["checksum"][:12], anchor["txid"][:12])
                except Exception:
                    keep.append(anchor)  # Keep for retry
            if keep:
                remaining[checksum] = keep
        self._pending_anchors = remaining
        return verified_count
