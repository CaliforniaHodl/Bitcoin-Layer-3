"""
Peer manager — manages the set of active peer connections.

Handles connecting to known peers, accepting inbound connections,
deduplication by node pubkey, broadcast helpers, peer scoring,
and persistence to ~/.pfm/l3/peers.json.

Security hardening:
  - SSRF protection: validates peer hosts against private IP ranges
  - Time-windowed nonce deduplication (OrderedDict, not set eviction)
  - PEERS_REQ rate limiting and random subset response
  - Trust decay: evicts peers not seen in TRUST_DECAY_DAYS
  - Peer scores used for eviction decisions
"""

from __future__ import annotations

import asyncio
import collections
import ipaddress
import json
import logging
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from l3 import P2P_DEFAULT_PORT
from l3.p2p.connection import PeerConnection, ConnectionError as PeerConnError
from l3.p2p.protocol import (
    INV, ANCHOR_ANN, PEERS_REQ, PEERS_RES,
    make_message,
)

log = logging.getLogger(__name__)

# Connection limits
MAX_OUTBOUND = 8
MAX_INBOUND = 16

# Peer states
CONNECTING = "connecting"
HANDSHAKING = "handshaking"
ACTIVE = "active"
DISCONNECTED = "disconnected"

# Default peers file
_DEFAULT_PEERS_PATH = Path.home() / ".pfm" / "l3" / "peers.json"

# Nonce deduplication: time-windowed (MBK-009 fix)
NONCE_WINDOW_SECONDS = 600  # 10 minutes
NONCE_MAX_SIZE = 10_000

# Trust decay: evict peers not seen in this many days (B-2.1)
TRUST_DECAY_DAYS = 7

# Per-IP inbound connection limit — prevents Sybil eclipse (B-R2-001, B-R2-007)
MAX_INBOUND_PER_IP = 2

# PEERS_REQ rate limiting (S-3.2)
PEERS_REQ_COOLDOWN = 30.0  # seconds between PEERS_REQ responses per peer
MAX_PEERS_RESPONSE = 8  # max peers returned in a PEERS_RES


def _is_private_or_reserved(host: str) -> bool:
    """Check if a host is a private/reserved/loopback IP (SSRF protection).

    Resolves hostnames to IPs before checking to prevent DNS rebinding bypass.
    """
    import socket
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_reserved or addr.is_loopback
    except ValueError:
        # Not a valid IP literal — resolve hostname to IP first
        try:
            resolved = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for family, _type, _proto, _canonname, sockaddr in resolved:
                ip_str = sockaddr[0]
                addr = ipaddress.ip_address(ip_str)
                if addr.is_private or addr.is_reserved or addr.is_loopback:
                    return True
            return False
        except (socket.gaierror, OSError):
            # Cannot resolve — reject as suspicious
            return True


def _normalize_ip(ip_str: str) -> str:
    """Normalize an IP address for consistent keying (BT-R3-008).

    Maps IPv4-mapped IPv6 addresses to their IPv4 equivalent:
    e.g., '::ffff:127.0.0.1' -> '127.0.0.1'
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            return str(addr.ipv4_mapped)
        return str(addr)
    except ValueError:
        return ip_str


@dataclass
class PeerInfo:
    """Metadata about a known peer."""
    host: str
    port: int
    pubkey: str = ""
    state: str = DISCONNECTED
    last_seen: float = 0.0
    score: float = 1.0       # higher = better (fast data, reliable)
    failures: int = 0
    last_peers_req: float = 0.0  # for rate limiting PEERS_REQ
    connection: PeerConnection | None = field(default=None, repr=False)


class PeerManager:
    """Manages peer connections, routing, and deduplication.

    Usage:
        pm = PeerManager(our_pubkey="...", our_privkey=b"...",
                         our_store_size=10, on_message=handler)
        await pm.connect_to("1.2.3.4", 9735)
        await pm.broadcast_inv(["checksum1", "checksum2"])
    """

    def __init__(
        self,
        our_pubkey: str,
        our_privkey: bytes | None = None,
        our_store_size: int = 0,
        on_message: Callable[[dict, PeerConnection], Any] | None = None,
        peers_path: Path | None = None,
        max_outbound: int = MAX_OUTBOUND,
        max_inbound: int = MAX_INBOUND,
    ) -> None:
        self.our_pubkey = our_pubkey
        self.our_privkey = our_privkey
        self.our_store_size = our_store_size
        self.on_message = on_message
        self.peers_path = peers_path or _DEFAULT_PEERS_PATH
        self.max_outbound = max_outbound
        self.max_inbound = max_inbound

        # Active peer table: pubkey -> PeerInfo
        self._peers: dict[str, PeerInfo] = {}
        # Connection tasks
        self._tasks: list[asyncio.Task] = []
        # Time-windowed nonce deduplication (OrderedDict for FIFO eviction)
        self._seen_nonces: collections.OrderedDict[str, float] = collections.OrderedDict()

        # Counters
        self._outbound_count = 0
        self._inbound_count = 0
        # Per-IP inbound tracking — prevents Sybil eclipse (B-R2-001, B-R2-007)
        self._inbound_ips: dict[str, int] = {}
        # Disconnect callback for SyncEngine cleanup (MBK-R2-004, B-R2-010)
        self.on_peer_disconnect: Callable[[str], Any] | None = None

    @property
    def active_peers(self) -> list[PeerInfo]:
        """Return all peers in ACTIVE state."""
        return [p for p in self._peers.values() if p.state == ACTIVE]

    @property
    def peer_count(self) -> int:
        return len(self.active_peers)

    def _is_duplicate_nonce(self, nonce: str) -> bool:
        """Check and record a message nonce for deduplication.

        Uses time-windowed OrderedDict (MBK-009, S-5.3 fix):
        - Entries expire after NONCE_WINDOW_SECONDS
        - Oldest entries evicted first when at capacity
        """
        now = time.monotonic()

        # Expire old entries
        while self._seen_nonces:
            oldest_key, oldest_time = next(iter(self._seen_nonces.items()))
            if now - oldest_time > NONCE_WINDOW_SECONDS:
                del self._seen_nonces[oldest_key]
            else:
                break

        if nonce in self._seen_nonces:
            return True

        self._seen_nonces[nonce] = now

        # Hard cap as safety net
        while len(self._seen_nonces) > NONCE_MAX_SIZE:
            self._seen_nonces.popitem(last=False)

        return False

    async def connect_to(self, host: str, port: int) -> PeerConnection | None:
        """Initiate an outbound connection to a peer.

        Returns the PeerConnection if successful, None otherwise.
        Validates host against private IP ranges (SSRF protection).

        Single DNS resolution (BT-R3-002 fix): resolve hostname ONCE,
        check RESOLVED IP against private ranges, connect to RESOLVED IP.
        Eliminates TOCTOU from double resolution.
        """
        if self._outbound_count >= self.max_outbound:
            log.warning("Max outbound connections reached (%d)", self.max_outbound)
            return None

        # Resolve hostname to IP ONCE — single resolution, three uses (BT-R3-002)
        import socket
        resolved_host = host
        try:
            addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if addr_info:
                resolved_host = addr_info[0][4][0]
        except (socket.gaierror, OSError):
            log.warning("Cannot resolve hostname: %s", host)
            return None

        # SSRF protection: check RESOLVED IP, not original hostname (BT-R3-002)
        # This is a direct ipaddress check — no second DNS resolution
        try:
            addr = ipaddress.ip_address(resolved_host)
            if addr.is_private or addr.is_reserved or addr.is_loopback:
                log.warning(
                    "Rejected outbound connection to private IP: %s (resolved from %s)",
                    resolved_host, host,
                )
                return None
        except ValueError:
            log.warning("Resolved host is not a valid IP: %s", resolved_host)
            return None

        addr = f"{host}:{port}"
        # Check if already connected to this address
        for p in self._peers.values():
            if p.host == host and p.port == port and p.state in (CONNECTING, HANDSHAKING, ACTIVE):
                log.debug("Already connected to %s", addr)
                return p.connection

        peer_info = PeerInfo(host=host, port=port, state=CONNECTING)
        log.info("Connecting to %s (resolved: %s)", addr, resolved_host)

        try:
            # Connect to resolved IP, not hostname (DNS rebinding TOCTOU fix)
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(resolved_host, port),
                timeout=10.0,
            )
        except (OSError, asyncio.TimeoutError) as e:
            log.warning("Failed to connect to %s: %s", addr, e)
            peer_info.state = DISCONNECTED
            peer_info.failures += 1
            return None

        conn = PeerConnection(
            reader, writer,
            our_privkey=self.our_privkey,
            on_message=self._handle_message,
        )
        peer_info.connection = conn
        peer_info.state = HANDSHAKING

        try:
            await conn.handshake(self.our_pubkey, self.our_store_size)
        except PeerConnError as e:
            log.warning("Handshake failed with %s: %s", addr, e)
            peer_info.state = DISCONNECTED
            peer_info.failures += 1
            return None

        # Dedup by pubkey — reject if we already have this peer
        if conn.peer_pubkey == self.our_pubkey:
            log.debug("Rejecting self-connection")
            await conn.close()
            return None

        if conn.peer_pubkey in self._peers and self._peers[conn.peer_pubkey].state == ACTIVE:
            log.debug("Already connected to pubkey %s", conn.peer_pubkey[:12])
            await conn.close()
            return None

        peer_info.pubkey = conn.peer_pubkey
        peer_info.state = ACTIVE
        peer_info.last_seen = time.time()
        self._peers[conn.peer_pubkey] = peer_info
        self._outbound_count += 1

        # Start the connection run loop in the background
        task = asyncio.create_task(self._run_peer(conn, peer_info, outbound=True))
        task.add_done_callback(self._task_done_cleanup)
        self._tasks.append(task)

        log.info("Connected to peer %s (%s)", conn.peer_pubkey[:12], addr)
        return conn

    async def handle_inbound(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an inbound TCP connection (called by the server listener)."""
        if self._inbound_count >= self.max_inbound:
            log.warning("Max inbound connections reached, rejecting")
            writer.close()
            await writer.wait_closed()
            return

        # Per-IP limit — prevents Sybil eclipse (B-R2-001, B-R2-007)
        peer_addr = writer.get_extra_info("peername")
        source_ip = _normalize_ip(peer_addr[0]) if peer_addr else ""
        if source_ip and self._inbound_ips.get(source_ip, 0) >= MAX_INBOUND_PER_IP:
            log.warning("Per-IP inbound limit reached for %s, rejecting", source_ip)
            writer.close()
            await writer.wait_closed()
            return

        conn = PeerConnection(
            reader, writer,
            our_privkey=self.our_privkey,
            on_message=self._handle_message,
        )
        log.info("Inbound connection from %s", conn.peer_addr)

        try:
            await conn.handshake(self.our_pubkey, self.our_store_size)
        except PeerConnError as e:
            log.warning("Inbound handshake failed from %s: %s", conn.peer_addr, e)
            return

        # Dedup
        if conn.peer_pubkey == self.our_pubkey:
            await conn.close()
            return
        if conn.peer_pubkey in self._peers and self._peers[conn.peer_pubkey].state == ACTIVE:
            log.debug("Duplicate inbound from %s", conn.peer_pubkey[:12])
            await conn.close()
            return

        inbound_host = conn.peer_addr.rsplit(":", 1)[0] if conn.peer_addr else ""
        peer_info = PeerInfo(
            host=inbound_host,
            port=int(conn.peer_addr.rsplit(":", 1)[1]) if ":" in conn.peer_addr else 0,
            pubkey=conn.peer_pubkey,
            state=ACTIVE,
            last_seen=time.time(),
            connection=conn,
        )
        self._peers[conn.peer_pubkey] = peer_info
        self._inbound_count += 1
        # Track per-IP count
        if source_ip:
            self._inbound_ips[source_ip] = self._inbound_ips.get(source_ip, 0) + 1

        task = asyncio.create_task(self._run_peer(conn, peer_info, outbound=False))
        task.add_done_callback(self._task_done_cleanup)
        self._tasks.append(task)

    async def _run_peer(self, conn: PeerConnection, info: PeerInfo, outbound: bool) -> None:
        """Run a peer connection until disconnect."""
        try:
            await conn.run()
        except Exception as e:
            log.debug("Peer %s disconnected: %s", info.pubkey[:12], e)
        finally:
            info.state = DISCONNECTED
            info.connection = None
            if outbound:
                self._outbound_count = max(0, self._outbound_count - 1)
            else:
                self._inbound_count = max(0, self._inbound_count - 1)
                # Decrement per-IP count (B-R2-007)
                if info.host and info.host in self._inbound_ips:
                    self._inbound_ips[info.host] = max(0, self._inbound_ips[info.host] - 1)
                    if self._inbound_ips[info.host] == 0:
                        del self._inbound_ips[info.host]
            # Notify SyncEngine to clean up peer's wants (MBK-R2-004, B-R2-010)
            if self.on_peer_disconnect and info.pubkey:
                try:
                    result = self.on_peer_disconnect(info.pubkey)
                    if asyncio.iscoroutine(result):
                        await result
                except Exception as e:
                    log.debug("Disconnect callback error for %s: %s", info.pubkey[:12], e)
            log.info("Peer %s disconnected", info.pubkey[:12] if info.pubkey else info.host)

    def _task_done_cleanup(self, task: asyncio.Task) -> None:
        """Remove completed tasks from the task list (B-R2-006)."""
        try:
            self._tasks.remove(task)
        except ValueError:
            pass

    async def _handle_message(self, msg: dict, conn: PeerConnection) -> None:
        """Internal message handler: dedup, score, then delegate."""
        nonce = msg.get("nonce", "")
        if self._is_duplicate_nonce(nonce):
            return

        # Update last_seen (wall-clock time for persistence across reboots)
        if conn.peer_pubkey in self._peers:
            self._peers[conn.peer_pubkey].last_seen = time.time()

        # Handle peer exchange internally
        if msg["type"] == PEERS_REQ:
            await self._handle_peers_req(conn)
            return

        # Delegate to external handler
        if self.on_message:
            result = self.on_message(msg, conn)
            if asyncio.iscoroutine(result):
                await result

    async def _handle_peers_req(self, conn: PeerConnection) -> None:
        """Respond to a peer exchange request.

        Rate limited (S-3.2): max one response per PEERS_REQ_COOLDOWN seconds.
        Returns a random subset of peers (not full topology).
        """
        # Rate limit per peer
        if conn.peer_pubkey in self._peers:
            peer = self._peers[conn.peer_pubkey]
            now = time.monotonic()
            if now - peer.last_peers_req < PEERS_REQ_COOLDOWN:
                log.debug("Rate limiting PEERS_REQ from %s", conn.peer_pubkey[:12])
                return
            peer.last_peers_req = now

        candidates = []
        for p in self.active_peers:
            if p.pubkey != conn.peer_pubkey and p.host:
                candidates.append({
                    "host": p.host,
                    "port": p.port,
                    "pubkey": p.pubkey,
                })

        # Return a random subset, not the full list (S-3.2)
        if len(candidates) > MAX_PEERS_RESPONSE:
            candidates = random.sample(candidates, MAX_PEERS_RESPONSE)

        resp = make_message(PEERS_RES, {"peers": candidates})
        await conn.send(resp)

    # --- Broadcast helpers ---

    async def broadcast(self, msg: dict, exclude_pubkey: str = "") -> None:
        """Send a message to all active peers (optionally excluding one)."""
        for peer in self.active_peers:
            if peer.pubkey == exclude_pubkey:
                continue
            if peer.connection:
                try:
                    await peer.connection.send(msg)
                except PeerConnError:
                    log.debug("Failed to send to %s", peer.pubkey[:12])

    async def broadcast_inv(self, checksums: list[str]) -> None:
        """Broadcast an INV message with the given checksums."""
        if not checksums:
            return
        msg = make_message(INV, {"checksums": checksums})
        await self.broadcast(msg)

    async def broadcast_anchor(self, checksum: str, txid: str, network: str) -> None:
        """Broadcast an anchor announcement."""
        msg = make_message(ANCHOR_ANN, {
            "checksum": checksum,
            "txid": txid,
            "network": network,
        })
        await self.broadcast(msg)

    # --- Peer scoring ---

    def score_peer(self, pubkey: str, delta: float) -> None:
        """Adjust a peer's score. Positive = good, negative = bad."""
        if pubkey in self._peers:
            self._peers[pubkey].score = max(0.0, self._peers[pubkey].score + delta)

    def _evict_lowest_scored_peer(self) -> None:
        """Evict the lowest-scored active peer to make room for a better one."""
        active = self.active_peers
        if not active:
            return
        worst = min(active, key=lambda p: p.score)
        if worst.connection:
            asyncio.create_task(worst.connection.close())
        worst.state = DISCONNECTED
        worst.connection = None
        log.info("Evicted lowest-scored peer %s (score=%.1f)", worst.pubkey[:12], worst.score)

    # --- Persistence ---

    def save_peers(self) -> None:
        """Persist known peers to disk."""
        data = []
        for p in self._peers.values():
            if p.host and p.port:
                data.append({
                    "host": p.host,
                    "port": p.port,
                    "pubkey": p.pubkey,
                    "score": p.score,
                    "last_seen": p.last_seen,
                })
        self.peers_path.parent.mkdir(parents=True, exist_ok=True)
        self.peers_path.write_text(json.dumps(data, indent=2))

    def load_peers(self) -> list[dict[str, Any]]:
        """Load persisted peers from disk. Applies trust decay (B-2.1)."""
        if not self.peers_path.is_file():
            return []
        try:
            data = json.loads(self.peers_path.read_text())
            if not isinstance(data, list):
                return []
        except (json.JSONDecodeError, OSError):
            return []

        # Trust decay: filter out peers not seen in TRUST_DECAY_DAYS
        # Uses time.time() (wall-clock) so values survive reboots
        now = time.time()
        decay_threshold = TRUST_DECAY_DAYS * 86400  # days to seconds
        valid = []
        for peer in data:
            last_seen = peer.get("last_seen", 0)
            # If last_seen is 0 (never connected), keep it (manual add)
            # If last_seen is set and too old, evict
            if last_seen > 0 and (now - last_seen) > decay_threshold:
                log.debug("Trust decay: evicting stale peer %s", peer.get("pubkey", "")[:12])
                continue
            valid.append(peer)
        return valid

    # --- Shutdown ---

    async def shutdown(self) -> None:
        """Close all connections and clean up."""
        self.save_peers()

        for peer in list(self._peers.values()):
            if peer.connection:
                await peer.connection.close()

        for task in self._tasks:
            if not task.done():
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass

        self._peers.clear()
        self._tasks.clear()
        log.info("Peer manager shut down")
