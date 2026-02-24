"""
TCP peer connection — handles a single peer-to-peer connection.

Wraps asyncio StreamReader/StreamWriter with the PFM3 wire protocol:
framing, challenge-response handshake, keepalive (PING/PONG), rate limiting,
and graceful close.

Security: Handshake uses challenge-response — each side proves ownership of
their claimed public key by signing a random nonce from the peer.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from typing import Any, Callable

from l3 import P2P_PROTOCOL_VERSION
from l3.p2p.protocol import (
    HANDSHAKE, HANDSHAKE_ACK, PING, PONG,
    HEADER_SIZE, ProtocolError,
    decode_header, decode_payload, encode, make_message,
)

log = logging.getLogger(__name__)

# Keepalive settings
PING_INTERVAL = 30.0    # seconds between PINGs
PONG_TIMEOUT = 90.0     # seconds to wait for PONG before disconnect

# Rate limiting — global
MAX_MESSAGES_PER_SEC = 100
_RATE_WINDOW = 1.0  # seconds

# Per-message-type rate limits (B-R2-011)
# Expensive operations get tighter limits than cheap ones
_TYPE_RATE_LIMITS: dict[str, int] = {
    "WANT": 10,       # triggers disk read + base64 + send
    "INV": 2,         # triggers N stat() calls
    "ANCHOR_ANN": 5,  # triggers verification logic
    # All other types use global limit only
}


class ConnectionError(Exception):
    """Error in peer connection."""


class PeerConnection:
    """Manages a single TCP connection to a peer.

    Usage:
        conn = PeerConnection(reader, writer, our_privkey=key, on_message=handler)
        await conn.handshake(our_pubkey, our_store_size)
        await conn.run()  # blocks until disconnect
    """

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        our_privkey: bytes | None = None,
        on_message: Callable[[dict, "PeerConnection"], Any] | None = None,
    ) -> None:
        self.reader = reader
        self.writer = writer
        self.our_privkey = our_privkey
        self.on_message = on_message

        # Peer identity (set during handshake)
        self.peer_pubkey: str = ""
        self.peer_version: str = ""
        self.peer_store_size: int = 0
        self.peer_addr: str = ""

        # State
        self.handshake_done = False
        self._closed = False
        self._last_pong: float = time.monotonic()
        self._msg_timestamps: list[float] = []
        # Per-type rate limit tracking (B-R2-011)
        self._type_timestamps: dict[str, list[float]] = {}
        self._ping_task: asyncio.Task | None = None

        # Set peer address from writer
        try:
            addr = writer.get_extra_info("peername")
            if addr:
                self.peer_addr = f"{addr[0]}:{addr[1]}"
        except Exception:
            pass

    @property
    def is_alive(self) -> bool:
        return self.handshake_done and not self._closed

    async def send(self, msg: dict) -> None:
        """Serialize and send a message over the wire."""
        if self._closed:
            raise ConnectionError("Connection closed")
        try:
            data = encode(msg)
            self.writer.write(data)
            await self.writer.drain()
        except (OSError, asyncio.IncompleteReadError) as e:
            await self.close()
            raise ConnectionError(f"Send failed: {e}") from e

    async def recv(self) -> dict:
        """Read and decode the next message from the wire.

        Rate limit is checked BEFORE reading the full payload to prevent
        resource exhaustion from oversized messages.
        """
        if self._closed:
            raise ConnectionError("Connection closed")
        try:
            # Check rate limit BEFORE reading payload (MBK-015 fix)
            self._check_rate_limit()

            # Read header
            header_data = await self.reader.readexactly(HEADER_SIZE)
            payload_len = decode_header(header_data)

            # Read payload
            payload_data = await self.reader.readexactly(payload_len)
            msg = decode_payload(payload_data)

            return msg

        except asyncio.IncompleteReadError:
            await self.close()
            raise ConnectionError("Peer disconnected")
        except ProtocolError as e:
            await self.close()
            raise ConnectionError(f"Protocol error: {e}") from e

    def _check_rate_limit(self) -> None:
        """Track message rate; raise if peer exceeds global limit."""
        now = time.monotonic()
        self._msg_timestamps.append(now)
        # Prune old timestamps
        cutoff = now - _RATE_WINDOW
        self._msg_timestamps = [t for t in self._msg_timestamps if t > cutoff]
        if len(self._msg_timestamps) > MAX_MESSAGES_PER_SEC:
            raise ProtocolError(
                f"Rate limit exceeded: {len(self._msg_timestamps)} msgs/sec"
            )

    def _check_type_rate_limit(self, msg_type: str) -> bool:
        """Check per-message-type rate limit (B-R2-011). Returns False if over limit."""
        limit = _TYPE_RATE_LIMITS.get(msg_type)
        if limit is None:
            return True  # No per-type limit for this type
        now = time.monotonic()
        timestamps = self._type_timestamps.get(msg_type, [])
        cutoff = now - _RATE_WINDOW
        timestamps = [t for t in timestamps if t > cutoff]
        if len(timestamps) >= limit:
            self._type_timestamps[msg_type] = timestamps
            return False
        timestamps.append(now)
        self._type_timestamps[msg_type] = timestamps
        return True

    async def handshake(self, our_pubkey: str, our_store_size: int) -> None:
        """Perform challenge-response handshake. Must be called before run().

        Protocol:
            1. Send HANDSHAKE with our identity + random challenge nonce
            2. Receive peer HANDSHAKE with their identity + their challenge
            3. Sign their challenge with our privkey, send HANDSHAKE_ACK
            4. Receive their HANDSHAKE_ACK with their sig of our challenge
            5. Verify their signature against their claimed pubkey

        This proves both sides own the private key for their claimed pubkey.
        """
        # Generate a 32-byte random challenge
        our_challenge = os.urandom(32).hex()

        # Send our handshake with challenge
        hs_msg = make_message(HANDSHAKE, {
            "node_pubkey": our_pubkey,
            "version": P2P_PROTOCOL_VERSION,
            "store_size": our_store_size,
            "challenge": our_challenge,
        })
        await self.send(hs_msg)

        # Receive peer handshake
        try:
            peer_msg = await asyncio.wait_for(self.recv(), timeout=10.0)
        except asyncio.TimeoutError:
            await self.close()
            raise ConnectionError("Handshake timeout")

        if peer_msg["type"] != HANDSHAKE:
            await self.close()
            raise ConnectionError(f"Expected HANDSHAKE, got {peer_msg['type']}")

        payload = peer_msg["payload"]
        self.peer_pubkey = payload["node_pubkey"]
        self.peer_version = payload["version"]
        self.peer_store_size = payload["store_size"]
        peer_challenge = payload["challenge"]

        # Sign their challenge with our private key — FAIL CLOSED if no key
        if not self.our_privkey:
            await self.close()
            raise ConnectionError(
                "Cannot handshake: no private key. All P2P operations require a node identity key."
            )
        from l3.p2p.nostr import _sign_event_hash
        import hashlib
        challenge_hash = hashlib.sha256(bytes.fromhex(peer_challenge)).digest()
        our_sig = _sign_event_hash(challenge_hash, self.our_privkey)

        # Send our challenge response
        ack_msg = make_message(HANDSHAKE_ACK, {"challenge_sig": our_sig})
        await self.send(ack_msg)

        # Receive their challenge response
        try:
            peer_ack = await asyncio.wait_for(self.recv(), timeout=10.0)
        except asyncio.TimeoutError:
            await self.close()
            raise ConnectionError("Handshake ACK timeout")

        if peer_ack["type"] != HANDSHAKE_ACK:
            await self.close()
            raise ConnectionError(f"Expected HANDSHAKE_ACK, got {peer_ack['type']}")

        # Verify their signature proves ownership of claimed pubkey — ALWAYS verify
        from l3.p2p.nostr import _verify_schnorr
        our_challenge_hash = hashlib.sha256(bytes.fromhex(our_challenge)).digest()
        peer_sig = bytes.fromhex(peer_ack["payload"]["challenge_sig"])
        peer_pubkey_bytes = bytes.fromhex(self.peer_pubkey)

        if not _verify_schnorr(peer_pubkey_bytes, our_challenge_hash, peer_sig):
            await self.close()
            raise ConnectionError(
                f"Challenge-response verification failed for {self.peer_pubkey[:12]}"
            )

        self.handshake_done = True

        log.info(
            "Handshake OK with %s (store=%d, version=%s, challenge-response verified)",
            self.peer_pubkey[:12], self.peer_store_size, self.peer_version,
        )

    async def run(self) -> None:
        """Main loop: read messages, dispatch to handler, manage keepalive.

        Blocks until the connection is closed.
        """
        if not self.handshake_done:
            raise ConnectionError("Must complete handshake before run()")

        self._ping_task = asyncio.create_task(self._keepalive_loop())

        try:
            while not self._closed:
                try:
                    msg = await asyncio.wait_for(self.recv(), timeout=PONG_TIMEOUT)
                except asyncio.TimeoutError:
                    log.warning("Peer %s timed out", self.peer_addr)
                    break
                except ConnectionError:
                    break

                msg_type = msg["type"]

                # Per-type rate limit check (B-R2-011)
                if not self._check_type_rate_limit(msg_type):
                    log.debug("Type rate limit hit for %s from %s", msg_type, self.peer_addr)
                    continue

                if msg_type == PING:
                    pong = make_message(PONG)
                    await self.send(pong)
                elif msg_type == PONG:
                    self._last_pong = time.monotonic()
                elif self.on_message:
                    try:
                        result = self.on_message(msg, self)
                        if asyncio.iscoroutine(result):
                            await result
                    except Exception as e:
                        log.error("Handler error for %s: %s", msg_type, e)
        finally:
            await self.close()

    async def _keepalive_loop(self) -> None:
        """Periodically send PING messages."""
        try:
            while not self._closed:
                await asyncio.sleep(PING_INTERVAL)
                if self._closed:
                    break

                # Check if we've heard from the peer recently
                if time.monotonic() - self._last_pong > PONG_TIMEOUT:
                    log.warning("Peer %s pong timeout", self.peer_addr)
                    await self.close()
                    break

                try:
                    ping = make_message(PING)
                    await self.send(ping)
                except ConnectionError:
                    break
        except asyncio.CancelledError:
            pass

    async def close(self) -> None:
        """Gracefully close the connection."""
        if self._closed:
            return
        self._closed = True

        if self._ping_task and not self._ping_task.done():
            self._ping_task.cancel()
            try:
                await self._ping_task
            except asyncio.CancelledError:
                pass

        try:
            self.writer.close()
            await self.writer.wait_closed()
        except Exception:
            pass

        log.info("Closed connection to %s", self.peer_addr or "unknown")
