"""
Nostr integration — key management, event signing, relay communication, peer discovery.

Requires secp256k1 (C bindings) for Schnorr signing. Will raise ImportError
if the library is unavailable — install with: pip install bitcoin-l3[p2p]

Node identity = Nostr public key (hex).
Peer discovery via custom event kind 30078 with tag ["d", "pfm3-node"].
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import stat
import time
from pathlib import Path
from typing import Any

from l3 import P2P_DEFAULT_RELAYS

log = logging.getLogger(__name__)

# Nostr event kind for application-specific data (NIP-78)
EVENT_KIND = 30078
DTAG = "pfm3-node"

# Default key file location
_DEFAULT_KEY_PATH = Path.home() / ".pfm" / "l3" / "node_key"


# ---------------------------------------------------------------------------
# Secp256k1 helpers — NO FALLBACK. secp256k1 is REQUIRED.
# ---------------------------------------------------------------------------

def _import_secp256k1():
    """Import secp256k1 C bindings. Raises ImportError if unavailable."""
    try:
        import secp256k1
        return secp256k1
    except ImportError:
        raise ImportError(
            "secp256k1 is required for P2P identity and signing. "
            "Install with: pip install bitcoin-l3[p2p]"
        )


def _generate_privkey() -> bytes:
    """Generate a 32-byte random private key."""
    return os.urandom(32)


def _privkey_to_pubkey(privkey: bytes) -> bytes:
    """Derive the x-only (32-byte) public key from a private key.

    Requires secp256k1 C bindings — raises ImportError if unavailable.
    """
    lib = _import_secp256k1()
    pk = lib.PrivateKey(privkey)
    # x-only pubkey: strip the 02/03 prefix byte
    full = pk.pubkey.serialize(compressed=True)
    return full[1:]  # 32 bytes (x-coordinate only)


def _sign_event_hash(event_hash: bytes, privkey: bytes) -> str:
    """Sign a 32-byte event hash with the private key.

    Returns the signature as 128-char hex string.
    Requires secp256k1 — raises ImportError if unavailable.
    """
    lib = _import_secp256k1()
    pk = lib.PrivateKey(privkey)
    sig = pk.schnorr_sign(event_hash, bip340tag=None, raw=True)
    return sig.hex()


def _verify_schnorr(pubkey_bytes: bytes, msg_hash: bytes, sig_bytes: bytes) -> bool:
    """Verify a Schnorr signature against a public key.

    Returns True if valid, False otherwise.
    """
    lib = _import_secp256k1()
    try:
        # Reconstruct the compressed pubkey (add 02 prefix for x-only)
        compressed = b"\x02" + pubkey_bytes
        pk = lib.PublicKey(compressed, raw=True)
        return pk.schnorr_verify(msg_hash, sig_bytes, bip340tag=None, raw=True)
    except Exception:
        return False


def verify_event_signature(event: dict) -> bool:
    """Verify a Nostr event's Schnorr signature.

    Recomputes the event ID and checks the signature against the pubkey.
    Returns True if valid, False otherwise.
    """
    try:
        pubkey_hex = event.get("pubkey", "")
        sig_hex = event.get("sig", "")
        if not pubkey_hex or not sig_hex or len(sig_hex) != 128:
            return False

        # Recompute the event ID
        expected_id = _compute_event_id(
            pubkey_hex,
            event["created_at"],
            event["kind"],
            event["tags"],
            event["content"],
        )

        # Verify event ID matches
        if expected_id != event.get("id", ""):
            return False

        # Verify the signature
        pubkey_bytes = bytes.fromhex(pubkey_hex)
        msg_hash = bytes.fromhex(expected_id)
        sig_bytes = bytes.fromhex(sig_hex)
        return _verify_schnorr(pubkey_bytes, msg_hash, sig_bytes)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------

def load_or_create_key(key_path: Path | None = None) -> tuple[bytes, str]:
    """Load or generate the node's secp256k1 keypair.

    Returns (privkey_bytes, pubkey_hex).
    Key file is stored as hex at ``~/.pfm/l3/node_key`` with mode 600.
    """
    path = key_path or _DEFAULT_KEY_PATH
    path = Path(path)

    if path.is_file():
        hex_key = path.read_text().strip()
        privkey = bytes.fromhex(hex_key)
    else:
        privkey = _generate_privkey()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(privkey.hex())
        try:
            path.chmod(0o600)
        except OSError:
            pass  # Windows may not support chmod 600

    pubkey = _privkey_to_pubkey(privkey)
    return privkey, pubkey.hex()


# ---------------------------------------------------------------------------
# Nostr event creation
# ---------------------------------------------------------------------------

def _compute_event_id(
    pubkey_hex: str,
    created_at: int,
    kind: int,
    tags: list,
    content: str,
) -> str:
    """Compute the Nostr event ID (SHA-256 of the serialized event array)."""
    serialized = json.dumps(
        [0, pubkey_hex, created_at, kind, tags, content],
        separators=(",", ":"),
    )
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def create_discovery_event(
    privkey: bytes,
    pubkey_hex: str,
    host: str,
    port: int,
    checksums_count: int = 0,
    version: str = "1.0",
) -> dict[str, Any]:
    """Create a Nostr event announcing this node's TCP address for peer discovery.

    Returns a signed Nostr event dict ready to send to relays.
    """
    created_at = int(time.time())
    content = json.dumps({
        "host": host,
        "port": port,
        "version": version,
        "checksums_count": checksums_count,
    }, separators=(",", ":"))

    tags = [["d", DTAG]]

    event_id = _compute_event_id(pubkey_hex, created_at, EVENT_KIND, tags, content)
    sig = _sign_event_hash(bytes.fromhex(event_id), privkey)

    return {
        "id": event_id,
        "pubkey": pubkey_hex,
        "created_at": created_at,
        "kind": EVENT_KIND,
        "tags": tags,
        "content": content,
        "sig": sig,
    }


def _is_private_ip(host: str) -> bool:
    """Check if a host is a private/reserved IP address (SSRF protection).

    Resolves hostnames to IPs before checking to prevent DNS rebinding bypass.
    """
    import socket
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_reserved or addr.is_loopback
    except ValueError:
        # Not a valid IP literal — resolve hostname first
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


def parse_discovery_event(event: dict) -> dict[str, Any] | None:
    """Parse a discovery event to extract host/port/version.

    Returns None if the event isn't a valid pfm3-node announcement.
    Verifies the Nostr event Schnorr signature before trusting content.
    Rejects hosts pointing to private/reserved IP addresses (SSRF).
    """
    if event.get("kind") != EVENT_KIND:
        return None

    tags = event.get("tags", [])
    has_dtag = any(t[0] == "d" and t[1] == DTAG for t in tags if len(t) >= 2)
    if not has_dtag:
        return None

    # CRITICAL-6: Verify Nostr event signature before trusting content
    if not verify_event_signature(event):
        log.warning(
            "Rejected discovery event with invalid signature from %s",
            event.get("pubkey", "unknown")[:12],
        )
        return None

    try:
        info = json.loads(event.get("content", ""))
    except (json.JSONDecodeError, TypeError):
        return None

    if not isinstance(info, dict) or "host" not in info or "port" not in info:
        return None

    host = info["host"]

    # SSRF protection: reject private/reserved IPs from discovery
    if _is_private_ip(host):
        log.warning("Rejected discovery event with private IP: %s", host)
        return None

    return {
        "pubkey": event.get("pubkey", ""),
        "host": host,
        "port": int(info["port"]),
        "version": info.get("version", ""),
        "checksums_count": info.get("checksums_count", 0),
    }


# ---------------------------------------------------------------------------
# Relay communication
# ---------------------------------------------------------------------------

class NostrRelay:
    """Async Nostr relay client via websockets."""

    def __init__(self, url: str) -> None:
        self.url = url
        self._ws = None

    async def connect(self) -> None:
        """Connect to the relay."""
        try:
            import websockets
        except ImportError:
            raise ImportError(
                "websockets is required for Nostr relay communication. "
                "Install with: pip install bitcoin-l3[p2p]"
            )
        self._ws = await websockets.connect(self.url)
        log.info("Connected to relay %s", self.url)

    async def close(self) -> None:
        if self._ws:
            await self._ws.close()
            self._ws = None

    async def publish(self, event: dict) -> None:
        """Publish an event to the relay."""
        if not self._ws:
            raise RuntimeError("Not connected to relay")
        msg = json.dumps(["EVENT", event])
        await self._ws.send(msg)
        log.debug("Published event %s to %s", event.get("id", "")[:12], self.url)

    async def subscribe(self, sub_id: str, filters: dict) -> None:
        """Subscribe to events matching the given filters."""
        if not self._ws:
            raise RuntimeError("Not connected to relay")
        msg = json.dumps(["REQ", sub_id, filters])
        await self._ws.send(msg)
        log.debug("Subscribed %s on %s", sub_id, self.url)

    async def receive(self) -> list:
        """Receive the next message from the relay. Returns parsed JSON array."""
        if not self._ws:
            raise RuntimeError("Not connected to relay")
        raw = await self._ws.recv()
        return json.loads(raw)


async def discover_peers(
    relays: list[str] | None = None,
    timeout: float = 10.0,
) -> list[dict[str, Any]]:
    """Discover L3 peers from Nostr relays.

    Connects to each relay, subscribes to pfm3-node events, collects
    announcements for ``timeout`` seconds, then returns unique peers.

    Returns list of dicts with keys: pubkey, host, port, version, checksums_count.
    """
    relay_urls = relays or P2P_DEFAULT_RELAYS
    peers: dict[str, dict] = {}  # keyed by pubkey for dedup

    async def _query_relay(url: str) -> None:
        relay = NostrRelay(url)
        try:
            await relay.connect()
            await relay.subscribe("pfm3-discover", {
                "kinds": [EVENT_KIND],
                "#d": [DTAG],
            })

            deadline = asyncio.get_event_loop().time() + timeout
            while asyncio.get_event_loop().time() < deadline:
                try:
                    msg = await asyncio.wait_for(
                        relay.receive(),
                        timeout=max(0.1, deadline - asyncio.get_event_loop().time()),
                    )
                except asyncio.TimeoutError:
                    break

                if isinstance(msg, list) and len(msg) >= 3 and msg[0] == "EVENT":
                    info = parse_discovery_event(msg[2])
                    if info and info["pubkey"]:
                        peers[info["pubkey"]] = info
                elif isinstance(msg, list) and msg[0] == "EOSE":
                    break  # End of stored events
        except Exception as e:
            log.warning("Relay %s error: %s", url, e)
        finally:
            await relay.close()

    tasks = [_query_relay(url) for url in relay_urls]
    await asyncio.gather(*tasks, return_exceptions=True)

    return list(peers.values())


async def publish_announcement(
    privkey: bytes,
    pubkey_hex: str,
    host: str,
    port: int,
    checksums_count: int = 0,
    relays: list[str] | None = None,
) -> None:
    """Publish this node's address to Nostr relays."""
    relay_urls = relays or P2P_DEFAULT_RELAYS
    event = create_discovery_event(privkey, pubkey_hex, host, port, checksums_count)

    for url in relay_urls:
        relay = NostrRelay(url)
        try:
            await relay.connect()
            await relay.publish(event)
            log.info("Announced to %s", url)
        except Exception as e:
            log.warning("Failed to announce to %s: %s", url, e)
        finally:
            await relay.close()
