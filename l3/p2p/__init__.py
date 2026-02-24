"""
L3 P2P Networking — peer discovery, document sync, and relay communication.

Optional layer: requires ``pip install bitcoin-l3[p2p]`` for websockets + secp256k1.
The core ``l3`` package remains zero-dependency.

Modules:
    protocol        — Wire protocol: message types, framing, validation
    nostr           — Nostr event signing, relay communication, peer discovery
    connection      — Single peer TCP connection handler
    peer_manager    — Manage peer connections, routing, deduplication
    sync            — Document sync logic (inventory exchange, data transfer)
    server          — TCP listener + main event loop (foreground node)
"""

from l3 import P2P_PROTOCOL_VERSION, P2P_DEFAULT_PORT

__all__ = [
    "P2P_PROTOCOL_VERSION",
    "P2P_DEFAULT_PORT",
]
