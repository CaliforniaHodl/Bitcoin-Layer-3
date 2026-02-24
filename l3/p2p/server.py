"""
L3 Node server — foreground process that runs TCP listener, peer manager,
Nostr discovery, and document sync.

Start with: ``l3 node start``
"""

from __future__ import annotations

import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Any

from l3 import P2P_DEFAULT_PORT, P2P_DEFAULT_RELAYS
from l3.store import L3Store
from l3.p2p.nostr import load_or_create_key, discover_peers, publish_announcement
from l3.p2p.peer_manager import PeerManager
from l3.p2p.sync import SyncEngine

log = logging.getLogger(__name__)

# Default config
DEFAULT_CONFIG = {
    "port": P2P_DEFAULT_PORT,
    "host": "127.0.0.1",
    "relays": P2P_DEFAULT_RELAYS,
    "max_outbound": 8,
    "max_inbound": 16,
    "nostr_discovery": True,
    "discovery_interval": 300,  # seconds between Nostr discovery rounds
}


def _load_config(config_path: Path | None = None) -> dict[str, Any]:
    """Load node config from TOML file, falling back to defaults."""
    config = dict(DEFAULT_CONFIG)

    path = config_path or (Path.home() / ".pfm" / "l3" / "node.toml")
    if path.is_file():
        try:
            import tomllib
        except ImportError:
            try:
                import tomli as tomllib
            except ImportError:
                log.warning("tomllib/tomli not available, using default config")
                return config

        try:
            with open(path, "rb") as f:
                file_config = tomllib.load(f)
            config.update(file_config)
        except Exception as e:
            log.warning("Failed to load config from %s: %s", path, e)

    return config


class L3Node:
    """The main L3 P2P node. Orchestrates server, peer manager, Nostr, and sync.

    Usage:
        node = L3Node(port=9735)
        await node.start()  # runs until SIGINT/SIGTERM
    """

    def __init__(
        self,
        port: int | None = None,
        host: str | None = None,
        relays: list[str] | None = None,
        store: L3Store | None = None,
        config_path: Path | None = None,
    ) -> None:
        self._config = _load_config(config_path)
        self.port = port or self._config["port"]
        self.host = host or self._config["host"]
        self.relays = relays or self._config["relays"]
        self.store = store or L3Store()

        # Load/create node identity
        self._privkey, self.pubkey = load_or_create_key()

        # Initialize sync engine and peer manager
        self.sync_engine = SyncEngine(self.store)
        self.peer_manager = PeerManager(
            our_pubkey=self.pubkey,
            our_privkey=self._privkey,
            our_store_size=len(self.store.list()),
            on_message=self.sync_engine.handle_message,
            max_outbound=self._config["max_outbound"],
            max_inbound=self._config["max_inbound"],
        )
        # Wire disconnect callback for want cleanup (MBK-R2-004)
        self.peer_manager.on_peer_disconnect = self.sync_engine.handle_peer_disconnect
        # Wire score callback for peer progression (BT-R3-003)
        self.sync_engine._score_callback = self.peer_manager.score_peer

        self._server: asyncio.Server | None = None
        self._shutdown_event = asyncio.Event()
        self._discovery_task: asyncio.Task | None = None

    async def start(self) -> None:
        """Start the node: TCP listener, Nostr discovery, sync loop."""
        log.info("Starting L3 node %s on %s:%d", self.pubkey[:12], self.host, self.port)

        # Start TCP listener
        self._server = await asyncio.start_server(
            self.peer_manager.handle_inbound,
            self.host,
            self.port,
        )

        addrs = [str(s.getsockname()) for s in self._server.sockets]
        log.info("Listening on %s", ", ".join(addrs))

        # Install signal handlers
        loop = asyncio.get_running_loop()
        for sig_name in ("SIGINT", "SIGTERM"):
            sig = getattr(signal, sig_name, None)
            if sig:
                try:
                    loop.add_signal_handler(sig, self._signal_shutdown)
                except NotImplementedError:
                    # Windows doesn't support add_signal_handler
                    pass

        # Connect to known peers
        await self._connect_known_peers()

        # Start Nostr discovery
        if self._config["nostr_discovery"]:
            self._discovery_task = asyncio.create_task(self._discovery_loop())

        # Announce ourselves
        await self._announce()

        print(f"L3 Node started")
        print(f"  pubkey: {self.pubkey}")
        print(f"  listen: {self.host}:{self.port}")
        print(f"  store:  {len(self.store.list())} documents")
        print(f"  relays: {len(self.relays)}")
        print()

        # Wait for shutdown
        try:
            await self._shutdown_event.wait()
        except asyncio.CancelledError:
            pass
        finally:
            await self.stop()

    async def stop(self) -> None:
        """Gracefully shut down the node."""
        log.info("Shutting down L3 node...")

        if self._discovery_task and not self._discovery_task.done():
            self._discovery_task.cancel()
            try:
                await self._discovery_task
            except asyncio.CancelledError:
                pass

        await self.peer_manager.shutdown()

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        log.info("L3 node stopped")
        print("\nL3 Node stopped.")

    def _signal_shutdown(self) -> None:
        """Signal handler for graceful shutdown."""
        log.info("Received shutdown signal")
        self._shutdown_event.set()

    async def _connect_known_peers(self) -> None:
        """Connect to peers from the persisted peer list."""
        saved = self.peer_manager.load_peers()
        for peer in saved:
            host = peer.get("host", "")
            port = peer.get("port", 0)
            if host and port:
                asyncio.create_task(self._connect_and_sync(host, port))

    async def _connect_and_sync(self, host: str, port: int) -> None:
        """Connect to a peer and send our inventory (trust-gated disclosure)."""
        conn = await self.peer_manager.connect_to(host, port)
        if conn and conn.is_alive:
            # Look up peer score for progressive disclosure (S-R2-004)
            peer_score = 1.0
            if conn.peer_pubkey in self.peer_manager._peers:
                peer_score = self.peer_manager._peers[conn.peer_pubkey].score
            await self.sync_engine.send_inventory(conn, peer_score=peer_score)

    async def _announce(self) -> None:
        """Publish our node address to Nostr relays."""
        try:
            await publish_announcement(
                self._privkey,
                self.pubkey,
                self.host,
                self.port,
                checksums_count=len(self.store.list()),
                relays=self.relays,
            )
        except Exception as e:
            log.warning("Nostr announcement failed: %s", e)

    async def _discovery_loop(self) -> None:
        """Periodically discover and connect to new peers via Nostr."""
        try:
            while not self._shutdown_event.is_set():
                try:
                    peers = await discover_peers(self.relays, timeout=10.0)
                    for peer_info in peers:
                        if peer_info["pubkey"] == self.pubkey:
                            continue  # skip self
                        host = peer_info["host"]
                        port = peer_info["port"]
                        if host and port:
                            asyncio.create_task(self._connect_and_sync(host, port))
                except Exception as e:
                    log.warning("Discovery round failed: %s", e)

                # Wait for next round or shutdown
                try:
                    await asyncio.wait_for(
                        self._shutdown_event.wait(),
                        timeout=self._config["discovery_interval"],
                    )
                    break  # shutdown was signaled
                except asyncio.TimeoutError:
                    pass  # time for next round
        except asyncio.CancelledError:
            pass

    async def add_peer(self, host: str, port: int) -> bool:
        """Manually add and connect to a peer. Returns True if successful."""
        conn = await self.peer_manager.connect_to(host, port)
        if conn and conn.is_alive:
            await self.sync_engine.send_full_inventory(conn)
            return True
        return False

    def status(self) -> dict[str, Any]:
        """Return current node status."""
        return {
            "pubkey": self.pubkey,
            "host": self.host,
            "port": self.port,
            "peers": self.peer_manager.peer_count,
            "documents": len(self.store.list()),
            "relays": len(self.relays),
        }


def run_node(
    port: int | None = None,
    host: str | None = None,
    relays: list[str] | None = None,
) -> None:
    """Entry point for ``l3 node start``. Runs the node in foreground."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    node = L3Node(port=port, host=host, relays=relays)

    try:
        asyncio.run(node.start())
    except KeyboardInterrupt:
        print("\nShutting down...")
