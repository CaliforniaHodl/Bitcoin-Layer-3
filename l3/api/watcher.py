"""
PaymentWatcher — background daemon thread that polls for payments and triggers anchoring.

Poll loop:
    1. Check pending_payment invoices for expiry or payment arrival
    2. Process paid invoices: anchor document to L1 via OP_RETURN

Uses existing anchor_document() and L3Store — zero duplication.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any

from l3 import API_POLL_INTERVAL_SECS

logger = logging.getLogger(__name__)


class PaymentWatcher:
    """Background daemon thread that watches for payments and anchors documents.

    Usage:
        watcher = PaymentWatcher(rpc, store, invoices)
        watcher.start()
        # ... later ...
        watcher.stop()
    """

    def __init__(
        self,
        rpc: Any,
        store: Any,
        invoices: Any,
        poll_interval: int = API_POLL_INTERVAL_SECS,
    ) -> None:
        self._rpc = rpc
        self._store = store
        self._invoices = invoices
        self._poll_interval = poll_interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Start the watcher daemon thread."""
        if self.is_running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name="payment-watcher", daemon=True
        )
        self._thread.start()
        logger.info("PaymentWatcher started (poll interval: %ds)", self._poll_interval)

    def stop(self) -> None:
        """Signal the watcher to stop."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None
        logger.info("PaymentWatcher stopped")

    def _run(self) -> None:
        """Main poll loop."""
        while not self._stop_event.is_set():
            try:
                self._check_payments()
                self._process_paid()
            except Exception:
                logger.exception("PaymentWatcher poll error")
            self._stop_event.wait(self._poll_interval)

    def _check_payments(self) -> None:
        """Check pending_payment invoices for expiry or payment arrival."""
        now = datetime.now(timezone.utc)

        for inv in self._invoices.list_by_status("pending_payment"):
            # Check expiry
            try:
                expires = datetime.fromisoformat(inv.expires_at)
                if now >= expires:
                    try:
                        self._invoices.transition(inv.anchor_id, "expired")
                        logger.info("Invoice %s expired", inv.anchor_id)
                    except Exception:
                        logger.exception("Failed to expire invoice %s", inv.anchor_id)
                    continue
            except (ValueError, TypeError):
                pass  # Malformed expiry — skip expiry check

            # Check for payment (0-conf)
            try:
                received = self._rpc.call(
                    "getreceivedbyaddress", inv.address, 0
                )
                # received is in BTC, convert to sats for comparison
                received_sats = int(float(received) * 100_000_000)
                if received_sats >= inv.amount_sats:
                    self._invoices.transition(inv.anchor_id, "paid")
                    logger.info(
                        "Invoice %s paid (%d sats received)",
                        inv.anchor_id, received_sats,
                    )
            except Exception:
                logger.debug(
                    "Failed to check payment for invoice %s", inv.anchor_id
                )

    def _process_paid(self) -> None:
        """Process paid invoices: anchor to L1."""
        from l3.anchor import anchor_document

        for inv in self._invoices.list_by_status("paid"):
            try:
                self._invoices.transition(inv.anchor_id, "anchoring")
            except Exception:
                logger.exception(
                    "Failed to transition invoice %s to anchoring", inv.anchor_id
                )
                continue

            try:
                # Retrieve the PFM document from L3 store
                doc = self._store.retrieve(inv.checksum)

                # Anchor to L1 using existing anchor.py logic
                txid = anchor_document(doc, self._rpc)

                # Update L3 index with txid
                network = self._rpc.get_network()
                self._store.update_txid(inv.checksum, txid, network, force=True)

                # Record txid on invoice and mark confirmed
                self._invoices.set_l1_txid(inv.anchor_id, txid)
                self._invoices.transition(inv.anchor_id, "confirmed")
                logger.info(
                    "Invoice %s anchored: txid=%s", inv.anchor_id, txid[:16]
                )
            except Exception:
                logger.exception(
                    "Failed to anchor invoice %s", inv.anchor_id
                )
                try:
                    self._invoices.transition(inv.anchor_id, "failed")
                except Exception:
                    logger.exception(
                        "Failed to mark invoice %s as failed", inv.anchor_id
                    )
