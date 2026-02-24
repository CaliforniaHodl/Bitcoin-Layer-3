"""
L3 Anchor API — Anchoring-as-a-Service over HTTP.

Provides a REST API for submitting data, paying Bitcoin invoices,
and anchoring document checksums to L1 via OP_RETURN.

Zero external dependencies — stdlib only.
"""

from l3.api.server import run_api

__all__ = ["run_api"]
