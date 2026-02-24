"""
API key authentication for the Anchor API.

Key sources (priority order):
    1. L3_API_KEY environment variable
    2. ~/.pfm/l3/api/api_key file

Uses hmac.compare_digest() for constant-time comparison.
"""

from __future__ import annotations

import hmac
import os
from pathlib import Path


_KEY_FILE = Path.home() / ".pfm" / "l3" / "api" / "api_key"


def load_api_key() -> str:
    """Load the API key from env var or file. Returns empty string if not set."""
    key = os.environ.get("L3_API_KEY", "").strip()
    if key:
        return key
    if _KEY_FILE.is_file():
        try:
            return _KEY_FILE.read_text(encoding="utf-8").strip()
        except OSError:
            return ""
    return ""


def check_auth(auth_header: str, api_key: str) -> bool:
    """Validate a Bearer token against the configured API key.

    Returns True if auth is valid. Uses constant-time comparison.
    Returns False if api_key is empty (auth not configured — deny all).
    """
    if not api_key:
        return False
    if not auth_header:
        return False
    parts = auth_header.split(" ", 1)
    if len(parts) != 2 or parts[0] != "Bearer":
        return False
    token = parts[1].strip()
    if not token:
        return False
    return hmac.compare_digest(token, api_key)
