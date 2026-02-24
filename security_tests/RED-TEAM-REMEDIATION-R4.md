# Red Team Remediation Report — Round 4
**Date:** 2026-02-24
**Project:** bitcoin-l3
**Scope:** l3/p2p/sync.py, l3/p2p/peer_manager.py, l3/p2p/server.py, l3/cli.py, tests/test_p2p.py
**Trigger:** BLACK-TEAM-REATTACK-R3-REPORT.md — 3 MEDIUM + 4 LOW findings

---

## Summary

All 7 findings from the Black Team Round 3 re-attack have been remediated:
- 3 MEDIUM (immediate priority): all fixed
- 4 LOW (before-beta): all fixed
- 10 new tests added, 147 total passing (11 skipped), 0 regressions

---

## Fixes Applied

### FIX-R4-1: Cross-Peer NOT_FOUND Source Validation
**Finding:** BT-R3-001 (MEDIUM)
**File:** `l3/p2p/sync.py:475-499`

**Problem:** `_handle_not_found` removed a checksum from `_pending_wants` without verifying the NOT_FOUND came from the peer the WANT was sent to. Peer B could cancel Peer A's legitimate WANTs.

**Fix:** Added `peer != conn.peer_pubkey` validation in `_handle_not_found`, identical to the DATA source validation pattern from R3-6. The method now uses `.get()` instead of `.pop()`, checks the stored peer, and only removes the entry if the source matches.

**Evidence:**
- `test_not_found_source_validation` — NOT_FOUND from wrong peer is rejected, want preserved
- `test_not_found_correct_peer_accepted` — NOT_FOUND from correct peer is accepted

### FIX-R4-2: Single DNS Resolution — SSRF TOCTOU Eliminated
**Finding:** BT-R3-002 (MEDIUM)
**File:** `l3/p2p/peer_manager.py:184-223`

**Problem:** `connect_to()` resolved the hostname twice: once inside `_is_private_or_reserved()` for the SSRF check, and again via `socket.getaddrinfo()` for connection. A DNS TTL=0 record could resolve to a public IP during check, then to `127.0.0.1` during connect.

**Fix:** Restructured `connect_to()` to:
1. Resolve hostname via `getaddrinfo()` ONCE at the top
2. Check the RESOLVED IP using `ipaddress.ip_address()` directly (no second DNS lookup)
3. Connect to the resolved IP

The `_is_private_or_reserved()` function is no longer called in `connect_to()`. Instead, `ipaddress.ip_address()` is used directly on the resolved IP, eliminating all TOCTOU risk. Resolution failure now returns `None` instead of falling back to the original hostname.

**Evidence:**
- `test_single_dns_resolution_ssrf` — design verification
- `test_ssrf_protection` — existing test still passes (validates IP checks)

### FIX-R4-3: Peer Score Progression
**Finding:** BT-R3-003 (MEDIUM)
**File:** `l3/p2p/sync.py`, `l3/p2p/server.py`

**Problem:** `score_peer()` existed in PeerManager but was never called. All peers remained at default score 1.0 permanently, meaning progressive disclosure permanently limited every peer to 10 checksums.

**Fix:**
- Added `_score_callback` attribute to SyncEngine (optional callable)
- Added score constants: `SCORE_SUCCESSFUL_DATA = 0.5`, `SCORE_VALID_RESPONSE = 0.1`
- Wired `_score_callback = peer_manager.score_peer` in L3Node constructor
- Score increments added in:
  - `_handle_data` (successful store): +0.5
  - `_handle_want` (successful serve): +0.1
  - `_handle_anchor_ann` (verified anchor): +0.1

**Score progression example:** A peer that delivers 8 documents and serves 10 WANTs would reach score 1.0 + (8 * 0.5) + (10 * 0.1) = 6.0, unlocking full inventory disclosure.

**Evidence:**
- `test_score_callback_attribute` — attribute exists, constants correct
- `test_score_progression_on_data` — callback fired with correct delta on DATA
- `test_score_callback_wired_in_server` — wiring present in L3Node constructor

### FIX-R4-4: `register_want()` Public Method
**Finding:** BT-R3-005 (LOW)
**File:** `l3/p2p/sync.py:500-511`, `l3/cli.py:384-386`

**Problem:** `cmd_fetch` directly accessed `sync_engine._pending_lock`, `sync_engine._pending_wants`, and `sync_engine._peer_want_counts`. Fragile coupling — internal changes break cmd_fetch silently.

**Fix:** Added `SyncEngine.register_want(checksum, peer_pubkey)` public async method. Updated `cmd_fetch` to call `await sync_engine.register_want(checksum, conn.peer_pubkey)` instead of manipulating internals.

**Evidence:**
- `test_register_want_public_method` — registers correctly via public API

### FIX-R4-5: Rate Tracking Dict Cleanup
**Finding:** BT-R3-006 (LOW)
**File:** `l3/p2p/sync.py:212-243`

**Problem:** `_want_serve_timestamps` and `_outbound_bytes` grew one key per unique peer. Keys for disconnected peers with expired timestamps persisted forever.

**Fix:** Extended `_expire_pending_wants()` to sweep stale entries from rate tracking dicts. Peers with no active pending wants have their rate tracking entries pruned if all timestamps are expired. Empty dicts are deleted entirely.

**Evidence:**
- `test_expire_sweeps_rate_tracking` — stale entries cleaned after expiry

### FIX-R4-6: Cache Pre-loaded at Construction
**Finding:** BT-R3-007 (LOW)
**File:** `l3/p2p/sync.py:83-85`

**Problem:** `_ensure_cache()` lazy-loaded from `store.list()` on the first INV, blocking the event loop for the duration of disk I/O. For large stores, this caused 50-100ms stalls.

**Fix:** Pre-load cache eagerly in `__init__`:
```python
self._checksum_cache: set[str] = {e["checksum"] for e in store.list()}
self._cache_loaded = True
```
This runs at construction time before the event loop accepts connections, so it blocks startup (acceptable) instead of blocking message handling (unacceptable).

**Evidence:**
- `test_cache_preloaded_at_construction` — cache loaded and populated before first use

### FIX-R4-7: IPv4-Mapped IPv6 Normalization
**Finding:** BT-R3-008 (LOW)
**File:** `l3/p2p/peer_manager.py:91-102, 299`

**Problem:** Per-IP inbound limit keyed on exact IP string. Same host connecting as `127.0.0.1` (IPv4) and `::ffff:127.0.0.1` (IPv6) got 2+2=4 connections.

**Fix:** Added `_normalize_ip()` helper that maps IPv4-mapped IPv6 addresses to their IPv4 equivalent using `ipaddress.IPv6Address.ipv4_mapped`. Applied at the `handle_inbound()` keying point before checking `_inbound_ips`.

**Evidence:**
- `test_ipv6_normalization` — all mapping cases verified

---

## Files Modified

| File | Changes |
|------|---------|
| `l3/p2p/sync.py` | FIX-R4-1 (NOT_FOUND validation), R4-3 (score callback + increments), R4-4 (register_want), R4-5 (rate tracking sweep), R4-6 (cache pre-load) |
| `l3/p2p/peer_manager.py` | FIX-R4-2 (single DNS resolution), R4-7 (_normalize_ip + usage) |
| `l3/p2p/server.py` | FIX-R4-3 (wire _score_callback) |
| `l3/cli.py` | FIX-R4-4 (use register_want) |
| `tests/test_p2p.py` | 10 new tests for all R4 fixes |

## Test Results

```
147 passed, 11 skipped, 0 failed (5.77s)
```

- 10 new R4 security tests
- 11 skipped (secp256k1 C bindings not installed)
- 0 regressions

---

## Cumulative Security Posture

| Round | Fixes | Status |
|-------|-------|--------|
| R1 (CRITICALs) | 7 | All DEAD |
| R2 (HIGHs + MEDIUMs) | 16 | All DEAD |
| R3 (MEDIUMs + LOWs) | 13 | All DEAD |
| R4 (MEDIUMs + LOWs) | 7 | All DEAD |
| **Total fixes** | **43** | **All verified** |

## Remaining Deferred Items (Unchanged)

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| MBK-006 / S-NEW-001 | No TLS on TCP | HIGH | DEFERRED |
| MBK-011 | Node key plaintext on disk | HIGH | DEFERRED |
| S-R2-003 | Handshake MITM (no channel binding) | MEDIUM | DEFERRED |
| C-R2-005 | update_txid TOCTOU race (file locking) | MEDIUM | DEFERRED |
| C-NEW-004 | anchor_verifier not wired | MEDIUM | DEFERRED |
| MBK-NEW-005 / S-009 | Rate limiter bypass (connection cycling) | MEDIUM | DEFERRED |
| S-007 | Sybil eclipse via legitimate Nostr | MEDIUM | DEFERRED |
| S-004 | Topology exfiltration via Sybil | MEDIUM | DEFERRED |
| MBK-008 | index.json TOCTOU race | MEDIUM | DEFERRED |
| MBK-NEW-004 | No version negotiation | LOW | DEFERRED |
| B-NEW-004 | Rate limiter lacks reconnect ban | LOW | DEFERRED |

---

*Red Team — Bitcoin L3 Project Security Division*
*Crimson (Lead) | Sentinel (Crypto) | Locksmith (Store) | Hardcoder (Static) | Hardener (Runtime) | Patcher (Test)*
*Round 4 Remediation Complete — All 7 Findings Fixed*
