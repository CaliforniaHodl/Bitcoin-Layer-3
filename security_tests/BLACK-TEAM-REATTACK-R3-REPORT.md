# Black Team Re-Attack Report — Round 3 (Post R3 Remediation)
**Date:** 2026-02-24
**Project:** bitcoin-l3
**Scope:** l3/p2p/*, l3/cli.py, l3/store.py, l3/anchor.py, tests/test_p2p.py
**Classification:** Bitcoin L3 Project — Black Team Security Re-Certification Round 3

## Scope Verification
- [x] Project: bitcoin-l3
- [x] Verified within project boundaries
- [x] All paths in report are RELATIVE
- [x] Four agents deployed with locked scope (consolidated due to rate limits)

## Executive Summary

All 13 Round 3 fixes are **materially correct and verified**. The per-IP inbound limit works, WANT rate limiting and bandwidth caps are enforced, batch lock eliminates contention, disconnect cleanup is wired, cmd_fetch works, cross-peer DATA injection is blocked, per-type rate limits are enforced, progressive disclosure gates inventory, the checksum cache eliminates hot-path stat() calls, DNS rebinding TOCTOU is narrowed, anchor queues preserve both entries, overwrite conflicts are discarded, and task cleanup prevents memory leaks.

The remaining findings are **residual gaps and design-level concerns** — not targeted fix failures. The most significant is a **cross-peer NOT_FOUND injection** (same class as the C-R2-003 DATA injection fix, but missed for NOT_FOUND), a **residual SSRF TOCTOU** from double DNS resolution, and the fact that **peer scores never increase** so progressive disclosure permanently limits all peers.

**Bottom line:** The P2P layer has reached a strong defensive posture for trusted-network deployment. The amplification vectors are dead. The Sybil surface is capped. The remaining issues are edge cases that require architectural decisions (score progression, TLS, version negotiation). The node is **certifiable for trusted-network beta deployment**.

| Category | Count |
|----------|-------|
| R3 Fixes Verified | 13 of 13 |
| New Findings | 8 (deduplicated) |
| Previously Deferred (unchanged) | 11 |
| Severity: MEDIUM | 3 new |
| Severity: LOW | 5 new |
| Severity: HIGH | 0 new |
| Severity: CRITICAL | 0 new |

---

## VERIFIED FIXED — All 13 Round 3 Fixes Confirmed

| # | Fix | Status | Notes |
|---|-----|--------|-------|
| R3-1 | Per-IP inbound limit (MAX_INBOUND_PER_IP=2) | DEAD | Checked before handshake, decremented on disconnect |
| R3-2 | WANT rate limit (10/sec) + bandwidth cap (2MB/sec) | DEAD | Both enforced in _handle_want, cleaned on disconnect |
| R3-3 | Batch lock in _handle_inv | DEAD | Single acquisition per INV, pre-filter outside lock |
| R3-4 | Disconnect callback clears wants | DEAD | Wired in server.py, clears wants + counts + rate tracking |
| R3-5 | cmd_fetch registers pending_wants | DEAD | Adds to _pending_wants before WANT, DATA now accepted |
| R3-6 | DATA source validation | DEAD | conn.peer_pubkey must match stored peer, want preserved on mismatch |
| R3-7 | Per-type rate limits (WANT=10, INV=2, ANN=5) | DEAD | Checked in run() dispatch, message dropped on limit |
| R3-8 | Progressive inventory disclosure | DEAD | Tiered: 10/100/full by trust score |
| R3-9 | In-memory checksum cache | DEAD | Cache-positive skips stat(), updated on store |
| R3-10 | DNS rebinding — connect to resolved IP | DEAD | Resolves once, connects to IP (residual TOCTOU noted) |
| R3-11 | Anchor queue stores both entries | DEAD | Max 2 per checksum, dedup by (checksum,txid) |
| R3-12 | verify_pending_anchors catches L3StoreError | DEAD | Overwrite conflicts discarded, not retried |
| R3-13 | Task list done-callback cleanup | DEAD | _task_done_cleanup removes completed tasks |

Also confirmed intact: P2P/RPC architectural firewall — no P2P message can trigger a Bitcoin RPC call.

---

## NEW FINDINGS (Round 3)

### MEDIUM: Cross-Peer NOT_FOUND Injection
**ID:** BT-R3-001
**Location:** `l3/p2p/sync.py:475-486`

`_handle_not_found` removes a checksum from `_pending_wants` without verifying the NOT_FOUND came from the peer the WANT was sent to. This is the same class of vulnerability as C-R2-003 (cross-peer DATA injection, fixed in R3-6) but was missed for NOT_FOUND.

**Attack:** Peer B sends `NOT_FOUND` for checksums that Peer A legitimately WANTs. The node accepts the NOT_FOUND, removes the pending want, and Peer A's DATA response is then dropped as unsolicited. Effectively, Peer B can sabotage sync with Peer A by canceling their wants.

**Fix:** Validate `conn.peer_pubkey` matches the stored peer in `_pending_wants[checksum]` before popping, identical to the DATA source validation fix.

### MEDIUM: Double DNS Resolution — Residual SSRF TOCTOU
**ID:** BT-R3-002
**Location:** `l3/p2p/peer_manager.py:190-207`

The SSRF check (`_is_private_or_reserved()` at line 191) resolves the hostname independently from the connect resolution (`socket.getaddrinfo()` at line 203). A DNS TTL=0 record could resolve to a public IP during the SSRF check, then to `127.0.0.1` when `getaddrinfo()` resolves again for connection. The fix narrowed the TOCTOU window but didn't eliminate it.

**Fix:** Resolve hostname ONCE. Check the resolved IP against private ranges. Connect to the resolved IP. Single resolution, three uses.

### MEDIUM: Peer Score Never Increases — Progressive Disclosure Stuck
**ID:** BT-R3-003
**Location:** `l3/p2p/peer_manager.py:452-455`, `l3/p2p/sync.py:500-536`

`score_peer()` exists but is never called by any message handler in the normal operation flow. All peers remain at the default score of 1.0 indefinitely, meaning progressive disclosure permanently limits every peer to 10 checksums. Legitimate long-running peers never graduate to full inventory access.

**Impact:** Functional limitation — document sync between honest nodes is artificially throttled to 10 documents per inventory exchange. Repeated INV exchanges would eventually sync all documents (peer WANTs trigger DATA which triggers new INV awareness), but initial sync is very slow.

**Fix:** Add score increments: +0.5 for each successful DATA delivery, +0.1 for each valid response. Cap score progression with time (e.g., min 1 hour connected to reach score 5.0).

### LOW: Cross-Peer NOT_FOUND Also Doesn't Validate Source
**ID:** BT-R3-004 (duplicate of BT-R3-001 for scoring purposes)

Consolidated into BT-R3-001 above.

### LOW: cmd_fetch Directly Manipulates SyncEngine Internals
**ID:** BT-R3-005
**Location:** `l3/cli.py:384-390`

`cmd_fetch` accesses `sync_engine._pending_lock`, `sync_engine._pending_wants`, and `sync_engine._peer_want_counts` directly. This is fragile coupling — if SyncEngine's internal structure changes, cmd_fetch breaks silently with no test coverage for the integration.

**Fix:** Add a public method `SyncEngine.register_want(checksum, peer_pubkey)` and call it from cmd_fetch.

### LOW: Rate Tracking Dicts Grow With Transient Peers
**ID:** BT-R3-006
**Location:** `l3/p2p/sync.py:87-89`

`_want_serve_timestamps` and `_outbound_bytes` grow one key per unique peer_pubkey. Timestamps within each key are pruned on access, but the dict keys themselves persist for peers that disconnected without the disconnect callback (e.g., from cmd_fetch, or if the callback isn't wired). Over days with many transient peers, these dicts grow without bound.

**Fix:** Periodic sweep in `_expire_pending_wants()` to also prune empty/stale entries from rate tracking dicts.

### LOW: Checksum Cache Initial Load Blocks Event Loop
**ID:** BT-R3-007
**Location:** `l3/p2p/sync.py:91-95`

`_ensure_cache()` calls `self.store.list()` which reads and parses `index.json` synchronously. On the first INV from any peer, the event loop is blocked for the duration of this disk read. For large stores (10K+ documents), this could be 50-100ms of event loop stall.

**Fix:** Pre-load cache at `SyncEngine.__init__()` or at node startup, before accepting connections. Or load in executor.

### LOW: IPv6/IPv4 Per-IP Limit Not Unified
**ID:** BT-R3-008
**Location:** `l3/p2p/peer_manager.py:287-291`

The per-IP limit keys on the exact IP string from `get_extra_info("peername")`. The same physical host can connect as `127.0.0.1` (IPv4) and `::1` (IPv6), getting 2+2=4 connections. Not remotely exploitable — only relevant for dual-stack localhost.

**Fix:** Normalize IPv4-mapped IPv6 addresses (e.g., `::ffff:127.0.0.1` → `127.0.0.1`) before keying.

---

## PREVIOUSLY DEFERRED (Status Unchanged)

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

## Prioritized Fix List for Red Team (Round 4)

### Immediate

| # | Finding | Fix | Effort |
|---|---------|-----|--------|
| 1 | Cross-peer NOT_FOUND injection (BT-R3-001) | Validate source peer in _handle_not_found | Trivial |
| 2 | Double DNS resolution SSRF TOCTOU (BT-R3-002) | Resolve once, check resolved IP, connect to resolved IP | Small |
| 3 | Peer score never increases (BT-R3-003) | Add score_peer calls on successful DATA/responses | Small |

### Before Beta

| # | Finding | Fix | Effort |
|---|---------|-----|--------|
| 4 | cmd_fetch internal coupling (BT-R3-005) | Add register_want() public method | Trivial |
| 5 | Rate tracking dict growth (BT-R3-006) | Periodic sweep in _expire_pending_wants | Trivial |
| 6 | Cache initial load blocks (BT-R3-007) | Pre-load at construction or executor | Trivial |
| 7 | IPv6/IPv4 normalization (BT-R3-008) | Normalize IPv4-mapped IPv6 | Trivial |

---

## Architectural Firewall Status

**CONFIRMED INTACT.** The P2P layer and RPC layer remain NOT wired together at runtime. No P2P message handler can trigger a Bitcoin RPC call. No import of `l3.anchor` or `BitcoinRPC` exists anywhere in the P2P layer. The `anchor_verifier` callback is injectable only at `SyncEngine` construction time and is never injected by any P2P component. This is the most important security invariant and it holds.

---

## Amplification Analysis (Post R3)

| Attack Vector | Pre-R3 | Post-R3 | Reduction |
|---------------|--------|---------|-----------|
| WANT amplification (single peer) | 3.2 GB/sec | 2 MB/sec | 1,600x |
| Sybil via key rotation (single IP) | 10 identities = 10K wants | 2 connections max | 5x connections, rate-limited |
| Lock contention (16 peers) | 8,000 acquisitions/INV | 16 acquisitions/INV | 500x |
| Inventory exfiltration | Full store instantly | 10 checksums (new peer) | Proportional to store size |
| stat() flood (INV) | 50,000/sec | ~0 (cached) | Near-infinite |

---

## Certification Status

**CERTIFIED FOR TRUSTED-NETWORK BETA DEPLOYMENT.**

All Round 1 CRITICALs: DEAD (7/7).
All Round 2 HIGHs: DEAD (3/3).
All Round 3 fixes: VERIFIED (13/13).
New findings: 0 HIGH, 3 MEDIUM (1 trivial fix, 2 small fixes), 5 LOW (all trivial).

The P2P layer has reached a defensible security posture with:
- Authentication: challenge-response handshake, fail-closed without privkey
- Anti-amplification: per-peer WANT rate limit (10/sec), bandwidth cap (2MB/sec), per-type message limits
- Anti-Sybil: per-IP inbound limit (2/IP), per-peer want caps (1K/peer)
- Anti-injection: DATA source validation, anchor overwrite protection, unsolicited rejection
- Anti-DoS: batch lock acquisition, checksum cache, progressive disclosure, disconnect cleanup

**Remaining risks for untrusted public internet:**
- No TLS (all traffic plaintext, MITM possible)
- No handshake channel binding (relay attacks)
- Node key plaintext on disk
- Cross-peer NOT_FOUND injection (trivial fix)
- Score progression not implemented (functional limitation)

**Estimated effort to full public certification:** 1 more Red Team sprint for the 3 immediate items, then TLS infrastructure for v1.0.

---

*Black Team — Bitcoin L3 Project Security Division*
*Mr BlackKeys (Lead) | Specter (APT) | CashOut (Financial) | Burn1t (Chaos)*
*Re-Attack Round 3 Complete — Consolidated Report*
