# Black Team Re-Attack Report (Post-Remediation)
**Date:** 2026-02-23
**Project:** bitcoin-l3
**Scope:** bitcoin-l3/l3/p2p/* + CLI + store + anchor (post Red Team remediation)
**Classification:** Bitcoin L3 Project — Black Team Security Re-Certification

## Scope Verification
- [x] Project: bitcoin-l3
- [x] Verified within project boundaries
- [x] All paths in report are RELATIVE
- [x] Four agents deployed with locked scope

## Executive Summary

The Red Team remediation was **substantive and well-executed** for the original 7 CRITICAL findings. Five of seven are genuinely and completely fixed. The P2P layer can no longer be crashed via oversized payloads, disk-filled via unsolicited DATA, or eclipsed via unsigned Nostr events.

However, the remediation introduced **new attack surface**. The most severe is a **HIGH-severity handshake authentication bypass** in the `l3 fetch` code path, where `our_privkey=None` causes the entire challenge-response verification to be skipped. Additionally, the trust decay mechanism is broken across reboots (uses `time.monotonic()` instead of wall-clock time), and the `_pending_anchors` queue lacks the same protections applied to `_pending_wants`.

**Bottom line:** 5 of 7 original CRITICALs are dead. 2 fixes are incomplete. 3 deferred items remain. 13 new findings discovered across all 4 agents (deduplicated).

| Severity | Original Fixed | Incomplete/Bypass | New Findings | Deferred |
|----------|---------------|-------------------|-------------|----------|
| CRITICAL | 5 | 0 | 0 | 0 |
| HIGH | 0 | 1 | 2 | 2 |
| MEDIUM | 0 | 1 | 6 | 1 |
| LOW | 0 | 1 | 4 | 0 |

## Team Reports
- [x] Mr BlackKeys: Lead Pentest — 7 verified fixed, 2 incomplete, 7 new findings
- [x] Specter: APT Simulation — 1 verified fixed, 6 incomplete, 4 new findings
- [x] CashOut: Financial Threat — 3 verified fixed, 1 incomplete, 6 new findings
- [x] Burn1t: Chaos Assessment — 4 verified fixed, 1 incomplete, 6 new findings

---

## VERIFIED FIXED (Original CRITICALs — Confirmed Dead)

| ID | Finding | Agents Confirming |
|----|---------|-------------------|
| CRITICAL-1 (MBK-001) | Pure-python crypto fallback removed | All four |
| CRITICAL-2 (MBK-004) | ANCHOR_ANN blind trust → verification queue | All four |
| CRITICAL-4 (MBK-002) | 100MB OOM → 2MB cap | All four |
| CRITICAL-5 | Unsolicited DATA disk fill → _pending_wants guard | MBK, Burn1t, CashOut |
| CRITICAL-6 (MBK-005) | Eclipse via unsigned Nostr → signature verification | MBK, Specter, Burn1t |
| CRITICAL-7 (C-1) | RPC creds in process listing → cookie auth | MBK, CashOut |

Also verified fixed: MBK-007 (INV cap 500), MBK-009 (time-windowed nonce), MBK-010 (127.0.0.1 default), B-4.1 (_pending_wants cap), P2P/RPC architectural firewall.

---

## INCOMPLETE FIXES / BYPASSES FOUND

### HIGH: Handshake Auth Bypass When privkey=None
**IDs:** MBK-003 / MBK-NEW-001 / S-001
**Agents:** Mr BlackKeys, Specter, CashOut
**Location:** `l3/p2p/connection.py:183-218`, `l3/cli.py:360`

The challenge-response verification is gated on `if self.our_privkey`. When `our_privkey` is `None`:
1. Sends dummy signature (`"0" * 128`)
2. **Skips verification of peer's signature entirely**
3. Sets `handshake_done = True` — connection considered authenticated

The `l3 fetch` command creates PeerManager without `our_privkey`, making every fetch session fully unauthenticated. An attacker can impersonate any node to `l3 fetch` clients.

**Fix:** Fail closed when privkey is None. Require key for all P2P operations. `cmd_fetch` must call `load_or_create_key()`.

### MEDIUM: Trust Decay Broken Across Reboots
**IDs:** MBK-NEW-007 / S-006 / B-2.1
**Agents:** All four
**Location:** `l3/p2p/peer_manager.py:418-441`

`time.monotonic()` resets on process restart. Persisted `last_seen` values become meaningless after reboot. Poisoned peers survive forever in `peers.json`.

**Fix:** Use `time.time()` for all values persisted to disk.

### LOW: CLI Help Text Says Default Host is 0.0.0.0
**IDs:** MBK-010 / C-NEW-003
**Agents:** Mr BlackKeys, CashOut
**Location:** `l3/cli.py:450`

Help string says `(default: 0.0.0.0)` but actual default is `127.0.0.1`. Misleading.

**Fix:** Update help text.

---

## NEW FINDINGS (Deduplicated Across All 4 Agents)

### HIGH: Handshake MITM — No Channel Binding (No TLS)
**ID:** S-NEW-001 / S-NEW-002
**Agents:** Specter
**Location:** `l3/p2p/connection.py`, `l3/p2p/server.py`

All TCP traffic is plaintext. The challenge-response proves identity but does not encrypt the channel. An active MITM can relay challenges between nodes and sit in the middle reading/modifying all messages. All document content, inventory, anchor data, and peer topology is transmitted in cleartext. Combined with ANCHOR_ANN data, an adversary can correlate documents to Bitcoin transactions.

**Fix:** Implement TLS or Noise Protocol Framework for transport encryption.

### HIGH: _pending_wants Saturation Sync DoS
**ID:** B-NEW-002
**Agents:** Burn1t
**Location:** `l3/p2p/sync.py:97-102`

The 10K `_pending_wants` cap can be weaponized. Attacker sends 20 INV messages of 500 fake checksums each, fills the cap, then never responds with DATA. For 5 minutes, the victim node cannot request ANY documents from ANY peer. Repeatable indefinitely. Stealth DoS — node appears healthy.

**Fix:** Partition `_pending_wants` per-peer with per-peer caps. Penalize non-responsive peers.

### MEDIUM: SSRF Bypass via DNS Rebinding / Hostnames
**IDs:** MBK-NEW-002 / S-002 / S-003 / B-NEW-005
**Agents:** Mr BlackKeys, Specter, Burn1t
**Location:** `l3/p2p/nostr.py:214-221`, `l3/p2p/peer_manager.py:63-69`

`_is_private_ip()` and `_is_private_or_reserved()` return `False` for hostnames. Attacker can use DNS names that resolve to private IPs, cloud metadata endpoints, or use DNS rebinding.

**Fix:** Resolve hostnames to IPs BEFORE the SSRF check. Reject connections to any hostname resolving to private/reserved ranges.

### MEDIUM: _pending_anchors Unbounded Growth
**IDs:** MBK-NEW-003 / C-NEW-001 / S-NEW-003 / B-NEW-003
**Agents:** All four
**Location:** `l3/p2p/sync.py:62,249,255`

`_pending_anchors` has no size cap and no expiration, unlike `_pending_wants`. An attacker can flood ANCHOR_ANN messages (~16MB/day memory growth). Since no `anchor_verifier` is wired in production, entries accumulate indefinitely.

**Fix:** Cap at 1,000 entries. Add per-checksum dedup. Add timestamp-based expiry.

### MEDIUM: anchor_verifier Never Wired — ANCHOR_ANN is Dead Code
**ID:** C-NEW-004
**Agents:** CashOut
**Location:** `l3/p2p/server.py:88`

`SyncEngine(self.store)` passes no verifier. All P2P anchors are queued and never verified. The entire ANCHOR_ANN protocol feature is non-functional in production. Operators may pay duplicate anchoring fees.

**Fix:** Wire verifier or add `l3 node verify-anchors` CLI command, or remove ANCHOR_ANN until infrastructure exists.

### MEDIUM: update_txid Allows Silent Anchor Overwrite
**ID:** C-NEW-005
**Agents:** CashOut
**Location:** `l3/store.py:194-207`

`update_txid()` unconditionally overwrites existing `anchor_txid`. If wired to a verifier in the future, an attacker could replace a legitimate anchor with their own transaction.

**Fix:** Refuse to overwrite existing `anchor_txid` without explicit `force=True`.

### MEDIUM: Rate Limiter Bypass via Connection Cycling
**IDs:** MBK-NEW-005 / S-009
**Agents:** Mr BlackKeys, Specter
**Location:** `l3/p2p/connection.py:129-139`

Rate limit state (`_msg_timestamps`) is per-connection-object. Disconnect + reconnect = fresh rate limit. No IP-level throttling or reconnect ban.

**Fix:** Add temporary ban (60s) for rate-limit violators. Track by IP, not just pubkey.

### MEDIUM: Eclipse via Legitimate Sybil Nostr Events
**ID:** S-007
**Agents:** Specter
**Location:** `l3/p2p/nostr.py:323-370`

Signature verification stops forged events but not Sybil attacks. Attacker generates N valid keypairs, publishes N signed discovery events, dominates peer discovery. No proof-of-work, reputation, or diversity enforcement.

**Fix:** Subnet diversity limits. Persistent anchor peers that can't be evicted. Proof-of-work on discovery events.

### MEDIUM: RPC Creds as Base64 in Memory
**ID:** C-2
**Agents:** CashOut
**Location:** `l3/anchor.py:50-52`

`self._auth_header` persists Base64 credentials for process lifetime. Memory dumps expose RPC password.

**Fix:** Compute auth header per-request. Zero password after use.

### MEDIUM: Topology Exfiltration via Sybil Polling
**ID:** S-004
**Agents:** Specter
**Location:** `l3/p2p/peer_manager.py:322-351`

Rate limit is per-pubkey, not per-IP. Attacker with N Sybil keys makes N requests per 30s window. Full topology mapped within hours.

**Fix:** Global rate limit per source IP.

### LOW: No Version Negotiation
**ID:** MBK-NEW-004
**Agents:** Mr BlackKeys
**Location:** `l3/p2p/connection.py:178`

Version field accepted but never validated. Incompatible protocol versions communicate silently.

### LOW: Rate Limiter Lacks Reconnect Ban
**ID:** B-NEW-004
**Agents:** Burn1t
**Location:** `l3/p2p/connection.py:129-139`

No temporary ban after rate limit violation. Attacker reconnects immediately.

### LOW: Cookie File Permissions Not Validated
**ID:** C-NEW-002
**Agents:** CashOut
**Location:** `l3/cli.py:40-51`

Cookie file read without checking file permissions. Should warn if world-readable.

### LOW: Nonce Replay After 10-Min Window
**ID:** B-NEW-006
**Agents:** Burn1t
**Location:** `l3/p2p/peer_manager.py:52`

After 10-min nonce expiry, captured messages can be replayed. No timestamp validation.

---

## DEFERRED ITEMS (Still Open)

| ID | Finding | Severity | Notes |
|----|---------|----------|-------|
| MBK-006 / S-NEW-002 | No TLS on TCP connections | HIGH | Enables MITM + passive surveillance |
| MBK-011 / S-005 | Node key plaintext on disk | HIGH | Windows chmod fails silently |
| MBK-008 / C-NEW-006 | index.json TOCTOU race condition | MEDIUM | Silent data loss under concurrency |

---

## Prioritized Fix List for Red Team (Round 2)

### Immediate (Before ANY network exposure)

| # | Finding | Fix | Effort |
|---|---------|-----|--------|
| 1 | Handshake auth bypass (privkey=None) | Fail closed; require key for all P2P ops; fix `cmd_fetch` | Small |
| 2 | Trust decay broken (monotonic time) | Use `time.time()` for persisted timestamps | Small |
| 3 | _pending_wants saturation DoS | Per-peer caps, penalize non-responsive peers | Medium |
| 4 | _pending_anchors unbounded | Cap at 1K, add expiry, per-checksum dedup | Small |
| 5 | CLI help text wrong default | Change "0.0.0.0" to "127.0.0.1" | Trivial |

### Before Beta

| # | Finding | Fix | Effort |
|---|---------|-----|--------|
| 6 | SSRF hostname bypass | Resolve DNS before SSRF check | Medium |
| 7 | Rate limiter bypass (connection cycling) | IP-level ban after rate violation | Medium |
| 8 | anchor_verifier not wired | Add CLI command or periodic verification | Medium |
| 9 | update_txid silent overwrite | Add conflict detection, refuse overwrite | Small |
| 10 | RPC creds in memory | Compute per-request, zero password | Small |

### Before v1.0

| # | Finding | Fix | Effort |
|---|---------|-----|--------|
| 11 | TLS / Noise Protocol | Transport encryption for all P2P | Large |
| 12 | Node key encryption at rest | DPAPI on Windows, keychain on macOS | Medium |
| 13 | index.json file locking | fcntl/msvcrt file locks | Medium |
| 14 | Sybil eclipse prevention | Subnet diversity, anchor peers, PoW | Large |
| 15 | Version negotiation | Validate protocol version in handshake | Small |

---

## Architectural Firewall Status

**CONFIRMED INTACT.** The P2P layer and RPC layer remain NOT wired together at runtime. No P2P message handler can trigger a Bitcoin RPC call. This is the most important security invariant and it holds.

---

## Certification Status

**NOT YET CERTIFIED** — 1 HIGH incomplete fix (handshake bypass) and 2 HIGH new findings (MITM/TLS, sync DoS) must be resolved.

**Progress:** 5/7 original CRITICALs verified dead. Significant improvement from Round 1. Estimated 1 more Red Team sprint to reach certification for non-TLS deployment.

---

*Black Team — Bitcoin L3 Project Security Division*
*Mr BlackKeys (Lead) | Specter (APT) | CashOut (Financial) | Burn1t (Chaos)*
*Re-Attack Round 1 Complete*
