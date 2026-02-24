# Black Team Offensive Assessment
**Date:** 2026-02-23
**Project:** bitcoin-l3
**Scope:** bitcoin-l3/ (P2P networking layer + existing codebase)
**Classification:** Bitcoin L3 Project — Black Team Security Certification

## Scope Verification
- [x] Project: bitcoin-l3
- [x] Verified within project boundaries
- [x] All paths in report are RELATIVE (no home directories)
- [x] Four agents deployed with locked scope

## Executive Summary

The bitcoin-l3 P2P networking layer has a **fundamentally unauthenticated trust model**. It trusts peer-claimed identities, relay-sourced discovery events, and peer-announced anchor data without cryptographic verification. For a system designed to anchor data to Bitcoin, this is a critical gap. The existing storage layer and document format are well-defended (atomic writes, checksum validation, path traversal protection), but the new P2P layer exposes all of it to remote attackers.

**Bottom line:** The P2P layer provides zero security guarantees in its current form. Four P0 fixes are required before any network exposure.

| Severity | Count |
|----------|-------|
| CRITICAL | 7 |
| HIGH | 10 |
| MEDIUM | 14 |
| LOW | 6 |

## Team Reports
- [x] Mr BlackKeys: Lead Pentest — 21 findings (MBK-001 through MBK-021)
- [x] Specter: APT Simulation — Kill chain analysis, 3 nation-state scenarios
- [x] CashOut: Financial Threat — Value map, 5 financial attack scenarios
- [x] Burn1t: Chaos Assessment — 6 nightmare scenarios, 10 destruction vectors

---

## CRITICAL Findings (Immediate Action Required)

### CRITICAL-1: Pure-Python Crypto Fallback Destroys All Identity Guarantees
**ID:** MBK-001 | **Agents:** Mr BlackKeys, Specter, Burn1t
**Location:** `l3/p2p/nostr.py:53-81`

The fallback "signing" when secp256k1 is unavailable uses `hashlib.sha256(b"pfm3-pubkey:" + privkey)` as the "public key" and `HMAC-SHA256` doubled as the "signature." This has zero relationship to elliptic curve cryptography. Any user who installs with `pip install bitcoin-l3` (without `[p2p]`) silently gets this broken fallback with no runtime warning. The "pubkey" cannot verify any signature and the derivation scheme is trivially reversible.

**Impact:** Complete identity forgery. Entire peer discovery trust model collapses.
**Remediation:** Remove the fallback entirely. Raise `ImportError` if secp256k1 is unavailable. Never silently downgrade cryptography.

### CRITICAL-2: Zero Authentication on Wire Protocol
**ID:** MBK-003 | **Agents:** All four
**Location:** `l3/p2p/connection.py:130-155`, `l3/p2p/protocol.py` (entire)

The handshake is a self-asserted identity claim. The peer says "my pubkey is X" and the node believes it. No challenge-response, no signature verification, no proof of key ownership. All messages are plain JSON with no signature or HMAC. Any attacker can connect to port 9735 and:
- Claim any pubkey (impersonate any node)
- Inject forged INV, DATA, ANCHOR_ANN messages
- Poison the peer table with fake identities

**Impact:** Full impersonation of any node. Attacker controls all peer communication.
**Remediation:** Implement challenge-response handshake: exchange nonces, each side signs with their private key, verify before promoting to ACTIVE.

### CRITICAL-3: ANCHOR_ANN Overwrites Legitimate Anchor Records Without Verification
**ID:** MBK-004 | **Agents:** All four
**Location:** `l3/p2p/sync.py:155-169`

Any connected peer can send `ANCHOR_ANN` with an arbitrary `txid` for any document checksum. Zero verification that the txid exists on-chain or contains the claimed checksum. Overwrites legitimate anchor data via `store.update_txid()`. This destroys the core trust property of the entire system — the L1-L3 verification chain.

**Impact:** Attacker can poison anchor metadata for every document in the store. Every `l3 verify-anchor` fails. Trust in the system is destroyed without touching Bitcoin.
**Remediation:** Verify ANCHOR_ANN against on-chain data via `lookup_anchor(txid, rpc)` before updating the index. If no RPC available, queue for async verification.

### CRITICAL-4: 100MB Per-Message Memory Allocation Enables Remote OOM
**ID:** MBK-002 | **Agents:** Mr BlackKeys, Burn1t
**Location:** `l3/__init__.py:21`, `l3/p2p/connection.py:99-104`

`P2P_MAX_PAYLOAD = 100MB`. An attacker opens 16 inbound connections, sends 100MB headers on each. Total: 1.6GB allocated before any parsing. Node is OOM-killed. The payload is fully read before rate limiting is checked.

**Impact:** Any remote attacker can crash a node with 16 TCP connections.
**Remediation:** Reduce `P2P_MAX_PAYLOAD` to 2MB. Check rate limits before reading payload. Add per-connection bandwidth limits.

### CRITICAL-5: Unsolicited DATA Messages Fill Disk Without Limit
**ID:** Burn1t Scenario 1 | **Agents:** Burn1t, CashOut
**Location:** `l3/p2p/sync.py:114-153`

`_handle_data` does NOT check whether a checksum was in `_pending_wants` before storing. The `discard()` on line 122 is a no-op if the checksum was never wanted. An attacker can flood valid PFM documents (each with correct checksums) and the node stores every one. No authorization, no disk quota, no maximum store size.

**Impact:** Disk exhaustion. Store polluted with unlimited garbage documents. No mechanism to distinguish legitimate from attacker-injected documents.
**Remediation:** Guard `_handle_data` — only store documents that exist in `_pending_wants`. Drop unsolicited DATA messages.

### CRITICAL-6: Eclipse Attack via Nostr Relay Poisoning
**ID:** MBK-005 | **Agents:** Mr BlackKeys, Specter, Burn1t
**Location:** `l3/p2p/nostr.py:168-195,250-297`, `l3/p2p/server.py:205-231`

Discovery events are consumed without verifying the Nostr event signature. `parse_discovery_event` never validates the `sig` field. An attacker publishes fake events on the default relays, fills all 8 outbound slots with attacker nodes. Combined with 16 inbound slots: total eclipse. Victim sees only attacker nodes.

**Impact:** Complete network isolation. Attacker controls the victim's entire view of the P2P network.
**Remediation:** Verify Nostr event Schnorr signatures. Implement peer diversity (subnet limits). Persist "anchor peers" that can't be evicted.

### CRITICAL-7: RPC Credentials Visible in Process Listing (Wallet Drain)
**ID:** C-1 | **Agents:** CashOut, Specter
**Location:** `l3/cli.py:27-30`

`--rpc-user` and `--rpc-pass` as CLI arguments are visible via `ps aux` / `/proc/pid/cmdline`. These credentials control a Bitcoin wallet — `fundrawtransaction`, `signrawtransactionwithwallet`, `sendrawtransaction` = drain entire wallet.

**Impact:** Full wallet balance stolen by any co-tenant on shared hosting or any local malware.
**Remediation:** Remove `--rpc-pass` from CLI. Support Bitcoin Core cookie auth. Use config file with chmod 600 only.

---

## HIGH Priority Findings

| ID | Finding | Location | Agents |
|----|---------|----------|--------|
| MBK-006 | No TLS on TCP connections — all traffic in cleartext | `l3/p2p/connection.py` | MBK, Specter |
| MBK-007 | Unbounded INV checksum list — 1M filesystem stat() calls | `l3/p2p/sync.py:60-83` | MBK, Burn1t |
| MBK-008 | index.json race condition — silent data loss under concurrency | `l3/store.py:62-94` | MBK, Burn1t |
| P-3 | No handshake auth — self-asserted identity enables impersonation | `l3/p2p/connection.py:130-155` | CashOut |
| P-4 | Peer address SSRF — connect to internal IPs via PEERS_RES/Nostr | `l3/p2p/peer_manager.py`, `l3/p2p/server.py` | CashOut, Specter |
| S-3.2 | Full peer topology exfiltration via PEERS_REQ (no rate limit) | `l3/p2p/peer_manager.py:259-270` | Specter |
| C-2 | RPC creds held as Base64 in memory for process lifetime | `l3/anchor.py:50-52` | CashOut |
| B-2.1 | peers.json auto-persistence = attacker C2 survives restarts | `l3/p2p/peer_manager.py:310-323` | Specter, Burn1t |
| B-4.1 | Unbounded _pending_wants set — memory exhaustion via INV flood | `l3/p2p/sync.py:60-83` | Burn1t |
| MBK-011 | Node private key stored plaintext, chmod fails on Windows | `l3/p2p/nostr.py:93-107` | All four |

---

## MEDIUM Priority Findings

| ID | Finding | Location |
|----|---------|----------|
| MBK-009 | Nonce dedup trivially bypassable (10K set, non-deterministic eviction) | `l3/p2p/peer_manager.py:101-111` |
| MBK-010 | Server binds 0.0.0.0 by default (unintended public exposure) | `l3/p2p/server.py:28` |
| MBK-012 | RPC creds exposed via CLI args and process table | `l3/cli.py:28-30` |
| MBK-013 | No validation of discovery host (SSRF via internal IPs) | `l3/p2p/nostr.py:186-195` |
| MBK-014 | No SSL context config for Nostr relay connections | `l3/p2p/nostr.py:218` |
| MBK-015 | Rate limiter checked AFTER full message read | `l3/p2p/connection.py:93-128` |
| MBK-016 | Full inventory auto-broadcast to every connecting peer | `l3/p2p/sync.py:185-199` |
| P-2 | Full document store enumerable via INV on connect | `l3/p2p/sync.py:185-199` |
| P-6 | Nostr discovery event spoofing (no sig verification) | `l3/p2p/nostr.py:168-195` |
| P-7 | Node key file world-readable on Windows | `l3/p2p/nostr.py:103-107` |
| C-3 | No credential file support, no secrets management | `l3/cli.py`, `l3/anchor.py` |
| B-4.2 | 100MB document memory amplification (300-400MB peak per doc) | `l3/p2p/sync.py:114-153` |
| S-3.3 | index.json leaks document IDs, agents, timestamps in plaintext | `l3/store.py:135-145` |
| S-5.3 | Nonce replay after eviction — time-windowed cache needed | `l3/p2p/peer_manager.py:101-111` |

---

## LOW Priority Findings

| ID | Finding | Location |
|----|---------|----------|
| MBK-017 | Handshake timeout asymmetry — 10s hold per slot | `l3/p2p/connection.py:130-155` |
| MBK-018 | Node identity leaked before authentication | `l3/p2p/connection.py:131-138` |
| MBK-019 | Nonce eviction uses non-deterministic set ordering | `l3/p2p/peer_manager.py:107-110` |
| MBK-020 | peers.json has no integrity protection (no HMAC) | `l3/p2p/peer_manager.py:310-333` |
| MBK-021 | Inbound counter bypass via pubkey collision | `l3/p2p/peer_manager.py:179-220` |
| B-Peer | Peer scoring tracked but never used for any decision | `l3/p2p/peer_manager.py:302-307` |

---

## Attack Scenarios (Cross-Agent)

### Scenario: Lazarus Group — Node Key Theft + Wallet Drain
**Source:** Specter + CashOut
1. Query Nostr relays for kind 30078 events — enumerate all L3 nodes
2. Connect to target on port 9735, claim plausible pubkey
3. Receive full inventory via INV, WANT every checksum, exfiltrate all documents
4. Get saved to peers.json for persistence across restarts
5. If target has Bitcoin RPC configured, read `BITCOIN_RPC_PASS` from process env
6. Drain Bitcoin wallet via `sendrawtransaction` to attacker address
7. Steal node_key from disk, impersonate node permanently

### Scenario: APT29 — Long-Term Passive Surveillance
**Source:** Specter
1. Run 3-5 L3 nodes on different VPS providers
2. Publish discovery events to all default relays
3. Every new L3 node connects, sends full inventory
4. Passively track every document anchor across the entire network for months
5. Correlate anchor txids with blockchain analysis for deanonymization
6. Zero detection — all activity looks like normal peer behavior

### Scenario: Scorched Earth — Total Network Destruction
**Source:** Burn1t
1. Discover all nodes via Nostr (no auth needed)
2. Eclipse every node (fill 16 inbound + poison 8 outbound)
3. Impersonate nodes to each other (fragment the network)
4. Flood ANCHOR_ANN to corrupt every anchor reference
5. Flood unsolicited DATA to fill disks
6. Flood INV with millions of fake checksums to exhaust memory
**Cost:** ~$50/month in VPS hosting, a few hours of scripting
**Recovery:** Days to weeks per operator

---

## Single Points of Failure

| Component | Backup? | Failure Mode | Recovery |
|-----------|---------|-------------|----------|
| node_key (private key) | NONE | Identity permanently lost/compromised | Generate new key, lose all reputation. No revocation |
| index.json | NONE | All metadata lost (anchors, timestamps) | Rebuild from .pfm files + re-query Bitcoin. No tool exists |
| peers.json | NONE | Can't reconnect to known peers | Re-discover via Nostr or manual add-peer |
| store/ directory | NONE | All documents lost | Re-fetch from peers (if any survive) |
| Nostr relay connectivity | 3 hardcoded | Discovery stops if all censored | Manual peer addition only |

---

## Architectural Firewall (PRESERVE THIS)

**The P2P layer and the RPC layer are currently NOT wired together at runtime.** No P2P message handler can trigger a Bitcoin RPC call. This is the single most important security invariant in the codebase. If anyone ever adds a P2P-triggered anchor feature, the entire wallet becomes remotely drainable.

**Recommendation:** Document and enforce this invariant. Consider splitting RPC into a separate process with IPC.

---

## Prioritized Fix List for Red Team

### Sprint 1 — P0 (Before ANY network exposure)

| # | Finding | Fix | Effort |
|---|---------|-----|--------|
| 1 | MBK-001 | Remove crypto fallback, require secp256k1 for P2P | Small |
| 2 | MBK-002 | Reduce P2P_MAX_PAYLOAD to 2MB | Small |
| 3 | MBK-003 | Signed challenge-response handshake | Medium |
| 4 | MBK-004 / CRITICAL-3 | Verify ANCHOR_ANN against on-chain data | Medium |
| 5 | Burn1t CRITICAL-5 | Guard _handle_data — only store if in _pending_wants | Small |
| 6 | MBK-005 / CRITICAL-6 | Verify Nostr event signatures | Medium |
| 7 | CRITICAL-7 | Remove --rpc-pass, support cookie auth | Small |

### Sprint 2 — P1 (Before beta)

| # | Finding | Fix | Effort |
|---|---------|-----|--------|
| 8 | MBK-006 | Add TLS to TCP connections | Medium |
| 9 | MBK-007 | Cap inbound INV to 500 checksums | Small |
| 10 | MBK-008 | File locking on index.json | Small |
| 11 | Burn1t B-4.1 | Cap _pending_wants to 10K, add timeout | Small |
| 12 | MBK-010 | Default bind to 127.0.0.1 | Small |
| 13 | S-3.2 | Rate limit PEERS_REQ, return random subset | Small |
| 14 | B-2.1 | peers.json trust decay — evict after 7 days | Small |
| 15 | MBK-016 | Don't auto-broadcast full inventory | Small |

### Sprint 3 — P2 (Before v1.0)

| # | Finding | Fix | Effort |
|---|---------|-----|--------|
| 16 | MBK-009 | Time-windowed nonce dedup with OrderedDict | Small |
| 17 | MBK-011 | Encrypt node_key at rest (DPAPI on Windows) | Medium |
| 18 | MBK-013 | Validate hosts against RFC1918 private ranges | Small |
| 19 | MBK-015 | Check rate limits before payload read | Small |
| 20 | MBK-012 | Read RPC creds from config file only | Small |
| 21 | Burn1t B-7 | Add store re-indexing tool for recovery | Medium |
| 22 | B-Peer | Use peer scores for eviction decisions | Small |

---

## Handoff

**Next Step:** `@red-team fix bitcoin-l3/`

Red Team will remediate findings in priority order, starting with Sprint 1 P0 items.
After remediation, Black Team will re-attack to verify fixes.

**Certification Status: NOT CERTIFIED** — 7 CRITICAL findings must be resolved.

---

*Black Team — Bitcoin L3 Project Security Division*
*Mr BlackKeys (Lead) | Specter (APT) | CashOut (Financial) | Burn1t (Chaos)*
