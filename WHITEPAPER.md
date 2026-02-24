# Bitcoin L3: A Document Anchoring Layer for Bitcoin

**Version:** 0.1.0
**Author:** Anonymous
**Date:** February 2026

---

## Abstract

Bitcoin's blockchain provides the strongest proof-of-existence guarantee in computing: once a transaction is buried under enough work, reversing it is economically infeasible. But Bitcoin was designed to move value, not store data. Every byte committed to L1 lives in every full node forever. Bitcoin L3 separates these concerns. Documents live off-chain in a content-addressed store with peer-to-peer distribution. Bitcoin L1 holds only a 36-byte anchor — a 4-byte protocol prefix and a 32-byte SHA-256 checksum embedded in an OP_RETURN output. The anchor is permanent. The data is portable. L1 proves existence. L3 provides availability.

---

## 1. The Problem: Data Doesn't Belong on L1

Bitcoin's UTXO set and blockchain are replicated across tens of thousands of nodes worldwide. Every byte stored on-chain has a permanent cost: bandwidth to propagate, disk to store, and CPU to validate — multiplied by every node in the network, for all time.

Despite this, L1 is increasingly misused as a data layer:

- **Inscriptions** encode images, text, and arbitrary files directly into witness data, consuming block space that competes with financial transactions.
- **BRC-20 tokens** embed JSON metadata into inscriptions, creating synthetic token ledgers on a chain designed for UTXO accounting.
- **Stamps** use bare multisig outputs to store image data in unspendable UTXOs that can never be pruned.

The result is blockchain bloat. The Bitcoin blockchain exceeded 600 GB in 2025. Full node operators bear the storage cost. Initial block download times increase. Fee markets become distorted by non-financial data competing for block space.

The fundamental error is conflating **proof of existence** with **data availability**. You don't need to store a document on-chain to prove it existed at a point in time. You only need to store its fingerprint.

---

## 2. Architecture: Anchors on L1, Data on L3

Bitcoin L3 implements a clean separation:

```
                        BITCOIN L3 ARCHITECTURE

    L1 (Bitcoin)              Bridge              L3 (Document Layer)
   +-----------------+    +-------------+    +------------------------+
   |                 |    |             |    |                        |
   |  Block N        |    |   36 bytes  |    |  ~/.pfm/l3/store/     |
   |  +-----------+  |    |             |    |  +------------------+ |
   |  | OP_RETURN |  |<---|  PFM3 +     |<---|  | <checksum>.pfm   | |
   |  | PFM3+hash |  |    |  SHA-256    |    |  | <checksum>.pfm   | |
   |  +-----------+  |    |             |    |  | <checksum>.pfm   | |
   |                 |    +-------------+    |  +------------------+ |
   |  Immutable.     |                       |                        |
   |  36 bytes/doc.  |                       |  P2P sync via Nostr    |
   |  Proves time.   |                       |  Content-addressed     |
   |                 |                       |  Cryptographic verify  |
   +-----------------+                       +------------------------+
```

### L1: The Trust Anchor

Bitcoin L1 serves one purpose: **timestamped proof of existence**. For each document, a single OP_RETURN transaction is broadcast containing:

```
OP_RETURN <36 bytes>
  [4 bytes]  "PFM3"     Protocol identifier
  [32 bytes] SHA-256    Document checksum
```

That's it. 36 bytes. No document content. No metadata. No file names. Just a cryptographic fingerprint locked into the most secure ledger ever built.

Once confirmed, this anchor provides:
- **Proof of existence** — the document existed at block height N
- **Tamper evidence** — any modification changes the checksum
- **Non-repudiation** — the anchor cannot be removed or altered
- **Timestamping** — block timestamp provides approximate dating

### L3: The Document Layer

All document data lives on L3:

- **Local store** — content-addressed filesystem at `~/.pfm/l3/store/`
- **Index** — `index.json` maps checksums to metadata (txid, network, timestamps)
- **P2P network** — nodes discover each other via Nostr relays and exchange documents
- **PFM format** — a purpose-built container format with cryptographic integrity

L3 is where the data lives. L1 is where the proof lives. The bridge between them is a 36-byte OP_RETURN.

---

## 3. The PFM Container Format

PFM (Pure Fucking Magic) is a section-based document container designed for content-addressed storage.

### Structure

```
#!PFM/1.0
#@meta
id: a1b2c3d4-...
agent: my-application
created: 2026-02-24T12:00:00Z
checksum: sha256:<hex>
#@index
content 247 1024
attachment 1271 8192
#@content
The actual document content goes here.
#@attachment
<binary or text data>
#!END
```

### Design Properties

| Property | Mechanism |
|----------|-----------|
| **Identity** | SHA-256 checksum of all section content |
| **Integrity** | Checksum embedded in metadata, verified on read |
| **Deduplication** | Content-addressed — identical content = identical checksum |
| **Lazy I/O** | Byte-offset index enables O(1) section access without reading entire file |
| **Portability** | Text-based format with escape sequences for binary safety |
| **Size limits** | 100 MB max file, 10,000 max sections |

### Checksum Computation

The document checksum is a SHA-256 hash of all section content concatenated in order. This checksum becomes the filename in the L3 store and the value anchored to L1. Any modification to any section changes the checksum, breaking the anchor chain.

---

## 4. The Anchoring Protocol

### On-Chain Format

Every PFM anchor follows an identical structure:

```
Script:  OP_RETURN OP_PUSH(36) <PFM3> <SHA-256>
Hex:     6a24 50464d33 <64 hex chars>
Size:    38 bytes scriptPubKey (2 opcode + 36 data)
```

### Transaction Lifecycle

```
1. COMPUTE    checksum = SHA-256(document sections)
2. CREATE     createrawtransaction [] [{"data": "50464d33" + checksum}]
3. FUND       fundrawtransaction(raw_tx)  — selects UTXOs, adds change
4. SIGN       signrawtransactionwithwallet(funded_tx)
5. BROADCAST  sendrawtransaction(signed_tx)
6. INDEX      store.update_txid(checksum, txid, network)
```

### Verification

Verification is fail-closed:

```
1. LOOKUP     getrawtransaction(txid, verbose=True)
2. PARSE      find OP_RETURN output, extract checksum
3. COMPUTE    hash the local document
4. COMPARE    hmac.compare_digest(on_chain, computed)
```

If any step fails — network error, missing transaction, checksum mismatch — verification returns `False`. There is no "maybe" state.

### Cost

An OP_RETURN output adds approximately 44 vbytes to a transaction (scriptPubKey + overhead). At 10 sat/vbyte, anchoring one document costs roughly 440 satoshis (~$0.40 at $100K/BTC). The marginal cost of adding OP_RETURN to an existing transaction is even lower.

---

## 5. P2P Document Network

Documents are useless if they can't be found. Bitcoin L3 includes a peer-to-peer network for document discovery and exchange.

### Peer Discovery via Nostr

Nodes publish their TCP address to Nostr relays as application-specific events (kind 30078, d-tag `pfm3-node`). Other nodes subscribe to these events and connect directly over TCP.

This means:
- No custom discovery infrastructure
- Leverages existing Nostr relay network
- Nodes are identified by secp256k1 public keys (same curve as Bitcoin)
- Discovery events are signed and verifiable

### Wire Protocol

Binary framing over TCP:

```
[4 bytes: "PFM3"]  [4 bytes: payload length]  [JSON payload]
```

Eleven message types:

| Message | Purpose |
|---------|---------|
| HANDSHAKE / HANDSHAKE_ACK | Identity exchange + challenge-response auth |
| PING / PONG | Keepalive (30s interval, 90s timeout) |
| INV | "I have these checksums" |
| WANT | "Send me this document" |
| DATA | Document bytes (base64 in JSON) |
| ANCHOR_ANN | "This checksum was anchored in this txid" |
| NOT_FOUND | "I don't have that document" |
| PEERS_REQ / PEERS_RES | Peer exchange |

### Authentication

Every connection begins with a challenge-response handshake:

1. Both sides exchange random 32-byte challenges
2. Each side signs the peer's challenge with their secp256k1 private key
3. Each side verifies the signature against the peer's claimed public key
4. Connection is established only if both signatures verify

No anonymous connections. Every peer proves ownership of their claimed identity.

### Sync Cycle

```
Node A                          Node B
  |                                |
  |-------- INV [checksums] ------>|
  |                                |  (checks local store)
  |<------- WANT [checksum] ------|
  |                                |
  |-------- DATA [document] ------>|
  |                                |  (validates checksum)
  |                                |  (stores document)
```

### Progressive Disclosure

New peers receive limited inventory to prevent store exfiltration by Sybil attackers:

| Trust Score | Checksums Disclosed |
|-------------|---------------------|
| New (score <= 1.0) | 10 |
| Known (1.0 < score <= 5.0) | 100 |
| Trusted (score > 5.0) | Full inventory |

Scores increase through successful document delivery (+0.5) and valid responses (+0.1).

---

## 6. Security Model

Bitcoin L3 has been through four rounds of adversarial security testing — a structured red-team/black-team cycle where attack agents attempt to exploit the system and defense agents fix what's found.

### Summary

| Round | Findings Fixed | Severity |
|-------|---------------|----------|
| Round 1 | 7 | 7 CRITICAL |
| Round 2 | 16 | 3 HIGH, 9 MEDIUM, 4 LOW |
| Round 3 | 13 | 13 MEDIUM/LOW |
| Round 4 | 7 | 3 MEDIUM, 4 LOW |
| **Total** | **43** | **0 CRITICAL/HIGH remaining** |

### Key Defenses

**Anti-Amplification**
- Per-peer WANT rate limit: 10/sec
- Per-peer outbound bandwidth cap: 2 MB/sec
- Per-message-type rate limits (WANT=10, INV=2, ANCHOR_ANN=5 per second)

**Anti-Sybil**
- Per-IP inbound connection limit: 2 connections/IP
- Per-peer pending wants cap: 1,000
- IPv4-mapped IPv6 normalization
- Progressive inventory disclosure

**Anti-Injection**
- DATA source validation (must come from the peer the WANT was sent to)
- NOT_FOUND source validation (same pattern)
- Anchor overwrite protection (existing anchors cannot be silently replaced)
- Unsolicited DATA rejection

**Anti-DoS**
- Batch lock acquisition (single lock per INV, not per checksum)
- In-memory checksum cache (eliminates stat() floods)
- Task cleanup callbacks (prevents memory leaks)
- Disconnect callbacks (immediate resource reclamation)

**Architectural Firewall**
- No P2P message handler can trigger a Bitcoin RPC call
- The P2P layer and RPC layer are not wired together at runtime
- Anchor verification is injectable only at construction time

### Certification

The system is certified for **trusted-network beta deployment**. Remaining deferred items for public internet deployment:
- TLS encryption on TCP connections
- Handshake channel binding (MITM prevention)
- Node key encryption at rest

---

## 7. Content Accountability

L1 inscriptions have a fatal flaw: illegal content stored on-chain lives in every full node forever, with no way to remove it. L3 solves this the same way Lightning solves payments — nothing hits L1 except a settlement hash.

### The Channel Model for Data

```
L1 Inscriptions:
  Content → embedded in witness data → every full node stores it forever
  Removal? Impossible. It's in the chain.

L3 Anchoring:
  Content → L3 node store (off-chain) → nodes choose what to store
  L1 gets: 36-byte hash only (reveals nothing about content)
  Removal? L3 nodes drop it. Hash on L1 becomes a dead pointer.
```

### Accountability via Bitcoin Address

Every anchor transaction has a **funding address**. That address is public, timestamped, and permanent on L1. This creates an audit trail that L1 inscriptions lack:

```
Illegal content detected on L3
    → checksum known
    → anchor txid found in L3 index
    → anchor tx has a funding Bitcoin address
    → address traced to exchange / KYC endpoint
    → identity of the person who anchored

Result:
  Content removed from L3 nodes (operator choice)
  Anchor hash remains on L1 (meaningless without data)
  Funding address is permanently linked to the act
```

L1 inscriptions: content is irremovable, uploader is anonymous. L3 anchoring: content is removable, uploader is traceable.

### Node Content Policies

L3 node operators choose what categories of content they accept, store, and relay. Content categories are declared in PFM metadata. Node policies are configured locally:

```toml
# ~/.pfm/l3/node.toml

[content_policy]
accept = ["legal", "record"]     # only store these categories
reject = ["*"]                    # reject everything else
max_document_size = "50MB"        # per-document cap
require_category = true           # reject untagged documents
```

Example node specializations:
- **Legal archive** — wills, contracts, deeds (run by law firms, notary services)
- **Art & media** — photography, music, NFTs (run by artists, galleries)
- **Personal storage** — family photos, personal records (run by individuals)
- **General purpose** — open archive (run by researchers, archivists)

### Report & Delete

```
1. FLAG     Any node operator flags a checksum
2. REVIEW   Each node operator reviews flagged content independently
3. DELETE   Operator removes content from their store: l3 delete <checksum>
4. RELAY    Flag propagates to peers — each peer makes their own decision
5. TRACE    Anchor tx on L1 links checksum → funding address → identity
```

No central authority. Every node decides independently. Content disappears from L3. The hash on L1 becomes a dead pointer. The uploader remains traceable via the anchor address.

### Why People Run Nodes

The same reason people run Bitcoin full nodes: because they want to use the network. Nobody pays you to run a Bitcoin node. You run it because you need it.

L3 is the same. Want to anchor legal documents? Run a node. Want to host your art? Run a node. Want a family photo archive with Bitcoin-grade proof of existence? Run a node. Two nodes find each other via Nostr, mesh, and now there's redundancy.

---

## 8. Roadmap

### Current State (v0.1)

- Documents stored locally and synced via P2P
- 36-byte OP_RETURN anchors committed to Bitcoin
- Manual anchoring via `l3 anchor` command
- Manual verification via `l3 verify-anchor`
- Node content policies (category-based opt-in)
- VeilCloud privacy primitives (built-in, native Python)

### VeilCloud Architecture

VeilCloud is a native Python privacy layer built directly into Bitcoin L3 as `l3/veilcloud/`. Pure Python implementations with zero external services -- only the encryption module requires an optional dependency (`cryptography`).

**Modules:**

| Module | Purpose | Dependencies |
|--------|---------|-------------|
| `merkle.py` | Merkle tree construction + inclusion proofs | stdlib (hashlib) |
| `crypto.py` | AES-256-GCM encryption + PBKDF2 key derivation | `cryptography` (optional) |
| `threshold.py` | Shamir's Secret Sharing over GF(256) | stdlib (secrets) |
| `audit.py` | Append-only hash-chained audit log | stdlib + merkle.py |
| `access.py` | HMAC-signed credentials with permissions + expiry | stdlib (hmac, secrets) |

**Security properties:**
- Domain-separated Merkle hashing (prevents second-preimage attacks)
- PBKDF2 at 600,000 iterations (OWASP 2023 minimum)
- Constant-time comparisons everywhere (`hmac.compare_digest`)
- Fail-closed verification (any error returns False)
- No secrets as CLI arguments (passwords via `getpass`, keys via files)
- Best-effort key zeroing after use
- Shamir SSS over the same GF(256) field as AES (Rijndael polynomial)

**Batch anchoring flow:**
```
1. Collect N checksums
2. Build MerkleTree.from_checksums(checksums)
3. Anchor merkle_root to Bitcoin (single OP_RETURN, 36 bytes)
4. For any checksum, generate inclusion proof: tree.get_proof(index)
5. Verifier: verify_proof(proof) + verify anchor on L1
```

This allows anchoring thousands of documents in a single transaction.

### Near-Term (v0.2)

- **Automatic anchoring** — node anchors new documents as they arrive via P2P
- **Batch anchoring** — multiple checksums in a single transaction using Merkle trees
- **Anchor verification daemon** — background process verifies pending anchors against on-chain data
- **Minimal L1 build** — [Bitcoin Finney](../Finney/) (stripped Knots: daemon + RPC only, no GUI, no tools, no BDB)

### Medium-Term (v0.3)

- **TLS on P2P connections** — required for public internet deployment
- **Handshake channel binding** — MITM prevention
- **Node key encryption at rest**

### Long-Term Vision

Bitcoin L1 is the anchor. Nothing more. Every byte of real data — documents, contracts, records, proofs — lives on L3 where it can be replicated, distributed, and verified without bloating the chain that secures $2 trillion in value.

The blockchain is a clock and a notary. It should not be a filing cabinet.

---

## 9. Technical Specifications

| Parameter | Value |
|-----------|-------|
| Protocol prefix | `PFM3` (0x50464d33) |
| Anchor size | 36 bytes (4 prefix + 32 SHA-256) |
| On-chain script | `OP_RETURN OP_PUSH(36) <data>` |
| Hash algorithm | SHA-256 |
| P2P port | 9735 |
| P2P magic | `PFM3` (4 bytes) |
| Max payload | 2 MB |
| Max document size | 100 MB |
| Handshake auth | secp256k1 Schnorr challenge-response |
| Peer discovery | Nostr kind 30078, d-tag `pfm3-node` |
| Default relays | relay.damus.io, nos.lol, relay.nostr.band |
| Store path | `~/.pfm/l3/store/<checksum>.pfm` |
| Index | `~/.pfm/l3/index.json` |
| Python | >= 3.11 |
| Core dependencies | None (stdlib only) |
| P2P dependencies | websockets >= 12.0, secp256k1 |
| VeilCloud dependencies | cryptography >= 41.0 (optional, for encryption only) |
| VeilCloud KDF | PBKDF2-HMAC-SHA256, 600,000 iterations |
| VeilCloud encryption | AES-256-GCM |
| VeilCloud threshold | Shamir SSS over GF(256), max 255 shares |

---

## 10. Conclusion

Bitcoin is the most secure timestamping system ever created. Using it to store data is like using a bank vault to hold Post-it notes — it works, but it wastes the vault's capacity and makes everyone's safe deposit box more expensive.

Bitcoin L3 uses L1 for what it does best: providing an immutable, globally-replicated commitment that a piece of data existed at a specific point in time. The data itself lives on L3, where it can be stored, replicated, searched, and shared without adding a single byte to every full node's disk.

36 bytes per document. Permanent proof. Zero bloat.

---

*Bitcoin L3 is open source under the MIT license.*
*2026*
