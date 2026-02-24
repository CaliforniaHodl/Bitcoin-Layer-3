# bitcoin-l3

**Bitcoin L3 -- Anchor document checksums to Bitcoin via OP_RETURN.**

`v0.1.0` | Python 3.11+ | MIT License | Zero core dependencies | 18 CLI commands | 276 tests

---

## What It Does

Bitcoin L3 anchors document fingerprints (SHA-256 checksums) to the Bitcoin blockchain using OP_RETURN transactions. Documents are stored locally in a content-addressed store and distributed via a P2P network. Bitcoin L1 holds only a 36-byte proof -- not the data itself.

```
L1 (Bitcoin)                    L3 (Document Layer)
+---------------------------+   +---------------------------+
| Block 891,234             |   | ~/.pfm/l3/store/          |
|   tx: abc123...           |   |   a1b2c3d4...64hex.pfm    |
|   OP_RETURN               |   |   e5f6a7b8...64hex.pfm    |
|     PFM3 + sha256(doc)    |   |                           |
|                           |   | P2P: Nostr discovery      |
| 36 bytes. Permanent.      |   | INV/WANT/DATA sync cycle  |
+---------------------------+   +---------------------------+
```

---

## Quick Start

### Install

```bash
pip install -e .
```

For P2P networking (optional):

```bash
pip install -e ".[p2p]"
```

For VeilCloud privacy primitives (optional):

```bash
pip install -e ".[veilcloud]"
```

### Store a Document

```bash
l3 store document.pfm
# Stored document.pfm in L3
#   checksum: a1b2c3d4e5f6...
```

### Anchor to Bitcoin

Requires a running Bitcoin node with RPC access.

```bash
# Using cookie auth (recommended)
l3 anchor document.pfm \
  --rpc-url http://127.0.0.1:18332 \
  --rpc-cookie ~/.bitcoin/testnet3/.cookie

# Using env vars
export BITCOIN_RPC_URL=http://127.0.0.1:18332
export BITCOIN_RPC_USER=rpcuser
export BITCOIN_RPC_PASS=rpcpassword
l3 anchor document.pfm
```

### Verify On-Chain

```bash
l3 verify-anchor document.pfm --rpc-url http://127.0.0.1:18332
# OK: document.pfm anchor verified on testnet
```

---

## CLI Reference

### Document Commands

| Command | Description |
|---------|-------------|
| `l3 store <file>` | Store a .pfm file in the local content-addressed store |
| `l3 get <checksum> [-o file]` | Retrieve a document from the store by checksum |
| `l3 list` | List all documents in the store |

### Anchoring Commands

| Command | Description |
|---------|-------------|
| `l3 anchor <file>` | Anchor a document's checksum to Bitcoin via OP_RETURN |
| `l3 verify-anchor <file>` | Verify the on-chain anchor matches the document |
| `l3 import <txid>` | Look up a PFM anchor on-chain by transaction ID |

### P2P Commands

| Command | Description |
|---------|-------------|
| `l3 node start [--port N] [--host H] [--relay URL]` | Start the P2P node (foreground) |
| `l3 node status` | Show node identity and config |
| `l3 node peers` | List known peers |
| `l3 node add-peer <host:port>` | Manually add a peer |
| `l3 fetch <checksum>` | Fetch a document from the P2P network |

### VeilCloud Commands

| Command | Description |
|---------|-------------|
| `l3 veilcloud encrypt <file>` | Encrypt a file with AES-256-GCM (password prompt) |
| `l3 veilcloud decrypt <file>` | Decrypt an encrypted file |
| `l3 veilcloud split-key <key> -t T -n N` | Split a key into N Shamir shares (threshold T) |
| `l3 veilcloud combine-key <shares...> -o <out>` | Combine shares to recover a key |
| `l3 veilcloud merkle-root [checksums...]` | Compute Merkle root (reads L3 store if omitted) |
| `l3 veilcloud audit log <name> <type> <actor>` | Add an audit log entry |
| `l3 veilcloud audit verify <name>` | Verify audit log chain integrity |
| `l3 veilcloud audit proof <name> <seq>` | Get Merkle inclusion proof for entry |
| `l3 veilcloud credential issue <user> <perms...>` | Issue an HMAC-signed credential |
| `l3 veilcloud credential verify <file>` | Verify a credential file |
| `l3 veilcloud credential revoke <id>` | Revoke a credential by ID |

---

## P2P Network

### Start a Node

```bash
l3 node start
# L3 Node started
#   pubkey: 03a1b2c3d4...
#   listen: 127.0.0.1:9735
#   store:  12 documents
#   relays: 3
```

### Add Peers

```bash
l3 node add-peer 203.0.113.10:9735
```

### Fetch a Document

```bash
l3 fetch a1b2c3d4e5f6a7b8...  # 64-char SHA-256 checksum
# Fetched a1b2c3d4e5f6... and stored in L3.
```

### How It Works

1. Nodes discover each other via Nostr relays
2. On connect, nodes exchange signed challenges (secp256k1 Schnorr)
3. Nodes announce their inventory via INV messages
4. Missing documents are requested via WANT and delivered via DATA
5. Anchor announcements propagate via ANCHOR_ANN
6. All received documents are checksum-verified before storage

---

## Configuration

### Bitcoin RPC

| Method | How |
|--------|-----|
| Cookie auth | `--rpc-cookie ~/.bitcoin/.cookie` |
| Env vars | `BITCOIN_RPC_URL`, `BITCOIN_RPC_USER`, `BITCOIN_RPC_PASS` |
| CLI flags | `--rpc-url`, `--rpc-user` (password via env only) |

RPC passwords are never accepted as CLI arguments (visible in `ps`).

### Node Config

Optional config at `~/.pfm/l3/node.toml`:

```toml
port = 9735
host = "127.0.0.1"
max_outbound = 8
max_inbound = 16
nostr_discovery = true
discovery_interval = 300

relays = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.nostr.band",
]

[content_policy]
accept = ["legal", "record"]     # only store these categories
reject = ["*"]                    # reject everything else
max_document_size = "50MB"        # per-document cap
require_category = true           # reject untagged documents
```

### Paths

| Path | Purpose |
|------|---------|
| `~/.pfm/l3/store/` | Content-addressed document store |
| `~/.pfm/l3/index.json` | Document metadata index |
| `~/.pfm/l3/node_key` | Node identity key (secp256k1 private key, hex) |
| `~/.pfm/l3/peers.json` | Known peers list |
| `~/.pfm/l3/node.toml` | Node configuration |

---

## Building L1 (Bitcoin Finney)

Bitcoin L3 requires a Bitcoin node for anchoring. [Bitcoin Finney](../Finney/) is a minimal fork of Bitcoin Knots stripped to just the daemon and CLI -- no GUI, no mining tools, no bloat.

```bash
cd Finney
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)
```

**Result:** `bitcoind` + `bitcoin-cli`. Two binaries. Full node. Full RPC. SQLite wallet for funding anchors.

### Start on Testnet

```bash
./build/bin/bitcoind -testnet -server -daemon -txindex
./build/bin/bitcoin-cli -testnet createwallet "l3"
```

### Dependencies

CMake 3.22+, C++20 compiler (GCC 11+, Clang 16+, or MSVC 2022+), Boost (headers), libevent 2.1.8+, SQLite 3.7.17+.

See the [Finney README](../Finney/README.md) for full build details.

---

## Security

Bitcoin L3 has been through 4 rounds of adversarial security testing (black-team attack, red-team fix).

| Metric | Value |
|--------|-------|
| Total fixes | 43 |
| Critical/High remaining | 0 |
| Test functions | 287 |
| Tests passing | 276 (11 skipped -- secp256k1 not in CI) |

### Key Defenses

- **Authentication:** secp256k1 challenge-response handshake, fail-closed without private key
- **Anti-amplification:** per-peer WANT rate limit (10/sec), bandwidth cap (2 MB/sec)
- **Anti-Sybil:** per-IP inbound limit (2/IP), progressive inventory disclosure
- **Anti-injection:** DATA/NOT_FOUND source validation, anchor overwrite protection
- **Anti-DoS:** batch locking, checksum cache, disconnect cleanup, task cleanup
- **Architectural firewall:** no P2P message can trigger a Bitcoin RPC call

### Content Accountability

L3 solves the content moderation problem that L1 inscriptions can't: content lives off-chain, so it can be removed. The hash on L1 becomes a dead pointer.

- **Channel model** -- nothing hits L1 except a 36-byte hash (reveals nothing about content)
- **Bitcoin address tracing** -- every anchor tx has a funding address, linking checksum to identity
- **Node content policies** -- operators opt in to content categories (legal, art, media, etc.)
- **Report & delete** -- flag content, each node decides independently, uploader traced via anchor address

### Deferred (Pre-Public Internet)

- TLS encryption on P2P connections
- Handshake channel binding
- Node key encryption at rest

Full reports in the project root: `BLACK-TEAM-*.md` and `RED-TEAM-*.md`.

---

## Development

### Run Tests

```bash
pip install -e ".[p2p]"
pip install pytest pytest-asyncio

pytest tests/ -v
# 276 passed, 11 skipped in ~13s
```

### Project Structure

```
l3/
  __init__.py           Constants, version
  anchor.py             Bitcoin RPC + OP_RETURN anchoring
  cli.py                CLI commands (18 commands)
  store.py              Content-addressed document store
  _format/
    document.py         PFMDocument model
    reader.py           Fast lazy PFM parser
    writer.py           PFM serialization
    spec.py             Format specification
  api/
    server.py           HTTP server + routing
    handlers.py         Request handlers (anchor, batch, Merkle proof)
    auth.py             API key authentication
    invoices.py         Invoice management
    watcher.py          Payment watcher
  p2p/
    protocol.py         Wire protocol (11 message types)
    nostr.py            Nostr key management + relay discovery
    connection.py       TCP peer connection + handshake
    peer_manager.py     Peer table, scoring, persistence
    sync.py             Document sync engine (INV/WANT/DATA)
    server.py           P2P node server
  veilcloud/
    __init__.py         Package init + re-exports
    merkle.py           Merkle tree + proof generation/verification
    crypto.py           AES-256-GCM encryption + PBKDF2 key derivation
    threshold.py        Shamir's Secret Sharing over GF(256)
    audit.py            Append-only audit log with hash chain
    access.py           HMAC-signed credentials + permissions
tests/
  test_anchor.py        Anchoring + store tests
  test_p2p.py           P2P protocol + security tests
  test_api.py           API handler tests
  test_veilcloud.py     VeilCloud module tests (74 tests)
```

### On-Chain Format

```
OP_RETURN  OP_PUSH(36)  "PFM3"        SHA-256 checksum
   6a         24        50464d33    <64 hex chars = 32 bytes>
```

36 bytes per document. Permanent proof. Zero bloat.

---

## Roadmap

### Current (v0.1)

- Documents stored locally and synced via P2P
- 36-byte OP_RETURN anchors committed to Bitcoin
- Manual anchoring and verification
- Node content policies (category-based opt-in)
- **VeilCloud privacy primitives** (native Python, zero external services):
  - AES-256-GCM client-side encryption with PBKDF2 key derivation
  - Shamir's Secret Sharing over GF(256) for threshold key management
  - Merkle tree construction + inclusion proofs (batch anchoring ready)
  - Append-only hash-chained audit logs with Merkle proofs
  - HMAC-signed credentials with permissions, expiry, and revocation
  - Batch anchoring API endpoint (`POST /batch-anchor`)

### Near-Term (v0.2)

- Automatic anchoring on document arrival
- Batch anchoring via Merkle trees (many docs per tx)
- Anchor verification daemon
- Minimal L1 build ([Bitcoin Finney](../Finney/) -- stripped Knots: daemon + RPC only)

### Medium-Term (v0.3)

- **TLS on P2P connections** -- required for public internet deployment
- Handshake channel binding (MITM prevention)
- Node key encryption at rest

---

## License

MIT -- see pyproject.toml.

2026
