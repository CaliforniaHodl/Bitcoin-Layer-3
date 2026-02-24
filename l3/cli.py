"""
L3 CLI — Bitcoin L3 anchoring commands for PFM documents.

Commands:
  l3 anchor        - Anchor a .pfm file's checksum to Bitcoin (OP_RETURN)
  l3 verify-anchor - Verify on-chain anchor matches document checksum
  l3 store         - Store a .pfm file in local L3 content-addressed store
  l3 get           - Retrieve a document from L3 store by checksum
  l3 list          - List all documents in L3 store
  l3 import        - Import anchor reference from L1 by txid
  l3 node start    - Start L3 P2P node (foreground)
  l3 node status   - Show node identity and config
  l3 node peers    - List known peers
  l3 node add-peer - Manually add a peer
  l3 fetch         - Fetch a document from the P2P network by checksum
  l3 api start     - Start the Anchor API HTTP server
  l3 api status    - Show Anchor API service status
  l3 veilcloud     - VeilCloud privacy primitives (encrypt, split-key, merkle, audit, credential)
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def _add_rpc_args(parser: argparse.ArgumentParser) -> None:
    """Add common Bitcoin RPC flags to a subparser.

    SECURITY: RPC password is NOT accepted via CLI args (visible in ps/proc).
    Use --rpc-cookie for Bitcoin Core cookie auth, or set BITCOIN_RPC_PASS env var.
    """
    parser.add_argument("--rpc-url", help="Bitcoin RPC URL (or set BITCOIN_RPC_URL)")
    parser.add_argument("--rpc-user", help="Bitcoin RPC username (or set BITCOIN_RPC_USER)")
    parser.add_argument(
        "--rpc-cookie",
        help="Path to Bitcoin Core .cookie file for cookie auth",
    )


def _read_cookie_file(cookie_path: str) -> tuple[str, str]:
    """Read Bitcoin Core cookie file. Returns (user, password)."""
    path = Path(cookie_path)
    if not path.is_file():
        print(f"Error: Cookie file not found: {cookie_path}", file=sys.stderr)
        sys.exit(1)
    content = path.read_text().strip()
    if ":" not in content:
        print(f"Error: Invalid cookie file format: {cookie_path}", file=sys.stderr)
        sys.exit(1)
    user, password = content.split(":", 1)
    return user, password


def _get_rpc(args: argparse.Namespace):
    """Build a BitcoinRPC from CLI flags, cookie auth, or env vars.

    Priority: --rpc-cookie > env vars > --rpc-user
    """
    from l3.anchor import BitcoinRPC

    url = getattr(args, "rpc_url", None) or os.environ.get("BITCOIN_RPC_URL", "")
    if not url:
        print(
            "Error: No Bitcoin RPC URL. Use --rpc-url or set BITCOIN_RPC_URL.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Cookie auth takes priority (most secure)
    cookie_path = getattr(args, "rpc_cookie", None)
    if cookie_path:
        user, password = _read_cookie_file(cookie_path)
        return BitcoinRPC(url, user, password)

    # Fall back to env vars (password never from CLI args)
    user = getattr(args, "rpc_user", None) or os.environ.get("BITCOIN_RPC_USER", "")
    password = os.environ.get("BITCOIN_RPC_PASS", "")
    return BitcoinRPC(url, user, password)


def cmd_anchor(args: argparse.Namespace) -> None:
    """Anchor a .pfm file's checksum to Bitcoin via OP_RETURN.

    Automatically stores the document in L3 and links the txid.
    """
    from l3._format.reader import PFMReader
    from l3.anchor import anchor_document
    from l3.store import L3Store

    doc = PFMReader.read(args.path)
    rpc = _get_rpc(args)

    try:
        txid = anchor_document(doc, rpc)
    except Exception as e:
        print(f"Error: Anchoring failed: {e}", file=sys.stderr)
        sys.exit(1)

    # Write updated doc with anchor metadata
    doc.write(args.path)
    network = doc.custom_meta.get("anchor_network", "unknown")
    checksum = doc.custom_meta.get("anchor_hash", "")

    # Auto-store in L3 and link the txid
    store = L3Store()
    store.store(doc)
    store.update_txid(checksum, txid, network, force=True)

    print(f"Anchored {args.path} to Bitcoin ({network})")
    print(f"  txid: {txid}")
    print(f"  hash: {checksum}")
    print(f"  L3:   stored and indexed")


def cmd_verify_anchor(args: argparse.Namespace) -> None:
    """Verify on-chain anchor matches document checksum."""
    from l3._format.reader import PFMReader
    from l3.anchor import verify_anchor

    doc = PFMReader.read(args.path)
    txid = doc.custom_meta.get("anchor_txid")
    if not txid:
        print(f"FAIL: {args.path} has no anchor metadata", file=sys.stderr)
        sys.exit(1)

    rpc = _get_rpc(args)

    try:
        valid = verify_anchor(doc, rpc)
    except Exception as e:
        print(f"Error: Verification failed: {e}", file=sys.stderr)
        sys.exit(1)

    if valid:
        network = doc.custom_meta.get("anchor_network", "unknown")
        print(f"OK: {args.path} anchor verified on {network}")
        print(f"  txid: {txid}")
    else:
        print(f"FAIL: {args.path} anchor mismatch (tampered or wrong transaction)")
        sys.exit(1)


def cmd_store(args: argparse.Namespace) -> None:
    """Store a .pfm file in local L3 content-addressed store."""
    from l3._format.reader import PFMReader
    from l3.store import L3Store

    doc = PFMReader.read(args.path)
    store = L3Store()
    checksum = store.store(doc)
    print(f"Stored {args.path} in L3")
    print(f"  checksum: {checksum}")


def cmd_get(args: argparse.Namespace) -> None:
    """Retrieve a document from L3 store by checksum."""
    from l3.store import L3Store, L3StoreError

    store = L3Store()
    try:
        doc = store.retrieve(args.checksum)
    except (ValueError, L3StoreError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    output = args.output or f"{args.checksum[:12]}.pfm"
    if ".." in Path(output).parts:
        print("Error: Output path must not contain '..' (path traversal)", file=sys.stderr)
        sys.exit(1)
    nbytes = doc.write(output)
    print(f"Retrieved -> {output} ({nbytes} bytes)")


def cmd_list(args: argparse.Namespace) -> None:
    """List all documents in L3 store."""
    from l3.store import L3Store

    store = L3Store()
    entries = store.list()

    if not entries:
        print("L3 store is empty.")
        return

    print(f"L3 Store: {len(entries)} document(s)\n")
    for entry in entries:
        checksum = entry["checksum"]
        txid = entry.get("anchor_txid", "")
        stored = entry.get("stored_at", "")
        doc_id = entry.get("doc_id", "")
        line = f"  {checksum[:16]}..."
        if doc_id:
            line += f"  id={doc_id[:8]}..."
        if txid:
            line += f"  tx={txid[:12]}..."
        if stored:
            line += f"  {stored[:19]}"
        print(line)


def cmd_import(args: argparse.Namespace) -> None:
    """Import a document reference from L1 — read checksum from on-chain txid, check L3."""
    from l3.anchor import lookup_anchor
    from l3.store import L3Store

    rpc = _get_rpc(args)
    txid = args.txid

    try:
        result = lookup_anchor(txid, rpc)
    except Exception as e:
        print(f"Error: Failed to read transaction: {e}", file=sys.stderr)
        sys.exit(1)

    if result is None:
        print(f"FAIL: Transaction {txid} has no PFM OP_RETURN data", file=sys.stderr)
        sys.exit(1)

    prefix, checksum = result
    print(f"Found PFM anchor in tx {txid[:16]}...")
    print(f"  prefix:   {prefix}")
    print(f"  checksum: {checksum}")

    store = L3Store()
    if store.contains(checksum):
        # Link the txid to the existing L3 entry
        try:
            store.update_txid(checksum, txid, rpc.get_network(), force=True)
        except Exception:
            pass  # Already linked or index mismatch — not fatal
        print(f"  L3:       found — document is stored locally")
    else:
        print(f"  L3:       NOT FOUND — document not in local store")
        print(f"            To store it, obtain the .pfm file and run: l3 store <file>")


def cmd_node_start(args: argparse.Namespace) -> None:
    """Start the L3 P2P node in foreground mode."""
    from l3.p2p.server import run_node

    relays = [args.relay] if getattr(args, "relay", None) else None
    run_node(
        port=getattr(args, "port", None),
        host=getattr(args, "host", None),
        relays=relays,
    )


def cmd_node_status(args: argparse.Namespace) -> None:
    """Show node identity and configuration."""
    from l3.p2p.nostr import load_or_create_key
    from l3.store import L3Store
    from l3 import P2P_DEFAULT_PORT, P2P_DEFAULT_RELAYS

    _privkey, pubkey = load_or_create_key()
    store = L3Store()
    docs = store.list()

    print(f"L3 Node Identity")
    print(f"  pubkey:    {pubkey}")
    print(f"  port:      {P2P_DEFAULT_PORT}")
    print(f"  documents: {len(docs)}")
    print(f"  relays:    {len(P2P_DEFAULT_RELAYS)}")


def cmd_node_peers(args: argparse.Namespace) -> None:
    """List known peers from the persisted peer file."""
    import json
    from pathlib import Path

    peers_path = Path.home() / ".pfm" / "l3" / "peers.json"
    if not peers_path.is_file():
        print("No known peers.")
        return

    try:
        data = json.loads(peers_path.read_text())
    except (json.JSONDecodeError, OSError):
        print("No known peers.")
        return

    if not data:
        print("No known peers.")
        return

    print(f"Known peers: {len(data)}\n")
    for peer in data:
        host = peer.get("host", "?")
        port = peer.get("port", "?")
        pubkey = peer.get("pubkey", "")[:12]
        score = peer.get("score", 0)
        line = f"  {host}:{port}"
        if pubkey:
            line += f"  key={pubkey}..."
        line += f"  score={score:.1f}"
        print(line)


def cmd_node_add_peer(args: argparse.Namespace) -> None:
    """Manually add a peer to the known peers list."""
    import asyncio
    import json
    from pathlib import Path

    addr = args.address
    if ":" not in addr:
        print("Error: Address must be host:port (e.g., 1.2.3.4:9735)", file=sys.stderr)
        sys.exit(1)

    host, port_str = addr.rsplit(":", 1)
    try:
        port = int(port_str)
    except ValueError:
        print(f"Error: Invalid port: {port_str}", file=sys.stderr)
        sys.exit(1)

    peers_path = Path.home() / ".pfm" / "l3" / "peers.json"
    peers_path.parent.mkdir(parents=True, exist_ok=True)

    data = []
    if peers_path.is_file():
        try:
            data = json.loads(peers_path.read_text())
        except (json.JSONDecodeError, OSError):
            data = []

    # Check for duplicates
    for p in data:
        if p.get("host") == host and p.get("port") == port:
            print(f"Peer {addr} already known.")
            return

    data.append({"host": host, "port": port, "pubkey": "", "score": 1.0, "last_seen": 0})
    peers_path.write_text(json.dumps(data, indent=2))
    print(f"Added peer {addr}")


def cmd_fetch(args: argparse.Namespace) -> None:
    """Fetch a document from the P2P network by checksum."""
    import asyncio
    from l3.store import L3Store
    from l3.p2p.nostr import load_or_create_key
    from l3.p2p.peer_manager import PeerManager
    from l3.p2p.sync import SyncEngine
    from l3.p2p.protocol import WANT, make_message
    from l3.p2p.connection import ConnectionError as PeerConnError

    checksum = args.checksum
    if len(checksum) != 64:
        print("Error: Checksum must be 64 hex characters", file=sys.stderr)
        sys.exit(1)

    store = L3Store()
    if store.contains(checksum):
        print(f"Document {checksum[:12]}... already in local store.")
        return

    _privkey, pubkey = load_or_create_key()
    sync_engine = SyncEngine(store)
    pm = PeerManager(
        our_pubkey=pubkey,
        our_privkey=_privkey,
        our_store_size=len(store.list()),
        on_message=sync_engine.handle_message,
    )

    async def _fetch() -> bool:
        # Connect to known peers and request the document
        saved = pm.load_peers()
        if not saved:
            print("No known peers. Add peers with: l3 node add-peer <host:port>")
            return False

        for peer in saved:
            host = peer.get("host", "")
            port = peer.get("port", 0)
            if not host or not port:
                continue

            conn = await pm.connect_to(host, port)
            if not conn or not conn.is_alive:
                continue

            try:
                # Register WANT via public API (BT-R3-005 fix — no internal access)
                await sync_engine.register_want(checksum, conn.peer_pubkey)

                want_msg = make_message(WANT, {"checksum": checksum})
                await conn.send(want_msg)
                print(f"Requested {checksum[:12]}... from {host}:{port}")

                # Wait briefly for a response
                await asyncio.sleep(5.0)

                if store.contains(checksum):
                    return True
            except PeerConnError:
                continue

        await pm.shutdown()
        return store.contains(checksum)

    found = asyncio.run(_fetch())

    if found:
        print(f"Fetched {checksum[:12]}... and stored in L3.")
    else:
        print(f"Document {checksum[:12]}... not found on the network.", file=sys.stderr)
        sys.exit(1)


def cmd_vc_encrypt(args: argparse.Namespace) -> None:
    """Encrypt a file with AES-256-GCM."""
    import getpass
    from l3.veilcloud.crypto import encrypt, EncryptedPayload

    path = Path(args.path)
    if not path.is_file():
        print(f"Error: File not found: {path}", file=sys.stderr)
        sys.exit(1)

    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Error: Passwords do not match", file=sys.stderr)
        sys.exit(1)

    plaintext = path.read_bytes()
    payload = encrypt(plaintext, password)

    out_path = Path(args.output) if args.output else path.with_suffix(path.suffix + ".enc")
    out_path.write_bytes(payload.to_bytes())
    print(f"Encrypted {path} -> {out_path} ({len(payload.to_bytes())} bytes)")


def cmd_vc_decrypt(args: argparse.Namespace) -> None:
    """Decrypt a file encrypted with VeilCloud."""
    import getpass
    from l3.veilcloud.crypto import decrypt, EncryptedPayload

    path = Path(args.path)
    if not path.is_file():
        print(f"Error: File not found: {path}", file=sys.stderr)
        sys.exit(1)

    password = getpass.getpass("Password: ")

    try:
        payload = EncryptedPayload.from_bytes(path.read_bytes())
        plaintext = decrypt(payload, password)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.output:
        out_path = Path(args.output)
    elif path.suffix == ".enc":
        out_path = path.with_suffix("")
    else:
        out_path = path.with_suffix(".dec")

    out_path.write_bytes(plaintext)
    print(f"Decrypted {path} -> {out_path} ({len(plaintext)} bytes)")


def cmd_vc_split_key(args: argparse.Namespace) -> None:
    """Split a secret into Shamir shares."""
    from l3.veilcloud.threshold import split_secret

    key_path = Path(args.key_file)
    if not key_path.is_file():
        print(f"Error: Key file not found: {key_path}", file=sys.stderr)
        sys.exit(1)

    secret = key_path.read_bytes()
    threshold = args.threshold
    total = args.total

    try:
        shares = split_secret(secret, threshold, total)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.output_dir) if args.output_dir else key_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    for share in shares:
        share_path = out_dir / f"share-{share.index:03d}.hex"
        share_path.write_text(share.to_hex())
        print(f"  Share {share.index}/{total} -> {share_path}")

    print(f"\nSplit into {total} shares (threshold: {threshold})")


def cmd_vc_combine_key(args: argparse.Namespace) -> None:
    """Combine Shamir shares to recover a secret."""
    from l3.veilcloud.threshold import combine_shares, Share

    shares = []
    for share_path_str in args.share_files:
        share_path = Path(share_path_str)
        if not share_path.is_file():
            print(f"Error: Share file not found: {share_path}", file=sys.stderr)
            sys.exit(1)
        hex_data = share_path.read_text().strip()
        try:
            shares.append(Share.from_hex(hex_data))
        except ValueError as e:
            print(f"Error parsing {share_path}: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        secret = combine_shares(shares)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    out_path = Path(args.output)
    out_path.write_bytes(secret)
    print(f"Recovered secret -> {out_path} ({len(secret)} bytes)")


def cmd_vc_merkle_root(args: argparse.Namespace) -> None:
    """Compute Merkle root from checksums."""
    from l3.veilcloud.merkle import MerkleTree

    checksums = list(args.checksums)

    # If no checksums provided, read from L3 store
    if not checksums:
        from l3.store import L3Store
        store = L3Store()
        entries = store.list()
        checksums = [e["checksum"] for e in entries]
        if not checksums:
            print("No checksums provided and L3 store is empty.", file=sys.stderr)
            sys.exit(1)
        print(f"Using {len(checksums)} checksums from L3 store")

    try:
        tree = MerkleTree.from_checksums(checksums)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Merkle root: {tree.root_hex}")
    print(f"  Leaves: {tree.leaf_count}")


def cmd_vc_audit_log(args: argparse.Namespace) -> None:
    """Add an entry to an audit log."""
    import json as json_mod
    from l3.veilcloud.audit import AuditLog

    log = AuditLog(args.name)
    data = {}
    if args.data:
        try:
            data = json_mod.loads(args.data)
        except json_mod.JSONDecodeError:
            data = {"message": args.data}

    entry = log.log(args.event_type, args.actor, data)
    print(f"Logged [{args.event_type}] by {args.actor}")
    print(f"  sequence: {entry.sequence}")
    print(f"  hash:     {entry.entry_hash[:16]}...")


def cmd_vc_audit_verify(args: argparse.Namespace) -> None:
    """Verify audit log chain integrity."""
    from l3.veilcloud.audit import AuditLog

    log = AuditLog(args.name)
    if len(log) == 0:
        print(f"Audit log '{args.name}' is empty.")
        return

    if log.verify_chain():
        print(f"OK: Audit log '{args.name}' chain verified ({len(log)} entries)")
    else:
        print(f"FAIL: Audit log '{args.name}' chain is broken", file=sys.stderr)
        sys.exit(1)


def cmd_vc_audit_proof(args: argparse.Namespace) -> None:
    """Generate Merkle proof for an audit entry."""
    from l3.veilcloud.audit import AuditLog
    from l3.veilcloud.merkle import verify_proof

    log = AuditLog(args.name)
    try:
        proof = log.get_proof(args.sequence)
    except (IndexError, ValueError) as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    valid = verify_proof(proof)
    print(f"Merkle proof for entry #{args.sequence} in '{args.name}':")
    print(f"  root:     {proof.root_hex}")
    print(f"  siblings: {len(proof.siblings)}")
    print(f"  valid:    {'yes' if valid else 'NO'}")


def cmd_vc_credential_issue(args: argparse.Namespace) -> None:
    """Issue an access credential."""
    from l3.veilcloud.access import CredentialManager, Permission

    key = _load_vc_signing_key()
    manager = CredentialManager(key)

    perm_map = {
        "read": Permission.READ,
        "write": Permission.WRITE,
        "delete": Permission.DELETE,
        "share": Permission.SHARE,
        "admin": Permission.ADMIN,
    }

    permissions = 0
    for p in args.permissions:
        p_lower = p.lower()
        if p_lower not in perm_map:
            print(f"Error: Unknown permission: {p}", file=sys.stderr)
            sys.exit(1)
        permissions |= perm_map[p_lower]

    cred = manager.issue_credential(
        args.user_id,
        permissions,
        expires_at=args.expires or "",
    )

    out_path = Path(args.output) if args.output else None
    cred_json = cred.to_json()

    if out_path:
        out_path.write_text(cred_json)
        print(f"Credential issued -> {out_path}")
    else:
        print(cred_json)

    print(f"  id:          {cred.credential_id}")
    print(f"  user:        {cred.user_id}")
    print(f"  permissions: {cred.permissions:#04x}")


def cmd_vc_credential_verify(args: argparse.Namespace) -> None:
    """Verify an access credential."""
    import json as json_mod
    from l3.veilcloud.access import CredentialManager, Credential

    key = _load_vc_signing_key()
    manager = CredentialManager(key)

    cred_path = Path(args.credential_file)
    if not cred_path.is_file():
        print(f"Error: Credential file not found: {cred_path}", file=sys.stderr)
        sys.exit(1)

    try:
        cred = Credential.from_json(cred_path.read_text())
    except (json_mod.JSONDecodeError, KeyError, TypeError) as e:
        print(f"Error: Invalid credential file: {e}", file=sys.stderr)
        sys.exit(1)

    if manager.verify_credential(cred):
        print(f"OK: Credential {cred.credential_id[:12]}... is valid")
        print(f"  user:        {cred.user_id}")
        print(f"  permissions: {cred.permissions:#04x}")
        if cred.expires_at:
            print(f"  expires:     {cred.expires_at}")
    else:
        print(f"FAIL: Credential verification failed", file=sys.stderr)
        sys.exit(1)


def cmd_vc_credential_revoke(args: argparse.Namespace) -> None:
    """Revoke an access credential."""
    from l3.veilcloud.access import CredentialManager

    key = _load_vc_signing_key()
    manager = CredentialManager(key)
    manager.revoke_credential(args.credential_id)
    print(f"Revoked credential {args.credential_id}")


def _load_vc_signing_key() -> bytes:
    """Load or generate the VeilCloud signing key.

    Stored at ~/.pfm/l3/veilcloud/signing_key (mode 600 equivalent).
    """
    key_path = Path.home() / ".pfm" / "l3" / "veilcloud" / "signing_key"
    if key_path.is_file():
        return bytes.fromhex(key_path.read_text().strip())

    import secrets as sec
    key = sec.token_bytes(32)
    key_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.write_text(key.hex())
    return key


def cmd_api_start(args: argparse.Namespace) -> None:
    """Start the Anchor API HTTP server."""
    from l3.api import run_api

    rpc = _get_rpc(args)
    host = getattr(args, "host", None) or "127.0.0.1"
    port = getattr(args, "port", None) or 8080

    run_api(rpc, host=host, port=port)


def cmd_api_status(args: argparse.Namespace) -> None:
    """Show Anchor API service status."""
    import urllib.request
    import urllib.error

    host = getattr(args, "host", None) or "127.0.0.1"
    port = getattr(args, "port", None) or 8080
    url = f"http://{host}:{port}/status"

    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as resp:
            import json
            data = json.loads(resp.read().decode())
    except urllib.error.URLError as e:
        print(f"Error: Cannot reach API at {url}: {e.reason}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"L3 Anchor API — {url}")
    healthy = data.get("healthy", False)
    print(f"  healthy: {'yes' if healthy else 'NO'}")

    l1 = data.get("l1", {})
    if l1.get("connected"):
        print(f"  L1:      {l1.get('chain', '?')} block {l1.get('blocks', '?')}")
    else:
        print(f"  L1:      NOT CONNECTED")

    wallet = data.get("wallet", {})
    balance = wallet.get("balance_btc", "?")
    print(f"  wallet:  {balance} BTC")

    l3_store = data.get("l3_store", {})
    print(f"  L3 docs: {l3_store.get('documents', '?')}")

    invoices = data.get("invoices", {})
    if invoices:
        parts = [f"{k}={v}" for k, v in sorted(invoices.items())]
        print(f"  invoices: {', '.join(parts)}")
    else:
        print(f"  invoices: none")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="l3",
        description="Bitcoin L3 — anchor PFM document checksums to Bitcoin via OP_RETURN.",
    )
    from l3 import __version__
    parser.add_argument("--version", action="version", version=f"l3 {__version__}")
    sub = parser.add_subparsers(dest="command")

    # anchor
    p_anchor = sub.add_parser("anchor", help="Anchor checksum to Bitcoin (OP_RETURN)")
    p_anchor.add_argument("path", help="Path to .pfm file")
    _add_rpc_args(p_anchor)

    # verify-anchor
    p_va = sub.add_parser("verify-anchor", help="Verify on-chain anchor matches checksum")
    p_va.add_argument("path", help="Path to .pfm file")
    _add_rpc_args(p_va)

    # store
    p_store = sub.add_parser("store", help="Store in local L3 content-addressed store")
    p_store.add_argument("path", help="Path to .pfm file")

    # get
    p_get = sub.add_parser("get", help="Retrieve from L3 store by checksum")
    p_get.add_argument("checksum", help="SHA-256 checksum of the document")
    p_get.add_argument("-o", "--output", help="Output file path")

    # list
    sub.add_parser("list", help="List all documents in L3 store")

    # import
    p_imp = sub.add_parser("import", help="Import anchor reference from L1 by txid")
    p_imp.add_argument("txid", help="Bitcoin transaction ID containing PFM OP_RETURN")
    _add_rpc_args(p_imp)

    # node (with subcommands)
    p_node = sub.add_parser("node", help="P2P node management")
    node_sub = p_node.add_subparsers(dest="node_command")

    p_ns = node_sub.add_parser("start", help="Start L3 P2P node (foreground)")
    p_ns.add_argument("--port", type=int, help="TCP listen port (default: 9735)")
    p_ns.add_argument("--host", help="Listen address (default: 127.0.0.1)")
    p_ns.add_argument("--relay", help="Nostr relay URL")

    node_sub.add_parser("status", help="Show node identity and config")
    node_sub.add_parser("peers", help="List known peers")

    p_nap = node_sub.add_parser("add-peer", help="Manually add a peer")
    p_nap.add_argument("address", help="Peer address as host:port")

    # fetch
    p_fetch = sub.add_parser("fetch", help="Fetch a document from the P2P network")
    p_fetch.add_argument("checksum", help="SHA-256 checksum of the document to fetch")

    # api (with subcommands)
    p_api = sub.add_parser("api", help="Anchor API HTTP server")
    api_sub = p_api.add_subparsers(dest="api_command")

    p_api_start = api_sub.add_parser("start", help="Start the Anchor API server")
    p_api_start.add_argument("--port", type=int, default=8080, help="Listen port (default: 8080)")
    p_api_start.add_argument("--host", default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    _add_rpc_args(p_api_start)

    p_api_status = api_sub.add_parser("status", help="Show API service status")
    p_api_status.add_argument("--port", type=int, default=8080, help="API port (default: 8080)")
    p_api_status.add_argument("--host", default="127.0.0.1", help="API host (default: 127.0.0.1)")

    # veilcloud (with subcommands)
    p_vc = sub.add_parser("veilcloud", help="VeilCloud privacy primitives")
    vc_sub = p_vc.add_subparsers(dest="vc_command")

    p_vc_enc = vc_sub.add_parser("encrypt", help="Encrypt a file (AES-256-GCM)")
    p_vc_enc.add_argument("path", help="File to encrypt")
    p_vc_enc.add_argument("-o", "--output", help="Output file path")

    p_vc_dec = vc_sub.add_parser("decrypt", help="Decrypt a file")
    p_vc_dec.add_argument("path", help="Encrypted file to decrypt")
    p_vc_dec.add_argument("-o", "--output", help="Output file path")

    p_vc_split = vc_sub.add_parser("split-key", help="Split a key into Shamir shares")
    p_vc_split.add_argument("key_file", help="File containing the secret key")
    p_vc_split.add_argument("-t", "--threshold", type=int, required=True, help="Minimum shares to reconstruct")
    p_vc_split.add_argument("-n", "--total", type=int, required=True, help="Total shares to create")
    p_vc_split.add_argument("-d", "--output-dir", help="Output directory for share files")

    p_vc_combine = vc_sub.add_parser("combine-key", help="Combine Shamir shares")
    p_vc_combine.add_argument("share_files", nargs="+", help="Share files to combine")
    p_vc_combine.add_argument("-o", "--output", required=True, help="Output file for recovered secret")

    p_vc_merkle = vc_sub.add_parser("merkle-root", help="Compute Merkle root from checksums")
    p_vc_merkle.add_argument("checksums", nargs="*", help="SHA-256 checksums (reads L3 store if omitted)")

    # veilcloud audit subcommands
    p_vc_audit = vc_sub.add_parser("audit", help="Audit trail operations")
    audit_sub = p_vc_audit.add_subparsers(dest="audit_command")

    p_vc_al = audit_sub.add_parser("log", help="Add audit log entry")
    p_vc_al.add_argument("name", help="Audit log name")
    p_vc_al.add_argument("event_type", help="Event type (e.g. STORE, ANCHOR)")
    p_vc_al.add_argument("actor", help="Who performed the action")
    p_vc_al.add_argument("--data", help="Event data (JSON string or plain text)")

    p_vc_av = audit_sub.add_parser("verify", help="Verify audit log chain")
    p_vc_av.add_argument("name", help="Audit log name")

    p_vc_ap = audit_sub.add_parser("proof", help="Get Merkle proof for entry")
    p_vc_ap.add_argument("name", help="Audit log name")
    p_vc_ap.add_argument("sequence", type=int, help="Entry sequence number")

    # veilcloud credential subcommands
    p_vc_cred = vc_sub.add_parser("credential", help="Access control credentials")
    cred_sub = p_vc_cred.add_subparsers(dest="cred_command")

    p_vc_ci = cred_sub.add_parser("issue", help="Issue a credential")
    p_vc_ci.add_argument("user_id", help="User to issue credential to")
    p_vc_ci.add_argument("permissions", nargs="+", help="Permissions: read write delete share admin")
    p_vc_ci.add_argument("--expires", help="Expiry timestamp (ISO 8601)")
    p_vc_ci.add_argument("-o", "--output", help="Output file for credential JSON")

    p_vc_cv = cred_sub.add_parser("verify", help="Verify a credential")
    p_vc_cv.add_argument("credential_file", help="Credential JSON file")

    p_vc_cr = cred_sub.add_parser("revoke", help="Revoke a credential")
    p_vc_cr.add_argument("credential_id", help="Credential ID to revoke")

    args = parser.parse_args()

    if not args.command:
        print("Bitcoin L3 — PFM document anchoring to Bitcoin")
        print()
        print("Usage:")
        print("  l3 anchor file.pfm --rpc-url ... --rpc-cookie ~/.bitcoin/.cookie")
        print("  l3 verify-anchor file.pfm --rpc-url ...")
        print("  l3 store file.pfm")
        print("  l3 get <checksum> -o recovered.pfm")
        print("  l3 list")
        print("  l3 import <txid> --rpc-url ...")
        print("  l3 node start [--port N] [--relay wss://...]")
        print("  l3 node status")
        print("  l3 node peers")
        print("  l3 node add-peer <host:port>")
        print("  l3 fetch <checksum>")
        print("  l3 api start [--port N] [--host ADDR] --rpc-url ...")
        print("  l3 api status")
        print("  l3 veilcloud encrypt <file>")
        print("  l3 veilcloud decrypt <file>")
        print("  l3 veilcloud split-key <key-file> -t 3 -n 5")
        print("  l3 veilcloud combine-key share1.hex share2.hex share3.hex -o key.bin")
        print("  l3 veilcloud merkle-root [checksums...]")
        print("  l3 veilcloud audit {log|verify|proof}")
        print("  l3 veilcloud credential {issue|verify|revoke}")
        print()
        print("Run 'l3 <command> --help' for details on any command.")
        sys.exit(0)

    # Handle veilcloud subcommands
    if args.command == "veilcloud":
        vc = getattr(args, "vc_command", None)
        if not vc:
            print("Usage: l3 veilcloud {encrypt|decrypt|split-key|combine-key|merkle-root|audit|credential}")
            sys.exit(0)

        if vc == "audit":
            audit_cmds = {
                "log": cmd_vc_audit_log,
                "verify": cmd_vc_audit_verify,
                "proof": cmd_vc_audit_proof,
            }
            ac = getattr(args, "audit_command", None)
            if not ac:
                print("Usage: l3 veilcloud audit {log|verify|proof}")
                sys.exit(0)
            audit_cmds[ac](args)
            return

        if vc == "credential":
            cred_cmds = {
                "issue": cmd_vc_credential_issue,
                "verify": cmd_vc_credential_verify,
                "revoke": cmd_vc_credential_revoke,
            }
            cc = getattr(args, "cred_command", None)
            if not cc:
                print("Usage: l3 veilcloud credential {issue|verify|revoke}")
                sys.exit(0)
            cred_cmds[cc](args)
            return

        vc_commands = {
            "encrypt": cmd_vc_encrypt,
            "decrypt": cmd_vc_decrypt,
            "split-key": cmd_vc_split_key,
            "combine-key": cmd_vc_combine_key,
            "merkle-root": cmd_vc_merkle_root,
        }
        vc_commands[vc](args)
        return

    # Handle api subcommands
    if args.command == "api":
        api_commands = {
            "start": cmd_api_start,
            "status": cmd_api_status,
        }
        ac = getattr(args, "api_command", None)
        if not ac:
            print("Usage: l3 api {start|status}")
            sys.exit(0)
        api_commands[ac](args)
        return

    # Handle node subcommands
    if args.command == "node":
        node_commands = {
            "start": cmd_node_start,
            "status": cmd_node_status,
            "peers": cmd_node_peers,
            "add-peer": cmd_node_add_peer,
        }
        nc = getattr(args, "node_command", None)
        if not nc:
            print("Usage: l3 node {start|status|peers|add-peer}")
            sys.exit(0)
        node_commands[nc](args)
        return

    commands = {
        "anchor": cmd_anchor,
        "verify-anchor": cmd_verify_anchor,
        "store": cmd_store,
        "get": cmd_get,
        "list": cmd_list,
        "import": cmd_import,
        "fetch": cmd_fetch,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
