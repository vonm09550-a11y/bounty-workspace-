#!/usr/bin/env python3
"""
Extract blockchain events for tBTC Bridge and WalletRegistry contracts.

Contracts (Ethereum mainnet):
  Bridge:         0x5e4861a80B55f035D899f66772117F00FA0E8e7B  (deployed ~block 16_397_413)
  WalletRegistry: 0x46d52E41C2F300BC82217Ce22b920c34995204eb  (deployed ~block 15_639_521)

Events (all parameters are indexed → values live in topics, not data):
  1. NewWalletRegistered(bytes32 indexed ecdsaWalletID, bytes20 indexed walletPubKeyHash)
  2. DkgResultApproved(bytes32 indexed resultHash, address indexed approver)
  3. MovingFundsCompleted(bytes20 indexed walletPubKeyHash, bytes32 movingFundsTxHash)
       ↑ walletPubKeyHash indexed; movingFundsTxHash is non-indexed (in data)

Usage:
  python3 extract_blockchain_events.py
  python3 extract_blockchain_events.py --out /path/to/output.json
"""

import argparse, json, sys, time
from web3 import Web3

# ── Config ────────────────────────────────────────────────────────────────────
RPC_URLS = [
    "https://eth-mainnet.public.blastapi.io",   # supports 500k-block ranges
    "https://1rpc.io/eth",                      # supports 10k-block ranges (fallback)
]

BRIDGE     = "0x5e4861a80B55f035D899f66772117F00FA0E8e7B"
WALLET_REG = "0x46d52E41C2F300BC82217Ce22b920c34995204eb"

BRIDGE_DEPLOY  = 16_397_413
WREG_DEPLOY    = 15_639_521

CHUNK          = 500_000
CHUNK_FALLBACK = 10_000
REQUEST_DELAY  = 0.15
MAX_RETRIES    = 4

# ── Event topic hashes ────────────────────────────────────────────────────────
T_NEW_WALLET   = "0x" + Web3.keccak(text="NewWalletRegistered(bytes32,bytes20)").hex()
T_DKG_APPROVED = "0x" + Web3.keccak(text="DkgResultApproved(bytes32,address)").hex()
T_MOVING_DONE  = "0x" + Web3.keccak(text="MovingFundsCompleted(bytes20,bytes32)").hex()


def connect() -> Web3:
    for url in RPC_URLS:
        try:
            w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 30}))
            if w3.is_connected():
                print(f"Connected to {url}  (latest block {w3.eth.block_number:,})")
                return w3
        except Exception:
            pass
    raise RuntimeError("All RPC endpoints failed to connect")


def get_logs_chunked(w3: Web3, address: str, topic: str,
                     from_block: int, to_block: int, label: str) -> list:
    all_logs = []
    chunk = CHUNK
    for start in range(from_block, to_block + 1, chunk):
        end = min(start + chunk - 1, to_block)
        for attempt in range(MAX_RETRIES):
            try:
                logs = w3.eth.get_logs({
                    "address":   Web3.to_checksum_address(address),
                    "topics":    [topic],
                    "fromBlock": start,
                    "toBlock":   end,
                })
                all_logs.extend(logs)
                if logs:
                    print(f"  [{label}] {start:,}–{end:,}: {len(logs)} event(s)")
                time.sleep(REQUEST_DELAY)
                break
            except Exception as exc:
                msg = str(exc)
                if "too large" in msg.lower() or "range" in msg.lower():
                    # Provider only supports smaller ranges; fall back
                    chunk = CHUNK_FALLBACK
                    end = min(start + chunk - 1, to_block)
                    continue
                wait = 2 ** (attempt + 1)
                print(f"  WARN [{start}–{end}] attempt {attempt+1}: {exc} (retry {wait}s)")
                time.sleep(wait)
    return all_logs


# ── Decoders ──────────────────────────────────────────────────────────────────

def decode_new_wallet(log) -> dict:
    """NewWalletRegistered: both params indexed → in topics[1], topics[2]."""
    t = log["topics"]
    return {
        "block":            log["blockNumber"],
        "txHash":           log["transactionHash"].hex(),
        "ecdsaWalletID":    "0x" + t[1].hex(),
        "walletPubKeyHash": "0x" + t[2].hex()[:40],   # bytes20 left-aligned in 32-byte topic
    }


def decode_dkg_approved(log) -> dict:
    """DkgResultApproved: both params indexed → in topics[1], topics[2]."""
    t = log["topics"]
    return {
        "block":      log["blockNumber"],
        "txHash":     log["transactionHash"].hex(),
        "resultHash": "0x" + t[1].hex(),
        "approver":   Web3.to_checksum_address("0x" + t[2].hex()[-40:]),  # addr right-aligned
    }


def decode_moving_funds(log) -> dict:
    """MovingFundsCompleted: walletPubKeyHash indexed (topic[1]), movingFundsTxHash in data."""
    t    = log["topics"]
    data = log["data"].hex() if hasattr(log["data"], "hex") else log["data"]
    return {
        "block":             log["blockNumber"],
        "txHash":            log["transactionHash"].hex(),
        "walletPubKeyHash":  "0x" + t[1].hex()[:40],
        "movingFundsTxHash": "0x" + data.lstrip("0x"),
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Extract tBTC blockchain events")
    parser.add_argument("--out", default="/home/user/bounty-workspace-/blockchain_events.json")
    args = parser.parse_args()

    print(f"Topics:")
    print(f"  NewWalletRegistered  : {T_NEW_WALLET}")
    print(f"  DkgResultApproved    : {T_DKG_APPROVED}")
    print(f"  MovingFundsCompleted : {T_MOVING_DONE}")
    print()

    w3     = connect()
    latest = w3.eth.block_number

    # ── 1. NewWalletRegistered ─────────────────────────────────────────────
    print(f"\n{'='*62}")
    print(f"[1] NewWalletRegistered — Bridge {BRIDGE}")
    print(f"    blocks {BRIDGE_DEPLOY:,} → {latest:,}")
    print(f"{'='*62}")
    nw_raw  = get_logs_chunked(w3, BRIDGE, T_NEW_WALLET, BRIDGE_DEPLOY, latest, "NWR")
    wallets = [decode_new_wallet(l) for l in nw_raw]
    print(f"  → {len(wallets)} total\n")

    # ── 2. DkgResultApproved ───────────────────────────────────────────────
    print(f"{'='*62}")
    print(f"[2] DkgResultApproved — WalletRegistry {WALLET_REG}")
    print(f"    blocks {WREG_DEPLOY:,} → {latest:,}")
    print(f"{'='*62}")
    dkg_raw = get_logs_chunked(w3, WALLET_REG, T_DKG_APPROVED, WREG_DEPLOY, latest, "DKG")
    dkg     = [decode_dkg_approved(l) for l in dkg_raw]
    print(f"  → {len(dkg)} total\n")

    # ── 3. MovingFundsCompleted ────────────────────────────────────────────
    print(f"{'='*62}")
    print(f"[3] MovingFundsCompleted — Bridge {BRIDGE}")
    print(f"    blocks {BRIDGE_DEPLOY:,} → {latest:,}")
    print(f"{'='*62}")
    mf_raw  = get_logs_chunked(w3, BRIDGE, T_MOVING_DONE, BRIDGE_DEPLOY, latest, "MFC")
    moving  = [decode_moving_funds(l) for l in mf_raw]
    print(f"  → {len(moving)} total\n")

    # ── Save ───────────────────────────────────────────────────────────────
    results = {
        "NewWalletRegistered":  wallets,
        "DkgResultApproved":    dkg,
        "MovingFundsCompleted": moving,
    }
    with open(args.out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Saved → {args.out}")

    # ── Summary ────────────────────────────────────────────────────────────
    print(f"\n{'='*65}")
    print("SUMMARY")
    print(f"{'='*65}")
    print(f"  NewWalletRegistered  : {len(wallets):>5}")
    print(f"  DkgResultApproved    : {len(dkg):>5}")
    print(f"  MovingFundsCompleted : {len(moving):>5}")

    if wallets:
        print(f"\n── Registered Wallets ({'all' if len(wallets) <= 20 else 'first 20'}) ────────────────────────────")
        print(f"  {'#':>3}  {'block':>10}  {'walletPubKeyHash':42}  ecdsaWalletID")
        for i, w in enumerate(wallets[:20]):
            print(f"  {i+1:>3}  {w['block']:>10,}  {w['walletPubKeyHash']:42}  {w['ecdsaWalletID'][:20]}…")

    if dkg:
        print(f"\n── DkgResultApproved (all {len(dkg)}) ─────────────────────────────────────")
        print(f"  {'#':>3}  {'block':>10}  {'resultHash':66}  approver")
        for i, d in enumerate(dkg):
            print(f"  {i+1:>3}  {d['block']:>10,}  {d['resultHash']:66}  {d['approver']}")

    if moving:
        print(f"\n── MovingFundsCompleted (all {len(moving)}) ────────────────────────────────")
        print(f"  {'#':>3}  {'block':>10}  {'walletPubKeyHash':42}  movingFundsTxHash")
        for i, m in enumerate(moving):
            print(f"  {i+1:>3}  {m['block']:>10,}  {m['walletPubKeyHash']:42}  {m['movingFundsTxHash']}")


if __name__ == "__main__":
    main()
