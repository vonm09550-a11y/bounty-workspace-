#!/usr/bin/env python3
"""Phase D6-A fallback for mega-tokens whose pool signature list cannot be walked back to creation:
scan every block in the window (getBlock with transactionDetails=accounts), keep transactions whose
account keys include the pool or the bonding curve, parse them, and rewrite the launch's rows/parsed files.

    python3 scripts/anatomy_blockscan.py --out data/anatomy/loop1 [--only <mint> ...]
Runs on launches whose meta has pool_pages >= 4000 (capped) unless --only is given. Resumable per launch.
"""
import argparse
import datetime
import glob
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from clients import Helius  # noqa: E402
from anatomy_pull import compact  # noqa: E402


def log(path, msg):
    line = f"{datetime.datetime.utcnow().isoformat(timespec='seconds')} {msg}"
    print(line, flush=True)
    with open(path, "a") as f:
        f.write(line + "\n")


def scan(h, meta_p, logp, max_sigs=30000):
    m = json.load(open(meta_p))
    d = os.path.dirname(meta_p)
    mint, cts, window = m["token"], m["create_ts"], m["window_s"]
    rows_p = meta_p.replace(".meta.json", ".rows.jsonl")
    rows = [json.loads(l) for l in open(rows_p)]
    if not rows:
        log(logp, f"  {m['symbol']}: no curve rows, cannot anchor the slot; skipped"); return
    slot0 = min(r["slot"] for r in rows)
    keys = {a for a in (m.get("pool"), m.get("bonding_curve")) if a}
    have = {r["signature"] for r in rows}
    found = []
    slot, t0, blocks, empties = slot0, time.time(), 0, 0
    while True:
        try:
            b = h.rpc("getBlock", [slot, {"transactionDetails": "accounts", "maxSupportedTransactionVersion": 0, "rewards": False, "encoding": "json"}])
        except Exception as e:  # noqa: BLE001
            b = None
            if "skipped" not in str(e) and "not available" not in str(e):
                log(logp, f"  getBlock {slot} error {str(e)[:80]}"); time.sleep(2)
        slot += 1
        blocks += 1
        if not b:
            empties += 1
            if empties > 300:
                break
            continue
        bt = b.get("blockTime") or 0
        if bt > cts + window:
            break
        if bt < cts:
            continue
        for tx in b.get("transactions") or []:
            if tx.get("meta", {}).get("err"):
                continue
            acc = tx.get("transaction", {}).get("accountKeys") or []
            ks = {a.get("pubkey") if isinstance(a, dict) else a for a in acc}
            if ks & keys:
                sig = tx["transaction"]["signatures"][0]
                if sig not in have:
                    found.append({"signature": sig, "slot": slot - 1, "blockTime": bt})
        if blocks % 500 == 0:
            log(logp, f"  {m['symbol']}: {blocks} blocks, +{bt - cts}s, {len(found)} new sigs, {time.time() - t0:.0f}s")
        if len(found) >= max_sigs:
            break
    todo = [f["signature"] for f in found]
    n = 0
    with open(meta_p.replace(".meta.json", ".parsed.jsonl"), "a") as fp, open(rows_p, "a") as fr:
        for i in range(0, len(todo), 100):
            h._pace("enh", 0.55)
            try:
                out = h._post(f"https://api.helius.xyz/v0/transactions?api-key={h.key}", {"transactions": todo[i:i + 100]})
            except Exception as e:  # noqa: BLE001
                log(logp, f"  parse error batch {i}: {str(e)[:80]}; sleep 20"); time.sleep(20); continue
            for t in out or []:
                fp.write(json.dumps(t, separators=(",", ":")) + "\n")
                fr.write(json.dumps(compact(t, mint), separators=(",", ":")) + "\n")
                n += 1
    m.update({"blockscan": True, "blockscan_blocks": blocks, "blockscan_added": n, "sigs_in_window": len(rows) + n, "parsed": len(rows) + n,
              "truncated": len(found) >= max_sigs, "blockscan_seconds": round(time.time() - t0, 1)})
    json.dump(m, open(meta_p, "w"))
    log(logp, f"  {m['symbol']}: blockscan done, {blocks} blocks, +{n} txs in {time.time() - t0:.0f}s")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--only", nargs="*")
    a = ap.parse_args()
    logp = os.path.join(a.out, "pull.log")
    h = Helius()
    metas = sorted(glob.glob(os.path.join(a.out, "*", "*.meta.json")))
    todo = []
    for p in metas:
        m = json.load(open(p))
        if a.only and m["token"] not in a.only:
            continue
        if m.get("blockscan"):
            continue
        if a.only or (m.get("pool_pages") or 0) >= 4000:
            todo.append(p)
    log(logp, f"=== blockscan: {len(todo)} launches ===")
    for p in todo:
        try:
            scan(h, p, logp)
        except Exception as e:  # noqa: BLE001
            log(logp, f"  blockscan error {p}: {type(e).__name__} {str(e)[:100]}")
    log(logp, "=== blockscan done ===")
