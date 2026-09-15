#!/usr/bin/env python3
"""Phase D6-A: every transaction in the first WINDOW seconds of each launch, from Helius. Resumable, read-only.

    python3 scripts/anatomy_pull.py --launches data/anatomy/launches_loop1.jsonl --out data/anatomy/loop1 [--window 1800] [--max-sigs 30000]

Per launch writes <out>/<dev>/<mint>.rows.jsonl (one compact row per transaction: signature, slot, ts, fee_payer,
fee_lamports, type, source, side, token_amount, sol_in, sol_out, n_token_transfers, accounts_n) and
<mint>.parsed.jsonl (the full Helius parsed objects), plus <mint>.meta.json with counts and a `done` flag.
Signature discovery: getSignaturesForAddress(mint) paged newest-first until blockTime < create_ts.
"""
import argparse
import datetime
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from clients import Helius  # noqa: E402


def log(path, msg):
    line = f"{datetime.datetime.utcnow().isoformat(timespec='seconds')} {msg}"
    print(line, flush=True)
    with open(path, "a") as f:
        f.write(line + "\n")


def compact(t, mint):
    fp = t.get("feePayer")
    tok_in = sum(x.get("tokenAmount") or 0 for x in (t.get("tokenTransfers") or []) if x.get("mint") == mint and x.get("toUserAccount") == fp)
    tok_out = sum(x.get("tokenAmount") or 0 for x in (t.get("tokenTransfers") or []) if x.get("mint") == mint and x.get("fromUserAccount") == fp)
    sol_out = sum(x.get("amount") or 0 for x in (t.get("nativeTransfers") or []) if x.get("fromUserAccount") == fp) / 1e9
    sol_in = sum(x.get("amount") or 0 for x in (t.get("nativeTransfers") or []) if x.get("toUserAccount") == fp) / 1e9
    side = "buy" if tok_in > tok_out else ("sell" if tok_out > tok_in else "other")
    return {"signature": t.get("signature"), "slot": t.get("slot"), "ts": t.get("timestamp"), "fee_payer": fp, "fee_lamports": t.get("fee"),
            "type": t.get("type"), "source": t.get("source"), "side": side, "token_amount": tok_in if side == "buy" else tok_out,
            "sol_spent": sol_out if side == "buy" else 0.0, "sol_received": sol_in if side == "sell" else 0.0,
            "n_token_transfers": len(t.get("tokenTransfers") or []), "accounts_n": len(t.get("accountData") or []),
            "err": bool(t.get("transactionError"))}


def pull_one(h, L, out_dir, window, max_sigs, logp):
    mint, cts, dev = L["token"], int(L["create_ts"]), L["dev"]
    d = os.path.join(out_dir, dev)
    os.makedirs(d, exist_ok=True)
    meta_p = os.path.join(d, f"{mint}.meta.json")
    if os.path.exists(meta_p) and json.load(open(meta_p)).get("done"):
        return None
    t0 = time.time()
    sigs, before, pages, oldest_bt = [], None, 0, None
    while True:
        params = [mint, {"limit": 1000}]
        if before:
            params[1]["before"] = before
        r = h.rpc("getSignaturesForAddress", params)
        pages += 1
        if not r:
            break
        for s in r:
            bt = s.get("blockTime") or 0
            if cts <= bt <= cts + window and not s.get("err"):
                sigs.append({"signature": s["signature"], "slot": s["slot"], "blockTime": bt})
        oldest_bt = r[-1].get("blockTime") or 0
        before = r[-1]["signature"]
        if len(r) < 1000 or oldest_bt < cts or pages >= 400:
            break
    sigs.sort(key=lambda s: (s["blockTime"], s["slot"]))
    truncated = len(sigs) > max_sigs
    sigs = sigs[:max_sigs]
    todo = [s["signature"] for s in sigs]
    parsed_p = os.path.join(d, f"{mint}.parsed.jsonl")
    rows_p = os.path.join(d, f"{mint}.rows.jsonl")
    n = 0
    with open(parsed_p, "w") as fp, open(rows_p, "w") as fr:
        for i in range(0, len(todo), 100):
            h._pace("enh", 0.55)
            try:
                out = h._post(f"https://api.helius.xyz/v0/transactions?api-key={h.key}", {"transactions": todo[i:i + 100]})
            except Exception as e:  # noqa: BLE001
                log(logp, f"  parse error {mint[:8]} batch {i}: {str(e)[:100]}; sleep 20"); time.sleep(20)
                try:
                    out = h._post(f"https://api.helius.xyz/v0/transactions?api-key={h.key}", {"transactions": todo[i:i + 100]})
                except Exception:  # noqa: BLE001
                    continue
            for t in out or []:
                fp.write(json.dumps(t, separators=(",", ":")) + "\n")
                fr.write(json.dumps(compact(t, mint), separators=(",", ":")) + "\n")
                n += 1
    meta = {"dev": dev, "creator": L["creator"], "token": mint, "symbol": L.get("symbol"), "create_ts": cts, "window_s": window, "hit": L.get("hit"),
            "ath_mc": L.get("ath_mc"), "sig_pages": pages, "sigs_in_window": len(sigs), "parsed": n, "truncated": truncated,
            "oldest_bt_reached": oldest_bt, "seconds": round(time.time() - t0, 1), "done": True}
    json.dump(meta, open(meta_p, "w"))
    return meta


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--launches", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--window", type=int, default=1800)
    ap.add_argument("--max-sigs", type=int, default=30000)
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    logp = os.path.join(a.out, "pull.log")
    launches = [json.loads(l) for l in open(a.launches)]
    h = Helius()
    log(logp, f"=== anatomy pull: {len(launches)} launches, window {a.window}s ===")
    for i, L in enumerate(launches, 1):
        try:
            m = pull_one(h, L, a.out, a.window, a.max_sigs, logp)
        except Exception as e:  # noqa: BLE001
            log(logp, f"  {i}/{len(launches)} {L['dev']} {L.get('symbol')} {L['token'][:8]} ERROR {type(e).__name__}: {str(e)[:120]}; sleep 30"); time.sleep(30); continue
        if m:
            log(logp, f"  {i}/{len(launches)} {m['dev']} {m['symbol']} hit={m['hit']} sigs={m['sigs_in_window']} parsed={m['parsed']} pages={m['sig_pages']} {m['seconds']}s{' TRUNCATED' if m['truncated'] else ''}")
    log(logp, "=== anatomy pull done ===")
