#!/usr/bin/env python3
"""Mini-phase 2.1: pull the wallet's full GMGN activity history in slot-range chunks.

Chunks run sequentially (never parallel — GMGN bans bursts). Each chunk has its own JSONL and
state file, so a rerun resumes exactly where it stopped. Stop condition per chunk: the `next`
cursor decodes to a slot at or below the chunk's lower bound.

    python3 scripts/pull_activity.py [--types buy sell] [--from-slot 368000000] [--to-slot 447500000] [--step 6500000]
"""
import argparse
import base64
import datetime
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from clients import DATA, GMGN_GAP_S, GmgnActivity, slot_cursor  # noqa: E402

WALLET = "4vw54BmAogeRV3vPKWyFet5yf8DTLcREzdSzx4rw9Ud9"
OUT = os.path.join(DATA, "activity")
LOG = os.path.join(OUT, "pull.log")


def log(msg):
    line = f"{datetime.datetime.utcnow().isoformat(timespec='seconds')} {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def cursor_slot(cursor):
    try:
        raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        return int(raw.split(":")[0][:-8])
    except Exception:  # noqa: BLE001
        return None


def pull_chunk(g, tag, upper, lower):
    out = os.path.join(OUT, f"{tag}_{upper}_{lower}.jsonl")
    state = out + ".state"
    st = json.load(open(state)) if os.path.exists(state) else {"cursor": slot_cursor(upper), "pages": 0, "rows": 0, "done": False}
    if st.get("done"):
        log(f"{tag} {upper}->{lower}: already done ({st['pages']} pages, {st['rows']} rows)")
        return st
    log(f"{tag} {upper}->{lower}: start at page {st['pages']}")
    t0 = time.time()
    with open(out, "a") as f:
        while True:
            try:
                d = g._http(st["cursor"])
            except RuntimeError as e:
                log(f"  error: {e}; sleeping 90 s then resuming")
                time.sleep(90)
                continue
            rows = d.get("activities") or []
            for a in rows:
                f.write(json.dumps(a, separators=(",", ":")) + "\n")
            f.flush()
            st["pages"] += 1
            st["rows"] += len(rows)
            nxt = d.get("next")
            st["cursor"] = nxt
            ns = cursor_slot(nxt) if nxt else None
            done = (not rows) or (not nxt) or (ns is not None and ns <= lower)
            st["done"] = done
            json.dump(st, open(state, "w"))
            if st["pages"] % 200 == 0:
                ts = float(rows[-1]["timestamp"]) if rows else 0
                log(f"  {tag} {upper}->{lower}: {st['pages']} pages {st['rows']} rows, at {datetime.datetime.utcfromtimestamp(ts).date() if ts else '?'} slot {ns}, {(time.time() - t0) / st['pages']:.2f}s/page")
            if done:
                break
            time.sleep(GMGN_GAP_S)
    log(f"{tag} {upper}->{lower}: done {st['pages']} pages {st['rows']} rows in {(time.time() - t0) / 60:.1f} min")
    return st


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--types", nargs="+", default=["buy", "sell"])
    ap.add_argument("--from-slot", type=int, default=368_000_000)   # oldest GMGN data ≈ 2025-09-13
    ap.add_argument("--to-slot", type=int, default=447_500_000)     # a little above the current slot
    ap.add_argument("--step", type=int, default=6_500_000)          # ≈ one month
    args = ap.parse_args()
    os.makedirs(OUT, exist_ok=True)
    g = GmgnActivity(WALLET, types=tuple(args.types), out=os.path.join(OUT, "unused.jsonl"), direct=True)
    tag = "-".join(args.types)
    bounds = list(range(args.from_slot, args.to_slot, args.step)) + [args.to_slot]
    chunks = [(bounds[i + 1], bounds[i]) for i in range(len(bounds) - 1)][::-1]   # newest first
    log(f"=== pull {tag}: {len(chunks)} chunks {args.from_slot}->{args.to_slot} ===")
    total_pages = total_rows = 0
    for upper, lower in chunks:
        st = pull_chunk(g, tag, upper, lower)
        total_pages += st["pages"]
        total_rows += st["rows"]
    log(f"=== pull {tag} complete: {total_pages} pages, {total_rows} rows ===")


if __name__ == "__main__":
    main()
