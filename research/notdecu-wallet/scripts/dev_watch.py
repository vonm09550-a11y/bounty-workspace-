#!/usr/bin/env python3
"""Strategy-2 / D1: live collector of graduations and top-ATH tokens with their creators.

Every `--every` seconds: `market trenches --type completed` (newest first, weight 3) -> data/devs/trenches_completed.jsonl
Every hour:               `market trending` 24h/6h/1h ordered by history_highest_market_cap, Pump.fun and all platforms
                          (weight 1 each) -> data/devs/trending.jsonl
Each row gets `_snap` (unix s of the snapshot) so repeated sightings of the same token are kept as a time series.
Read-only. Runs forever; Ctrl-C / kill to stop. Resumes are trivial (append-only files).

    nohup python3 scripts/dev_watch.py --every 300 >> data/devs/watch.out 2>&1 &
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data", "devs")
os.makedirs(DATA, exist_ok=True)
LOG = os.path.join(DATA, "watch.log")


def log(msg):
    line = f"{datetime.datetime.utcnow().isoformat(timespec='seconds')} {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def cli(args, timeout=90):
    r = subprocess.run(["gmgn-cli"] + args + ["--raw"], capture_output=True, text=True, timeout=timeout,
                       env={**os.environ, "GMGN_RATE_LIMIT_AUTO_RETRY_MAX_WAIT_MS": "120000"})
    if r.returncode != 0 or not r.stdout.strip():
        raise RuntimeError((r.stderr or "empty stdout")[:200])
    d = json.loads(r.stdout)
    return d.get("data", d) if isinstance(d, dict) and "data" in d else d


def append(path, rows, snap, extra):
    with open(path, "a") as f:
        for r in rows:
            r["_snap"] = snap
            r.update(extra)
            f.write(json.dumps(r, separators=(",", ":")) + "\n")


def trenches(snap):
    d = cli(["market", "trenches", "--chain", "sol", "--type", "completed", "--limit", "80",
             "--sort-by", "created_timestamp", "--direction", "desc"])
    rows = d.get("completed") or []
    append(os.path.join(DATA, "trenches_completed.jsonl"), rows, snap, {"_src": "trenches_completed"})
    return len(rows)


def trending(snap):
    n = 0
    for iv in ("1h", "6h", "24h"):
        for plat in ("Pump.fun", None):
            args = ["market", "trending", "--chain", "sol", "--interval", iv, "--limit", "100",
                    "--order-by", "history_highest_market_cap", "--direction", "desc", "--max-created", "7d"]
            if plat:
                args += ["--platform", plat]
            try:
                d = cli(args)
            except Exception as e:  # noqa: BLE001
                log(f"  trending {iv}/{plat} failed: {str(e)[:100]}")
                time.sleep(5)
                continue
            rows = d.get("rank") or []
            append(os.path.join(DATA, "trending.jsonl"), rows, snap, {"_src": f"trending_{iv}_{plat or 'all'}"})
            n += len(rows)
            time.sleep(1.5)
    return n


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--every", type=int, default=300, help="seconds between trenches snapshots")
    ap.add_argument("--trending-every", type=int, default=3600)
    a = ap.parse_args()
    log(f"=== dev_watch start: trenches every {a.every}s, trending every {a.trending_every}s ===")
    last_tr = 0.0
    while True:
        snap = int(time.time())
        try:
            n = trenches(snap)
            msg = f"trenches {n} rows"
            if time.time() - last_tr >= a.trending_every:
                time.sleep(1.5)
                m = trending(snap)
                last_tr = time.time()
                msg += f", trending {m} rows"
            log(msg)
        except Exception as e:  # noqa: BLE001
            log(f"  error: {type(e).__name__}: {str(e)[:150]}; sleeping 60 s")
            time.sleep(60)
            continue
        time.sleep(a.every)
