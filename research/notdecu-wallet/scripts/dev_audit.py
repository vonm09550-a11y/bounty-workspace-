#!/usr/bin/env python3
"""Phase 3 / D4: deep audit pulls for the `d4_shortlist` devs. Every stage is resumable from disk.

    python3 scripts/dev_audit.py --tokens   # token info for every listed launch of the shortlist (w1) -> data/tokens/token_info.jsonl
    python3 scripts/dev_audit.py --stats    # portfolio stats per dev (w3): fund_from_address, tags, counts -> data/devs/audit/stats.jsonl
    python3 scripts/dev_audit.py --score    # gmgn-dev-score/dev_score.py per dev (conduct + power) -> data/devs/audit/score_<dev>.json
    python3 scripts/dev_audit.py --kline    # 1m first 100 min + 15m first 24 h for every hit token (ATH >= 100K) (w2 each) -> data/devs/audit/kline.jsonl
    python3 scripts/dev_audit.py --all
Read-only. No swap/order/create/signing anywhere in this file.
"""
import argparse
import datetime
import json
import os
import subprocess
import sys
import time

import duckdb

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from clients import DATA, GmgnToken  # noqa: E402

DEVS = os.path.join(DATA, "devs")
AUDIT = os.path.join(DEVS, "audit")
os.makedirs(AUDIT, exist_ok=True)
DB = os.path.join(DATA, "notdecu.duckdb")
TOKEN_CACHE = os.path.join(DATA, "tokens", "token_info.jsonl")
LOG = os.path.join(AUDIT, "audit.log")
DEV_SCORE = os.path.join(HERE, "..", "..", "..", ".claude", "skills", "gmgn-dev-score", "dev_score.py")


def log(msg):
    line = f"{datetime.datetime.utcnow().isoformat(timespec='seconds')} {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def cli(args, timeout=120):
    r = subprocess.run(["gmgn-cli"] + args + ["--raw"], capture_output=True, text=True, timeout=timeout,
                       env={**os.environ, "GMGN_RATE_LIMIT_AUTO_RETRY_MAX_WAIT_MS": "120000"})
    if r.returncode != 0 or not r.stdout.strip():
        raise RuntimeError((r.stderr or "empty stdout")[:200])
    d = json.loads(r.stdout)
    return d.get("data", d) if isinstance(d, dict) and "data" in d else d


def shortlist():
    con = duckdb.connect(DB, read_only=True)
    devs = [r[0] for r in con.execute("SELECT creator FROM d4_shortlist ORDER BY best_rank, lists").fetchall()]
    toks = con.execute("""SELECT t.creator, t.token, t.ath_mc, t.create_ts FROM dev_tokens t JOIN d4_shortlist s USING(creator)
                          ORDER BY s.best_rank, t.ath_mc DESC""").fetchall()
    con.close()
    return devs, toks


def stage_tokens(gap=0.05):
    devs, toks = shortlist()
    have = set()
    if os.path.exists(TOKEN_CACHE):
        for line in open(TOKEN_CACHE):
            have.add(json.loads(line)["_address"])
    todo = [t[1] for t in toks if t[1] not in have]
    log(f"=== tokens: {len(toks)} listed, {len(todo)} to fetch ===")
    g = GmgnToken()
    t0, n = time.time(), 0
    with open(TOKEN_CACHE, "a") as f:
        for addr in todo:
            try:
                d = g.info(addr) or {}
            except Exception as e:  # noqa: BLE001
                log(f"  error {addr[:8]}: {str(e)[:100]}; sleep 60"); time.sleep(60); continue
            d["_address"] = addr
            d["_fetched_at"] = int(time.time())
            f.write(json.dumps(d, separators=(",", ":")) + "\n"); f.flush()
            n += 1
            if n % 200 == 0:
                el = time.time() - t0
                log(f"  {n}/{len(todo)} in {el / 60:.1f} min, ETA {(len(todo) - n) * el / n / 60:.0f} min")
            time.sleep(gap)
    log(f"=== tokens done: {n} fetched in {(time.time() - t0) / 60:.1f} min ===")


def stage_stats(gap=1.5):
    devs, _ = shortlist()
    out = os.path.join(AUDIT, "stats.jsonl")
    have = {json.loads(l)["_creator"] for l in open(out)} if os.path.exists(out) else set()
    log(f"=== stats: {len(devs)} devs, {len(have)} cached ===")
    with open(out, "a") as f:
        for d in devs:
            if d in have:
                continue
            try:
                s = cli(["portfolio", "stats", "--chain", "sol", "--wallet", d])
            except Exception as e:  # noqa: BLE001
                log(f"  error {d[:8]}: {str(e)[:100]}; sleep 30"); time.sleep(30); continue
            s["_creator"] = d
            s["_fetched_at"] = int(time.time())
            f.write(json.dumps(s, separators=(",", ":")) + "\n"); f.flush()
            time.sleep(gap)
    log("=== stats done ===")


def stage_score(max_pages=25, gap=3.0):
    devs, _ = shortlist()
    log(f"=== dev_score: {len(devs)} devs ===")
    for i, d in enumerate(devs, 1):
        out = os.path.join(AUDIT, f"score_{d}.json")
        if os.path.exists(out) and os.path.getsize(out) > 2:
            continue
        t0 = time.time()
        r = subprocess.run([sys.executable, DEV_SCORE, "sol", d, str(max_pages)], capture_output=True, text=True, timeout=1800,
                           env={**os.environ, "GMGN_RATE_LIMIT_AUTO_RETRY_MAX_WAIT_MS": "120000"})
        if r.returncode != 0 or not r.stdout.strip():
            log(f"  {i}/{len(devs)} {d[:8]} FAILED: {(r.stderr or '')[-200:]}")
            time.sleep(30)
            continue
        open(out, "w").write(r.stdout)
        open(os.path.join(AUDIT, f"score_{d}.stderr"), "w").write(r.stderr or "")
        try:
            j = json.loads(r.stdout)
            sc = j.get("score") or {}
            log(f"  {i}/{len(devs)} {d[:8]} scored={j.get('scored')} total={sc.get('total')} conduct={sc.get('conduct')} power={sc.get('power')} band={sc.get('band')} in {time.time() - t0:.0f}s")
        except Exception:  # noqa: BLE001
            log(f"  {i}/{len(devs)} {d[:8]} written (unparsed) in {time.time() - t0:.0f}s")
        time.sleep(gap)
    log("=== dev_score done ===")


def stage_kline(gap=1.0):
    _, toks = shortlist()
    hits = [t for t in toks if t[2] and 1e5 <= t[2] < 5e9 and t[3]]
    out = os.path.join(AUDIT, "kline.jsonl")
    have = set()
    if os.path.exists(out):
        for l in open(out):
            j = json.loads(l)
            have.add((j["token"], j["res"]))
    plan = [(t, "1m", t[3], t[3] + 100 * 60) for t in hits] + [(t, "15m", t[3], t[3] + 96 * 900) for t in hits]
    plan = [p for p in plan if (p[0][1], p[1]) not in have]
    log(f"=== kline: {len(hits)} hit tokens, {len(plan)} calls to make ===")
    t0, n = time.time(), 0
    with open(out, "a") as f:
        for (creator, token, ath, cts), res, fr, to in plan:
            try:
                k = cli(["market", "kline", "--chain", "sol", "--address", token, "--resolution", res, "--from", str(fr), "--to", str(to)])
            except Exception as e:  # noqa: BLE001
                log(f"  error {token[:8]} {res}: {str(e)[:100]}; sleep 30"); time.sleep(30); continue
            rows = k.get("list") if isinstance(k, dict) else k
            f.write(json.dumps({"creator": creator, "token": token, "res": res, "from": fr, "to": to, "ath_mc": ath,
                                "candles": rows or []}, separators=(",", ":")) + "\n"); f.flush()
            n += 1
            if n % 100 == 0:
                el = time.time() - t0
                log(f"  {n}/{len(plan)} in {el / 60:.1f} min, ETA {(len(plan) - n) * el / n / 60:.0f} min")
            time.sleep(gap)
    log(f"=== kline done: {n} calls in {(time.time() - t0) / 60:.1f} min ===")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    for s in ("tokens", "stats", "score", "kline", "all"):
        ap.add_argument(f"--{s}", action="store_true")
    a = ap.parse_args()
    if a.tokens or a.all:
        stage_tokens()
    if a.stats or a.all:
        stage_stats()
    if a.score or a.all:
        stage_score()
    if a.kline or a.all:
        stage_kline()
