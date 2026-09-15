#!/usr/bin/env python3
"""Phase 3 / D5a: deepen the top-10 (from D4 §5) to narrow to 5. Resumable, read-only.

    python3 scripts/dev_deep.py --nonhit-kline [--per-dev 40]   # 1m + 15m klines on the newest N non-hit launches per dev -> audit/kline.jsonl
    python3 scripts/dev_deep.py --walk [--max-pages 120]         # full dev_score trade walk for devs whose D4 walk truncated -> audit/score_full_<dev>.json
    python3 scripts/dev_deep.py --all
"""
import argparse
import json
import os
import subprocess
import sys
import time

import duckdb

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from dev_audit import AUDIT, DB, DEV_SCORE, cli, log  # noqa: E402

TOP10 = ["9VXuNqqqzniYYW3fRDeaCtUUtqWsEeWWn5umh3aF9h17", "EgJoaEBSZA3wjgpPq8am9YjkxJPLa2LpXwxaQyUzB2XY", "5YRgrP3mjGzrzirYYN5HAQH19cTYREYwGxW6XRJQUzij",
         "BFmgjdgepMxNnEyndQZC68Db3ajPdD3V8is1bQbdj4h4", "G4krkerMkeYw7ffTUgdf7qXEXnuMGHpWUESBQpYqvtwU", "GeBJSHK4WsGrz2HRvTbqvWGx4JRMpHfJG2ikzrYBDuwR",
         "FAX4qRQdiSj2iWDYvkJ21VieVCXGREtwMhEyAHSJ1aqp", "4LTJU2qfJdmDuEQAmWXcf5hvkpomYrLebuTBz2svwRd4", "CzwWvTVn39dSd4LiVc6W9gZxgu36737M2fcX4EWhquh4",
         "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe"]
TRUNCATED = ["yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe", "GeBJSHK4WsGrz2HRvTbqvWGx4JRMpHfJG2ikzrYBDuwR", "5YRgrP3mjGzrzirYYN5HAQH19cTYREYwGxW6XRJQUzij",
             "G4krkerMkeYw7ffTUgdf7qXEXnuMGHpWUESBQpYqvtwU", "FAX4qRQdiSj2iWDYvkJ21VieVCXGREtwMhEyAHSJ1aqp", "CzwWvTVn39dSd4LiVc6W9gZxgu36737M2fcX4EWhquh4"]


def nonhit_kline(per_dev, gap=1.0):
    con = duckdb.connect(DB, read_only=True)
    toks = con.execute(f"""SELECT creator, token, ath_mc, create_ts FROM (
        SELECT creator, token, ath_mc, create_ts, row_number() OVER (PARTITION BY creator ORDER BY create_ts DESC) rn
        FROM dev_tokens WHERE creator IN ({','.join("'" + c + "'" for c in TOP10)}) AND ath_mc < 1e5 AND create_ts > 0) WHERE rn <= {per_dev}""").fetchall()
    con.close()
    out = os.path.join(AUDIT, "kline.jsonl")
    have = set()
    if os.path.exists(out):
        for l in open(out):
            j = json.loads(l)
            have.add((j["token"], j["res"]))
    plan = [(t, "1m", t[3], t[3] + 100 * 60) for t in toks] + [(t, "15m", t[3], t[3] + 96 * 900) for t in toks]
    plan = [p for p in plan if (p[0][1], p[1]) not in have]
    log(f"=== non-hit kline: {len(toks)} tokens, {len(plan)} calls ===")
    t0, n = time.time(), 0
    with open(out, "a") as f:
        for (creator, token, ath, cts), res, fr, to in plan:
            try:
                k = cli(["market", "kline", "--chain", "sol", "--address", token, "--resolution", res, "--from", str(fr), "--to", str(to)])
            except Exception as e:  # noqa: BLE001
                log(f"  error {token[:8]} {res}: {str(e)[:100]}; sleep 30"); time.sleep(30); continue
            rows = k.get("list") if isinstance(k, dict) else k
            f.write(json.dumps({"creator": creator, "token": token, "res": res, "from": fr, "to": to, "ath_mc": ath, "hit": False,
                                "candles": rows or []}, separators=(",", ":")) + "\n"); f.flush()
            n += 1
            if n % 100 == 0:
                el = time.time() - t0
                log(f"  {n}/{len(plan)} in {el / 60:.1f} min, ETA {(len(plan) - n) * el / n / 60:.0f} min")
            time.sleep(gap)
    log(f"=== non-hit kline done: {n} calls in {(time.time() - t0) / 60:.1f} min ===")


def walk(max_pages, gap=5.0):
    log(f"=== full walks: {len(TRUNCATED)} devs at {max_pages} pages ===")
    for i, d in enumerate(TRUNCATED, 1):
        out = os.path.join(AUDIT, f"score_full_{d}.json")
        if os.path.exists(out) and os.path.getsize(out) > 2:
            continue
        t0 = time.time()
        r = subprocess.run([sys.executable, DEV_SCORE, "sol", d, str(max_pages)], capture_output=True, text=True, timeout=3600,
                           env={**os.environ, "GMGN_RATE_LIMIT_AUTO_RETRY_MAX_WAIT_MS": "120000"})
        if r.returncode != 0 or not r.stdout.strip():
            log(f"  {i} {d[:8]} FAILED: {(r.stderr or '')[-200:]}"); time.sleep(30); continue
        open(out, "w").write(r.stdout)
        try:
            j = json.loads(r.stdout); sc = j.get("score") or {}; cv = j.get("coverage") or {}
            log(f"  {i} {d[:8]} total={sc.get('total')} conduct={sc.get('conduct')} band={sc.get('band')} pages={cv.get('pages_walked')} truncated={cv.get('trade_history_truncated')} in {time.time() - t0:.0f}s")
        except Exception:  # noqa: BLE001
            log(f"  {i} {d[:8]} written in {time.time() - t0:.0f}s")
        time.sleep(gap)
    log("=== full walks done ===")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--nonhit-kline", action="store_true")
    ap.add_argument("--walk", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--per-dev", type=int, default=40)
    ap.add_argument("--max-pages", type=int, default=120)
    a = ap.parse_args()
    if a.nonhit_kline or a.all:
        nonhit_kline(a.per_dev)
    if a.walk or a.all:
        walk(a.max_pages)
