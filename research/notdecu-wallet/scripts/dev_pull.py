#!/usr/bin/env python3
"""Strategy-2 / D2: per-dev launch history at scale via `portfolio created-tokens` (weight 2, <=101 newest tokens).

    python3 scripts/dev_pull.py --candidates            # (re)build data/devs/candidates.jsonl from all sources
    python3 scripts/dev_pull.py --pull [--gap 1.0]      # resumable pull into data/devs/created_tokens.jsonl
    python3 scripts/dev_pull.py --load                  # DuckDB tables `dev_books` (one row per dev) and `dev_tokens`

Candidate sources (union, each tagged):
  cache   : 2.4 token-info cache, creators with creator_open_count >= 2 (decu's picks, Feb-Sep 2026)
  trenches: creators of every graduation seen by dev_watch
  trending: creators of every top-ATH token seen by dev_watch
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
DATA = os.path.join(HERE, "..", "data")
DEVS = os.path.join(DATA, "devs")
os.makedirs(DEVS, exist_ok=True)
DB = os.path.join(DATA, "notdecu.duckdb")
CAND = os.path.join(DEVS, "candidates.jsonl")
CACHE = os.path.join(DEVS, "created_tokens.jsonl")
LOG = os.path.join(DEVS, "pull.log")
TOKEN_CACHE = os.path.join(DATA, "tokens", "token_info.jsonl")


def log(msg):
    line = f"{datetime.datetime.utcnow().isoformat(timespec='seconds')} {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def candidates(min_open=2):
    con = duckdb.connect()
    out = {}
    if os.path.exists(TOKEN_CACHE):
        for creator, open_cnt, created_cnt, n in con.execute(f"""
            SELECT dev.creator_address, max(TRY_CAST(dev.creator_open_count AS INT)), max(TRY_CAST(stat.creator_created_count AS INT)), count(*)
            FROM read_json_auto('{TOKEN_CACHE}', union_by_name=true, maximum_object_size=8000000)
            WHERE dev.creator_address IS NOT NULL AND TRY_CAST(dev.creator_open_count AS INT) >= {min_open}
            GROUP BY 1""").fetchall():
            out[creator] = {"creator": creator, "src": ["cache"], "open_cnt": open_cnt, "created_cnt": created_cnt, "decu_picks": n}
    for fn, src, key in (("trenches_completed.jsonl", "trenches", "creator"), ("trending.jsonl", "trending", "creator")):
        p = os.path.join(DEVS, fn)
        if not os.path.exists(p):
            continue
        for creator, n in con.execute(f"SELECT {key}, count(DISTINCT address) FROM read_json_auto('{p}', union_by_name=true, maximum_object_size=8000000) WHERE {key} IS NOT NULL AND {key}<>'' GROUP BY 1").fetchall():
            e = out.setdefault(creator, {"creator": creator, "src": []})
            if src not in e["src"]:
                e["src"].append(src)
            e[f"{src}_tokens"] = n
    with open(CAND, "w") as f:
        for e in out.values():
            f.write(json.dumps(e) + "\n")
    srcs = {}
    for e in out.values():
        for s in e["src"]:
            srcs[s] = srcs.get(s, 0) + 1
    log(f"candidates: {len(out):,} devs {srcs}")
    return out


def cli(args, timeout=90):
    r = subprocess.run(["gmgn-cli"] + args + ["--raw"], capture_output=True, text=True, timeout=timeout,
                       env={**os.environ, "GMGN_RATE_LIMIT_AUTO_RETRY_MAX_WAIT_MS": "120000"})
    if r.returncode != 0 or not r.stdout.strip():
        raise RuntimeError((r.stderr or "empty stdout")[:200])
    d = json.loads(r.stdout)
    return d.get("data", d) if isinstance(d, dict) and "data" in d else d


def pull(gap):
    cand = [json.loads(l) for l in open(CAND)] if os.path.exists(CAND) else list(candidates().values())
    have = set()
    if os.path.exists(CACHE):
        for line in open(CACHE):
            have.add(json.loads(line)["_creator"])
    # order: most sources first, then most graduations known
    cand.sort(key=lambda e: (-len(e["src"]), -(e.get("open_cnt") or 0)))
    todo = [e["creator"] for e in cand if e["creator"] not in have]
    log(f"=== created-tokens pull: {len(cand):,} candidates, cached {len(have):,}, to fetch {len(todo):,} at {gap}s gap ===")
    t0, n = time.time(), 0
    with open(CACHE, "a") as f:
        for c in todo:
            try:
                d = cli(["portfolio", "created-tokens", "--chain", "sol", "--wallet", c, "--order-by", "token_ath_mc"])
            except Exception as e:  # noqa: BLE001
                log(f"  error on {c[:8]}: {str(e)[:120]}; sleeping 30 s")
                time.sleep(30)
                continue
            if not isinstance(d, dict):
                d = {"_raw": d}
            d["_creator"] = c
            d["_fetched_at"] = int(time.time())
            f.write(json.dumps(d, separators=(",", ":")) + "\n")
            f.flush()
            n += 1
            if n % 100 == 0:
                el = time.time() - t0
                log(f"  {n:,}/{len(todo):,} in {el / 60:.1f} min ({el / n:.2f} s/dev), ETA {(len(todo) - n) * el / n / 60:.0f} min")
            time.sleep(gap)
    log(f"=== created-tokens pull complete: {n:,} devs in {(time.time() - t0) / 60:.1f} min ===")


def load():
    con = duckdb.connect(DB)
    con.execute("DROP TABLE IF EXISTS dev_books")
    con.execute(f"""CREATE TABLE dev_books AS
        SELECT _creator creator, TRY_CAST(inner_count AS INT) inner_count, TRY_CAST(open_count AS INT) open_count,
               TRY_CAST(open_ratio AS DOUBLE) open_ratio, TRY_CAST(last_create_timestamp AS BIGINT) last_create_ts,
               TRY_CAST(creator_ath_info.ath_mc AS DOUBLE) creator_ath_mc, creator_ath_info.ath_token creator_ath_token,
               creator_ath_info.token_symbol creator_ath_symbol, len(tokens) tokens_listed, _fetched_at fetched_at
        FROM read_json_auto('{CACHE}', union_by_name=true, maximum_object_size=16000000)""")
    con.execute("DROP TABLE IF EXISTS dev_tokens")
    con.execute(f"""CREATE TABLE dev_tokens AS
        SELECT _creator creator, t.token_address token, t.symbol, TRY_CAST(t.is_open AS BOOLEAN) is_open,
               TRY_CAST(t.token_ath_mc AS DOUBLE) ath_mc, TRY_CAST(t.market_cap AS DOUBLE) mcap_now,
               TRY_CAST(t.holders AS INT) holders, TRY_CAST(t.create_timestamp AS BIGINT) create_ts,
               t.launchpad_platform, TRY_CAST(t.bundler_rate AS DOUBLE) bundler_rate, TRY_CAST(t.total_fee AS DOUBLE) total_fee,
               TRY_CAST(t.coin_creator_fee AS DOUBLE) coin_creator_fee, TRY_CAST(t.pool_liquidity AS DOUBLE) pool_liquidity,
               TRY_CAST(t.liquidity_less_4k AS BOOLEAN) liq_lt_4k, TRY_CAST(t.cto_flag AS INT) cto_flag, TRY_CAST(t.is_pump AS BOOLEAN) is_pump
        FROM read_json_auto('{CACHE}', union_by_name=true, maximum_object_size=16000000), UNNEST(tokens) AS u(t)""")
    d, t = con.execute("SELECT (SELECT count(*) FROM dev_books), (SELECT count(*) FROM dev_tokens)").fetchone()
    print(f"dev_books {d:,} devs, dev_tokens {t:,} tokens")
    con.execute(f"COPY dev_books TO '{os.path.join(DEVS, 'dev_books.parquet')}' (FORMAT PARQUET)")
    con.execute(f"COPY dev_tokens TO '{os.path.join(DEVS, 'dev_tokens.parquet')}' (FORMAT PARQUET)")
    con.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--candidates", action="store_true")
    ap.add_argument("--pull", action="store_true")
    ap.add_argument("--load", action="store_true")
    ap.add_argument("--gap", type=float, default=1.0)
    ap.add_argument("--min-open", type=int, default=2)
    a = ap.parse_args()
    if a.candidates:
        candidates(a.min_open)
    if a.pull:
        pull(a.gap)
    if a.load:
        load()
