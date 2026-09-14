#!/usr/bin/env python3
"""Mini-phase 2.4: GMGN `token info` for every ring-B token (positions opened 2026-02-01 onward),
most important positions first (|realized| desc), resumable via a JSONL cache.

    python3 scripts/enrich_tokens.py --pull [--since 2026-02-01] [--gap 0.2]
    python3 scripts/enrich_tokens.py --load        # flatten cache into DuckDB table `tokens`
"""
import argparse
import datetime
import json
import os
import sys
import time

import duckdb

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from clients import DATA, GmgnToken  # noqa: E402

DB = os.path.join(DATA, "notdecu.duckdb")
CACHE = os.path.join(DATA, "tokens", "token_info.jsonl")
LOG = os.path.join(DATA, "tokens", "pull.log")


def log(msg):
    line = f"{datetime.datetime.utcnow().isoformat(timespec='seconds')} {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def pull(since, gap):
    os.makedirs(os.path.dirname(CACHE), exist_ok=True)
    con = duckdb.connect(DB, read_only=True)
    toks = [r[0] for r in con.execute(f"""SELECT token FROM positions WHERE first_buy_t >= '{since}' OR first_buy_t IS NULL
                                          ORDER BY abs(realized_avg) DESC, buy_usd DESC""").fetchall()]
    con.close()
    have = set()
    if os.path.exists(CACHE):
        for line in open(CACHE):
            have.add(json.loads(line)["_address"])
    todo = [t for t in toks if t not in have]
    log(f"=== token info pull: {len(toks):,} tokens, cached {len(have):,}, to fetch {len(todo):,} at {gap}s gap ===")
    g = GmgnToken()
    t0 = time.time()
    n = 0
    with open(CACHE, "a") as f:
        for addr in todo:
            try:
                d = g.info(addr)
            except Exception as e:  # noqa: BLE001 — never let one bad call end a multi-hour pull
                log(f"  error on {addr[:8]}: {type(e).__name__}: {str(e)[:120]}; sleeping 60 s")
                time.sleep(60)
                continue
            if d is None:
                d = {}
            d["_address"] = addr
            d["_fetched_at"] = int(time.time())
            f.write(json.dumps(d, separators=(",", ":")) + "\n")
            f.flush()
            n += 1
            if n % 500 == 0:
                el = time.time() - t0
                log(f"  {n:,}/{len(todo):,} in {el / 60:.1f} min ({el / n:.2f} s/token), ETA {(len(todo) - n) * el / n / 60:.0f} min")
            time.sleep(gap)
    log(f"=== token info pull complete: {n:,} fetched in {(time.time() - t0) / 60:.1f} min ===")


def load():
    con = duckdb.connect(DB)
    con.execute("DROP TABLE IF EXISTS tokens")
    cols = [c[0] for c in con.execute(f"DESCRIBE SELECT * FROM read_json_auto('{CACHE}', union_by_name=true, maximum_object_size=8000000)").fetchall()]
    err = "_error" if "_error" in cols else "NULL::INTEGER"   # column only exists when at least one 400/404 was cached
    con.execute(f"""
        CREATE TABLE tokens AS
        SELECT _address AS token, symbol, name, TRY_CAST(total_supply AS DOUBLE) total_supply, decimals,
               TRY_CAST(creation_timestamp AS BIGINT) creation_ts, TRY_CAST(open_timestamp AS BIGINT) open_ts,
               TRY_CAST(migrated_timestamp AS BIGINT) migrated_ts,
               launchpad, launchpad_platform, TRY_CAST(launchpad_status AS INTEGER) launchpad_status,
               TRY_CAST(launchpad_progress AS DOUBLE) launchpad_progress, TRY_CAST(migration_market_cap AS DOUBLE) migration_mcap,
               TRY_CAST(holder_count AS INTEGER) holder_count, TRY_CAST(liquidity AS DOUBLE) liquidity,
               TRY_CAST(price.price AS DOUBLE) price_now, TRY_CAST(ath_price AS DOUBLE) ath_price,
               TRY_CAST(total_fee AS DOUBLE) total_fee, TRY_CAST(image_dup_count AS INTEGER) image_dup_count,
               dev.creator_address creator, dev.creator_token_status creator_status, TRY_CAST(dev.creator_open_count AS INTEGER) creator_open_count,
               TRY_CAST(dev.cto_flag AS INTEGER) cto_flag, dev.fund_from creator_fund_from,
               TRY_CAST(dev.dexscr_ad AS INTEGER) dexscr_ad, TRY_CAST(dev.dexscr_update_link AS INTEGER) dexscr_update_link,
               TRY_CAST(dev.twitter_create_token_count AS INTEGER) tw_create_token_count,
               TRY_CAST(stat.top_10_holder_rate AS DOUBLE) top10_rate, TRY_CAST(stat.creator_hold_rate AS DOUBLE) creator_hold_rate,
               TRY_CAST(stat.top_rat_trader_percentage AS DOUBLE) rat_pct, TRY_CAST(stat.top_bundler_trader_percentage AS DOUBLE) bundler_pct,
               TRY_CAST(stat.top_entrapment_trader_percentage AS DOUBLE) entrapment_pct, TRY_CAST(stat.bot_degen_rate AS DOUBLE) bot_degen_rate,
               TRY_CAST(stat.fresh_wallet_rate AS DOUBLE) fresh_wallet_rate, TRY_CAST(stat.top70_sniper_hold_rate AS DOUBLE) sniper_hold_rate,
               TRY_CAST(stat.creator_created_count AS INTEGER) creator_created_count,
               TRY_CAST(wallet_tags_stat.smart_wallets AS INTEGER) smart_wallets, TRY_CAST(wallet_tags_stat.renowned_wallets AS INTEGER) renowned_wallets,
               TRY_CAST(wallet_tags_stat.sniper_wallets AS INTEGER) sniper_wallets, TRY_CAST(wallet_tags_stat.bundler_wallets AS INTEGER) bundler_wallets,
               link.twitter_username twitter, link.website website, link.telegram telegram,
               pool.quote_symbol quote_symbol, pool.exchange exchange, fee_distribution.launchpad fee_launchpad,
               {err} AS error_code, _fetched_at fetched_at
        FROM read_json_auto('{CACHE}', union_by_name=true, maximum_object_size=8000000)
    """)
    n, e = con.execute("SELECT count(*), sum(error_code IS NOT NULL) FROM tokens").fetchone()
    print(f"tokens table: {n:,} rows, {e} errors")
    print(con.execute("SELECT launchpad_platform, count(*) c FROM tokens GROUP BY 1 ORDER BY c DESC LIMIT 10").df().to_string(index=False))
    con.execute(f"COPY tokens TO '{os.path.join(DATA, 'tokens.parquet')}' (FORMAT PARQUET)")
    con.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pull", action="store_true")
    ap.add_argument("--load", action="store_true")
    ap.add_argument("--since", default="2026-02-01")
    ap.add_argument("--gap", type=float, default=0.2)
    a = ap.parse_args()
    if a.pull:
        pull(a.since, a.gap)
    if a.load:
        load()
