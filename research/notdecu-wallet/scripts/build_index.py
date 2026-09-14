#!/usr/bin/env python3
"""Mini-phase 2.1 (offline): load all activity chunks into DuckDB, dedupe, reconcile, summarise.

    python3 scripts/build_index.py            # builds data/notdecu.duckdb and prints the monthly table

Tables:
  activity_raw  every row as pulled (one JSON row per leg)
  activity      deduped legs (chunk boundaries can overlap by a page)
  monthly       per-month counts used in 02-index.md
"""
import glob
import json
import os
import sys

import duckdb

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
DB = os.path.join(DATA, "notdecu.duckdb")
WALLET = "4vw54BmAogeRV3vPKWyFet5yf8DTLcREzdSzx4rw9Ud9"


def main():
    files = sorted(glob.glob(os.path.join(DATA, "activity", "buy-sell_*.jsonl")))
    if not files:
        sys.exit("no chunks in data/activity")
    con = duckdb.connect(DB)
    con.execute("DROP TABLE IF EXISTS activity_raw")
    con.execute(f"""
        CREATE TABLE activity_raw AS
        SELECT
            tx_hash,
            CAST(timestamp AS BIGINT)                  AS ts,
            to_timestamp(CAST(timestamp AS BIGINT))    AS t,
            event_type,
            token.address                              AS token,
            token.symbol                               AS symbol,
            TRY_CAST(token.total_supply AS DOUBLE)     AS total_supply,
            TRY_CAST(token_amount AS DOUBLE)           AS token_amount,
            TRY_CAST(quote_amount AS DOUBLE)           AS quote_amount,
            TRY_CAST(cost_usd AS DOUBLE)               AS cost_usd,
            TRY_CAST(buy_cost_usd AS DOUBLE)           AS buy_cost_usd,
            TRY_CAST(price_usd AS DOUBLE)              AS price_usd,
            TRY_CAST(price AS DOUBLE)                  AS price_quote,
            is_open_or_close,
            quote_token.symbol                         AS quote_symbol,
            quote_address,
            TRY_CAST(gas_usd AS DOUBLE)                AS gas_usd,
            TRY_CAST(priority_fee AS DOUBLE)           AS priority_fee,
            TRY_CAST(tip_fee AS DOUBLE)                AS tip_fee,
            launchpad,
            launchpad_platform,
            filename                                    AS chunk
        FROM read_json_auto({files!r}, filename=true, union_by_name=true, maximum_object_size=4000000)
    """)
    con.execute("DROP TABLE IF EXISTS activity")
    con.execute("""
        CREATE TABLE activity AS
        SELECT * EXCLUDE (chunk, rn) FROM (
            SELECT *, row_number() OVER (
                PARTITION BY tx_hash, event_type, token, quote_address, token_amount, cost_usd
                ORDER BY chunk) AS rn
            FROM activity_raw
        ) WHERE rn = 1
    """)
    raw, dedup = con.execute("SELECT (SELECT count(*) FROM activity_raw), (SELECT count(*) FROM activity)").fetchone()
    print(f"rows raw {raw:,}  deduped {dedup:,}  removed {raw - dedup:,}")
    con.execute("DROP TABLE IF EXISTS monthly")
    con.execute("""
        CREATE TABLE monthly AS
        SELECT strftime(t, '%Y-%m') AS month,
               count(*)                                            AS legs,
               count(DISTINCT tx_hash)                             AS txs,
               count(DISTINCT token)                               AS tokens,
               sum(CASE WHEN event_type='buy'  THEN 1 ELSE 0 END)  AS buy_legs,
               sum(CASE WHEN event_type='sell' THEN 1 ELSE 0 END)  AS sell_legs,
               round(sum(CASE WHEN event_type='buy'  THEN cost_usd END))  AS buy_usd,
               round(sum(CASE WHEN event_type='sell' THEN cost_usd END))  AS sell_usd,
               round(sum(CASE WHEN event_type='sell' THEN cost_usd - buy_cost_usd END)) AS realized_usd,
               round(sum(gas_usd + coalesce(priority_fee,0)*0 ))   AS gas_usd,
               min(t) AS first_t, max(t) AS last_t
        FROM activity GROUP BY 1 ORDER BY 1
    """)
    print(con.execute("SELECT * FROM monthly").df().to_string(index=False))
    tot = con.execute("""SELECT count(*), count(DISTINCT tx_hash), count(DISTINCT token), min(t), max(t),
                         round(sum(CASE WHEN event_type='sell' THEN cost_usd - buy_cost_usd END)) FROM activity""").fetchone()
    print(f"\nTOTAL legs {tot[0]:,} txs {tot[1]:,} tokens {tot[2]:,} span {tot[3]} -> {tot[4]} realized(sum of sell legs) ${tot[5]:,.0f}")
    # reconcile with GMGN stats windows (7d/30d) if the baseline files exist
    for win, days in (("7d", 7), ("30d", 30)):
        p = os.path.join(DATA, "baseline", f"stats_{win}.json")
        if os.path.exists(p):
            s = json.load(open(p)); s = s.get("data", s)
            last = con.execute("SELECT max(ts) FROM activity").fetchone()[0]
            b, sl, u = con.execute(f"""SELECT count(DISTINCT CASE WHEN event_type='buy' THEN tx_hash||token END),
                                              count(DISTINCT CASE WHEN event_type='sell' THEN tx_hash||token END),
                                              round(sum(CASE WHEN event_type='sell' THEN cost_usd - buy_cost_usd END))
                                       FROM activity WHERE ts > {last} - {days}*86400""").fetchone()
            print(f"reconcile {win}: GMGN buys {s['buy']} sells {s['sell']} realized ${float(s['realized_profit']):,.0f} | ours (tx,token) buys {b} sells {sl} realized ${u:,.0f}  (windows differ by pull time)")
    con.execute(f"COPY activity TO '{os.path.join(DATA, 'activity.parquet')}' (FORMAT PARQUET)")
    # transfer / liquidity legs (separate pull; mostly inbound dust drops)
    tfiles = sorted(glob.glob(os.path.join(DATA, "activity", "transferIn-transferOut-add-remove_*.jsonl")))
    if tfiles:
        con.execute("DROP TABLE IF EXISTS transfers")
        con.execute(f"""
            CREATE TABLE transfers AS
            SELECT DISTINCT tx_hash, CAST(timestamp AS BIGINT) AS ts, to_timestamp(CAST(timestamp AS BIGINT)) AS t,
                   event_type, token.address AS token, token.symbol AS symbol,
                   TRY_CAST(token_amount AS DOUBLE) AS token_amount, TRY_CAST(cost_usd AS DOUBLE) AS cost_usd,
                   from_address, to_address
            FROM read_json_auto({tfiles!r}, union_by_name=true, maximum_object_size=4000000)
        """)
        n = con.execute("SELECT count(*) FROM transfers").fetchone()[0]
        print(f"\ntransfers table: {n:,} legs")
        print(con.execute("SELECT event_type, count(*) c, count(DISTINCT token) tokens, count(DISTINCT tx_hash) txs FROM transfers GROUP BY 1").df().to_string(index=False))
        con.execute(f"COPY transfers TO '{os.path.join(DATA, 'transfers.parquet')}' (FORMAT PARQUET)")
    con.close()


if __name__ == "__main__":
    main()
