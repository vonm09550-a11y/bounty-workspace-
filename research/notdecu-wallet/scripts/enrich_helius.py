#!/usr/bin/env python3
"""Mini-phase 2.2: enrich every unique tx_hash from the activity index with Helius parseTransactions.

Resumable (signature cache in data/helius/parsed.jsonl). Paced to the free plan (2 enhanced req/s).
Then flattens the parsed transactions into DuckDB table `tx` (one row per transaction) and
`tx_native_out` (SOL leaving the wallet per transaction: fees, tips, bot charges).

    python3 scripts/enrich_helius.py --pull      # fetch missing signatures
    python3 scripts/enrich_helius.py --load      # (re)build the tx tables from the cache
"""
import argparse
import json
import os
import sys
import time

import duckdb

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from clients import DATA, Helius  # noqa: E402

DB = os.path.join(DATA, "notdecu.duckdb")
CACHE = os.path.join(DATA, "helius", "parsed.jsonl")
WALLET = "4vw54BmAogeRV3vPKWyFet5yf8DTLcREzdSzx4rw9Ud9"
SKIP = ("ComputeBudget111111111111111111111111111111", "11111111111111111111111111111111")


def pull():
    con = duckdb.connect(DB, read_only=True)
    sigs = [r[0] for r in con.execute("SELECT DISTINCT tx_hash FROM activity ORDER BY 1").fetchall()]
    con.close()
    have = set()
    if os.path.exists(CACHE):
        for line in open(CACHE):
            have.add(json.loads(line)["signature"])
    todo = [s for s in sigs if s not in have]
    print(f"unique tx {len(sigs):,}, cached {len(have):,}, to fetch {len(todo):,} (~{len(todo) / 100 / 2 / 60:.0f} min)")
    h = Helius()
    t0 = time.time()
    for i in range(0, len(todo), 2000):
        h.parse(todo[i:i + 2000], cache=CACHE)
        print(f"  {min(i + 2000, len(todo)):,}/{len(todo):,} in {(time.time() - t0) / 60:.1f} min", flush=True)


def load():
    con = duckdb.connect(DB)
    con.execute("DROP TABLE IF EXISTS tx")
    con.execute(f"""
        CREATE TABLE tx AS
        SELECT signature, slot, timestamp AS ts, to_timestamp(timestamp) AS t, type, source, fee, feePayer AS fee_payer,
               transactionError IS NOT NULL AS failed,
               list_transform(instructions, i -> i.programId) AS top_programs,
               len(tokenTransfers) AS n_token_transfers,
               len(nativeTransfers) AS n_native_transfers
        FROM read_json_auto('{CACHE}', union_by_name=true, maximum_object_size=8000000)
    """)
    con.execute("DROP TABLE IF EXISTS tx_native_out")
    con.execute(f"""
        CREATE TABLE tx_native_out AS
        SELECT signature, n.toUserAccount AS to_account, n.amount / 1e9 AS sol
        FROM (SELECT signature, unnest(nativeTransfers) AS n
              FROM read_json_auto('{CACHE}', union_by_name=true, maximum_object_size=8000000))
        WHERE n.fromUserAccount = '{WALLET}'
    """)
    con.execute("DROP TABLE IF EXISTS tx_programs")
    con.execute(f"""
        CREATE TABLE tx_programs AS
        SELECT DISTINCT signature, p AS program, depth FROM (
            SELECT signature, unnest(list_transform(instructions, i -> i.programId)) AS p, 'top' AS depth
            FROM read_json_auto('{CACHE}', union_by_name=true, maximum_object_size=8000000)
            UNION ALL
            SELECT signature, ii.programId AS p, 'inner' AS depth
            FROM (SELECT signature, unnest(instructions) AS i FROM read_json_auto('{CACHE}', union_by_name=true, maximum_object_size=8000000)),
                 unnest(i.innerInstructions) AS u(ii)
        ) WHERE p NOT IN {SKIP}
    """)
    n, f, fp = con.execute(f"SELECT count(*), sum(failed::int), sum((fee_payer='{WALLET}')::int) FROM tx").fetchone()
    print(f"tx {n:,}  failed {f}  fee_payer==wallet {fp:,}")
    print(con.execute("SELECT type, source, count(*) c FROM tx GROUP BY 1,2 ORDER BY c DESC LIMIT 12").df().to_string(index=False))
    print(con.execute("SELECT program, depth, count(*) c FROM tx_programs GROUP BY 1,2 ORDER BY c DESC LIMIT 15").df().to_string(index=False))
    con.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pull", action="store_true")
    ap.add_argument("--load", action="store_true")
    a = ap.parse_args()
    if a.pull:
        pull()
    if a.load:
        load()
    if not (a.pull or a.load):
        ap.print_help()
