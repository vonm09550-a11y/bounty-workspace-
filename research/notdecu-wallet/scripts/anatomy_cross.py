#!/usr/bin/env python3
"""Phase D6-C: cross-launch tables for loop 1 (slingoor 32 + retardmode 19), offline and read-only.

    python3 scripts/anatomy_cross.py [--out data/anatomy/loop1] [--members data/anatomy/member_wallets.json]
                                     [--db data/notdecu.duckdb] [--notes data/anatomy/loop1/notes_cross.md] [--rebuild-trades]

Inputs: <out>/anatomy_<dev>.parquet (Phase B), <out>/<dev>/<mint>.parsed.jsonl + .meta.json (Phase A), the member list,
and dev_tokens / dev_runs from DuckDB. Outputs, all under <out>/:
  cross_trades.parquet          every trade of every launch, re-derived from account-level token balance changes (cache;
                                --rebuild-trades forces a rebuild). One row per (tx, trader); quote = curve/pool-side amount
                                in the launch's quote asset, sol = the same converted to SOL (NaN when no SOL<->quote rate
                                is observable in the window's own router legs).
  cross_member_launches.*       one row per (member wallet, launch) with a buy or sell in the window.
  cross_members.*               the member graph, one row per member wallet (32 rows; the creator is excluded on his own launches).
  cross_launches.*              per-launch features measurable at 60 s and 300 s, plus 10-second-bucket price multiples.
  cross_launchers.*             launcher fingerprints, long format (dev, group, metric, n, median, p25, p75, note).
  cross_separation.csv          hit vs miss distributions per launcher for the minute-1 / minute-5 features.
  cross_thresholds.csv          simple threshold rules and how many hits / misses pass them, per launcher.
  cross_entry.csv               the entry window on hits: price multiple vs the dev's first-buy price at 30/60/120/300 s vs the peak.
  SUMMARY_cross.md              the tables above, a data-problems section, and the notes file (reading) at the top.

Trade derivation follows scripts/anatomy_build.py (trader = user account whose balance of the mint changed; quote amount = the
market account's own change of the quote asset, split pro rata across traders) with one extension: the set of market accounts
is the meta's bonding_curve/pool plus every non-creator user account that receives >= 5% of supply in the create transaction.
This catches Raydium LaunchLab ("stonkfun") launches, whose vault authority is not in the meta and which are quoted in
another token; Phase B recorded rent (0.002 SOL) as the dev's buy on those. Prices and multiples are computed in quote units
(unit-free), so they are valid even where SOL conversion is not. Seconds are relative to meta.create_ts. NULL means
unmeasurable, never 0.
"""
import argparse
import glob
import json
import os
import statistics
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import anatomy_build as ab  # noqa: E402

SUPPLY = ab.SUPPLY
BASE_FEE = ab.BASE_FEE
WSOL = ab.WSOL
CREATORS = {"slingoor": "5YRgrP3mjGzrzirYYN5HAQH19cTYREYwGxW6XRJQUzij",
            "retardmode": "ASv4ktNwZ8uBbUj94ACnr7Nj1sTtcYnEUZgWxkMsakA7"}
DEVS = ["slingoor", "retardmode"]
BUCKET = 10
MARKS_ENTRY = [30, 60, 120, 300]
fmt, md_table = ab.fmt, ab.md_table


# ----------------------------------------------------------------------------------------------------------------- trades
def market_accounts(txs, meta, creator):
    """meta pools + non-creator user accounts receiving >= 5% of supply in the create tx (LaunchLab vault authority etc.)."""
    pools = {p for p in (meta.get("bonding_curve"), meta.get("pool")) if p}
    mint = meta["token"]
    for t in txs:
        if t.get("transactionError"):
            continue
        inflow = defaultdict(float)
        for a in t.get("accountData") or []:
            for ch in a.get("tokenBalanceChanges") or []:
                if ch.get("mint") == mint:
                    inflow[ch.get("userAccount")] += ab.tok_amt(ch)
        if t.get("type") == "CREATE" or sum(v for v in inflow.values() if v > 0) >= 0.5 * SUPPLY:
            for u, v in inflow.items():
                if u != creator and v >= 0.05 * SUPPLY:
                    pools.add(u)
            break
    return pools


def extract_trades(txs, meta, creator, pools, qmint, per_min, glob_med):
    """anatomy_build.extract_trades with an explicit market-account set and a raw `quote` column."""
    mint, cts = meta["token"], meta["create_ts"]
    trades, kinds, create_sig, first_ts, migrate_s = [], Counter(), None, None, None
    for t in txs:
        if t.get("transactionError"):
            kinds["err"] += 1
            continue
        ts = t["timestamp"]
        first_ts = ts if first_ts is None else min(first_ts, ts)
        if t.get("type") == "MIGRATE_LIQUIDITY" and migrate_s is None:
            migrate_s = ts - cts
        net, mkt_tok, mkt_q, minted = defaultdict(float), 0.0, 0.0, 0.0
        for a in t.get("accountData") or []:
            if a["account"] in pools and qmint is None:
                mkt_q += (a.get("nativeBalanceChange") or 0) / 1e9
            for ch in a.get("tokenBalanceChanges") or []:
                amt = ab.tok_amt(ch)
                u = ch.get("userAccount")
                if ch.get("mint") == mint:
                    minted += max(amt, 0.0)
                    if u in pools:
                        mkt_tok += amt
                    else:
                        net[u] += amt
                elif u in pools and ((qmint is None and ch.get("mint") == WSOL) or (qmint is not None and ch.get("mint") == qmint)):
                    mkt_q += amt
        if t.get("type") == "CREATE" or minted >= 0.5 * SUPPLY:  # the create: the whole supply appears (curve + dev on LaunchLab)
            create_sig = create_sig or t["signature"]
        traders = {u: v for u, v in net.items() if abs(v) >= 1e-6}
        if not traders:
            kinds["noop"] += 1
            continue
        if mkt_tok == 0 and abs(mkt_q) < 1e-9:
            kinds["transfer"] += 1
            continue
        kinds["trade"] += 1
        tot = sum(abs(v) for v in traders.values())
        q = abs(mkt_q)
        if qmint is None:
            q_sol = q
        else:
            r = ab.rate_at(per_min, glob_med, (ts - cts) // 60)
            q_sol = q / r if r else float("nan")
        for u, v in sorted(traders.items()):
            trades.append({"sig": t["signature"], "slot": t["slot"], "ts": ts, "s": ts - cts, "wallet": u,
                           "side": "buy" if v > 0 else "sell", "tokens": abs(v), "quote": q * abs(v) / tot,
                           "sol": q_sol * abs(v) / tot, "fee_payer": t.get("feePayer"), "fee": t.get("fee") or 0})
    return pd.DataFrame(trades), kinds, create_sig, first_ts, migrate_s


def build_trades(out, book):
    rows, infos = [], []
    for dev in DEVS:
        creator = CREATORS[dev]
        for mp in sorted(glob.glob(os.path.join(out, dev, "*.meta.json"))):
            meta = json.load(open(mp))
            txs = ab.load_parsed(mp.replace(".meta.json", ".parsed.jsonl"))
            pools = market_accounts(txs, meta, creator)
            qmint = ab.quote_mint_of(txs, meta["token"], pools)
            per_min, glob_med = ab.rate_series(txs, qmint, pools, meta["create_ts"]) if qmint else ({}, None)
            tr, kinds, create_sig, first_ts, migrate_s = extract_trades(txs, meta, creator, pools, qmint, per_min, glob_med)
            sources = Counter(t.get("source") for t in txs if not t.get("transactionError"))
            last_s = max((t["timestamp"] for t in txs), default=meta["create_ts"]) - meta["create_ts"]
            truncated = bool(meta.get("truncated"))
            # coverage: the window is observed up to 1800 s unless the pull was truncated, or the curve migrated to a pool
            # that was never pulled (LaunchLab launches with pool=None): after that point nothing is observed.
            coverage_s = last_s if (truncated or (migrate_s is not None and not meta.get("pool"))) else 1800
            b = book.get(meta["token"], {})
            info = {"dev": dev, "creator": creator, "token": meta["token"], "symbol": (meta.get("symbol") or "").strip(),
                    "create_ts": meta["create_ts"], "hit": bool(meta.get("hit")), "ath_mc": meta.get("ath_mc"),
                    "sig_source": meta.get("sig_source"), "n_tx": len(txs), "n_trades": len(tr), "n_noop": kinds["noop"],
                    "n_transfer": kinds["transfer"], "create_sig": create_sig, "first_tx_s": (first_ts - meta["create_ts"]) if first_ts else None,
                    "window_last_s": last_s, "truncated": truncated, "coverage_s": coverage_s, "migrate_s": migrate_s,
                    "curve_last_s": meta.get("curve_last_s"), "pool": meta.get("pool"), "n_market_accounts": len(pools),
                    "quote_mint": qmint, "quote_per_sol_med": glob_med, "n_rate_minutes": len(per_min),
                    "sol_ok": (qmint is None) or (glob_med is not None), "launchpad_platform": b.get("launchpad_platform"),
                    "book_bundler_rate": b.get("bundler_rate"), "book_holders": b.get("holders"),
                    "src_main": sources.most_common(1)[0][0] if sources else None}
            infos.append(info)
            if len(tr):
                tr.insert(0, "symbol", info["symbol"])
                tr.insert(0, "token", meta["token"])
                tr.insert(0, "dev", dev)
                tr["hit"] = info["hit"]
                rows.append(tr)
            print(f"{dev:>10} {info['symbol']:>10} tx={len(txs):6d} trades={len(tr):6d} qmint={'SOL' if qmint is None else qmint[:6]} "
                  f"rate={fmt(glob_med)} coverage={coverage_s}s markets={len(pools)}", flush=True)
    trades = pd.concat(rows, ignore_index=True).sort_values(["dev", "create_ts" if False else "token", "s", "slot", "sig", "wallet"]).reset_index(drop=True)
    return trades, pd.DataFrame(infos)


# ---------------------------------------------------------------------------------------------------------------- helpers
def nn(v):
    """None for NULL/NaN, else the value (parquet round-trips None as NaN)."""
    return None if v is None or (not isinstance(v, str) and pd.isna(v)) else v


def q(x, p):
    x = pd.Series(x).dropna()
    return float(np.percentile(x, p)) if len(x) else None


def dist(x):
    x = pd.Series(x, dtype="float64").dropna()
    return {"n": int(len(x)), "median": float(x.median()) if len(x) else None,
            "p25": q(x, 25), "p75": q(x, 75), "min": float(x.min()) if len(x) else None, "max": float(x.max()) if len(x) else None}


def price_buckets(tr, min_quote):
    """10-second buy VWAP (quote per token) for buckets with >= min_quote traded; index = bucket start second."""
    b = tr[(tr.side == "buy") & (tr.tokens > 0) & (tr.quote > 0)]
    if b.empty:
        return pd.Series(dtype="float64")
    g = b.assign(bk=(b.s // BUCKET) * BUCKET).groupby("bk").agg(quote=("quote", "sum"), tokens=("tokens", "sum"))
    g = g[g.quote >= min_quote]
    return (g.quote / g.tokens).astype("float64")


def mult_at(px, dev_price, t):
    """multiple over the dev's first-buy price at second t: VWAP of the last complete bucket (start <= t - BUCKET)."""
    if dev_price is None or px.empty:
        return None
    sel = px[px.index <= t - BUCKET]
    return float(sel.iloc[-1] / dev_price) if len(sel) else None


def max_after(px, dev_price, t):
    if dev_price is None or px.empty:
        return None, None
    sel = px[px.index >= t]
    if not len(sel):
        return None, None
    return float(sel.max() / dev_price), int(sel.idxmax())


def top10_share(tr, t, dust=1.0):
    w = tr[tr.s <= t]
    net = w[w.side == "buy"].groupby("wallet").tokens.sum().sub(w[w.side == "sell"].groupby("wallet").tokens.sum(), fill_value=0.0)
    longs = net[net > dust].sort_values(ascending=False)
    return (float(longs.head(10).sum() / longs.sum()) if len(longs) else None), int(len(longs))


# ------------------------------------------------------------------------------------------------------ per-launch features
def launch_features(tr, info, members, phaseb):
    creator = info["creator"]
    mem = {a for a in members if a != creator}
    cov = info["coverage_s"]
    r = {k: info[k] for k in ["dev", "token", "symbol", "create_ts", "hit", "ath_mc", "coverage_s", "truncated", "sol_ok",
                              "quote_mint", "launchpad_platform", "migrate_s", "curve_last_s", "n_trades"]}
    r["measurable"] = len(tr) > 0
    r["n_markets"] = info["n_market_accounts"]
    if tr.empty:
        return r
    tr = tr.sort_values(["s", "slot", "sig", "wallet"]).reset_index(drop=True)
    buys, sells = tr[tr.side == "buy"], tr[tr.side == "sell"]
    db, ds = buys[buys.wallet == creator], sells[sells.wallet == creator]
    dev_price = None
    if len(db):
        f = db.iloc[0]
        r.update({"dev_first_buy_s": int(f.s), "dev_first_buy_sol": float(f.sol) if info["sol_ok"] else None,
                  "dev_first_buy_quote": float(f.quote), "dev_first_buy_tokens": float(f.tokens), "dev_supply_share": float(f.tokens / SUPPLY),
                  "dev_same_slot_buyers": int(buys[(buys.slot == f.slot) & (buys.wallet != creator)].wallet.nunique()),
                  "dev_fee_first_tx": int(f.fee - BASE_FEE) if f.fee_payer == creator else None})
        dev_price = f.quote / f.tokens if f.tokens > 0 and f.quote > 0 else None
        dfees = tr[(tr.fee_payer == creator) & (tr.s <= 60)].drop_duplicates("sig")
        r["dev_fee_med_60s"] = float((dfees.fee - BASE_FEE).median()) if len(dfees) else None
        for t in (60, 120, 300):
            if cov >= t:
                sold = ds[ds.s <= t].tokens.sum()
                r[f"dev_sold_by_{t}s"] = bool(sold > 0)
                r[f"dev_sold_share_{t}s"] = float(min(1.0, sold / db[db.s <= t].tokens.sum())) if db[db.s <= t].tokens.sum() > 0 else None
    r["dev_fee_lamports_med"] = phaseb.get("dev_fee_lamports_med")
    r["dev_first_sell_s"] = int(ds.iloc[0].s) if len(ds) else None
    r["dev_sold_share_30m"] = float(min(1.0, ds.tokens.sum() / db.tokens.sum())) if len(db) and cov >= 1800 else None
    r["dev_sell_sol_30m"] = float(ds.sol.sum()) if info["sol_ok"] and cov >= 1800 else None
    mb = buys[buys.wallet.isin(mem)]
    ob = buys[(buys.wallet != creator) & (~buys.wallet.isin(mem))]
    r["member_first_buy_s"] = int(mb.iloc[0].s) if len(mb) else None
    r["outside_first_buy_s"] = int(ob.iloc[0].s) if len(ob) else None
    for t, k in ((60, "1m"), (300, "5m")):
        if cov < t:
            continue
        r[f"sol_in_{k}"] = float(buys[buys.s <= t].sol.sum()) if info["sol_ok"] else None
        r[f"sol_out_{k}"] = float(sells[sells.s <= t].sol.sum()) if info["sol_ok"] else None
        r[f"net_sol_{k}"] = (r[f"sol_in_{k}"] - r[f"sol_out_{k}"]) if info["sol_ok"] else None
        r[f"n_buys_{k}"] = int((buys.s <= t).sum())
        r[f"n_wallets_{k}"] = int(tr[tr.s <= t].wallet.nunique())
        r[f"member_buy_by_{k}"] = bool((mb.s <= t).any())
        r[f"member_buy_sol_{k}"] = float(mb[mb.s <= t].sol.sum()) if info["sol_ok"] else None
        r[f"member_buyers_{k}"] = int(mb[mb.s <= t].wallet.nunique())
        r[f"outside_buy_sol_{k}"] = float(ob[ob.s <= t].sol.sum()) if info["sol_ok"] else None
        r[f"top10_share_{k}"], r[f"n_net_long_{k}"] = top10_share(tr, t)
    # price path in quote units (unit-free multiples)
    min_quote = 0.01 * (nn(info["quote_per_sol_med"]) or 1.0) if info["sol_ok"] else 0.001 * (r.get("dev_first_buy_quote") or 1.0)
    px = price_buckets(tr, min_quote)
    r["n_price_buckets"] = int(len(px))
    if dev_price and len(px):
        r["peak10_mult"] = float(px.max() / dev_price)
        r["peak10_ts_s"] = int(px.idxmax())
        r["end_mult"] = float(px.iloc[-1] / dev_price)
        for t in MARKS_ENTRY:
            if cov >= t:
                r[f"mult_{t}s"] = mult_at(px, dev_price, t)
                r[f"max_after_{t}s"], r[f"max_after_{t}s_ts"] = max_after(px, dev_price, t)
                r[f"ahead_{t}s"] = (r[f"max_after_{t}s"] / r[f"mult_{t}s"]) if r.get(f"mult_{t}s") and r.get(f"max_after_{t}s") else None
    r["peak1_ts_s"] = phaseb.get("peak_ts_s")
    r["peak1_mult"] = phaseb.get("peak_mult_vs_dev")
    return r


# ------------------------------------------------------------------------------------------------------------ member graph
def member_launch_rows(trades, infos, members):
    rows = []
    for _, info in infos.iterrows():
        tr = trades[trades.token == info.token]
        if tr.empty:
            continue
        creator = info.creator
        mem = {a: v for a, v in members.items() if a != creator}
        tl = tr[tr.wallet.isin(mem)].sort_values(["s", "slot", "sig"])
        dbuy = tr[(tr.wallet == creator) & (tr.side == "buy")]
        dev_price = None
        if len(dbuy):
            f = dbuy.sort_values(["s", "slot", "sig"]).iloc[0]
            dev_price = f.quote / f.tokens if f.tokens > 0 and f.quote > 0 else None
        min_quote = 0.01 * (nn(info.quote_per_sol_med) or 1.0) if info.sol_ok else 0.0
        px = price_buckets(tr, min_quote)
        end_px = float(px.iloc[-1]) if len(px) else None  # quote per token, last bucket in the window
        rate = nn(info.quote_per_sol_med) if nn(info.quote_mint) else 1.0
        for w in sorted(tl.wallet.unique()):
            g = tl[tl.wallet == w]
            b, s = g[g.side == "buy"], g[g.side == "sell"]
            rec = {"username": mem[w]["username"], "wallet": w, "dev": info.dev, "token": info.token, "symbol": info.symbol, "hit": bool(info.hit),
                   "coverage_s": int(info.coverage_s), "sol_ok": bool(info.sol_ok),
                   "n_buys": int(len(b)), "n_sells": int(len(s)), "bought": len(b) > 0, "sold": len(s) > 0,
                   "first_buy_s": int(b.iloc[0].s) if len(b) else None, "last_buy_s": int(b.iloc[-1].s) if len(b) else None,
                   "first_buy_sol": float(b.iloc[0].sol) if len(b) and info.sol_ok else None,
                   "buy_sol": float(b.sol.sum()) if len(b) and info.sol_ok else None, "buy_tokens": float(b.tokens.sum()),
                   "first_sell_s": int(s.iloc[0].s) if len(s) else None, "sell_sol": float(s.sol.sum()) if len(s) and info.sol_ok else None,
                   "sell_tokens": float(s.tokens.sum()), "buy_supply_share": float(b.tokens.sum() / SUPPLY)}
            rec["hold_s"] = (rec["first_sell_s"] - rec["first_buy_s"]) if rec["sold"] and rec["bought"] else None
            rec["sold_share"] = float(min(1.0, s.tokens.sum() / b.tokens.sum())) if len(b) else None
            rec["closed"] = bool(rec["sold_share"] is not None and rec["sold_share"] >= 0.95)
            rec["entry_mult_vs_dev"] = float((b.iloc[0].quote / b.iloc[0].tokens) / dev_price) if len(b) and dev_price and b.iloc[0].tokens > 0 else None
            remaining = max(0.0, b.tokens.sum() - s.tokens.sum())
            rec["remaining_tokens"] = float(remaining)
            if info.sol_ok and len(b):
                rec["net_sol_realized"] = float((s.sol.sum() if len(s) else 0.0) - b.sol.sum())
                rec["remaining_marked_sol"] = float(remaining * end_px / rate) if end_px is not None and rate else None
                rec["net_sol_marked"] = rec["net_sol_realized"] + rec["remaining_marked_sol"] if rec["remaining_marked_sol"] is not None else None
            rows.append(rec)
    return pd.DataFrame(rows)


def member_graph(ml, members):
    rows = []
    for w, v in members.items():
        g = ml[(ml.wallet == w) & ml.bought] if len(ml) else ml
        so = ml[(ml.wallet == w) & (~ml.bought)] if len(ml) else ml
        rec = {"username": v["username"], "wallet": w, "role": v.get("role") or "", "tags": ",".join(v.get("tags") or []),
               "n_launches_bought": int(len(g)), **{f"n_{d}": int((g.dev == d).sum()) for d in DEVS},
               "n_hits": int(g.hit.sum()) if len(g) else 0, "n_nonhits": int((~g.hit).sum()) if len(g) else 0,
               **{f"n_hits_{d}": (int(g[g.dev == d].hit.sum()) if len(g) else 0) for d in DEVS},
               "hit_share_of_bought": float(g.hit.mean()) if len(g) else None,
               "med_entry_s": float(g.first_buy_s.median()) if len(g) else None, "min_entry_s": int(g.first_buy_s.min()) if len(g) else None,
               "p75_entry_s": q(g.first_buy_s, 75) if len(g) else None,
               "med_entry_mult_vs_dev": float(g.entry_mult_vs_dev.median()) if len(g) and g.entry_mult_vs_dev.notna().any() else None,
               "med_first_buy_sol": float(g.first_buy_sol.median()) if len(g) and g.first_buy_sol.notna().any() else None,
               "med_buy_sol_per_launch": float(g.buy_sol.median()) if len(g) and g.buy_sol.notna().any() else None,
               "total_buy_sol": float(g.buy_sol.sum()) if len(g) and g.buy_sol.notna().any() else None,
               "n_sol_computable": int(g.buy_sol.notna().sum()) if len(g) else 0,
               "med_buy_supply_share": float(g.buy_supply_share.median()) if len(g) else None,
               "n_sold_in_window": int(g.sold.sum()) if len(g) else 0,
               "share_sold_in_window": float(g.sold.mean()) if len(g) else None,
               "n_closed_in_window": int(g.closed.sum()) if len(g) else 0,
               "med_hold_s": float(g.hold_s.median()) if len(g) and g.hold_s.notna().any() else None,
               "med_sold_share": float(g.sold_share.median()) if len(g) else None,
               "net_sol_realized": float(g.net_sol_realized.sum()) if len(g) and g.net_sol_realized.notna().any() else None,
               "net_sol_marked": float(g.net_sol_marked.sum()) if len(g) and g.net_sol_marked.notna().any() else None,
               "net_sol_closed": float(g[g.closed].net_sol_realized.sum()) if len(g) and g.closed.any() and g[g.closed].net_sol_realized.notna().any() else None,
               "n_truncated_after_buy": int((g.coverage_s < 1800).sum()) if len(g) else 0,
               "n_sell_only": int(len(so)),
               "launches_bought": ",".join(f"{r.symbol}{'*' if r.hit else ''}@{r.first_buy_s}s" for r in g.sort_values(["first_buy_s", "symbol"]).itertuples()) if len(g) else ""}
        rows.append(rec)
    df = pd.DataFrame(rows).sort_values(["n_launches_bought", "med_entry_s", "username"], ascending=[False, True, True]).reset_index(drop=True)
    return df


# --------------------------------------------------------------------------------------------------- launcher fingerprints
FP_METRICS = ["dev_supply_share", "dev_first_buy_sol", "dev_same_slot_buyers", "dev_fee_lamports_med", "dev_fee_first_tx",
              "dev_first_sell_s", "dev_sold_share_30m", "dev_sell_sol_30m", "dev_sold_share_60s", "dev_sold_share_300s",
              "grad_s", "peak10_mult", "peak10_ts_s", "sol_in_1m", "sol_in_5m", "n_wallets_1m", "n_wallets_5m"]


def launcher_fingerprints(lf, infos):
    rows = []
    for dev in DEVS:
        d = lf[(lf.dev == dev) & lf.measurable].copy()
        d["grad_s"] = d.curve_last_s.astype("float64").where(d.curve_last_s.notna(), d.migrate_s.astype("float64"))
        for grp, g in (("all", d), ("hits", d[d.hit]), ("misses", d[~d.hit])):
            for m in FP_METRICS:
                s = dist(g[m]) if m in g else dist([])
                rows.append({"dev": dev, "group": grp, "metric": m, **s, "note": ""})
            rows.append({"dev": dev, "group": grp, "metric": "n_launches", "n": int(len(g)), "note": "measurable launches (with trades)"})
            rows.append({"dev": dev, "group": grp, "metric": "n_dev_sold_in_window", "n": int(g.dev_first_sell_s.notna().sum()), "note": "launches with a dev sell in the window"})
            rows.append({"dev": dev, "group": grp, "metric": "n_dev_sold_by_60s", "n": int(g.dev_sold_by_60s.fillna(False).astype(bool).sum()) if "dev_sold_by_60s" in g else 0, "note": ""})
            rows.append({"dev": dev, "group": grp, "metric": "n_dev_sold_by_300s", "n": int(g.dev_sold_by_300s.fillna(False).astype(bool).sum()) if "dev_sold_by_300s" in g else 0, "note": ""})
            rows.append({"dev": dev, "group": grp, "metric": "n_non_sol_quote", "n": int(g.quote_mint.notna().sum()), "note": "launches quoted in a token other than SOL"})
            rows.append({"dev": dev, "group": grp, "metric": "n_graduated_in_window", "n": int(g.grad_s.notna().sum()), "note": "curve completed inside the 30-min window"})
            rows.append({"dev": dev, "group": grp, "metric": "n_graduated_by_60s", "n": int((g.grad_s <= 60).sum()), "note": ""})
            rows.append({"dev": dev, "group": grp, "metric": "n_dev_buy_in_create_slot", "n": int((g.dev_first_buy_s == 0).sum()), "note": "dev_first_buy_s == 0"})
            for plat, n in Counter(g.launchpad_platform.fillna("?")).items():
                rows.append({"dev": dev, "group": grp, "metric": f"launchpad:{plat}", "n": int(n), "note": "dev_tokens.launchpad_platform"})
        # cadence and hour of day, all launches of the dev (including mint-only ones, which are launches too)
        allx = infos[infos.dev == dev].sort_values("create_ts")
        hours = [datetime.fromtimestamp(int(t), tz=timezone.utc).hour for t in allx.create_ts]
        for h, n in sorted(Counter(hours).items()):
            rows.append({"dev": dev, "group": "all", "metric": f"launch_hour_utc:{h:02d}", "n": int(n), "note": "launches created in this UTC hour (all rows of the launch list)"})
        for h, n in sorted(Counter(datetime.fromtimestamp(int(t), tz=timezone.utc).hour for t in allx[allx.hit].create_ts).items()):
            rows.append({"dev": dev, "group": "hits", "metric": f"launch_hour_utc:{h:02d}", "n": int(n), "note": ""})
        wd = Counter(datetime.fromtimestamp(int(t), tz=timezone.utc).strftime("%a") for t in allx.create_ts)
        for k, n in sorted(wd.items()):
            rows.append({"dev": dev, "group": "all", "metric": f"launch_weekday:{k}", "n": int(n), "note": ""})
        gaps = np.diff(allx.create_ts.values) / 3600.0
        rows.append({"dev": dev, "group": "all", "metric": "gap_between_launches_h", **dist(gaps), "note": "hours between consecutive launches"})
        rows.append({"dev": dev, "group": "all", "metric": "n_gaps_lt_1h", "n": int((gaps < 1).sum()), "note": "launch followed by another within 1 h"})
        rows.append({"dev": dev, "group": "all", "metric": "n_gaps_lt_24h", "n": int((gaps < 24).sum()), "note": ""})
        rows.append({"dev": dev, "group": "all", "metric": "span_days", "n": int(len(allx)), "median": float((allx.create_ts.max() - allx.create_ts.min()) / 86400.0), "note": "median = days from first to last launch"})
        rows.append({"dev": dev, "group": "all", "metric": "hour_utc", **dist(hours), "note": "distribution of the UTC hour of creation"})
        rows.append({"dev": dev, "group": "all", "metric": "book_bundler_rate", **dist(allx.book_bundler_rate), "note": "dev_tokens.bundler_rate"})
    df = pd.DataFrame(rows)
    for c in ["n", "median", "p25", "p75", "min", "max"]:
        if c not in df:
            df[c] = None
    return df[["dev", "group", "metric", "n", "median", "p25", "p75", "min", "max", "note"]]


# ------------------------------------------------------------------------------------------------------ hit/miss separation
SEP_1M = ["dev_supply_share", "dev_first_buy_sol", "dev_same_slot_buyers", "dev_fee_first_tx", "dev_fee_med_60s", "dev_fee_lamports_med",
          "dev_sold_share_60s", "sol_in_1m", "sol_out_1m", "net_sol_1m", "n_buys_1m", "n_wallets_1m", "member_buy_sol_1m", "outside_buy_sol_1m",
          "top10_share_1m", "n_net_long_1m", "mult_30s", "mult_60s"]
SEP_5M = ["dev_sold_share_120s", "dev_sold_share_300s", "sol_in_5m", "sol_out_5m", "net_sol_5m", "n_buys_5m", "n_wallets_5m",
          "member_buy_sol_5m", "member_buyers_5m", "outside_buy_sol_5m", "top10_share_5m", "n_net_long_5m", "mult_120s", "mult_300s"]
BOOL_1M = ["dev_sold_by_60s", "member_buy_by_1m"]
BOOL_5M = ["dev_sold_by_120s", "dev_sold_by_300s", "member_buy_by_5m"]


def separation(lf):
    rows = []
    for dev in DEVS:
        for mark, cols, bools in (("1m", SEP_1M, BOOL_1M), ("5m", SEP_5M, BOOL_5M)):
            d = lf[(lf.dev == dev) & lf.measurable & (lf.coverage_s >= (60 if mark == "1m" else 300)) & lf.dev_supply_share.notna()]
            for c in cols:
                h, m = dist(d[d.hit][c]), dist(d[~d.hit][c])
                rows.append({"dev": dev, "mark": mark, "column": c, "hits_n": h["n"], "hits_med": h["median"], "hits_p25": h["p25"], "hits_p75": h["p75"],
                             "miss_n": m["n"], "miss_med": m["median"], "miss_p25": m["p25"], "miss_p75": m["p75"]})
            for c in bools:
                h, m = d[d.hit][c].dropna().astype(bool), d[~d.hit][c].dropna().astype(bool)
                rows.append({"dev": dev, "mark": mark, "column": c + " (share true)", "hits_n": int(len(h)), "hits_med": float(h.mean()) if len(h) else None,
                             "miss_n": int(len(m)), "miss_med": float(m.mean()) if len(m) else None})
    return pd.DataFrame(rows)


def rules(d):
    s = d.dev_supply_share
    ns60 = ~d.dev_sold_by_60s.fillna(True).astype(bool)
    ns120 = ~d.dev_sold_by_120s.fillna(True).astype(bool)
    ns300 = ~d.dev_sold_by_300s.fillna(True).astype(bool)
    return [
        ("1m", "dev share >= 0.35", s >= 0.35),
        ("1m", "dev share >= 0.50", s >= 0.50),
        ("1m", "no dev sell by 60 s", ns60),
        ("1m", "dev share >= 0.35 and no dev sell by 60 s", (s >= 0.35) & ns60),
        ("1m", "dev share >= 0.35 and no dev sell by 60 s and same-slot buyers >= 2", (s >= 0.35) & ns60 & (d.dev_same_slot_buyers >= 2)),
        ("1m", "dev share >= 0.35 and no dev sell by 60 s and sol_in_1m >= 50", (s >= 0.35) & ns60 & (d.sol_in_1m >= 50)),
        ("1m", "no dev sell by 60 s and sol_in_1m >= 100", ns60 & (d.sol_in_1m >= 100)),
        ("1m", "no dev sell by 60 s and n_wallets_1m >= 100", ns60 & (d.n_wallets_1m >= 100)),
        ("1m", "dev share >= 0.35 and mult_60s >= 2", (s >= 0.35) & (d.mult_60s >= 2)),
        ("5m", "dev share >= 0.35 and no dev sell by 120 s", (s >= 0.35) & ns120),
        ("5m", "dev share >= 0.35 and no dev sell by 300 s", (s >= 0.35) & ns300),
        ("5m", "no dev sell by 300 s", ns300),
        ("5m", "no dev sell by 300 s and sol_in_5m >= 100", ns300 & (d.sol_in_5m >= 100)),
        ("5m", "no dev sell by 300 s and n_wallets_5m >= 200", ns300 & (d.n_wallets_5m >= 200)),
        ("5m", "dev share >= 0.35 and no dev sell by 300 s and member buy by 300 s", (s >= 0.35) & ns300 & d.member_buy_by_5m.fillna(False).astype(bool)),
        ("5m", "member buy by 300 s", d.member_buy_by_5m.fillna(False).astype(bool)),
        ("5m", "dev share >= 0.35 and no dev sell by 300 s and mult_300s >= 3", (s >= 0.35) & ns300 & (d.mult_300s >= 3)),
    ]


def thresholds(lf):
    rows = []
    for dev in DEVS:
        for mark, cov in (("1m", 60), ("5m", 300)):
            d = lf[(lf.dev == dev) & lf.measurable & (lf.coverage_s >= cov) & lf.dev_supply_share.notna()]
            for mk, name, mask in rules(d):
                if mk != mark:
                    continue
                mask = mask.fillna(False).astype(bool)
                hp, hn = int((mask & d.hit).sum()), int(d.hit.sum())
                mp, mn = int((mask & ~d.hit).sum()), int((~d.hit).sum())
                rows.append({"dev": dev, "mark": mark, "rule": name, "hits_pass": hp, "hits_n": hn, "miss_pass": mp, "miss_n": mn,
                             "precision": hp / (hp + mp) if hp + mp else None, "recall": hp / hn if hn else None})
    return pd.DataFrame(rows)


# ------------------------------------------------------------------------------------------------------------ entry window
def entry_table(lf, runs):
    h = lf[lf.hit & lf.measurable].copy()
    cols = ["dev", "symbol", "coverage_s", "dev_supply_share", "member_first_buy_s", "outside_first_buy_s", "peak1_ts_s", "peak1_mult",
            "peak10_ts_s", "peak10_mult", "end_mult"]
    for t in MARKS_ENTRY:
        cols += [f"mult_{t}s", f"max_after_{t}s", f"ahead_{t}s"]
    h = h[cols].copy()
    if runs is not None and len(runs):
        h = h.merge(runs, on=["dev", "symbol"], how="left") if "symbol" in runs else h
    return h.sort_values(["dev", "peak10_ts_s"], na_position="last").reset_index(drop=True)


# ---------------------------------------------------------------------------------------------------------------- summary
def sec_dist_table(df, cols, label):
    out = [f"| {label} | n | median | p25 | p75 | min | max |", "|---|---|---|---|---|---|---|"]
    for c in cols:
        s = dist(df[c])
        out.append(f"| {c} | {s['n']} | {fmt(s['median'])} | {fmt(s['p25'])} | {fmt(s['p75'])} | {fmt(s['min'])} | {fmt(s['max'])} |")
    return "\n".join(out)


def summary(members_df, ml, lf, fp, sep, thr, ent, infos, notes_path):
    out = ["# SUMMARY_cross — cross-launch tables, loop 1 (Phase C, offline)", ""]
    if notes_path and os.path.exists(notes_path):
        out += [open(notes_path).read().rstrip(), ""]
    out += ["Built by `scripts/anatomy_cross.py` from the Phase A transaction files and the Phase B tables (see the script docstring). "
            "Trades are re-derived from account-level token balance changes with an extended market-account set; multiples are in quote units; "
            "SOL figures for non-SOL-quoted launches use the window's own router rate. `kol_*` was never fetched, so 'outside' = everyone but the creator and the 31 other members.", ""]
    # coverage
    out += ["## Coverage", ""]
    for dev in DEVS:
        d = lf[lf.dev == dev]
        m = d[d.measurable]
        out.append(f"- {dev}: {len(d)} rows in the launch list, {len(m)} with trades (hits {int(m.hit.sum())}, misses {int((~m.hit).sum())}); "
                   f"coverage >= 60 s: {int((m.coverage_s >= 60).sum())}, >= 300 s: {int((m.coverage_s >= 300).sum())}, full 1800 s: {int((m.coverage_s >= 1800).sum())}; "
                   f"non-SOL quote: {int(m.quote_mint.notna().sum())} (SOL rate observable on {int((m.quote_mint.notna() & m.sol_ok).sum())}); "
                   f"dev never bought: {int(m.dev_supply_share.isna().sum())}")
    out.append(f"- trades in the cache: {int(lf.n_trades.sum())} across {int(lf.measurable.sum())} launches; member-launch rows: {len(ml)} ({int(ml.bought.sum())} with a buy)")
    # 1. member graph
    out += ["", "## 1. Member graph (creator excluded on his own launches; entry = first buy, s after create)", "",
            "Columns: launches bought per launcher, hits among them, median/min entry lag, median first-buy SOL and per-launch SOL, share of bought launches with any sell "
            "inside the observed window, median hold (first sell − first buy), realized net SOL (sells − buys, unrealized remainder counted at 0) and marked net SOL "
            "(remainder valued at the window's last 10-s buy VWAP), over launches where SOL is computable. `*` marks hits in the launch list; the 3 truncated slingoor hits "
            "and the LaunchLab launches shorten the observable window (n_trunc).", ""]
    cols = ["username", "n_launches_bought"] + [f"n_{d}" for d in DEVS] + ["n_hits", "n_nonhits", "med_entry_s", "min_entry_s", "med_entry_mult_vs_dev",
            "med_first_buy_sol", "med_buy_sol_per_launch", "total_buy_sol", "share_sold_in_window", "med_hold_s", "n_closed_in_window",
            "net_sol_realized", "net_sol_marked", "n_sol_computable", "n_truncated_after_buy", "n_sell_only", "tags"]
    out += [md_table(members_df, cols), ""]
    out += ["Launches bought per member (symbol, `*` = hit, @ first-buy second):", ""]
    for r in members_df[members_df.n_launches_bought > 0].itertuples():
        out.append(f"- {r.username}: {r.launches_bought}")
    out += ["", "Members never seen buying in any window: " + ", ".join(members_df[members_df.n_launches_bought == 0].username), ""]
    # member-launch detail, hits only
    out += ["### Member positions on hits (one row per member × hit)", ""]
    mh = ml[ml.bought & ml.hit].sort_values(["dev", "symbol", "first_buy_s"])
    out += [md_table(mh, ["dev", "symbol", "username", "first_buy_s", "entry_mult_vs_dev", "first_buy_sol", "buy_sol", "buy_supply_share", "sold", "first_sell_s", "hold_s", "sold_share", "net_sol_realized", "net_sol_marked", "coverage_s"]), ""]
    out += ["### Member positions on misses", ""]
    mm = ml[ml.bought & ~ml.hit].sort_values(["dev", "symbol", "first_buy_s"])
    out += [md_table(mm, ["dev", "symbol", "username", "first_buy_s", "entry_mult_vs_dev", "first_buy_sol", "buy_sol", "sold", "first_sell_s", "hold_s", "sold_share", "net_sol_realized", "net_sol_marked", "coverage_s"]), ""]
    # 2. fingerprints
    out += ["## 2. Launcher fingerprints", ""]
    for dev in DEVS:
        out += [f"### {dev}", "", "| metric | all n | all med [p25, p75] | hits n | hits med [p25, p75] | misses n | misses med [p25, p75] |", "|---|---|---|---|---|---|---|"]
        f = fp[fp.dev == dev]
        for m in FP_METRICS:
            cells = []
            for grp in ("all", "hits", "misses"):
                r = f[(f.group == grp) & (f.metric == m)].iloc[0]
                cells += [str(int(r.n)), f"{fmt(r['median'])} [{fmt(r.p25)}, {fmt(r.p75)}]"]
            out.append(f"| {m} | " + " | ".join(cells) + " |")
        counts = f[(f.metric.str.startswith("n_") | f.metric.str.startswith("launchpad:")) & ~f.metric.isin(FP_METRICS)]
        out += ["", "| count | all | hits | misses |", "|---|---|---|---|"]
        for m in counts.metric.unique():
            if m == "n_gaps_lt_1h" or m == "n_gaps_lt_24h":
                continue
            row = []
            for grp in ("all", "hits", "misses"):
                x = f[(f.group == grp) & (f.metric == m)]
                row.append(str(int(x.iloc[0].n)) if len(x) else "0")
            out.append(f"| {m} | " + " | ".join(row) + " |")
        hrs = f[f.metric.str.startswith("launch_hour_utc:") & (f.group == "all")]
        hrs_h = f[f.metric.str.startswith("launch_hour_utc:") & (f.group == "hits")]
        hh = {r.metric.split(":")[1]: int(r.n) for r in hrs_h.itertuples()}
        out += ["", "Launch hour (UTC), all launches in the list (hits in brackets): " + ", ".join(f"{r.metric.split(':')[1]}h: {int(r.n)} ({hh.get(r.metric.split(':')[1], 0)})" for r in hrs.itertuples())]
        wds = f[f.metric.str.startswith("launch_weekday:")]
        out += ["", "Weekday (UTC): " + ", ".join(f"{r.metric.split(':')[1]} {int(r.n)}" for r in wds.itertuples())]
        for m in ("hour_utc", "gap_between_launches_h", "book_bundler_rate"):
            r = f[(f.metric == m) & (f.group == "all")].iloc[0]
            out.append(f"- {m}: n={int(r.n)} median={fmt(r['median'])} p25={fmt(r.p25)} p75={fmt(r.p75)} min={fmt(r['min'])} max={fmt(r['max'])} ({r.note})")
        r = f[(f.metric == "span_days") & (f.group == "all")].iloc[0]
        out.append(f"- span: {int(r.n)} launches over {fmt(r['median'])} days (first to last in the list)")
        g1 = f[(f.metric == "n_gaps_lt_1h")].iloc[0].n
        g24 = f[(f.metric == "n_gaps_lt_24h")].iloc[0].n
        out.append(f"- gaps < 1 h: {int(g1)}; gaps < 24 h: {int(g24)}")
        out.append("")
    out += ["### Per-launch dev fingerprint (both launchers)", ""]
    out += [md_table(lf[lf.measurable].sort_values(["dev", "create_ts"]), ["dev", "symbol", "hit", "launchpad_platform", "coverage_s", "dev_supply_share", "dev_first_buy_sol", "dev_same_slot_buyers",
                                                                           "dev_fee_first_tx", "dev_fee_lamports_med", "dev_first_sell_s", "dev_sold_share_60s", "dev_sold_share_300s", "dev_sold_share_30m",
                                                                           "grad_s", "peak10_mult", "peak10_ts_s"]), ""]
    # 3. separation
    out += ["## 3. Hit vs miss at minute 1 and minute 5 (distributions; n = launches with a value; in-sample, no model)", ""]
    for dev in DEVS:
        for mark in ("1m", "5m"):
            s = sep[(sep.dev == dev) & (sep.mark == mark)]
            out += [f"### {dev}, minute {mark[0]}", "", "| column | hits n | hits med | hits p25 | hits p75 | misses n | misses med | misses p25 | misses p75 |", "|---|---|---|---|---|---|---|---|---|"]
            for r in s.itertuples():
                out.append(f"| {r.column} | {r.hits_n} | {fmt(r.hits_med)} | {fmt(r.hits_p25)} | {fmt(r.hits_p75)} | {r.miss_n} | {fmt(r.miss_med)} | {fmt(r.miss_p25)} | {fmt(r.miss_p75)} |")
            out.append("")
    out += ["### Threshold rules (hits passing / hits, misses passing / misses; launches with a dev buy and coverage to the mark)", "",
            "| dev | mark | rule | hits | misses | precision | recall |", "|---|---|---|---|---|---|---|"]
    for r in thr.itertuples():
        out.append(f"| {r.dev} | {r.mark} | {r.rule} | {r.hits_pass} of {r.hits_n} | {r.miss_pass} of {r.miss_n} | {fmt(r.precision)} | {fmt(r.recall)} |")
    # 4. entry window
    out += ["", "## 4. The entry window on hits", "",
            "Multiples are the 10-second buy VWAP over the dev's first-buy price (quote units). `mult_Ts` = last complete bucket before T; "
            "`max_after_Ts` = best bucket at or after T inside the observed window; `ahead_Ts` = max_after / mult (how much of the run was still ahead of a buyer at T). "
            "`peak1_*` is Phase B's 1-second peak. Retardmode hits and slingoor's PEACE-like cases ran after the window, so window peaks are lower bounds.", ""]
    for dev in DEVS:
        e = ent[ent.dev == dev]
        out += [f"### {dev} hits (n={len(e)})", "", sec_dist_table(e, ["member_first_buy_s", "outside_first_buy_s", "peak1_ts_s", "peak10_ts_s", "peak10_mult", "mult_30s", "mult_60s", "mult_120s", "mult_300s",
                                                                       "ahead_30s", "ahead_60s", "ahead_120s", "ahead_300s"], "column"), ""]
        out += [md_table(e, ["symbol", "coverage_s", "member_first_buy_s", "outside_first_buy_s", "peak10_ts_s", "peak10_mult", "peak1_mult", "mult_30s", "ahead_30s", "mult_60s", "ahead_60s",
                             "mult_120s", "ahead_120s", "mult_300s", "ahead_300s", "end_mult"] + [c for c in ("kl_mult_5m", "kl_mult_30m", "kl_max_mult_100m", "kl_min_to_max_100m") if c in e]), ""]
    out += ["### Both launchers pooled, hits", "", sec_dist_table(ent, ["member_first_buy_s", "outside_first_buy_s", "peak10_ts_s", "peak10_mult", "mult_30s", "mult_60s", "mult_120s", "mult_300s",
                                                                    "ahead_30s", "ahead_60s", "ahead_120s", "ahead_300s"], "column"), "",
            "`kl_*` columns are DuckDB dev_runs kline multiples relative to the first candle's open, not to the dev's average price, so they are not on the same scale as `mult_*`.", ""]
    out += ["Misses, for contrast (same multiples):", ""]
    mz = lf[lf.measurable & ~lf.hit & lf.dev_supply_share.notna()].sort_values(["dev", "create_ts"])
    out += [md_table(mz, ["dev", "symbol", "coverage_s", "peak10_ts_s", "peak10_mult", "mult_30s", "mult_60s", "mult_120s", "mult_300s", "end_mult", "dev_first_sell_s"]), ""]
    # data problems
    out += ["## Data problems", ""]
    probs = []
    hits_late = lf[lf.hit & lf.measurable & (lf.peak10_ts_s.fillna(0) >= 1500)]
    if len(hits_late):
        probs.append("- hits whose in-window peak lies in the last 5 minutes (the run continued after the window; window multiples are lower bounds): "
                     + ", ".join(f"{r.dev}/{r.symbol} (peak at {int(r.peak10_ts_s)} s, {fmt(r.peak10_mult)}x)" for r in hits_late.itertuples()))
    thin = lf[lf.hit & lf.measurable & (lf.n_trades < 50)]
    if len(thin):
        probs.append("- hits with fewer than 50 trades in the window (nothing happened until after minute 30): " + ", ".join(f"{r.dev}/{r.symbol} ({int(r.n_trades)} trades)" for r in thin.itertuples()))
    for r in infos.sort_values(["dev", "create_ts"]).itertuples():
        if r.n_trades == 0:
            probs.append(f"- {r.dev}/{r.symbol}: no trades in the window (sig_source={r.sig_source}, {r.n_tx} tx); excluded from every denominator")
            continue
        if r.coverage_s < 1800:
            why = "pull truncated at 30,000 tx" if r.truncated else f"LaunchLab curve migrated at {r.migrate_s} s and the pool was never pulled"
            probs.append(f"- {r.dev}/{r.symbol}: observed window ends at {r.coverage_s} s ({why}); later marks NULL")
        if nn(r.quote_mint):
            probs.append(f"- {r.dev}/{r.symbol}: quoted in {r.quote_mint} (launchpad {r.launchpad_platform}); SOL rate {fmt(r.quote_per_sol_med)} quote/SOL from {r.n_rate_minutes} minute(s) of router legs"
                         + ("" if r.sol_ok else "; NO rate observable, SOL columns NULL"))
        if r.n_market_accounts > 2 or (r.launchpad_platform == "stonkfun"):
            probs.append(f"- {r.dev}/{r.symbol}: LaunchLab launch; market accounts taken from the create tx ({r.n_market_accounts}, vault authority WLHv2UAZ… added); Phase B's dev_first_buy_sol/sol_in_* for this launch are rent only and were not used")
        if nn(r.create_sig) is None:
            probs.append(f"- {r.dev}/{r.symbol}: no create transaction found in the window")
    out += probs
    out += ["- Phase B `dev_fee_lamports_med` is a window median over every dev tx; `dev_fee_first_tx` here is the create-tx fee minus 5000 (measurable at second 0).",
            "- `outside_*` includes KOL / smart-money wallets (kol_* never fetched). Members are the 32 wallets in member_wallets.json; slingoor counts as a member on retardmode's launches and vice versa.",
            "- Sells after a truncated or migrated window are unobservable, so `share_sold_in_window` and `net_sol_*` understate exits on catcall, sling, LIZARD (slingoor hits) and on ETH/GRND/LMAO! (LaunchLab).",
            "- `net_sol_marked` values the unsold remainder at the last 10-s buy VWAP of the observed window; for launches whose run came after minute 30 (PEACE, MRHATE, RETARDIO) this understates the eventual result.",
            "- Multiples for non-SOL-quoted launches are in quote units and assume the quote/SOL rate is flat over the mark; `sol_*` for them carries the per-minute router rate.",
            "- Threshold rules are evaluated in-sample on 14/4 hits; they describe the sample, they do not predict."]
    return "\n".join(out) + "\n"


# ------------------------------------------------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="data/anatomy/loop1")
    ap.add_argument("--members", default="data/anatomy/member_wallets.json")
    ap.add_argument("--db", default="data/notdecu.duckdb")
    ap.add_argument("--notes", default="data/anatomy/loop1/notes_cross.md")
    ap.add_argument("--rebuild-trades", action="store_true")
    ap.add_argument("--launches", default=None, help="launch list jsonl; sets the launcher set (default: slingoor + retardmode)")
    a = ap.parse_args()
    if a.launches:
        global CREATORS, DEVS
        CREATORS = {}
        for line in open(a.launches):
            L = json.loads(line); CREATORS[L["dev"]] = L["creator"]
        DEVS = list(CREATORS)
    members = json.load(open(a.members))
    book, runs = {}, None
    if a.db and os.path.exists(a.db):
        import duckdb
        con = duckdb.connect(a.db, read_only=True)
        for tok, ath, hold, cts, plat, br in con.execute("select token, ath_mc, holders, create_ts, launchpad_platform, bundler_rate from dev_tokens where creator in (%s)" % ",".join("?" * len(CREATORS)),
                                                        list(CREATORS.values())).fetchall():
            book[tok] = {"ath_mc": ath, "holders": hold, "create_ts": cts, "launchpad_platform": plat, "bundler_rate": br}
        try:
            runs = con.execute("select creator, token, mult_5m as kl_mult_5m, mult_30m as kl_mult_30m, max_mult_100m as kl_max_mult_100m, min_to_max_100m as kl_min_to_max_100m "
                               "from dev_runs where creator in (%s)" % ",".join("?" * len(CREATORS)), list(CREATORS.values())).df()
        except Exception as e:  # noqa: BLE001
            print("dev_runs not read:", e)
        con.close()
    cache = os.path.join(a.out, "cross_trades.parquet")
    infos_p = os.path.join(a.out, "cross_launch_infos.parquet")
    if a.rebuild_trades or not (os.path.exists(cache) and os.path.exists(infos_p)):
        trades, infos = build_trades(a.out, book)
        trades.to_parquet(cache, index=False)
        infos.to_parquet(infos_p, index=False)
    trades, infos = pd.read_parquet(cache), pd.read_parquet(infos_p)
    print(f"trades {len(trades)}, launches {len(infos)}, dev_runs rows {0 if runs is None else len(runs)}")
    phaseb = pd.concat([pd.read_parquet(os.path.join(a.out, f"anatomy_{d}.parquet")) for d in DEVS], ignore_index=True).set_index("token")

    # per-launch features
    feats = []
    for _, info in infos.iterrows():
        pb = phaseb.loc[info.token].to_dict() if info.token in phaseb.index else {}
        pb = {k: (None if (not isinstance(v, str) and pd.isna(v)) else v) for k, v in pb.items()}
        feats.append(launch_features(trades[trades.token == info.token], info, members, pb))
    lf = pd.DataFrame(feats)
    lf["grad_s"] = lf.curve_last_s.astype("float64").where(lf.curve_last_s.notna(), lf.migrate_s.astype("float64"))
    lf = lf.sort_values(["dev", "create_ts"]).reset_index(drop=True)
    lf.to_parquet(os.path.join(a.out, "cross_launches.parquet"), index=False)
    lf.to_csv(os.path.join(a.out, "cross_launches.csv"), index=False)

    ml = member_launch_rows(trades, infos, members)
    ml = ml.sort_values(["username", "dev", "symbol"]).reset_index(drop=True)
    ml.to_parquet(os.path.join(a.out, "cross_member_launches.parquet"), index=False)
    ml.to_csv(os.path.join(a.out, "cross_member_launches.csv"), index=False)
    members_df = member_graph(ml, members)
    members_df.to_parquet(os.path.join(a.out, "cross_members.parquet"), index=False)
    members_df.to_csv(os.path.join(a.out, "cross_members.csv"), index=False)

    fp = launcher_fingerprints(lf, infos)
    fp.to_parquet(os.path.join(a.out, "cross_launchers.parquet"), index=False)
    fp.to_csv(os.path.join(a.out, "cross_launchers.csv"), index=False)
    sep = separation(lf)
    sep.to_csv(os.path.join(a.out, "cross_separation.csv"), index=False)
    thr = thresholds(lf)
    thr.to_csv(os.path.join(a.out, "cross_thresholds.csv"), index=False)
    if runs is not None and len(runs):
        runs = runs.merge(infos[["token", "dev", "symbol"]], on="token", how="inner").drop(columns=["creator", "token"])
    ent = entry_table(lf, runs)
    ent.to_csv(os.path.join(a.out, "cross_entry.csv"), index=False)
    open(os.path.join(a.out, "SUMMARY_cross.md"), "w").write(summary(members_df, ml, lf, fp, sep, thr, ent, infos, a.notes))
    print("wrote cross_members, cross_member_launches, cross_launches, cross_launchers, cross_separation, cross_thresholds, cross_entry, SUMMARY_cross.md ->", a.out)
    print(thr.to_string())


if __name__ == "__main__":
    main()
