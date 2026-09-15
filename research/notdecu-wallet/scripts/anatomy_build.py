#!/usr/bin/env python3
"""Phase D6-B: per-launch anatomy table for one launcher, from the Phase A files (offline, read-only).

    python3 scripts/anatomy_build.py --dev retardmode --creator ASv4kt...akA7 --out data/anatomy/loop1
        [--members data/anatomy/member_wallets.json] [--db data/notdecu.duckdb] [--notes <md file appended to the summary>]

Reads <out>/<dev>/<mint>.parsed.jsonl + .meta.json, writes <out>/anatomy_<dev>.parquet, .csv and SUMMARY_<dev>.md.
Trades are re-derived from the Helius accountData token-balance changes (not from the compact rows), because the
compact rows attribute a trade to the fee payer; routers, sponsored-fee bots and gasless swaps make the fee payer
differ from the wallet that received or gave the tokens in ~1-12% of trades, and the compact `sol_received` is 0 on
most sells. Definitions:
  trader        = user account (not curve/pool) whose balance of the mint changed in the tx; one trade per such user.
  side          = buy if the balance rose, sell if it fell.
  quote amount  = the curve's / pool's own change of the quote asset in the tx (native SOL + WSOL, or the pump.fun
                  quote token when the launch is not SOL-quoted), split across traders pro rata to |tokens|. Fees
                  and tips paid to other accounts are therefore excluded; price = quote / tokens.
  non-SOL quote = converted to SOL with the per-minute median SOL<->quote rate observed in the window's own
                  router legs (x_quote_mint, x_quote_per_sol_med say which and how much).
  create tx     = type CREATE, or the tx in which the curve receives >= 50% of supply (a create hidden inside a swap).
Every column is NULL when the event did not occur or cannot be measured; genuine zeros (no member bought => 0 SOL) stay 0.
No GMGN call is made; kol_* stay NULL.
"""
import argparse
import glob
import json
import os
import statistics
from collections import Counter, defaultdict

import numpy as np
import pandas as pd

WSOL = "So11111111111111111111111111111111111111112"
SUPPLY = 1e9
BASE_FEE = 5000
MARKS = {"1m": 60, "5m": 300, "15m": 900, "30m": 1800}

SCHEMA = ["dev", "creator", "token", "symbol", "create_ts", "hit", "ath_mc",
          "n_tx_30m", "n_buys_30m", "n_sells_30m", "n_wallets_30m",
          "first_tx_ts", "create_sig",
          "dev_first_buy_s", "dev_first_buy_sol", "dev_first_buy_tokens", "dev_supply_share",
          "dev_same_slot_buyers", "dev_fee_lamports_med",
          "dev_first_sell_s", "dev_sold_share_30m",
          "member_first_buy_s", "member_first_buyer", "member_buyers_n", "member_buy_sol_30m",
          "member_first_sell_s", "member_sell_sol_30m",
          "kol_first_buy_s", "kol_buyers_n", "kol_buy_sol_30m",
          "outside_first_buy_s", "outside_buy_sol_5m", "outside_buy_sol_30m",
          "sol_in_1m", "sol_in_5m", "sol_in_15m", "sol_in_30m",
          "peak_ts_s", "peak_price_sol", "peak_mult_vs_dev",
          "top10_wallets_share_30m", "n_wallets_net_long_30m"]
EXTRAS = ["x_truncated", "x_window_last_s", "x_pool_phase", "x_curve_last_s", "x_quote_mint", "x_quote_per_sol_med",
          "x_n_trade_tx_30m", "x_n_noop_tx_30m", "x_n_transfer_tx_30m", "x_trader_ne_feepayer_n",
          "x_dev_n_tx", "x_dev_n_buys", "x_dev_n_sells", "x_dev_buy_sol_30m", "x_dev_sell_sol_30m",
          "x_member_buyers", "x_member_sellers_n", "x_book_ath_mc", "x_book_holders", "x_book_create_ts"]
LAG_SIZE_COLS = ["n_tx_30m", "n_buys_30m", "n_sells_30m", "n_wallets_30m",
                 "dev_first_buy_s", "dev_first_buy_sol", "dev_first_buy_tokens", "dev_supply_share",
                 "dev_same_slot_buyers", "dev_fee_lamports_med", "dev_first_sell_s", "dev_sold_share_30m",
                 "member_first_buy_s", "member_buyers_n", "member_buy_sol_30m", "member_first_sell_s", "member_sell_sol_30m",
                 "outside_first_buy_s", "outside_buy_sol_5m", "outside_buy_sol_30m",
                 "sol_in_1m", "sol_in_5m", "sol_in_15m", "sol_in_30m",
                 "peak_ts_s", "peak_price_sol", "peak_mult_vs_dev", "top10_wallets_share_30m", "n_wallets_net_long_30m"]


def tok_amt(c):
    return int(c["rawTokenAmount"]["tokenAmount"]) / 10 ** c["rawTokenAmount"]["decimals"]


def load_parsed(path):
    txs = [json.loads(line) for line in open(path)]
    txs.sort(key=lambda t: (t.get("timestamp") or 0, t.get("slot") or 0, t.get("signature") or ""))
    return txs


def quote_mint_of(txs, mint, pools):
    """The asset the curve/pool takes in exchange for the mint: WSOL/native SOL, or a pump.fun quote token."""
    c = Counter()
    for t in txs:
        for a in t.get("accountData") or []:
            for ch in a.get("tokenBalanceChanges") or []:
                if ch.get("userAccount") in pools and ch.get("mint") != mint:
                    c[ch["mint"]] += 1
    if not c:
        return None
    top = c.most_common(1)[0][0]
    return None if top == WSOL else top


def rate_series(txs, qmint, pools, cts):
    """quote units per SOL, per minute of the window, from router legs where a user swapped SOL<->quote (>0.02 SOL)."""
    obs = defaultdict(list)
    for t in txs:
        users = defaultdict(lambda: defaultdict(float))
        nat = {}
        for a in t.get("accountData") or []:
            nat[a["account"]] = (a.get("nativeBalanceChange") or 0) / 1e9
            for ch in a.get("tokenBalanceChanges") or []:
                users[ch["userAccount"]][ch["mint"]] += tok_amt(ch)
        for u, d in users.items():
            if u in pools:
                continue
            qa = d.get(qmint, 0.0)
            sol = d.get(WSOL, 0.0)
            if abs(sol) < 0.02:
                sol = nat.get(u, 0.0)
            if qa > 0 and sol < -0.02:
                obs[(t["timestamp"] - cts) // 60].append(qa / -sol)
            elif qa < 0 and sol > 0.02:
                obs[(t["timestamp"] - cts) // 60].append(-qa / sol)
    per_min = {m: statistics.median(v) for m, v in obs.items()}
    if not per_min:
        return {}, None
    allv = [x for v in obs.values() for x in v]
    return per_min, statistics.median(allv)


def rate_at(per_min, glob_med, minute):
    if minute in per_min:
        return per_min[minute]
    if not per_min:
        return glob_med
    near = min(per_min, key=lambda m: (abs(m - minute), m))
    return per_min[near]


def extract_trades(txs, meta, qmint, per_min, glob_med):
    """One record per (tx, trader). Also returns per-tx kinds and the create tx."""
    mint, cts = meta["token"], meta["create_ts"]
    pools = {p for p in (meta.get("bonding_curve"), meta.get("pool")) if p}
    trades, kinds, create_sig, first_ts = [], Counter(), None, None
    ne_fp = 0
    for t in txs:
        if t.get("transactionError"):
            kinds["err"] += 1
            continue
        ts = t["timestamp"]
        first_ts = ts if first_ts is None else min(first_ts, ts)
        net = defaultdict(float)
        mkt_tok = 0.0
        mkt_q = 0.0
        for a in t.get("accountData") or []:
            if a["account"] in pools and qmint is None:
                mkt_q += (a.get("nativeBalanceChange") or 0) / 1e9
            for ch in a.get("tokenBalanceChanges") or []:
                amt = tok_amt(ch)
                u = ch.get("userAccount")
                if ch.get("mint") == mint:
                    if u in pools:
                        mkt_tok += amt
                    else:
                        net[u] += amt
                elif u in pools and ((qmint is None and ch.get("mint") == WSOL) or (qmint is not None and ch.get("mint") == qmint)):
                    mkt_q += amt
        if t.get("type") == "CREATE" or mkt_tok >= 0.5 * SUPPLY:
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
        q_sol = abs(mkt_q)
        if qmint is not None:
            r = rate_at(per_min, glob_med, (ts - cts) // 60)
            q_sol = q_sol / r if r else float("nan")
        for u, v in sorted(traders.items()):
            if u != t.get("feePayer"):
                ne_fp += 1
            trades.append({"sig": t["signature"], "slot": t["slot"], "ts": ts, "s": ts - cts, "wallet": u,
                           "side": "buy" if v > 0 else "sell", "tokens": abs(v), "sol": q_sol * abs(v) / tot,
                           "fee_payer": t.get("feePayer"), "fee": t.get("fee") or 0})
    return pd.DataFrame(trades), kinds, create_sig, first_ts, ne_fp


def med(x):
    x = [v for v in x if v is not None and not (isinstance(v, float) and np.isnan(v))]
    return float(np.median(x)) if x else None


def build_row(meta, txs, members, creator, book):
    cts = meta["create_ts"]
    pools = {p for p in (meta.get("bonding_curve"), meta.get("pool")) if p}
    qmint = quote_mint_of(txs, meta["token"], pools)
    per_min, glob_med = rate_series(txs, qmint, pools, cts) if qmint else ({}, None)
    tr, kinds, create_sig, first_ts, ne_fp = extract_trades(txs, meta, qmint, per_min, glob_med)
    n_ok = sum(1 for t in txs if not t.get("transactionError"))
    dev_fees = [t["fee"] - BASE_FEE for t in txs if t.get("feePayer") == creator and not t.get("transactionError")]
    truncated = bool(meta.get("truncated"))
    last_s = max((t["timestamp"] for t in txs), default=cts) - cts

    def covered(mark):
        return not truncated or last_s >= mark

    r = {k: None for k in SCHEMA + EXTRAS}
    r.update({"dev": meta["dev"], "creator": creator, "token": meta["token"], "symbol": (meta.get("symbol") or "").strip(),
              "create_ts": cts, "hit": bool(meta.get("hit")), "ath_mc": meta.get("ath_mc"),
              "n_tx_30m": n_ok if covered(1800) else None, "first_tx_ts": first_ts, "create_sig": create_sig,
              "dev_fee_lamports_med": med(dev_fees), "x_truncated": truncated, "x_window_last_s": last_s,
              "x_pool_phase": bool(meta.get("pool")) and meta.get("curve_last_s") is not None and meta["curve_last_s"] < 1740,
              "x_curve_last_s": meta.get("curve_last_s"), "x_quote_mint": qmint, "x_quote_per_sol_med": glob_med,
              "x_n_trade_tx_30m": kinds["trade"], "x_n_noop_tx_30m": kinds["noop"], "x_n_transfer_tx_30m": kinds["transfer"],
              "x_trader_ne_feepayer_n": ne_fp, "x_dev_n_tx": len(dev_fees),
              "x_book_ath_mc": book.get("ath_mc"), "x_book_holders": book.get("holders"), "x_book_create_ts": book.get("create_ts")})
    if tr.empty:
        return r
    tr = tr.sort_values(["s", "slot", "sig", "wallet"]).reset_index(drop=True)
    buys, sells = tr[tr.side == "buy"], tr[tr.side == "sell"]
    r["n_buys_30m"] = int(len(buys)) if covered(1800) else None
    r["n_sells_30m"] = int(len(sells)) if covered(1800) else None
    r["n_wallets_30m"] = int(tr.wallet.nunique()) if covered(1800) else None

    # creator
    db, ds = buys[buys.wallet == creator], sells[sells.wallet == creator]
    r["x_dev_n_buys"], r["x_dev_n_sells"] = int(len(db)), int(len(ds))
    r["x_dev_buy_sol_30m"], r["x_dev_sell_sol_30m"] = float(db.sol.sum()), float(ds.sol.sum())
    dev_price = None
    if len(db):
        f = db.iloc[0]
        r["dev_first_buy_s"], r["dev_first_buy_sol"], r["dev_first_buy_tokens"] = int(f.s), float(f.sol), float(f.tokens)
        r["dev_supply_share"] = float(f.tokens / SUPPLY)
        dev_price = f.sol / f.tokens if f.tokens > 0 and f.sol > 0 else None
        same = buys[(buys.slot == f.slot) & (buys.wallet != creator)]
        r["dev_same_slot_buyers"] = int(same.wallet.nunique())
        r["dev_sold_share_30m"] = float(min(1.0, ds.tokens.sum() / db.tokens.sum())) if covered(1800) else None
    if len(ds):
        r["dev_first_sell_s"] = int(ds.iloc[0].s)

    # members (creator excluded)
    mem = {k: v for k, v in members.items() if k != creator}
    mb, ms = buys[buys.wallet.isin(mem)], sells[sells.wallet.isin(mem)]
    r["member_buyers_n"] = int(mb.wallet.nunique()) if covered(1800) else None
    r["member_buy_sol_30m"] = float(mb.sol.sum()) if covered(1800) else None
    r["member_sell_sol_30m"] = float(ms.sol.sum()) if covered(1800) else None
    r["x_member_sellers_n"] = int(ms.wallet.nunique())
    if len(mb):
        f = mb.iloc[0]
        r["member_first_buy_s"], r["member_first_buyer"] = int(f.s), mem[f.wallet]["username"]
        r["x_member_buyers"] = ",".join(sorted({mem[w]["username"] for w in mb.wallet}))
    if len(ms):
        r["member_first_sell_s"] = int(ms.iloc[0].s)

    # outside = neither creator nor member (kol_* not fetched, so no tagged set to exclude)
    ob = buys[(buys.wallet != creator) & (~buys.wallet.isin(mem))]
    if len(ob):
        r["outside_first_buy_s"] = int(ob.iloc[0].s)
    r["outside_buy_sol_5m"] = float(ob[ob.s <= 300].sol.sum()) if covered(300) else None
    r["outside_buy_sol_30m"] = float(ob.sol.sum()) if covered(1800) else None
    for k, m in MARKS.items():
        r[f"sol_in_{k}"] = float(buys[buys.s <= m].sol.sum()) if covered(m) else None

    # peak: highest 1-second buy VWAP with >= 0.01 SOL traded in that second (robust to dust and rounding)
    pb = buys[(buys.sol > 0) & (buys.tokens > 0)]
    if len(pb):
        g = pb.groupby("s").agg(sol=("sol", "sum"), tokens=("tokens", "sum"))
        g = g[g.sol >= 0.01]
        if len(g):
            px = g.sol / g.tokens
            r["peak_ts_s"], r["peak_price_sol"] = int(px.idxmax()), float(px.max())
            if dev_price:
                r["peak_mult_vs_dev"] = float(px.max() / dev_price)

    # end-of-window holdings from window flows (buys - sells), dust below 1 token ignored
    if covered(1800):
        net = buys.groupby("wallet").tokens.sum().sub(sells.groupby("wallet").tokens.sum(), fill_value=0.0)
        longs = net[net > 1.0].sort_values(ascending=False)
        r["n_wallets_net_long_30m"] = int(len(longs))
        r["top10_wallets_share_30m"] = float(longs.head(10).sum() / longs.sum()) if len(longs) else None
    return r


def fmt(v, nd=3):
    if v is None or (not isinstance(v, str) and pd.isna(v)):
        return "NULL"
    if isinstance(v, (bool, np.bool_)):
        return str(bool(v))
    if isinstance(v, (int, np.integer)):
        return str(int(v))
    if isinstance(v, float):
        return f"{v:.{nd}g}" if abs(v) < 1e-3 or abs(v) >= 1e6 else f"{v:,.{nd}f}".rstrip("0").rstrip(".")
    return str(v)


def md_table(df, cols):
    lines = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for _, row in df.iterrows():
        lines.append("| " + " | ".join(fmt(row[c]) for c in cols) + " |")
    return "\n".join(lines)


def summary(df, dev, notes_path):
    hits, miss = df[df.hit], df[~df.hit]
    out = [f"# SUMMARY_{dev} — launch anatomy, loop 1 (Phase B, offline)", "",
           "Built by `scripts/anatomy_build.py` from `data/anatomy/loop1/" + dev + "/*.parsed.jsonl`. "
           "Trades are re-derived from Helius account-level token balance changes (see the script docstring); "
           "SOL figures are the curve/pool-side amounts (fees and tips excluded); non-SOL-quoted launches are converted to SOL "
           "at the window's own router rate. `kol_*` columns are NULL (GMGN not called).", "",
           "## Coverage", "",
           f"- launches: {len(df)} (hits {int(df.hit.sum())}, non-hits {int((~df.hit).sum())})",
           f"- truncated windows (>30,000 tx): {int(df.x_truncated.sum())}",
           f"- launches with an AMM pool phase inside the window: {int(df.x_pool_phase.sum())} "
           f"({', '.join(df[df.x_pool_phase].symbol)})" if df.x_pool_phase.any() else "- launches with an AMM pool phase inside the window: 0",
           f"- launches quoted in a non-SOL token: {int(df.x_quote_mint.notna().sum())} "
           + (f"({', '.join(df[df.x_quote_mint.notna()].symbol)})" if df.x_quote_mint.notna().any() else ""),
           f"- launches with no member buy in the window: {int(df.member_first_buy_s.isna().sum())}",
           f"- launches with no dev sell in the window: {int(df.dev_first_sell_s.isna().sum())}",
           f"- transactions in windows: {int(df.n_tx_30m.fillna(0).sum())}, of which trades {int(df.x_n_trade_tx_30m.sum())}, "
           f"no-op/fee-only {int(df.x_n_noop_tx_30m.sum())}, wallet-to-wallet transfers {int(df.x_n_transfer_tx_30m.sum())}",
           "", "## Medians, hits vs non-hits (every lag/size column; n = launches with a value)", "",
           "| column | hits median | n | non-hits median | n |", "|---|---|---|---|---|"]
    for c in LAG_SIZE_COLS:
        h, m_ = hits[c].dropna(), miss[c].dropna()
        out.append(f"| {c} | {fmt(float(h.median()) if len(h) else None)} | {len(h)} | {fmt(float(m_.median()) if len(m_) else None)} | {len(m_)} |")
    cols_e = ["symbol", "hit", "member_first_buy_s", "member_first_buyer", "member_buyers_n", "member_buy_sol_30m", "dev_first_buy_s", "peak_ts_s", "peak_mult_vs_dev"]
    wm = df[df.member_first_buy_s.notna()].sort_values(["member_first_buy_s", "token"])
    out += ["", "## Member entry: five earliest", "", md_table(wm.head(5), cols_e),
            "", "## Member entry: five latest", "", md_table(wm.tail(5).iloc[::-1], cols_e)]
    if df.member_first_buy_s.isna().any():
        out += ["", "No member buy in the window: " + ", ".join(df[df.member_first_buy_s.isna()].symbol)]
    cols_d = ["symbol", "hit", "dev_first_buy_s", "dev_supply_share", "dev_first_buy_sol", "dev_same_slot_buyers", "dev_fee_lamports_med", "dev_first_sell_s", "dev_sold_share_30m", "x_dev_sell_sol_30m"]
    out += ["", "## The dev's own pattern", "",
            "| group | first-buy share median | first-buy SOL median | first-sell s median (n sold) | sold share median | fee med (lamports − 5000) |", "|---|---|---|---|---|---|"]
    for name, g in (("hits", hits), ("non-hits", miss)):
        out.append(f"| {name} | {fmt(g.dev_supply_share.median())} | {fmt(g.dev_first_buy_sol.median())} | "
                   f"{fmt(g.dev_first_sell_s.median())} ({int(g.dev_first_sell_s.notna().sum())}/{len(g)}) | "
                   f"{fmt(g.dev_sold_share_30m.median())} | {fmt(g.dev_fee_lamports_med.median())} |")
    out += ["", md_table(df.sort_values("create_ts"), cols_d)]
    out += ["", "## Data problems (auto-detected)", ""]
    probs = []
    for _, row in df.iterrows():
        r = pd.Series({k: (None if (not isinstance(v, str) and pd.isna(v)) else v) for k, v in row.items()})
        if r.create_sig is None:
            probs.append(f"- {r.symbol}: no create transaction found in the window (create_ts later than the mint?)")
        if r.dev_first_buy_s is None:
            probs.append(f"- {r.symbol}: creator never bought in the window")
        elif r.dev_first_buy_s > 0:
            probs.append(f"- {r.symbol}: creator's first buy is {int(r.dev_first_buy_s)} s after create_ts, not in the create tx")
        if r.x_quote_mint:
            probs.append(f"- {r.symbol}: quoted in {r.x_quote_mint} (not SOL); SOL columns converted at ~{fmt(r.x_quote_per_sol_med)} quote/SOL")
        if r.x_n_noop_tx_30m and r.n_tx_30m and r.x_n_noop_tx_30m / r.n_tx_30m > 0.3:
            probs.append(f"- {r.symbol}: {int(r.x_n_noop_tx_30m)} of {int(r.n_tx_30m)} transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only")
        if r.x_trader_ne_feepayer_n:
            probs.append(f"- {r.symbol}: {int(r.x_trader_ne_feepayer_n)} trades where the trader is not the fee payer (compact rows label these 'other')")
        if r.x_book_ath_mc is not None and r.ath_mc and abs(r.x_book_ath_mc - r.ath_mc) / max(r.ath_mc, 1) > 0.01:
            probs.append(f"- {r.symbol}: ath_mc differs between launch list ({fmt(r.ath_mc)}) and dev_tokens ({fmt(r.x_book_ath_mc)})")
        if r.x_book_create_ts is not None and r.x_book_create_ts != r.create_ts:
            probs.append(f"- {r.symbol}: create_ts differs between launch list ({r.create_ts}) and dev_tokens ({r.x_book_create_ts})")
        if r.x_truncated:
            probs.append(f"- {r.symbol}: window truncated at {int(r.x_window_last_s)} s; *_30m columns NULL")
        if not r.x_pool_phase and r.x_curve_last_s is None and r.ath_mc and r.ath_mc > 60000:
            probs.append(f"- {r.symbol}: meta has no curve_last_s although the token graduated later (older pull); whole window is curve phase")
    out += probs or ["- none"]
    if notes_path and os.path.exists(notes_path):
        out += ["", open(notes_path).read().rstrip()]
    return "\n".join(out) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dev", required=True)
    ap.add_argument("--creator", required=True)
    ap.add_argument("--out", default="data/anatomy/loop1")
    ap.add_argument("--members", default="data/anatomy/member_wallets.json")
    ap.add_argument("--db", default="data/notdecu.duckdb")
    ap.add_argument("--notes", default=None, help="markdown appended verbatim to the summary")
    a = ap.parse_args()
    members = json.load(open(a.members))
    book = {}
    if a.db and os.path.exists(a.db):
        import duckdb
        con = duckdb.connect(a.db, read_only=True)
        for tok, ath, hold, cts in con.execute("select token, ath_mc, holders, create_ts from dev_tokens where creator = ?", [a.creator]).fetchall():
            book[tok] = {"ath_mc": ath, "holders": hold, "create_ts": cts}
        con.close()
    rows = []
    for mp in sorted(glob.glob(os.path.join(a.out, a.dev, "*.meta.json"))):
        meta = json.load(open(mp))
        txs = load_parsed(mp.replace(".meta.json", ".parsed.jsonl"))
        rows.append(build_row(meta, txs, members, a.creator, book.get(meta["token"], {})))
        print(f"{meta.get('symbol', ''):>12} tx={len(txs):6d} dev_first_buy_s={rows[-1]['dev_first_buy_s']} member_first_buy_s={rows[-1]['member_first_buy_s']} peak_mult={fmt(rows[-1]['peak_mult_vs_dev'])}")
    df = pd.DataFrame(rows, columns=SCHEMA + EXTRAS).sort_values("create_ts").reset_index(drop=True)
    for c in ["n_tx_30m", "n_buys_30m", "n_sells_30m", "n_wallets_30m", "first_tx_ts", "dev_first_buy_s", "dev_same_slot_buyers",
              "dev_first_sell_s", "member_first_buy_s", "member_buyers_n", "member_first_sell_s", "kol_first_buy_s", "kol_buyers_n",
              "outside_first_buy_s", "peak_ts_s", "n_wallets_net_long_30m", "x_curve_last_s", "x_book_holders", "x_book_create_ts"]:
        df[c] = df[c].astype("Int64")
    for c in ["kol_buy_sol_30m", "dev_fee_lamports_med"]:
        df[c] = df[c].astype("float64")
    df["x_quote_mint"] = df["x_quote_mint"].astype("string")
    df.to_parquet(os.path.join(a.out, f"anatomy_{a.dev}.parquet"), index=False)
    df.to_csv(os.path.join(a.out, f"anatomy_{a.dev}.csv"), index=False)
    open(os.path.join(a.out, f"SUMMARY_{a.dev}.md"), "w").write(summary(df, a.dev, a.notes))
    print(f"wrote {len(df)} rows -> {a.out}/anatomy_{a.dev}.parquet/.csv, SUMMARY_{a.dev}.md")


if __name__ == "__main__":
    main()
