#!/usr/bin/env python3
"""Backtest of the D6 rule as stated, on the loop-1 trade cache. Read-only, no trading.

Rule: launcher is tracked; create-tx self-buy >= 35% of supply; SOL-quoted; dev has not sold by the mark
(slingoor 60 s, retardmode 120 s). Entry at the mark: VWAP of buys in [mark, mark+10 s] (next trade if none).
Exit: trailing stop 40% below the running high of 10-s buy VWAP, hard stop -50%, else last price in the window.
Costs: pump.fun fee 1.25% on the curve / 0.25% on the pool, +1% slippage, each side. $50 per trigger at $100/SOL.

    python3 scripts/backtest_loop1.py [--last 10] [--all]
"""
import argparse
import os

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
L1 = os.path.join(HERE, "..", "data", "anatomy", "loop1")
MARK = {"slingoor": 60, "retardmode": 120}
SOL_USD, STAKE = 100.0, 50.0
SLIP = 0.01


def vwap_series(tr, bucket=10):
    b = tr[tr.side == "buy"].copy()
    b["b"] = (b.s // bucket) * bucket
    g = b.groupby("b").agg(q=("quote", "sum"), t=("tokens", "sum"))
    g = g[g.t > 0]
    return (g.q / g.t)


def run(launch, tr, mark):
    tr = tr.sort_values(["s", "slot"])
    dev_sells = tr[(tr.wallet == launch.creator) & (tr.side == "sell") & (tr.s <= mark)]
    reasons = []
    if launch.dev_supply_share is None or np.isnan(launch.dev_supply_share) or launch.dev_supply_share < 0.35:
        reasons.append("self-buy < 35%")
    if not bool(launch.sol_ok):
        reasons.append("non-SOL quote")
    if len(dev_sells):
        reasons.append(f"dev sold at {int(dev_sells.s.min())} s")
    if launch.coverage_s is not None and launch.coverage_s < mark + 10:
        reasons.append(f"window ends at {int(launch.coverage_s)} s")
    if reasons:
        return {"triggered": False, "reason": "; ".join(reasons)}
    px = vwap_series(tr)
    after = px[px.index >= mark]
    if after.empty:
        return {"triggered": False, "reason": "no buys after the mark"}
    entry_t, entry = after.index[0], after.iloc[0]
    on_curve = launch.curve_last_s is None or np.isnan(launch.curve_last_s) or entry_t <= launch.curve_last_s
    fee = 0.0125 if on_curve else 0.0025
    hi, exit_p, exit_t, why = entry, None, None, None
    for t, p in after.iloc[1:].items():
        hi = max(hi, p)
        if p <= 0.5 * entry:
            exit_p, exit_t, why = p, t, "hard stop -50%"; break
        if p <= 0.6 * hi and hi >= 1.2 * entry:
            exit_p, exit_t, why = p, t, "trail 40% off high"; break
    if exit_p is None:
        exit_p, exit_t, why = after.iloc[-1], after.index[-1], "end of window"
    gross = exit_p / entry
    net = gross * (1 - fee - SLIP) ** 2
    return {"triggered": True, "entry_s": int(entry_t), "exit_s": int(exit_t), "why": why, "on_curve": on_curve,
            "gross_x": round(gross, 2), "net_x": round(net, 2), "pnl_usd": round(STAKE * (net - 1), 2),
            "max_x_after_entry": round(after.max() / entry, 2)}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--last", type=int, default=10)
    ap.add_argument("--all", action="store_true")
    a = ap.parse_args()
    launches = pd.read_parquet(os.path.join(L1, "cross_launches.parquet"))
    infos = pd.read_parquet(os.path.join(L1, "cross_launch_infos.parquet"))[["token", "creator"]]
    launches = launches.merge(infos, on="token").sort_values("create_ts")
    trades = pd.read_parquet(os.path.join(L1, "cross_trades.parquet"))
    sel = launches if a.all else launches.tail(a.last)
    rows = []
    for _, L in sel.iterrows():
        r = run(L, trades[trades.token == L.token], MARK[L.dev])
        rows.append({"date": pd.to_datetime(L.create_ts, unit="s").strftime("%m-%d %H:%M"), "dev": L.dev, "symbol": L.symbol, "hit": bool(L.hit),
                     "self_buy": None if pd.isna(L.dev_supply_share) else round(L.dev_supply_share, 2), **r})
    df = pd.DataFrame(rows)
    pd.set_option("display.width", 250)
    print(df.to_string(index=False))
    t = df[df.triggered == True]  # noqa: E712
    print(f"\nlaunches {len(df)}, triggered {len(t)}, wins {(t.pnl_usd > 0).sum() if len(t) else 0}, "
          f"total P&L ${t.pnl_usd.sum():.2f} on ${STAKE * len(t):.0f} staked, avg per trigger ${t.pnl_usd.mean() if len(t) else 0:.2f}, "
          f"hits caught {int((t.hit).sum()) if len(t) else 0}/{int(df.hit.sum())}, misses entered {int((~t.hit).sum()) if len(t) else 0}/{int((~df.hit).sum())}")
    df.to_csv(os.path.join(L1, "backtest_last%s.csv" % ("all" if a.all else a.last)), index=False)
