#!/usr/bin/env python3
"""D6 backtester v2: explicit cost model + parameter grid on the anatomy trade caches. Read-only, no trading.

    python3 scripts/backtest_v2.py --loop loop1 [--grid] [--config KEY=VAL ...] [--stake-usd 50] [--sol-usd 100]

Cost model (every term is explicit and printed):
  pump.fun trading fee by venue and market cap at the trade (docs/fees table, effective 2025-09-01):
     bonding curve: 1.25% ; PumpSwap pool: 1.25% (<420 SOL mcap), 1.20% (420-1470), 1.15% (1470-2460),
     1.10% (2460-3440), 1.05% (3440-4420), 1.00% (4420-9820), 0.95% (9820-14740), 0.90% (14740-19670),
     0.85% (19670-24580), 0.80% (24580-49150), 0.60% (49150-98240), 0.30% (>98240)
  base fee: 5,000 lamports per signature (1 signature) each side
  priority fee: empirical = median fee_lamports paid by buyers in [mark, mark+10 s] on that launch (entry),
     and by sellers in [exit, exit+10 s] (exit); floor 20,000 lamports (what a same-block fill needed in loop 1)
  rent: 0.0018444 SOL user_volume_accumulator (first trade ever per wallet; charged once, param) + 0.00203928 SOL
     ATA rent, refunded on close (net 0 if we close the ATA; param rent_ata_refund)
  slippage / price impact: constant-product estimate impact = size / (2 * L) where L is the SOL-side liquidity:
     curve: 30 SOL virtual + real SOL raised at the mark; pool: 85 SOL + net SOL inflow since migration (floor 60)
  MEV / sandwich: param mev_pct (default 0.5%) each side, applied because a market buy with slippage tolerance
     can be sandwiched; set 0 if using Jito bundles, then jito_tip_sol (default 0.0001) is charged instead.
  veto_dev_sell: 0 = off; else skip when the dev has sold >= this fraction of his own tokens by the mark (added after DUDAS live loss).
Rule (parameters): entry mark seconds (per dev default: slingoor 60, retardmode 120, others 120),
  self-buy floor (share of supply), require SOL quote, exit: trailing stop pct off running high, take-profit
  multiple (0 = none), hard stop pct, time stop seconds. Price series = 10-s buy VWAP.
"""
import argparse
import itertools
import json
import os

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
ANAT = os.path.join(HERE, "..", "data", "anatomy")
TIERS = [(420, .0125), (1470, .0120), (2460, .0115), (3440, .0110), (4420, .0105), (9820, .0100), (14740, .0095), (19670, .0090), (24580, .0085), (49150, .0080), (98240, .0060), (float("inf"), .0030)]
SUPPLY = 1e9
DEFAULT_MARK = {"slingoor": 60, "retardmode": 120}


def pool_fee(mcap_sol):
    for th, f in TIERS:
        if mcap_sol < th:
            return f
    return .0030


def load(loop):
    d = os.path.join(ANAT, loop)
    L = pd.read_parquet(os.path.join(d, "cross_launches.parquet"))
    I = pd.read_parquet(os.path.join(d, "cross_launch_infos.parquet"))[["token", "creator", "quote_per_sol_med"]]
    L = L.merge(I, on="token").sort_values("create_ts")
    T = pd.read_parquet(os.path.join(d, "cross_trades.parquet"))
    return L, T


def series(tr, bucket=10):
    b = tr[tr.side == "buy"].copy()
    b["b"] = (b.s // bucket) * bucket
    g = b.groupby("b").agg(q=("sol", "sum"), t=("tokens", "sum"), fee=("fee", "median"))
    g = g[g.t > 0]
    g["p"] = g.q / g.t          # SOL per token
    return g


def simulate(L, tr, cfg, stake_sol):
    mark = cfg.get("mark") or DEFAULT_MARK.get(L.dev, 120)
    tr = tr.sort_values(["s", "slot"])
    out = {"dev": L.dev, "symbol": L.symbol, "hit": bool(L.hit), "self_buy": None if pd.isna(L.dev_supply_share) else round(float(L.dev_supply_share), 2)}
    why = []
    if cfg.get("rule", "hold") == "flow":
        base = cfg["_baseline"].get(L.token)
        col = "sol_in_1m" if mark < 300 else "sol_in_5m"   # no look-ahead: the 5-min inflow exists only from 300 s
        if base is None:
            why.append("no prior launches for baseline")
        elif pd.isna(getattr(L, col)) or getattr(L, col) < cfg["flow_mult"] * base:
            why.append(f"flow {getattr(L, col):.0f} < {cfg['flow_mult']}x baseline {base:.0f}")
    elif pd.isna(L.dev_supply_share) or L.dev_supply_share < cfg["self_buy_floor"]:
        why.append("self-buy < floor")
    if cfg["sol_only"] and not bool(L.sol_ok):
        why.append("non-SOL quote")
    ds = tr[(tr.wallet == L.creator) & (tr.side == "sell") & (tr.s <= mark)]
    dev_sold_frac = None
    if len(ds):
        bought = tr[(tr.wallet == L.creator) & (tr.side == "buy") & (tr.s <= mark)].tokens.sum()
        dev_sold_frac = float(ds.tokens.sum() / bought) if bought > 0 else 1.0
    out["dev_sold_by_mark"] = round(dev_sold_frac, 2) if dev_sold_frac is not None else 0.0
    if len(ds) and (cfg.get("rule", "hold") == "hold" or (cfg.get("veto_dev_sell", 0) and dev_sold_frac >= cfg["veto_dev_sell"])):
        why.append(f"dev sold {100*dev_sold_frac:.0f}% at {int(ds.s.min())} s")
    if cfg.get("min_wallets_1m") and (pd.isna(L.n_wallets_1m) or L.n_wallets_1m < cfg["min_wallets_1m"]):
        why.append("too few wallets in minute 1")
    if cfg.get("min_co_buyers") and (pd.isna(L.dev_same_slot_buyers) or L.dev_same_slot_buyers < cfg["min_co_buyers"]):
        why.append("too few co-buyers in the dev slot")
    if pd.notna(L.coverage_s) and L.coverage_s < mark + 10:
        why.append("window ends before the mark")
    if why:
        out.update(triggered=False, reason="; ".join(why)); return out
    g = series(tr)
    after = g[g.index >= mark]
    if after.empty:
        out.update(triggered=False, reason="no buys after the mark"); return out
    t0 = after.index[0]
    entry_raw = after.p.iloc[0]
    dev_px = (L.dev_first_buy_sol / L.dev_first_buy_tokens) if (pd.notna(L.dev_first_buy_sol) and pd.notna(L.dev_first_buy_tokens) and L.dev_first_buy_tokens > 0) else None
    entry_mult_vs_dev = (entry_raw / dev_px) if dev_px else None
    if cfg.get("max_entry_mult") and entry_mult_vs_dev is not None and entry_mult_vs_dev > cfg["max_entry_mult"]:
        out.update(triggered=False, reason=f"price at mark {entry_mult_vs_dev:.1f}x dev > max {cfg['max_entry_mult']}"); return out
    if cfg.get("min_entry_mult") and entry_mult_vs_dev is not None and entry_mult_vs_dev < cfg["min_entry_mult"]:
        out.update(triggered=False, reason=f"price at mark {entry_mult_vs_dev:.1f}x dev < min {cfg['min_entry_mult']}"); return out
    on_curve = pd.isna(L.curve_last_s) or t0 <= L.curve_last_s
    # liquidity for impact
    sol_in = tr[(tr.side == "buy") & (tr.s <= t0)].sol.sum(); sol_out = tr[(tr.side == "sell") & (tr.s <= t0)].sol.sum()
    liq = (30 + max(sol_in - sol_out, 0)) if on_curve else max(60.0, 85 + (sol_in - sol_out) - (tr[(tr.s <= L.curve_last_s)].sol.sum() if pd.notna(L.curve_last_s) else 0) * 0)
    impact_in = stake_sol / (2 * liq)
    mcap_sol = entry_raw * SUPPLY
    fee_in = .0125 if on_curve else pool_fee(mcap_sol)
    prio_in = max(cfg["prio_floor_lamports"], float(after.fee.iloc[0]) if pd.notna(after.fee.iloc[0]) else 0) / 1e9
    entry_eff = entry_raw * (1 + impact_in)
    tokens = stake_sol * (1 - fee_in - cfg["mev_pct"]) / entry_eff
    hi = entry_raw; exit_p = exit_t = None; how = None
    for t, p in after.p.iloc[1:].items():
        hi = max(hi, p)
        if p <= entry_raw * (1 - cfg["hard_stop_pct"]):
            exit_p, exit_t, how = p, t, "hard stop"; break
        if cfg["tp_mult"] and p >= entry_raw * cfg["tp_mult"]:
            exit_p, exit_t, how = p, t, "take profit"; break
        if hi >= entry_raw * cfg["trail_arm_mult"] and p <= hi * (1 - cfg["trail_pct"]):
            exit_p, exit_t, how = p, t, "trailing stop"; break
        if t - t0 >= cfg["time_stop_s"]:
            exit_p, exit_t, how = p, t, "time stop"; break
    if exit_p is None:
        exit_p, exit_t, how = after.p.iloc[-1], after.index[-1], "end of data"
    on_curve_x = pd.isna(L.curve_last_s) or exit_t <= L.curve_last_s
    fee_out = .0125 if on_curve_x else pool_fee(exit_p * SUPPLY)
    sol_in2 = tr[(tr.side == "buy") & (tr.s <= exit_t)].sol.sum(); sol_out2 = tr[(tr.side == "sell") & (tr.s <= exit_t)].sol.sum()
    liq_x = (30 + max(sol_in2 - sol_out2, 0)) if on_curve_x else max(60.0, 85 + (sol_in2 - sol_out2))
    impact_out = stake_sol * (exit_p / entry_raw) / (2 * liq_x)
    sells = tr[(tr.side == "sell") & (tr.s >= exit_t) & (tr.s <= exit_t + 10)]
    prio_out = max(cfg["prio_floor_lamports"], float(sells.fee.median()) if len(sells) else 0) / 1e9
    proceeds = tokens * exit_p * (1 - impact_out) * (1 - fee_out - cfg["mev_pct"])
    fixed = 2 * 5000 / 1e9 + prio_in + prio_out + (cfg["rent_first_trade_sol"] if cfg["charge_rent"] else 0) + (0.00203928 if not cfg["rent_ata_refund"] else 0) + (2 * cfg["jito_tip_sol"] if cfg["mev_pct"] == 0 else 0)
    net_sol = proceeds - stake_sol - fixed
    out.update(triggered=True, entry_s=int(t0), exit_s=int(exit_t), how=how, on_curve=bool(on_curve), gross_x=round(exit_p / entry_raw, 3),
               fee_in_pct=round(100 * fee_in, 2), fee_out_pct=round(100 * fee_out, 2), impact_in_pct=round(100 * impact_in, 2), impact_out_pct=round(100 * impact_out, 2),
               prio_in_sol=round(prio_in, 5), prio_out_sol=round(prio_out, 5), fixed_sol=round(fixed, 5), net_sol=round(net_sol, 4),
               max_x_after=round(after.p.max() / entry_raw, 2), entry_mult_vs_dev=round(entry_mult_vs_dev, 2) if entry_mult_vs_dev else None)
    return out


BASE = {"veto_dev_sell": 0.0, "max_entry_mult": 0, "min_entry_mult": 0, "rule": "hold", "flow_mult": 1.5, "min_prior": 3, "mark": None, "self_buy_floor": 0.35, "sol_only": True, "min_wallets_1m": 0, "min_co_buyers": 0, "trail_pct": 0.40, "trail_arm_mult": 1.2, "tp_mult": 0,
        "hard_stop_pct": 0.50, "time_stop_s": 1800, "prio_floor_lamports": 20000, "mev_pct": 0.005, "jito_tip_sol": 0.0001, "charge_rent": True,
        "rent_first_trade_sol": 0.0018444, "rent_ata_refund": True}


def baselines(L, cfg):
    """walk-forward: for each launch, median inflow (sol_in_1m if mark<=60 else sol_in_5m) of the same dev's earlier launches."""
    out = {}
    for dev, g in L.sort_values("create_ts").groupby("dev"):
        mark = cfg.get("mark") or DEFAULT_MARK.get(dev, 120)
        col = "sol_in_1m" if mark < 300 else "sol_in_5m"
        prior = []
        for _, r in g.iterrows():
            if len(prior) >= cfg["min_prior"]:
                out[r.token] = float(np.nanmedian(prior))
            if pd.notna(getattr(r, col)):
                prior.append(float(getattr(r, col)))
    return out


def run_cfg(L, T, cfg, stake_sol, sol_usd):
    cfg = dict(cfg); cfg["_baseline"] = baselines(L, cfg) if cfg.get("rule") == "flow" else {}
    rows = [simulate(Lr, T[T.token == Lr.token], cfg, stake_sol) for _, Lr in L.iterrows()]
    df = pd.DataFrame(rows)
    t = df[df.triggered == True] if "triggered" in df else df.iloc[0:0]  # noqa: E712
    pnl = (t.net_sol * sol_usd) if len(t) else pd.Series(dtype=float)
    summ = {"triggers": len(t), "wins": int((pnl > 0).sum()) if len(t) else 0, "pnl_usd": round(pnl.sum(), 2) if len(t) else 0.0,
            "avg_usd": round(pnl.mean(), 2) if len(t) else 0.0, "median_usd": round(pnl.median(), 2) if len(t) else 0.0,
            "worst_usd": round(pnl.min(), 2) if len(t) else 0.0, "hits_caught": int(t.hit.sum()) if len(t) else 0, "hits_total": int(df.hit.sum()),
            "misses_entered": int((~t.hit).sum()) if len(t) else 0, "pnl_ex_best_usd": round(pnl.sum() - pnl.max(), 2) if len(t) else 0.0}
    return df, summ


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", default="loop1")
    ap.add_argument("--grid", action="store_true")
    ap.add_argument("--joint", action="store_true", help="grid over loop1 and loop2 together; keep configs positive on both")
    ap.add_argument("--config", nargs="*", default=[])
    ap.add_argument("--stake-usd", type=float, default=50)
    ap.add_argument("--sol-usd", type=float, default=100)
    a = ap.parse_args()
    stake_sol = a.stake_usd / a.sol_usd
    if a.joint:
        sets = {lp: load(lp) for lp in ("loop1", "loop2")}
        grid = {"rule": ["hold", "flow"], "mark": [60, 120, 300], "self_buy_floor": [0.2, 0.35], "flow_mult": [1.5, 2.0], "max_entry_mult": [0, 3, 5],
                "trail_pct": [0.4, 0.5], "tp_mult": [0, 5], "hard_stop_pct": [0.3, 0.5], "time_stop_s": [900, 1800]}
        res = []
        for vals in itertools.product(*grid.values()):
            c = dict(BASE); c.update(dict(zip(grid.keys(), vals)))
            if c["rule"] == "hold" and c["flow_mult"] != 1.5: continue
            if c["rule"] == "flow" and c["self_buy_floor"] != 0.2: continue
            row = dict(zip(grid.keys(), vals))
            for lp, (L_, T_) in sets.items():
                _, s_ = run_cfg(L_, T_, c, stake_sol, a.sol_usd)
                for k in ("triggers", "wins", "pnl_usd", "pnl_ex_best_usd", "hits_caught", "misses_entered", "worst_usd", "median_usd"):
                    row[f"{lp}_{k}"] = s_[k]
            row["min_ex_best"] = min(row["loop1_pnl_ex_best_usd"], row["loop2_pnl_ex_best_usd"])
            row["total_pnl"] = row["loop1_pnl_usd"] + row["loop2_pnl_usd"]
            row["wr"] = (row["loop1_wins"] + row["loop2_wins"]) / max(1, row["loop1_triggers"] + row["loop2_triggers"])
            res.append(row)
        R = pd.DataFrame(res)
        R.to_csv(os.path.join(ANAT, "backtest_v2_joint.csv"), index=False)
        ok = R[(R.loop1_triggers >= 6) & (R.loop2_triggers >= 6)]
        print(f"{len(R)} configs; {len(ok)} with >=6 triggers on both; {(ok.min_ex_best > 0).sum()} positive ex-best on BOTH loops")
        pd.set_option("display.width", 300)
        cols = list(grid.keys()) + ["loop1_triggers", "loop1_wins", "loop1_pnl_usd", "loop1_pnl_ex_best_usd", "loop2_triggers", "loop2_wins", "loop2_pnl_usd", "loop2_pnl_ex_best_usd", "loop2_median_usd", "loop2_worst_usd", "wr"]
        print("\ntop by min(ex-best P&L over the two loops):"); print(ok.sort_values("min_ex_best", ascending=False).head(15)[cols].to_string(index=False))
        print("\ntop by combined win rate (min 6 triggers each):"); print(ok.sort_values(["wr", "total_pnl"], ascending=False).head(8)[cols].to_string(index=False))
        raise SystemExit
    L, T = load(a.loop)
    cfg = dict(BASE)
    for kv in a.config:
        k, v = kv.split("=")
        if isinstance(BASE[k], bool): cfg[k] = v.lower() == "true"
        elif isinstance(BASE[k], (int, float)): cfg[k] = type(BASE[k])(float(v))
        elif BASE[k] is None: cfg[k] = int(v)
        else: cfg[k] = v
    pd.set_option("display.width", 260)
    if a.grid:
        grid = {"mark": [None, 90, 180], "self_buy_floor": [0.20, 0.35, 0.50], "trail_pct": [0.30, 0.40, 0.50], "tp_mult": [0, 3, 5], "hard_stop_pct": [0.40, 0.50], "time_stop_s": [900, 1800]}
        res = []
        for vals in itertools.product(*grid.values()):
            c = dict(cfg); c.update(dict(zip(grid.keys(), vals)))
            _, s = run_cfg(L, T, c, stake_sol, a.sol_usd)
            res.append({**{k: (v if v is not None else "dev") for k, v in zip(grid.keys(), vals)}, **s})
        R = pd.DataFrame(res)
        R.to_csv(os.path.join(ANAT, a.loop, "backtest_v2_grid.csv"), index=False)
        print("top 12 configs by P&L excluding the single best trade (min 6 triggers):")
        print(R[R.triggers >= 6].sort_values("pnl_ex_best_usd", ascending=False).head(12).to_string(index=False))
        print("\ntop 8 by win rate then P&L (min 6 triggers):")
        R["wr"] = R.wins / R.triggers.replace(0, np.nan)
        print(R[R.triggers >= 6].sort_values(["wr", "pnl_usd"], ascending=False).head(8).to_string(index=False))
    else:
        df, s = run_cfg(L, T, cfg, stake_sol, a.sol_usd)
        print("config:", json.dumps({k: v for k, v in cfg.items() if not k.startswith("_")}))
        cols = ["dev", "symbol", "hit", "self_buy", "triggered", "reason", "entry_s", "exit_s", "how", "on_curve", "gross_x", "fee_in_pct", "fee_out_pct", "impact_in_pct", "impact_out_pct", "prio_in_sol", "prio_out_sol", "fixed_sol", "net_sol", "max_x_after"]
        print(df[[c for c in cols if c in df.columns]].to_string(index=False))
        print("\nsummary:", json.dumps(s))
        df.to_csv(os.path.join(ANAT, a.loop, "backtest_v2_run.csv"), index=False)
