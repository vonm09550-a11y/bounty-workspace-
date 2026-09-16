#!/usr/bin/env python3
"""Hourly paper replay: full-coverage paper test that needs no live process (the container sleeps between wakeups).

  python3 scripts/paper_replay.py [--hours 3] [--no-collect]

1. runs bitquery_collect.py --hours H (discovers launches by tracked creators, pulls each 30-min tape once it is complete)
2. for every collected launch by a launcher with a baseline (>= 3 prior launches) not yet in the ledger, replays the
   live rule exactly as scripts/live_paper.py would have traded it, using backtest_v2.simulate (same cost model):
   flow >= 1.5x the dev's median minute-1 inflow at 60 s, dev-sell veto at 50%, buy at the 60-70 s VWAP, exit on
   5x TP / 40% trail (armed 1.2x) / -50% hard / 30 min. One position at a time, $50 per trigger capped by capital.
3. ledger: data/anatomy/live/replay_trades.jsonl, replay_signals.jsonl, replay_state.json. Research only, no trading.
"""
import argparse
import json
import os
import subprocess
import sys
import time

import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from backtest_v2 import BASE, simulate  # noqa: E402
from live_paper import sol_usd  # noqa: E402

LIVE = os.path.join(HERE, "..", "data", "anatomy", "live")
STATE = os.path.join(LIVE, "replay_state.json")
CFG = dict(BASE, rule="flow", mark=60, flow_mult=1.5, tp_mult=5, veto_dev_sell=0.5, min_prior=3)
SUPPLY = 1e9


def launch_row(e, tr):
    """the subset of anatomy_cross launch columns simulate() reads, built from the Bitquery tape."""
    buys = tr[tr.side == "buy"]; sells = tr[tr.side == "sell"]
    d = buys[buys.wallet == e["creator"]].sort_values("s")
    f = d.iloc[0] if len(d) else None
    sol_ok = bool(buys.head(20).quote_mint.isin(["So11111111111111111111111111111111111111112", "11111111111111111111111111111111"]).all()) if len(buys) else False
    curve = tr[tr.protocol.isin(["pump", "raydium_launchpad"])]
    amm = tr[tr.protocol == "pump_amm"]
    curve_last_s = float(curve.s.max()) if len(curve) and len(amm) else np.nan
    return pd.Series({"dev": e["dev"], "token": e["token"], "symbol": e["symbol"], "creator": e["creator"], "create_ts": e["create_ts"], "hit": False,
                      "coverage_s": float(tr.s.max()) if len(tr) else 0.0, "sol_ok": sol_ok, "curve_last_s": curve_last_s,
                      "dev_first_buy_sol": float(f.sol) if f is not None and pd.notna(f.sol) else np.nan,
                      "dev_first_buy_tokens": float(f.tokens) if f is not None else np.nan,
                      "dev_supply_share": float(f.tokens / SUPPLY) if f is not None else np.nan,
                      "dev_same_slot_buyers": int(buys[(buys.slot == f.slot) & (buys.wallet != e["creator"])].wallet.nunique()) if f is not None else 0,
                      "sol_in_1m": float(buys[buys.s <= 60].sol.sum()), "sol_in_5m": float(buys[buys.s <= 300].sol.sum()),
                      "n_wallets_1m": int(buys[buys.s <= 60].wallet.nunique())})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=3)
    ap.add_argument("--no-collect", action="store_true")
    a = ap.parse_args()
    if not a.no_collect:
        subprocess.run([sys.executable, os.path.join(HERE, "bitquery_collect.py"), "--hours", str(a.hours)], check=False)
    st = json.load(open(STATE)) if os.path.exists(STATE) else {"capital_usd": 50.0, "seen": [], "n_trades": 0, "busy_until": 0}
    bases = {b["creator"]: b for b in json.load(open(os.path.join(LIVE, "baselines.json"))) if b["n"] >= CFG["min_prior"]}
    idx = [json.loads(l) for l in open(os.path.join(LIVE, "index.jsonl"))]
    T = pd.read_parquet(os.path.join(LIVE, "trades.parquet"))
    todo = sorted([e for e in idx if e["creator"] in bases and e["token"] not in st["seen"]], key=lambda e: e["create_ts"])
    px = sol_usd()
    closed = []
    for e in todo:
        tr = T[T.token == e["token"]].copy()
        L = launch_row(e, tr)
        cfg = dict(CFG); cfg["_baseline"] = {e["token"]: bases[e["creator"]]["med_sol_in_1m"]}
        if e["create_ts"] + cfg["mark"] < st["busy_until"]:
            out = {"dev": e["dev"], "symbol": e["symbol"], "triggered": False, "reason": "position already open"}
            # still evaluate for the signal log
            probe = simulate(L, tr, cfg, 0.5); out["would_trigger"] = bool(probe.get("triggered"))
        else:
            stake_sol = min(50.0, st["capital_usd"]) / px
            out = simulate(L, tr, cfg, stake_sol)
            if out.get("triggered"):
                net = round(out["net_sol"] * px, 2)
                st["capital_usd"] = round(st["capital_usd"] + net, 2); st["n_trades"] += 1
                st["busy_until"] = e["create_ts"] + out["exit_s"]
                rec = {"token": e["token"], "symbol": e["symbol"], "dev": e["dev"], "create_ts": e["create_ts"], "entry_s": out["entry_s"], "exit_s": out["exit_s"],
                       "how": out["how"], "gross_x": out["gross_x"], "net_usd": net, "capital_usd": st["capital_usd"], "sol_usd": px,
                       "fee_in_pct": out["fee_in_pct"], "fee_out_pct": out["fee_out_pct"], "impact_in_pct": out["impact_in_pct"], "dev_sold_by_mark": out.get("dev_sold_by_mark"), "replayed_at": int(time.time())}
                with open(os.path.join(LIVE, "replay_trades.jsonl"), "a") as f:
                    f.write(json.dumps(rec) + "\n")
                closed.append(rec)
        sig = {"token": e["token"], "symbol": e["symbol"], "dev": e["dev"], "create_ts": e["create_ts"], "sol_in_1m": round(L.sol_in_1m, 1), "baseline": round(bases[e["creator"]]["med_sol_in_1m"], 1),
               "dev_sold_by_mark": out.get("dev_sold_by_mark"), "triggered": bool(out.get("triggered")), "reason": out.get("reason"), "would_trigger": out.get("would_trigger")}
        with open(os.path.join(LIVE, "replay_signals.jsonl"), "a") as f:
            f.write(json.dumps(sig) + "\n")
        st["seen"].append(e["token"])
        print(f"{time.strftime('%Y-%m-%dT%H:%M:%S', time.gmtime(e['create_ts']))} {e['dev']:12} {e['symbol']!s:10} inflow {L.sol_in_1m:7.1f} vs base {bases[e['creator']]['med_sol_in_1m']:6.1f} dev_sold {out.get('dev_sold_by_mark')} -> "
              + (f"TRADE {out['how']} {out['gross_x']}x net ${round(out['net_sol'] * px, 2)} capital ${st['capital_usd']}" if out.get("triggered") else f"skip: {out.get('reason')}"))
    json.dump(st, open(STATE, "w"))
    print(f"replay: {len(todo)} new launches, {len(closed)} trades this run, total {st['n_trades']} trades, capital ${st['capital_usd']}")
