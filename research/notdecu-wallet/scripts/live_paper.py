#!/usr/bin/env python3
"""Live PAPER test of the flow-at-60s rule on tracked launchers. Records what the rule would do; moves no money.

Rule: launcher in data/anatomy/live/baselines.json (>= 3 prior launches); at create+60 s the SOL inflow (Bitquery realtime,
SOL-quoted buys) >= flow_mult x the dev's median minute-1 inflow -> paper buy at the VWAP of buys in [60 s, 70 s] with the
backtest cost model (pump.fun fee by venue/tier, impact vs liquidity, priority floor, 0.5% MEV allowance, base fee, rent).
Exit: +5x take-profit, 40% trailing stop from the running high, -50% hard stop, or 30 min; price polled from pump.fun
coins-v2 (free) every 5 s. One position at a time; capital starts at $50 and each trade risks min($50, capital).

    nohup python3 scripts/live_paper.py >> data/anatomy/live/paper.out 2>&1 &
Files: data/anatomy/live/paper_trades.jsonl (closed trades), paper_signals.jsonl (every evaluated launch), paper_state.json.
"""
import datetime
import json
import os
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from clients import load_env  # noqa: E402
from bitquery_collect import gql, iso, ts_of, SOL_MINTS, Q_TRADES, PUMP_PROTOCOLS  # noqa: E402
from backtest_v2 import pool_fee  # noqa: E402

LIVE = os.path.join(HERE, "..", "data", "anatomy", "live")
LOG = os.path.join(LIVE, "paper.log")
STATE = os.path.join(LIVE, "paper_state.json")
CFG = {"flow_mult": 1.5, "mark": 60, "veto_dev_sell": 0.5, "trail_pct": 0.40, "trail_arm_mult": 1.2, "tp_mult": 5.0, "hard_stop_pct": 0.50, "time_stop_s": 1800,
       "mev_pct": 0.005, "prio_floor_sol": 0.00002, "base_fee_sol": 0.000005, "rent_sol": 0.0018444, "stake_usd": 50.0, "capital_usd": 50.0}
UA = {"User-Agent": "notdecu-research/0.1"}


def log(msg):
    line = f"{datetime.datetime.utcnow().isoformat(timespec='seconds')} {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def http(url):
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode())


def sol_usd():
    try:
        return float(http("https://frontend-api-v3.pump.fun/sol-price")["solPrice"])
    except Exception:  # noqa: BLE001
        return 100.0


def coin(mint):
    return http(f"https://frontend-api-v3.pump.fun/coins-v2/{mint}")


def price_sol(c):
    """SOL per token from coins-v2 (market_cap is in SOL; supply 1e9)."""
    mc = c.get("market_cap")
    return float(mc) / 1e9 if mc else None


def load_state():
    if os.path.exists(STATE):
        return json.load(open(STATE))
    return {"capital_usd": CFG["capital_usd"], "seen": [], "pending": {}, "open": None, "n_trades": 0}


def save_state(st):
    json.dump(st, open(STATE, "w"))


def evaluate(mint, launch, base, tok, st):
    """At >= 60 s: measure minute-1 inflow via Bitquery and decide."""
    cts = launch["create_ts"]
    rows = gql(Q_TRADES, {"mint": mint, "since": iso(cts - 5), "before": iso(cts + CFG["mark"] + 10), "offset": 0}, tok)
    rows = [r for r in rows if r["Trade"]["Dex"]["ProtocolName"] in PUMP_PROTOCOLS]   # drop aggregator duplicate legs
    buys = [r for r in rows if r["Trade"]["Side"]["Type"] == "buy" and r["Trade"]["Side"]["Currency"]["MintAddress"] in SOL_MINTS]
    inflow = sum(float(r["Trade"]["Side"]["Amount"] or 0) for r in buys if ts_of(r["Block"]["Time"]) <= cts + CFG["mark"])
    entry_rows = [r for r in buys if cts + CFG["mark"] <= ts_of(r["Block"]["Time"]) <= cts + CFG["mark"] + 10]
    vwap = (sum(float(r["Trade"]["Side"]["Amount"]) for r in entry_rows) / sum(float(r["Trade"]["Amount"]) for r in entry_rows)) if entry_rows and sum(float(r["Trade"]["Amount"]) for r in entry_rows) > 0 else None
    med_fee = sorted(float(r["Transaction"]["Fee"] or 0) for r in entry_rows)[len(entry_rows) // 2] if entry_rows else 0.0
    # dev-sell veto (added after the DUDAS live loss: dev sold 100% at 39-49 s, we bought at 60 s)
    creator = launch.get("creator")
    dev_rows = [r for r in rows if r["Trade"]["Account"]["Owner"] == creator and ts_of(r["Block"]["Time"]) <= cts + CFG["mark"]]
    dev_bought = sum(float(r["Trade"]["Amount"] or 0) for r in dev_rows if r["Trade"]["Side"]["Type"] == "buy")
    dev_sold = sum(float(r["Trade"]["Amount"] or 0) for r in dev_rows if r["Trade"]["Side"]["Type"] == "sell")
    dev_sold_frac = (dev_sold / dev_bought) if dev_bought > 0 else (1.0 if dev_sold > 0 else 0.0)
    dev_first_sell_s = min((ts_of(r["Block"]["Time"]) - cts for r in dev_rows if r["Trade"]["Side"]["Type"] == "sell"), default=None)
    vetoed = bool(CFG["veto_dev_sell"] and dev_sold_frac >= CFG["veto_dev_sell"])
    sig = {"t": int(time.time()), "mint": mint, "dev": base["dev"], "symbol": launch.get("symbol"), "create_ts": cts, "inflow_1m_sol": round(inflow, 3),
           "baseline_sol": round(base["med_sol_in_1m"], 3), "ratio": round(inflow / base["med_sol_in_1m"], 2) if base["med_sol_in_1m"] else None,
           "n_trades_1m": len(rows), "vwap_60_70": vwap, "dev_sold_frac_by_mark": round(dev_sold_frac, 3), "dev_first_sell_s": dev_first_sell_s, "vetoed_dev_sell": vetoed,
           "triggered": bool(inflow >= CFG["flow_mult"] * base["med_sol_in_1m"] and vwap and not vetoed), "position_open": st["open"] is not None}
    with open(os.path.join(LIVE, "paper_signals.jsonl"), "a") as f:
        f.write(json.dumps(sig) + "\n")
    log(f"  signal {base['dev']:12} {launch.get('symbol')!s:10} inflow {inflow:.1f} SOL vs base {base['med_sol_in_1m']:.1f} x{sig['ratio']} dev sold {dev_sold_frac * 100:.0f}%{f' at {dev_first_sell_s} s' if dev_first_sell_s is not None else ''} -> {'TRIGGER' if sig['triggered'] else ('VETO dev sell' if vetoed and inflow >= CFG['flow_mult'] * base['med_sol_in_1m'] else 'skip')}{' (position already open)' if st['open'] else ''}")
    if sig["triggered"] and st["open"] is None:
        px = sol_usd()
        stake = min(CFG["stake_usd"], st["capital_usd"]) / px
        c = coin(mint)
        on_curve = not c.get("complete")
        fee_in = 0.0125 if on_curve else pool_fee(vwap * 1e9)
        liq = 30 + inflow if on_curve else max(60.0, 85 + inflow)
        impact = stake / (2 * liq)
        tokens = stake * (1 - fee_in - CFG["mev_pct"]) / (vwap * (1 + impact))
        fixed = CFG["base_fee_sol"] + max(CFG["prio_floor_sol"], med_fee) + CFG["rent_sol"]
        st["open"] = {"mint": mint, "dev": base["dev"], "symbol": launch.get("symbol"), "create_ts": cts, "entry_t": int(time.time()), "entry_px": vwap, "tokens": tokens,
                      "stake_sol": stake, "sol_usd": px, "fee_in": fee_in, "impact_in": impact, "fixed_in_sol": fixed, "hi": vwap, "inflow_1m": inflow}
        log(f"  PAPER BUY {launch.get('symbol')} {mint[:8]} at {vwap:.3e} SOL/token, {stake:.3f} SOL (${stake * px:.0f}), fee {fee_in * 100:.2f}% impact {impact * 100:.2f}%")


def manage(st):
    o = st["open"]
    if not o:
        return
    try:
        c = coin(o["mint"])
    except Exception as e:  # noqa: BLE001
        log(f"  price poll error {str(e)[:80]}"); return
    p = price_sol(c)
    if not p:
        return
    o["hi"] = max(o["hi"], p)
    age = time.time() - o["entry_t"]
    why = None
    if p >= o["entry_px"] * CFG["tp_mult"]:
        why = "take profit"
    elif p <= o["entry_px"] * (1 - CFG["hard_stop_pct"]):
        why = "hard stop"
    elif o["hi"] >= o["entry_px"] * CFG["trail_arm_mult"] and p <= o["hi"] * (1 - CFG["trail_pct"]):
        why = "trailing stop"
    elif age >= CFG["time_stop_s"]:
        why = "time stop"
    if not why:
        return
    on_curve = not c.get("complete")
    fee_out = 0.0125 if on_curve else pool_fee(p * 1e9)
    liq = max(60.0, float(c.get("virtual_sol_reserves") or 0) / 1e9) if on_curve else max(60.0, 85.0)
    impact = (o["tokens"] * p) / (2 * liq)
    proceeds = o["tokens"] * p * (1 - impact) * (1 - fee_out - CFG["mev_pct"])
    fixed_out = CFG["base_fee_sol"] + CFG["prio_floor_sol"]
    net_sol = proceeds - o["stake_sol"] - o["fixed_in_sol"] - fixed_out
    net_usd = net_sol * o["sol_usd"]
    st["capital_usd"] = round(st["capital_usd"] + net_usd, 2)
    st["n_trades"] += 1
    tr = {**o, "exit_t": int(time.time()), "exit_px": p, "why": why, "gross_x": round(p / o["entry_px"], 3), "fee_out": fee_out, "impact_out": impact,
          "net_sol": round(net_sol, 5), "net_usd": round(net_usd, 2), "capital_after_usd": st["capital_usd"], "hold_s": int(age)}
    with open(os.path.join(LIVE, "paper_trades.jsonl"), "a") as f:
        f.write(json.dumps(tr) + "\n")
    log(f"  PAPER SELL {o['symbol']} {why}: {tr['gross_x']}x gross, net ${net_usd:+.2f}, capital ${st['capital_usd']:.2f}")
    st["open"] = None


if __name__ == "__main__":
    tok = load_env()["BITQUERY_TOKEN"]
    bases = {b["creator"]: b for b in json.load(open(os.path.join(LIVE, "baselines.json"))) if b["n"] >= 3}
    st = load_state()
    if st["open"]:
        log(f"restart with an open paper position in {st['open']['symbol']}; keeping it")
    log(f"=== live paper start: {len(bases)} launchers with baselines, capital ${st['capital_usd']:.2f}, cfg {json.dumps(CFG)} ===")
    last_poll = 0
    while True:
        now = time.time()
        if now - last_poll >= 4:
            last_poll = now
            try:
                coins = http("https://frontend-api-v3.pump.fun/coins?offset=0&limit=50&sort=created_timestamp&order=DESC&includeNsfw=true")
                for c in coins:
                    m, cr = c.get("mint"), c.get("creator")
                    if cr in bases and m not in st["seen"]:
                        st["seen"].append(m); st["seen"] = st["seen"][-2000:]
                        st["pending"][m] = {"create_ts": int(c["created_timestamp"] / 1000), "symbol": c.get("symbol"), "creator": cr}
                        log(f"NEW LAUNCH by {bases[cr]['dev']}: {c.get('symbol')} {m} (base {bases[cr]['med_sol_in_1m']:.1f} SOL/min)")
            except Exception as e:  # noqa: BLE001
                log(f"  feed error {str(e)[:80]}")
            for m, L in list(st["pending"].items()):
                if now >= L["create_ts"] + CFG["mark"] + 12:
                    try:
                        evaluate(m, L, bases[L["creator"]], tok, st)
                    except Exception as e:  # noqa: BLE001
                        log(f"  evaluate error {m[:8]}: {str(e)[:100]}")
                    del st["pending"][m]
            save_state(st)
        if st["open"]:
            manage(st); save_state(st)
        time.sleep(1.0 if st["open"] else 2.0)
