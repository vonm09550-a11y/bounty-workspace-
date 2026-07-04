"""
Phase 9: High leverage scenarios - 5x and 10x on the same strategy.
Compare risk/reward at different leverage levels.

Key risk: liquidation prices get dangerously close at higher leverage.
- 2x: liquidation at ~50% below entry
- 5x: liquidation at ~20% below entry
- 10x: liquidation at ~10% below entry
- 20x: liquidation at ~5% below entry

BTC max drawdown in this 30-day window: -9.2% from start.
"""
import requests
import json
import time
from datetime import datetime

BASE = "https://api.hyperliquid.xyz"

def post_info(payload):
    r = requests.post(f"{BASE}/info", json=payload, timeout=30)
    return r.json()

now_ms = int(time.time() * 1000)
sixty_days_ago = now_ms - (60 * 24 * 60 * 60 * 1000)

print("Fetching BTC price data...")
candles = post_info({
    "type": "candleSnapshot",
    "req": {"coin": "BTC", "interval": "1h", "startTime": sixty_days_ago, "endTime": now_ms}
})

prices = []
for c in sorted(candles, key=lambda x: x["t"]):
    prices.append({
        "time": c["t"], "open": float(c["o"]), "high": float(c["h"]),
        "low": float(c["l"]), "close": float(c["c"]),
        "dt": datetime.fromtimestamp(c["t"]/1000),
    })

thirty_days_ago_ms = now_ms - (30 * 24 * 60 * 60 * 1000)
bp = [p for p in prices if p["time"] >= thirty_days_ago_ms]

btc_start = bp[0]["open"]
btc_end = bp[-1]["close"]
btc_low = min(p["low"] for p in bp)
btc_high = max(p["high"] for p in bp)

print(f"Period: {bp[0]['dt'].strftime('%Y-%m-%d')} to {bp[-1]['dt'].strftime('%Y-%m-%d')}")
print(f"BTC: ${btc_start:,.0f} -> ${btc_end:,.0f} ({(btc_end/btc_start-1)*100:+.1f}%)")
print(f"Range: ${btc_low:,.0f} - ${btc_high:,.0f}")
print(f"Max intra-period drop from start: {(btc_low/btc_start-1)*100:.1f}%")

CAPITAL = 100.0
FEE_BUDGET = 5.0
TAKER_FEE = 0.00035
MAKER_FEE = 0.00015
NUM_EXIT_LEVELS = 5
EXIT_PCT = 1.0 / NUM_EXIT_LEVELS
GRID_SPACING = 300
DIP_THRESHOLD = 0.03
LOOKBACK = 48
TRAILING_STOP_ACTIVATION = 0.04
TRAILING_STOP_DISTANCE = 0.03
MIN_ENTRY_GAP = 24


def run_backtest(leverage, emergency_stop_pct, label):
    capital = CAPITAL
    position = 0.0
    entry_price = 0.0
    fees_paid = 0.0
    trades = []
    equities = []
    pnl_total = 0.0
    wins = 0
    losses = 0
    grid_orders = []
    highest = 0.0
    trailing_active = False
    last_close_idx = -MIN_ENTRY_GAP
    liquidated = False
    liq_date = None
    liq_price = 0

    # Liquidation price for isolated margin:
    # liq_price = entry * (1 - 1/leverage) for longs (approximate, ignoring fees)
    # More precisely: you lose all margin when price drops by (margin/notional) = 1/leverage

    for i, candle in enumerate(bp):
        if liquidated:
            equities.append({"dt": candle["dt"], "eq": 0})
            continue

        # Equity calc
        if position > 0:
            unrealized = (candle["close"] - entry_price) * position
            margin = position * entry_price / leverage
            eq = capital + margin + unrealized
        else:
            eq = capital
        equities.append({"dt": candle["dt"], "eq": eq})

        if position > 0:
            # Check liquidation
            liq_px = entry_price * (1 - 1 / leverage * 0.95)  # 95% of margin = liquidation
            if candle["low"] <= liq_px:
                liquidated = True
                liq_date = candle["dt"]
                liq_price = liq_px
                margin_lost = position * entry_price / leverage
                fee = position * liq_px * TAKER_FEE
                # Liquidation: lose all margin
                capital = capital  # margin was already subtracted
                fees_paid += fee
                pnl_total -= margin_lost + fee
                losses += 1
                trades.append({
                    "dt": candle["dt"], "type": "LIQUIDATED", "price": liq_px,
                    "size": position, "pnl": -(margin_lost + fee), "fee": fee
                })
                position = 0
                grid_orders = []
                continue

            # Emergency stop (if set)
            if emergency_stop_pct and emergency_stop_pct < 1/leverage:
                estop = entry_price * (1 - emergency_stop_pct)
                if candle["low"] <= estop:
                    notional = position * estop
                    fee = notional * TAKER_FEE
                    pnl = (estop - entry_price) * position - fee
                    margin_ret = position * entry_price / leverage
                    capital += margin_ret + pnl
                    fees_paid += fee
                    pnl_total += pnl
                    if pnl > 0: wins += 1
                    else: losses += 1
                    trades.append({
                        "dt": candle["dt"], "type": "EMERGENCY_STOP", "price": estop,
                        "size": position, "pnl": pnl, "fee": fee
                    })
                    position = 0
                    grid_orders = []
                    last_close_idx = i
                    continue

            highest = max(highest, candle["high"])

            # Grid fills
            for order in grid_orders:
                if not order["filled"] and candle["high"] >= order["price"]:
                    order["filled"] = True
                    sell_not = order["size"] * order["price"]
                    fee = sell_not * MAKER_FEE
                    pnl = (order["price"] - entry_price) * order["size"] - fee
                    margin_ret = order["size"] * entry_price / leverage
                    position -= order["size"]
                    capital += margin_ret + pnl
                    fees_paid += fee
                    pnl_total += pnl
                    if pnl > 0: wins += 1
                    else: losses += 1
                    trades.append({
                        "dt": candle["dt"], "type": "GRID_SELL", "price": order["price"],
                        "size": order["size"], "pnl": pnl, "fee": fee
                    })

            if grid_orders and all(g["filled"] for g in grid_orders):
                position = 0
                grid_orders = []
                last_close_idx = i

            # Trailing stop
            if position > 0:
                prof_pct = (highest - entry_price) / entry_price
                if prof_pct >= TRAILING_STOP_ACTIVATION:
                    trailing_active = True
                if trailing_active:
                    trail_px = highest * (1 - TRAILING_STOP_DISTANCE)
                    if candle["low"] <= trail_px:
                        notional = position * trail_px
                        fee = notional * TAKER_FEE
                        pnl = (trail_px - entry_price) * position - fee
                        margin_ret = position * entry_price / leverage
                        capital += margin_ret + pnl
                        fees_paid += fee
                        pnl_total += pnl
                        if pnl > 0: wins += 1
                        else: losses += 1
                        trades.append({
                            "dt": candle["dt"], "type": "TRAILING_STOP", "price": trail_px,
                            "size": position, "pnl": pnl, "fee": fee
                        })
                        position = 0
                        grid_orders = []
                        last_close_idx = i
                        trailing_active = False

        # Entry
        if position == 0 and not liquidated and i - last_close_idx >= MIN_ENTRY_GAP:
            lookback_start = max(0, i - LOOKBACK)
            recent_high = max(p["high"] for p in bp[lookback_start:i+1])
            dip_pct = (recent_high - candle["close"]) / recent_high

            if dip_pct >= DIP_THRESHOLD and capital >= 10:
                notional = capital * leverage
                fee = notional * TAKER_FEE
                if fees_paid + fee <= FEE_BUDGET:
                    size = notional / candle["close"]
                    margin = notional / leverage
                    position = size
                    entry_price = candle["close"]
                    capital -= margin
                    fees_paid += fee
                    highest = candle["close"]
                    trailing_active = False

                    grid_orders = []
                    for j in range(1, NUM_EXIT_LEVELS + 1):
                        exit_px = candle["close"] + (GRID_SPACING * j)
                        grid_orders.append({
                            "price": exit_px, "size": size * EXIT_PCT, "filled": False
                        })

                    trades.append({
                        "dt": candle["dt"], "type": "BUY", "price": candle["close"],
                        "size": size, "pnl": 0, "fee": fee
                    })

    # Close remaining at end
    if position > 0 and not liquidated:
        px = bp[-1]["close"]
        notional = position * px
        fee = notional * TAKER_FEE
        pnl = (px - entry_price) * position - fee
        margin_ret = position * entry_price / leverage
        capital += margin_ret + pnl
        fees_paid += fee
        pnl_total += pnl
        if pnl > 0: wins += 1
        else: losses += 1
        trades.append({
            "dt": bp[-1]["dt"], "type": "END_OF_PERIOD", "price": px,
            "size": position, "pnl": pnl, "fee": fee
        })
        position = 0

    final_eq = capital if not liquidated else 0
    total_trades = wins + losses
    eq_vals = [e["eq"] for e in equities]
    peak = eq_vals[0]
    max_dd = 0
    max_dd_pct = 0
    for ev in eq_vals:
        peak = max(peak, ev)
        dd = peak - ev
        dd_pct = dd / peak if peak > 0 else 0
        max_dd = max(max_dd, dd)
        max_dd_pct = max(max_dd_pct, dd_pct)

    return {
        "label": label,
        "leverage": leverage,
        "final_eq": final_eq,
        "pnl": pnl_total,
        "return_pct": pnl_total / CAPITAL * 100,
        "fees": fees_paid,
        "wins": wins,
        "losses": losses,
        "total_trades": total_trades,
        "win_rate": wins / total_trades * 100 if total_trades > 0 else 0,
        "max_dd": max_dd,
        "max_dd_pct": max_dd_pct * 100,
        "liquidated": liquidated,
        "liq_date": str(liq_date) if liq_date else None,
        "liq_price": liq_price,
        "trades": trades,
        "equities": equities,
    }


# Run all scenarios
scenarios = [
    (2, 0.15, "2x Conservative (baseline)"),
    (3, 0.12, "3x Moderate"),
    (5, 0.08, "5x Aggressive"),
    (7, 0.06, "7x High Risk"),
    (10, 0.04, "10x Extreme"),
    (10, None, "10x No Stop (YOLO)"),
    (20, None, "20x Degen (YOLO)"),
]

results = []
for lev, estop, label in scenarios:
    r = run_backtest(lev, estop, label)
    results.append(r)

# Print comparison table
print(f"\n{'='*120}")
print("LEVERAGE SCENARIO COMPARISON - $100 CAPITAL, SAME STRATEGY")
print(f"{'='*120}\n")

print(f"{'Scenario':<30} {'Lev':>4} {'Final$':>8} {'Return':>8} {'WR':>6} {'W/L':>6} "
      f"{'MaxDD':>7} {'Fees':>7} {'Sharpe':>7} {'Liq?':>12}")
print(f"{'-'*120}")

for r in results:
    # Quick sharpe calc
    daily_eq = {}
    for e in r["equities"]:
        d = e["dt"].strftime("%Y-%m-%d")
        daily_eq[d] = e["eq"]
    days = sorted(daily_eq.keys())
    daily_ret = []
    for i in range(1, len(days)):
        if daily_eq[days[i-1]] > 0:
            daily_ret.append((daily_eq[days[i]] - daily_eq[days[i-1]]) / daily_eq[days[i-1]])
        else:
            daily_ret.append(0)
    if daily_ret and any(x != 0 for x in daily_ret):
        avg = sum(daily_ret) / len(daily_ret)
        std = (sum((x-avg)**2 for x in daily_ret) / len(daily_ret)) ** 0.5
        sharpe = avg / std * (365**0.5) if std > 0 else 0
    else:
        sharpe = 0

    liq_str = f"YES {r['liq_date'][:10]}" if r["liquidated"] else "No"
    wl = f"{r['wins']}/{r['losses']}"

    print(f"{r['label']:<30} {r['leverage']:>3}x ${r['final_eq']:>7.2f} {r['return_pct']:>+7.1f}% "
          f"{r['win_rate']:>5.1f}% {wl:>6} {r['max_dd_pct']:>6.1f}% ${r['fees']:>5.2f} "
          f"{sharpe:>7.2f} {liq_str:>12}")

# Detailed breakdown of each scenario
print(f"\n{'='*120}")
print("DETAILED SCENARIO ANALYSIS")
print(f"{'='*120}")

for r in results:
    print(f"\n{'─'*80}")
    print(f"  {r['label']} ({r['leverage']}x leverage)")
    print(f"{'─'*80}")

    if r["liquidated"]:
        print(f"  *** LIQUIDATED on {r['liq_date'][:10]} at ${r['liq_price']:,.0f} ***")
        print(f"  Liquidation price was {(1 - r['liq_price']/btc_start)*100:.1f}% below period start")
        print(f"  Result: TOTAL LOSS of $100")
        # Find what trade triggered it
        for t in r["trades"]:
            if t["type"] == "LIQUIDATED":
                print(f"  Entry was at ${t.get('price',0):,.0f}, liquidated at ${r['liq_price']:,.0f}")
        print()
        continue

    print(f"  Final equity:  ${r['final_eq']:>10.2f}")
    print(f"  Net PnL:       ${r['pnl']:>10.2f} ({r['return_pct']:+.1f}%)")
    print(f"  Win/Loss:      {r['wins']}/{r['losses']} ({r['win_rate']:.1f}%)")
    print(f"  Max Drawdown:  {r['max_dd_pct']:.1f}% (${r['max_dd']:.2f})")
    print(f"  Fees:          ${r['fees']:.4f}")

    # Notional exposure per trade
    notional = CAPITAL * r["leverage"]
    liq_drop = (1 / r["leverage"]) * 0.95 * 100
    print(f"  Notional/trade: ${notional:,.0f}")
    print(f"  Liq distance:  {liq_drop:.1f}% below entry")
    print()

    print(f"  Trade Log:")
    print(f"  {'Date':<20} {'Type':<16} {'Price':>10} {'Size':>10} {'PnL':>10}")
    for t in r["trades"]:
        dt_str = t["dt"].strftime("%Y-%m-%d %H:%M") if isinstance(t["dt"], datetime) else str(t["dt"])[:16]
        pnl_str = f"${t['pnl']:>8.2f}" if t["pnl"] != 0 else ""
        print(f"  {dt_str:<20} {t['type']:<16} ${t['price']:>8,.0f} {t['size']:>9.6f} {pnl_str}")

# Risk analysis
print(f"\n{'='*120}")
print("RISK ANALYSIS")
print(f"{'='*120}\n")

print(f"BTC worst intra-period drop: {(btc_low/btc_start-1)*100:.1f}% (${btc_start:,.0f} -> ${btc_low:,.0f})")
print(f"BTC worst drop from any entry point varies by timing.\n")

print("Liquidation distance by leverage:")
print(f"  {'Leverage':>8} {'Liq Drop':>10} {'Liq from $64K':>14} {'Liq from $62K':>14} {'Liq from $60K':>14} {'Safe?':>8}")
for lev in [2, 3, 5, 7, 10, 15, 20]:
    drop = (1/lev) * 0.95
    liq64 = 64000 * (1 - drop)
    liq62 = 62000 * (1 - drop)
    liq60 = 60000 * (1 - drop)
    safe = "YES" if liq64 < btc_low and liq62 < btc_low and liq60 < btc_low else "RISK" if liq60 < btc_low else "NO"
    print(f"  {lev:>7}x {drop*100:>9.1f}% ${liq64:>12,.0f} ${liq62:>12,.0f} ${liq60:>12,.0f} {safe:>8}")

print(f"\n  Period low: ${btc_low:,.0f}")
print(f"  Any liq price above ${btc_low:,.0f} = LIQUIDATED in this window")

# Final recommendation
print(f"\n{'='*120}")
print("RECOMMENDATION")
print(f"{'='*120}\n")

safe_results = [r for r in results if not r["liquidated"] and r["return_pct"] > 0]
if safe_results:
    best = max(safe_results, key=lambda x: x["return_pct"])
    safest = min(safe_results, key=lambda x: x["max_dd_pct"])
    best_ratio = max(safe_results, key=lambda x: x["return_pct"] / max(x["max_dd_pct"], 1))

    print(f"  Highest Return:      {best['label']} -> {best['return_pct']:+.1f}% (DD: {best['max_dd_pct']:.1f}%)")
    print(f"  Lowest Drawdown:     {safest['label']} -> {safest['return_pct']:+.1f}% (DD: {safest['max_dd_pct']:.1f}%)")
    print(f"  Best Return/Risk:    {best_ratio['label']} -> {best_ratio['return_pct']:+.1f}% (DD: {best_ratio['max_dd_pct']:.1f}%)")

liq_results = [r for r in results if r["liquidated"]]
if liq_results:
    print(f"\n  LIQUIDATED scenarios: {len(liq_results)}")
    for r in liq_results:
        print(f"    {r['label']} -> TOTAL LOSS on {r['liq_date'][:10]}")

# Save
save_data = []
for r in results:
    save_data.append({
        "label": r["label"], "leverage": r["leverage"],
        "final_equity": r["final_eq"], "pnl": r["pnl"],
        "return_pct": r["return_pct"], "fees": r["fees"],
        "wins": r["wins"], "losses": r["losses"],
        "win_rate": r["win_rate"], "max_dd_pct": r["max_dd_pct"],
        "liquidated": r["liquidated"],
        "liq_date": r["liq_date"],
    })

with open("leverage_scenarios.json", "w") as f:
    json.dump(save_data, f, indent=2, default=str)

print(f"\nResults saved to leverage_scenarios.json")
