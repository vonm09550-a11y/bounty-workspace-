"""
Phase 6: Final forensic audit of top 2 candidates.
Deep dive: every fill, leverage patterns, drawdowns, position sizing,
sub-accounts, deposit/withdrawal flows, consistency validation.
"""
import requests
import json
import time
from collections import defaultdict
from datetime import datetime

BASE = "https://api.hyperliquid.xyz"

def post_info(payload):
    for attempt in range(3):
        try:
            r = requests.post(f"{BASE}/info", json=payload, timeout=30)
            return r.json()
        except:
            time.sleep(1)
    return None

FINALISTS = [
    "0x0e3f5bb797e3953fed2a319544d0e821b4a11e1c",  # ETH scalper
    "0x2d99fe0f36c1aebd28a1a2c0e82e8ca13c2ea351",  # BTC machine
]

now_ms = int(time.time() * 1000)
six_months_ago = now_ms - (180 * 24 * 60 * 60 * 1000)

for addr in FINALISTS:
    print(f"\n{'#'*100}")
    print(f"# FINAL FORENSIC: {addr}")
    print(f"{'#'*100}")

    # 1. Account state
    state = post_info({"type": "clearinghouseState", "user": addr})
    margin = state.get("marginSummary", {}) if state else {}
    acct_val = float(margin.get("accountValue", 0))
    positions = state.get("assetPositions", []) if state else []

    print(f"\n[ACCOUNT STATE]")
    print(f"  Value: ${acct_val:,.2f}")
    print(f"  Margin Used: ${float(margin.get('totalMarginUsed', 0)):,.2f}")
    print(f"  Notional: ${float(margin.get('totalNtlPos', 0)):,.2f}")

    for p in positions:
        pos = p.get("position", {})
        coin = pos.get("coin", "")
        szi = float(pos.get("szi", 0))
        entry = float(pos.get("entryPx", 0) or 0)
        lev = pos.get("leverage", {})
        upnl = float(pos.get("unrealizedPnl", 0))
        roe = float(pos.get("returnOnEquity", 0))
        liq = pos.get("liquidationPx", "N/A")
        print(f"  Position: {coin} | size={szi} | entry=${entry:,.2f} | lev={lev} | uPnL=${upnl:,.2f} | ROE={roe:.1%} | liq={liq}")

    time.sleep(0.3)

    # 2. Ledger (full history)
    ledger = post_info({"type": "userNonFundingLedgerUpdates", "user": addr, "startTime": six_months_ago})
    print(f"\n[LEDGER - 6 months]")
    deposits = 0.0
    withdrawals = 0.0
    liquidations = []
    transfers = []

    if ledger and isinstance(ledger, list):
        for entry in ledger:
            delta = entry.get("delta", {})
            etype = delta.get("type", "")
            ts = datetime.fromtimestamp(entry.get("time", 0)/1000).strftime("%Y-%m-%d %H:%M")

            if etype == "deposit":
                amt = float(delta.get("usdc", 0))
                deposits += amt
                print(f"  [{ts}] DEPOSIT: ${amt:,.2f}")
            elif etype == "withdraw":
                amt = float(delta.get("usdc", 0))
                withdrawals += amt
                print(f"  [{ts}] WITHDRAW: ${amt:,.2f}")
            elif etype == "liquidation":
                liquidations.append(entry)
                print(f"  [{ts}] LIQUIDATION: {json.dumps(delta)[:200]}")
            elif etype == "accountClassTransfer":
                amt = float(delta.get("usdc", 0))
                transfers.append(amt)
                print(f"  [{ts}] TRANSFER: ${amt:,.2f}")
            elif etype == "internalTransfer":
                amt = float(delta.get("usdc", 0))
                transfers.append(amt)
                print(f"  [{ts}] INTERNAL TRANSFER: ${amt:,.2f}")

        print(f"\n  Total Deposits: ${deposits:,.2f}")
        print(f"  Total Withdrawals: ${withdrawals:,.2f}")
        print(f"  Net Flow: ${deposits - withdrawals:,.2f}")
        print(f"  Liquidations: {len(liquidations)}")
        print(f"  Transfers: {len(transfers)}")

    time.sleep(0.3)

    # 3. Sub-accounts
    subs = post_info({"type": "subAccounts", "user": addr})
    print(f"\n[SUB-ACCOUNTS]")
    if subs and isinstance(subs, list) and len(subs) > 0:
        print(f"  WARNING: Has {len(subs)} sub-accounts")
        for s in subs:
            print(f"    {json.dumps(s)[:200]}")
    else:
        print(f"  Clean - no sub-accounts")

    time.sleep(0.3)

    # 4. All fills - full analysis
    fills = post_info({"type": "userFillsByTime", "user": addr, "startTime": six_months_ago, "aggregateByTime": True})
    print(f"\n[FILL ANALYSIS - 6 months]")
    print(f"  Total fills: {len(fills) if fills else 0}")

    if fills and isinstance(fills, list):
        # Separate by coin and direction
        trade_analysis = defaultdict(lambda: {
            "long_wins": 0, "long_losses": 0, "short_wins": 0, "short_losses": 0,
            "long_pnl": 0.0, "short_pnl": 0.0,
            "sizes": [], "pnls": [], "hold_durations": [],
            "fills": 0, "closing": 0, "volume": 0.0,
        })

        daily_pnl = defaultdict(float)
        hourly_activity = defaultdict(int)
        consecutive_wins = 0
        max_consecutive_wins = 0
        consecutive_losses = 0
        max_consecutive_losses = 0
        max_drawdown = 0.0
        running_pnl = 0.0
        peak_pnl = 0.0
        all_pnls = []

        for fill in fills:
            coin = fill.get("coin", "")
            pnl = float(fill.get("closedPnl", "0"))
            sz = float(fill.get("sz", "0"))
            px = float(fill.get("px", "0"))
            side = fill.get("side", "")
            direction = fill.get("dir", "")
            ts = fill.get("time", 0)
            vol = sz * px

            dt = datetime.fromtimestamp(ts/1000)
            day_key = dt.strftime("%Y-%m-%d")
            hour = dt.hour

            trade_analysis[coin]["fills"] += 1
            trade_analysis[coin]["volume"] += vol
            trade_analysis[coin]["sizes"].append(vol)
            daily_pnl[day_key] += pnl
            hourly_activity[hour] += 1

            if pnl != 0:
                trade_analysis[coin]["closing"] += 1
                trade_analysis[coin]["pnls"].append(pnl)
                all_pnls.append(pnl)
                running_pnl += pnl
                peak_pnl = max(peak_pnl, running_pnl)
                dd = peak_pnl - running_pnl
                max_drawdown = max(max_drawdown, dd)

                is_long_close = "Close Long" in direction or "Short" in side
                is_short_close = "Close Short" in direction or "Buy" in direction

                if pnl > 0:
                    consecutive_wins += 1
                    consecutive_losses = 0
                    max_consecutive_wins = max(max_consecutive_wins, consecutive_wins)
                    if "Long" in direction:
                        trade_analysis[coin]["long_wins"] += 1
                        trade_analysis[coin]["long_pnl"] += pnl
                    else:
                        trade_analysis[coin]["short_wins"] += 1
                        trade_analysis[coin]["short_pnl"] += pnl
                else:
                    consecutive_losses += 1
                    consecutive_wins = 0
                    max_consecutive_losses = max(max_consecutive_losses, consecutive_losses)
                    if "Long" in direction:
                        trade_analysis[coin]["long_losses"] += 1
                        trade_analysis[coin]["long_pnl"] += pnl
                    else:
                        trade_analysis[coin]["short_losses"] += 1
                        trade_analysis[coin]["short_pnl"] += pnl

        # Overall stats
        total_closing = sum(s["closing"] for s in trade_analysis.values())
        total_wins = sum(s["long_wins"] + s["short_wins"] for s in trade_analysis.values())
        total_pnl = sum(p for p in all_pnls)
        winning_pnl = sum(p for p in all_pnls if p > 0)
        losing_pnl = sum(p for p in all_pnls if p < 0)

        print(f"\n  Overall Stats:")
        print(f"    Total Closing Fills: {total_closing}")
        print(f"    Win Rate: {total_wins/total_closing*100:.1f}%" if total_closing > 0 else "    Win Rate: N/A")
        print(f"    Total PnL: ${total_pnl:,.2f}")
        print(f"    Gross Profit: ${winning_pnl:,.2f}")
        print(f"    Gross Loss: ${losing_pnl:,.2f}")
        pf = (winning_pnl/abs(losing_pnl)) if losing_pnl != 0 else float('inf')
        print(f"    Profit Factor: {pf:.2f}")
        if all_pnls:
            avg_win = sum(p for p in all_pnls if p > 0) / max(sum(1 for p in all_pnls if p > 0), 1)
            avg_loss = sum(p for p in all_pnls if p < 0) / max(sum(1 for p in all_pnls if p < 0), 1)
            print(f"    Avg Win: ${avg_win:,.2f}")
            print(f"    Avg Loss: ${avg_loss:,.2f}")
            print(f"    Risk/Reward: {abs(avg_win/avg_loss):.2f}x" if avg_loss != 0 else "    Risk/Reward: inf")
        print(f"    Max Consecutive Wins: {max_consecutive_wins}")
        print(f"    Max Consecutive Losses: {max_consecutive_losses}")
        print(f"    Max Drawdown: ${max_drawdown:,.2f}")
        if peak_pnl > 0:
            print(f"    Max DD as % of Peak: {max_drawdown/peak_pnl*100:.1f}%")

        # Per-coin detail
        print(f"\n  Per-Coin Breakdown:")
        print(f"  {'Coin':<10} {'Close':>6} {'LW':>4} {'LL':>4} {'SW':>4} {'SL':>4} {'WR':>7} {'PnL':>14} {'AvgWin':>10} {'AvgLoss':>10}")
        print(f"  {'-'*80}")
        for coin, s in sorted(trade_analysis.items(), key=lambda x: x[1]["volume"], reverse=True):
            if s["closing"] == 0:
                continue
            total_w = s["long_wins"] + s["short_wins"]
            total_l = s["long_losses"] + s["short_losses"]
            wr = (total_w / s["closing"] * 100) if s["closing"] > 0 else 0
            total_p = sum(s["pnls"])
            wins = [p for p in s["pnls"] if p > 0]
            losses = [p for p in s["pnls"] if p < 0]
            avg_w = sum(wins)/len(wins) if wins else 0
            avg_l = sum(losses)/len(losses) if losses else 0
            print(f"  {coin:<10} {s['closing']:>6} {s['long_wins']:>4} {s['long_losses']:>4} "
                  f"{s['short_wins']:>4} {s['short_losses']:>4} {wr:>6.1f}% ${total_p:>12,.0f} "
                  f"${avg_w:>8,.0f} ${avg_l:>8,.0f}")

        # Daily PnL consistency
        print(f"\n  Daily PnL (last 30 days):")
        days = sorted(daily_pnl.keys())[-30:]
        losing_days = 0
        for d in days:
            marker = " <<<" if daily_pnl[d] < 0 else ""
            if daily_pnl[d] < 0:
                losing_days += 1
            print(f"    {d}: ${daily_pnl[d]:>12,.2f}{marker}")
        print(f"\n  Losing days (last 30): {losing_days}/{len(days)}")

        # Trading hours pattern
        print(f"\n  Trading Hours (UTC):")
        for h in range(24):
            count = hourly_activity.get(h, 0)
            bar = "#" * min(count // 5, 40)
            print(f"    {h:02d}:00  {count:>5} {bar}")

    # 5. Fee tier
    fees = post_info({"type": "userFees", "user": addr})
    if fees:
        print(f"\n[FEE TIER]")
        print(f"  Maker: {fees.get('userAddRate', 'N/A')}")
        print(f"  Taker: {fees.get('userCrossRate', 'N/A')}")

    # 6. Portfolio (official)
    portfolio = post_info({"type": "portfolio", "user": addr})
    if portfolio and isinstance(portfolio, dict):
        print(f"\n[PORTFOLIO PERFORMANCE]")
        for key in portfolio:
            val = portfolio[key]
            if isinstance(val, (int, float, str)):
                print(f"  {key}: {val}")
            elif isinstance(val, list) and len(val) > 0:
                print(f"  {key}: {len(val)} data points")

    print(f"\n{'#'*100}\n")
    time.sleep(0.5)
