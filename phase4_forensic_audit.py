"""
Phase 4: Forensic audit of top 3 candidates.
Check for: hidden losses, liquidations, deposit/withdrawal patterns,
consistency over time, leverage behavior, all-time fill history.
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

TOP_3 = [
    "0x20bc9cd229dfd681740834d9b4f55641ce435da3",  # 97.7% WR, BTC-only
    "0x517bb82ad25d90b9d9e0af57682931c44f7ff64c",  # 90.2% WR, BTC-only
    "0x7ca519838f6d8dbbd8488b63f5f2cc461b89028c",  # 92.5% ETH/BTC WR
]

now_ms = int(time.time() * 1000)

for addr in TOP_3:
    print(f"\n{'='*100}")
    print(f"FORENSIC AUDIT: {addr}")
    print(f"{'='*100}\n")

    # 1. Full portfolio history
    portfolio = post_info({"type": "portfolio", "user": addr})
    if portfolio:
        print("--- Portfolio Performance ---")
        if isinstance(portfolio, list):
            for period in portfolio:
                if isinstance(period, dict):
                    for k, v in period.items():
                        print(f"  {k}: {str(v)[:200]}")
        elif isinstance(portfolio, dict):
            for k, v in portfolio.items():
                if isinstance(v, list) and len(v) > 0:
                    print(f"  {k}: {len(v)} entries, sample: {str(v[0])[:200]}")
                else:
                    print(f"  {k}: {str(v)[:200]}")

    time.sleep(0.3)

    # 2. Current state (positions + margin)
    state = post_info({"type": "clearinghouseState", "user": addr})
    if state:
        print("\n--- Current State ---")
        margin = state.get("marginSummary", {})
        print(f"  Account Value: ${float(margin.get('accountValue', 0)):,.2f}")
        print(f"  Total Margin Used: ${float(margin.get('totalMarginUsed', 0)):,.2f}")
        print(f"  Total Notional: ${float(margin.get('totalNtlPos', 0)):,.2f}")
        print(f"  Withdrawable: ${float(state.get('withdrawable', 0)):,.2f}")

        positions = state.get("assetPositions", [])
        if positions:
            print(f"\n  Open Positions ({len(positions)}):")
            for p in positions:
                pos = p.get("position", {})
                coin = pos.get("coin", "")
                szi = float(pos.get("szi", 0))
                entry = float(pos.get("entryPx", 0) or 0)
                lev = pos.get("leverage", {})
                upnl = float(pos.get("unrealizedPnl", 0))
                liq = pos.get("liquidationPx", "N/A")
                margin_used = float(pos.get("marginUsed", 0))
                print(f"    {coin}: size={szi}, entry=${entry:,.2f}, leverage={lev}, uPnL=${upnl:,.2f}, margin=${margin_used:,.2f}")
        else:
            print("  No open positions")

    time.sleep(0.3)

    # 3. Non-funding ledger (deposits, withdrawals, liquidations)
    ninety_days_ago = now_ms - (90 * 24 * 60 * 60 * 1000)
    ledger = post_info({
        "type": "userNonFundingLedgerUpdates",
        "user": addr,
        "startTime": ninety_days_ago
    })

    if ledger and isinstance(ledger, list):
        print(f"\n--- Non-Funding Ledger (90d): {len(ledger)} entries ---")
        event_types = defaultdict(lambda: {"count": 0, "total": 0.0})
        deposits = 0.0
        withdrawals = 0.0
        liquidations = 0
        liq_losses = 0.0

        for entry in ledger:
            delta = entry.get("delta", {})
            etype = delta.get("type", "unknown")
            event_types[etype]["count"] += 1

            if etype == "deposit":
                usdc = float(delta.get("usdc", 0))
                deposits += usdc
                event_types[etype]["total"] += usdc
            elif etype == "withdraw":
                usdc = float(delta.get("usdc", 0))
                withdrawals += usdc
                event_types[etype]["total"] += usdc
            elif etype == "liquidation":
                liquidations += 1
                lev_pnl = float(delta.get("leveragedPnl", 0))
                liq_losses += lev_pnl
                event_types[etype]["total"] += lev_pnl
            elif etype == "accountClassTransfer":
                event_types[etype]["total"] += float(delta.get("usdc", 0))

        for etype, stats in sorted(event_types.items()):
            print(f"  {etype}: count={stats['count']}, total=${stats['total']:,.2f}")

        print(f"\n  NET FLOW: deposits=${deposits:,.2f}, withdrawals=${withdrawals:,.2f}")
        print(f"  LIQUIDATIONS: {liquidations} events, loss=${liq_losses:,.2f}")

        # RED FLAG: if deposits >> PnL, they might be faking profitability
        acct_val = float(margin.get('accountValue', 0))
        if deposits > 0 and acct_val > 0:
            print(f"  WARNING CHECK: deposit ratio to account = {deposits/acct_val:.2f}x")
        elif acct_val == 0:
            print(f"  RED FLAG: Account value is $0 (fully withdrawn or inactive)")

    time.sleep(0.3)

    # 4. All fills (last 90 days) for detailed trade analysis
    print(f"\n--- Trade Analysis (90 days) ---")
    fills_90d = post_info({
        "type": "userFillsByTime",
        "user": addr,
        "startTime": ninety_days_ago,
        "aggregateByTime": True
    })

    if fills_90d and isinstance(fills_90d, list):
        print(f"  Total fills: {len(fills_90d)}")

        # Weekly breakdown
        weekly = defaultdict(lambda: {"trades": 0, "wins": 0, "pnl": 0.0, "volume": 0.0})
        trade_sizes = []
        hold_times = []
        leverage_usage = []

        for fill in fills_90d:
            ts = fill.get("time", 0)
            week_key = datetime.fromtimestamp(ts/1000).strftime("%Y-W%U")
            coin = fill.get("coin", "")
            pnl = float(fill.get("closedPnl", "0"))
            sz = float(fill.get("sz", "0"))
            px = float(fill.get("px", "0"))
            vol = sz * px

            weekly[week_key]["trades"] += 1
            weekly[week_key]["volume"] += vol
            if pnl != 0:
                weekly[week_key]["pnl"] += pnl
                if pnl > 0:
                    weekly[week_key]["wins"] += 1
            trade_sizes.append(vol)

        print(f"\n  Weekly Breakdown:")
        print(f"  {'Week':<12} {'Trades':>7} {'PnL':>14} {'Volume':>16}")
        print(f"  {'-'*55}")
        for week in sorted(weekly.keys()):
            w = weekly[week]
            print(f"  {week:<12} {w['trades']:>7} ${w['pnl']:>12,.0f} ${w['volume']:>14,.0f}")

        # Trade size distribution
        if trade_sizes:
            trade_sizes.sort()
            n = len(trade_sizes)
            print(f"\n  Trade Size Distribution:")
            print(f"    Min:    ${min(trade_sizes):>12,.0f}")
            print(f"    25th:   ${trade_sizes[n//4]:>12,.0f}")
            print(f"    Median: ${trade_sizes[n//2]:>12,.0f}")
            print(f"    75th:   ${trade_sizes[3*n//4]:>12,.0f}")
            print(f"    Max:    ${max(trade_sizes):>12,.0f}")
            print(f"    Avg:    ${sum(trade_sizes)/n:>12,.0f}")

        # Coin breakdown (all time for this window)
        coin_detail = defaultdict(lambda: {
            "fills": 0, "closing": 0, "wins": 0, "losses": 0,
            "pnl": 0.0, "volume": 0.0, "win_pnl": 0.0, "loss_pnl": 0.0
        })
        for fill in fills_90d:
            coin = fill.get("coin", "")
            pnl = float(fill.get("closedPnl", "0"))
            sz = float(fill.get("sz", "0"))
            px = float(fill.get("px", "0"))
            vol = sz * px

            coin_detail[coin]["fills"] += 1
            coin_detail[coin]["volume"] += vol
            if pnl != 0:
                coin_detail[coin]["closing"] += 1
                coin_detail[coin]["pnl"] += pnl
                if pnl > 0:
                    coin_detail[coin]["wins"] += 1
                    coin_detail[coin]["win_pnl"] += pnl
                else:
                    coin_detail[coin]["losses"] += 1
                    coin_detail[coin]["loss_pnl"] += pnl

        print(f"\n  Coin Breakdown (90d):")
        print(f"  {'Coin':<8} {'Fills':>6} {'Close':>6} {'Wins':>5} {'Loss':>5} {'WR':>7} {'PnL':>14} {'PF':>8}")
        print(f"  {'-'*65}")
        for coin, stats in sorted(coin_detail.items(), key=lambda x: x[1]["volume"], reverse=True):
            wr = (stats["wins"]/stats["closing"]*100) if stats["closing"] > 0 else 0
            pf = (stats["win_pnl"]/abs(stats["loss_pnl"])) if stats["loss_pnl"] != 0 else float('inf')
            print(f"  {coin:<8} {stats['fills']:>6} {stats['closing']:>6} {stats['wins']:>5} {stats['losses']:>5} "
                  f"{wr:>6.1f}% ${stats['pnl']:>12,.0f} {pf:>7.2f}")

    time.sleep(0.3)

    # 5. Fee tier check (indicates volume level / VIP status)
    fees = post_info({"type": "userFees", "user": addr})
    if fees:
        print(f"\n--- Fee Information ---")
        print(f"  Maker rate: {fees.get('userAddRate', 'N/A')}")
        print(f"  Taker rate: {fees.get('userCrossRate', 'N/A')}")

    # 6. Sub-accounts check
    subs = post_info({"type": "subAccounts", "user": addr})
    if subs:
        print(f"\n--- Sub-accounts ---")
        if isinstance(subs, list) and len(subs) > 0:
            print(f"  Has {len(subs)} sub-accounts (may hide losses)")
            for s in subs[:3]:
                print(f"    {s}")
        else:
            print(f"  No sub-accounts (clean)")

    # 7. Historical orders for TP/SL patterns
    hist_orders = post_info({"type": "historicalOrders", "user": addr})
    if hist_orders and isinstance(hist_orders, list):
        print(f"\n--- Historical Orders ---")
        print(f"  Total: {len(hist_orders)}")
        order_types = defaultdict(int)
        for o in hist_orders:
            order = o.get("order", {})
            otype = order.get("orderType", "unknown")
            order_types[otype] += 1
        for ot, count in sorted(order_types.items(), key=lambda x: x[1], reverse=True):
            print(f"    {ot}: {count}")

    print(f"\n{'='*100}\n")
    time.sleep(0.5)
