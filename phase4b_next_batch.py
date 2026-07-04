"""
Phase 4b: Forensic audit of next batch.
Focus on: active accounts, consistent ETH/BTC traders, no hidden losses.
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

# Next batch to audit (from elite_eth_btc.json)
CANDIDATES = [
    ("0x42b9594f12bddd170416e94c42e4cb5e42965f39", "69.4% WR, 89.8% ETH/BTC, $95K PnL"),
    ("0x368fa5b858e4c8f94c5c8dd8fa73a12a4e1dd70c", "62.3% WR, 92.5% ETH/BTC, $164K PnL"),  # Fixed addr from earlier data
    ("0x341892ca9af16ff90c91bb4a119655dfffb0e5d3", "96% WR, 100% ETH/BTC, $421K PnL"),
    ("0xb981a0c739dddb86a40c576aa1fd75f491184e0e", "100% WR ETH/BTC, $157K PnL, PF=27.8"),
    ("0x997ec678fb354904f57a8240866ad72b2988374c", "93.3% BTC WR, $117K PnL"),
    ("0x3a122449de235a40481689442271c0731b805d69", "100% WR, BTC-only, $1.2M acct"),
]

now_ms = int(time.time() * 1000)
ninety_days_ago = now_ms - (90 * 24 * 60 * 60 * 1000)

results = []

for addr, desc in CANDIDATES:
    print(f"\n{'='*90}")
    print(f"AUDIT: {addr}")
    print(f"DESC:  {desc}")
    print(f"{'='*90}")

    # Current state
    state = post_info({"type": "clearinghouseState", "user": addr})
    margin = state.get("marginSummary", {}) if state else {}
    acct_val = float(margin.get("accountValue", 0))
    positions = state.get("assetPositions", []) if state else []

    print(f"\n  Account Value: ${acct_val:,.2f}")
    print(f"  Open Positions: {len(positions)}")
    for p in positions:
        pos = p.get("position", {})
        print(f"    {pos.get('coin','')}: size={pos.get('szi','')}, entry={pos.get('entryPx','')}, "
              f"lev={pos.get('leverage',{})}, uPnL=${float(pos.get('unrealizedPnl',0)):,.0f}")

    if acct_val == 0:
        print("  *** INACTIVE - SKIPPING ***")
        time.sleep(0.2)
        continue

    time.sleep(0.2)

    # Ledger
    ledger = post_info({"type": "userNonFundingLedgerUpdates", "user": addr, "startTime": ninety_days_ago})
    deposits = sum(float(e.get("delta",{}).get("usdc",0)) for e in (ledger or []) if e.get("delta",{}).get("type") == "deposit")
    withdrawals = sum(float(e.get("delta",{}).get("usdc",0)) for e in (ledger or []) if e.get("delta",{}).get("type") == "withdraw")
    liquidations = sum(1 for e in (ledger or []) if e.get("delta",{}).get("type") == "liquidation")

    print(f"\n  Deposits (90d): ${deposits:,.0f}")
    print(f"  Withdrawals (90d): ${withdrawals:,.0f}")
    print(f"  Liquidations: {liquidations}")

    time.sleep(0.2)

    # Fills analysis
    fills = post_info({"type": "userFillsByTime", "user": addr, "startTime": ninety_days_ago, "aggregateByTime": True})

    if not fills or not isinstance(fills, list):
        print("  No fills data")
        continue

    print(f"\n  Total fills (90d): {len(fills)}")

    # Weekly + coin breakdown
    weekly = defaultdict(lambda: {"trades": 0, "closing": 0, "wins": 0, "pnl": 0.0, "vol": 0.0})
    coin_stats = defaultdict(lambda: {"fills": 0, "closing": 0, "wins": 0, "losses": 0, "pnl": 0.0, "vol": 0.0, "win_pnl": 0.0, "loss_pnl": 0.0})

    for fill in fills:
        ts = fill.get("time", 0)
        wk = datetime.fromtimestamp(ts/1000).strftime("%Y-W%U")
        coin = fill.get("coin", "")
        pnl = float(fill.get("closedPnl", "0"))
        sz = float(fill.get("sz", "0"))
        px = float(fill.get("px", "0"))
        vol = sz * px

        weekly[wk]["trades"] += 1
        weekly[wk]["vol"] += vol
        coin_stats[coin]["fills"] += 1
        coin_stats[coin]["vol"] += vol

        if pnl != 0:
            weekly[wk]["closing"] += 1
            weekly[wk]["pnl"] += pnl
            coin_stats[coin]["closing"] += 1
            coin_stats[coin]["pnl"] += pnl
            if pnl > 0:
                weekly[wk]["wins"] += 1
                coin_stats[coin]["wins"] += 1
                coin_stats[coin]["win_pnl"] += pnl
            else:
                coin_stats[coin]["losses"] += 1
                coin_stats[coin]["loss_pnl"] += pnl

    print(f"\n  Weekly PnL:")
    print(f"  {'Week':<12} {'Trds':>5} {'Close':>6} {'Wins':>5} {'WR':>7} {'PnL':>14}")
    print(f"  {'-'*55}")
    losing_weeks = 0
    total_weeks = 0
    for wk in sorted(weekly.keys()):
        w = weekly[wk]
        wr = (w["wins"]/w["closing"]*100) if w["closing"] > 0 else 0
        marker = " <<<" if w["pnl"] < 0 else ""
        print(f"  {wk:<12} {w['trades']:>5} {w['closing']:>6} {w['wins']:>5} {wr:>6.1f}% ${w['pnl']:>12,.0f}{marker}")
        total_weeks += 1
        if w["pnl"] < 0:
            losing_weeks += 1

    print(f"\n  Coin Breakdown:")
    print(f"  {'Coin':<8} {'Close':>6} {'Wins':>5} {'Loss':>5} {'WR':>7} {'PnL':>14} {'PF':>8}")
    print(f"  {'-'*60}")
    for coin, s in sorted(coin_stats.items(), key=lambda x: x[1]["vol"], reverse=True):
        if s["closing"] > 0:
            wr = s["wins"]/s["closing"]*100
            pf = (s["win_pnl"]/abs(s["loss_pnl"])) if s["loss_pnl"] != 0 else float('inf')
            marker = " ***" if coin in ("ETH", "BTC") else ""
            print(f"  {coin:<8} {s['closing']:>6} {s['wins']:>5} {s['losses']:>5} {wr:>6.1f}% ${s['pnl']:>12,.0f} {pf:>7.2f}{marker}")

    # Sub-accounts
    subs = post_info({"type": "subAccounts", "user": addr})
    has_subs = isinstance(subs, list) and len(subs) > 0
    print(f"\n  Sub-accounts: {'YES - may hide losses' if has_subs else 'None (clean)'}")

    # Summary score
    total_closing = sum(s["closing"] for s in coin_stats.values())
    total_wins = sum(s["wins"] for s in coin_stats.values())
    total_pnl = sum(s["pnl"] for s in coin_stats.values())
    overall_wr = (total_wins/total_closing*100) if total_closing > 0 else 0

    eth_btc_closing = coin_stats.get("ETH",{}).get("closing",0) + coin_stats.get("BTC",{}).get("closing",0)
    eth_btc_wins = coin_stats.get("ETH",{}).get("wins",0) + coin_stats.get("BTC",{}).get("wins",0)
    eth_btc_pnl = coin_stats.get("ETH",{}).get("pnl",0) + coin_stats.get("BTC",{}).get("pnl",0)
    eth_btc_wr = (eth_btc_wins/eth_btc_closing*100) if eth_btc_closing > 0 else 0

    results.append({
        "address": addr,
        "account_value": acct_val,
        "active": acct_val > 0,
        "has_positions": len(positions) > 0,
        "deposits_90d": deposits,
        "withdrawals_90d": withdrawals,
        "liquidations": liquidations,
        "total_fills_90d": len(fills),
        "total_closing_90d": total_closing,
        "overall_wr": overall_wr,
        "total_pnl_90d": total_pnl,
        "eth_btc_closing": eth_btc_closing,
        "eth_btc_wr": eth_btc_wr,
        "eth_btc_pnl": eth_btc_pnl,
        "losing_weeks": losing_weeks,
        "total_weeks": total_weeks,
        "has_subaccounts": has_subs,
        "coins_traded": len(coin_stats),
    })

    print(f"\n  SUMMARY: Active={'YES' if acct_val > 0 else 'NO'}, WR={overall_wr:.1f}%, "
          f"ETH/BTC WR={eth_btc_wr:.1f}%, PnL=${total_pnl:,.0f}, "
          f"Losing weeks={losing_weeks}/{total_weeks}")

    time.sleep(0.3)

# Final comparison
print(f"\n\n{'='*90}")
print("FINAL COMPARISON OF ACTIVE CANDIDATES")
print(f"{'='*90}\n")
active = [r for r in results if r["active"]]
for r in active:
    score = r["eth_btc_wr"] * (1 if r["eth_btc_pnl"] > 0 else 0) * (1 - r["losing_weeks"]/max(r["total_weeks"],1))
    print(f"{r['address'][:14]}... AcctVal=${r['account_value']:>10,.0f} | "
          f"WR={r['overall_wr']:>5.1f}% | EB_WR={r['eth_btc_wr']:>5.1f}% | "
          f"PnL=${r['total_pnl_90d']:>10,.0f} | EB_PnL=${r['eth_btc_pnl']:>10,.0f} | "
          f"BadWks={r['losing_weeks']}/{r['total_weeks']} | Score={score:.0f}")

with open("final_candidates.json", "w") as f:
    json.dump(results, f, indent=2, default=str)
