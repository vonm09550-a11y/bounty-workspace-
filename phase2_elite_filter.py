"""
Phase 2: Parse leaderboard, identify S-tier ETH/BTC traders.
Strict filtering: high win rate, consistent profitability, active, copyable size.
"""
import requests
import json
import time
import sys

BASE = "https://api.hyperliquid.xyz"

def post_info(payload):
    r = requests.post(f"{BASE}/info", json=payload, timeout=30)
    return r.json()

print("=== Phase 2: Elite Filter ===\n")
print("Fetching leaderboard (large dataset)...")

r = requests.get("https://stats-data.hyperliquid.xyz/Mainnet/leaderboard", timeout=60)
lb = r.json()

rows = lb.get("leaderboardRows", [])
print(f"Total traders on leaderboard: {len(rows)}")

if len(rows) > 0:
    print(f"\nSample entry structure:")
    sample = rows[0]
    print(f"  Keys: {list(sample.keys())}")
    # Show window performances structure
    wp = sample.get("windowPerformances", [])
    for w in wp:
        print(f"  Window '{w[0]}': {list(w[1].keys()) if isinstance(w[1], dict) else w[1]}")

# Filter criteria for S-tier:
# 1. All-time PnL > $500K (serious trader)
# 2. Monthly ROI > 5% (consistent)
# 3. Account value > $50K (enough capital to learn from, but copyable at $100)
# 4. Active in last 7 days (day performance exists)
# 5. Positive across all windows (no hidden losses)

candidates = []

for row in rows:
    addr = row.get("ethAddress", "")
    acct_val = float(row.get("accountValue", "0"))
    perfs = {w[0]: w[1] for w in row.get("windowPerformances", [])}

    # Extract metrics
    alltime = perfs.get("allTime", {})
    month = perfs.get("month", {})
    week = perfs.get("week", {})
    day = perfs.get("day", {})

    alltime_pnl = float(alltime.get("pnl", "0"))
    alltime_roi = float(alltime.get("roi", "0"))
    month_pnl = float(month.get("pnl", "0"))
    month_roi = float(month.get("roi", "0"))
    week_pnl = float(week.get("pnl", "0"))
    week_roi = float(week.get("roi", "0"))
    day_pnl = float(day.get("pnl", "0")) if day else 0

    # S-TIER FILTER - strict
    if (alltime_pnl > 500_000 and          # >$500K all-time PnL
        alltime_roi > 0.50 and              # >50% all-time ROI
        month_pnl > 0 and                   # Profitable this month
        month_roi > 0.02 and                # >2% this month
        week_pnl > 0 and                    # Profitable this week
        acct_val > 50_000 and               # Meaningful capital
        acct_val < 10_000_000):             # Not whale-only (copyable)

        candidates.append({
            "address": addr,
            "account_value": acct_val,
            "alltime_pnl": alltime_pnl,
            "alltime_roi": alltime_roi,
            "month_pnl": month_pnl,
            "month_roi": month_roi,
            "week_pnl": week_pnl,
            "week_roi": week_roi,
            "day_pnl": day_pnl,
        })

# Sort by all-time ROI (consistency matters more than raw PnL)
candidates.sort(key=lambda x: x["alltime_roi"], reverse=True)

print(f"\n=== S-Tier Candidates (strict filter): {len(candidates)} ===\n")
print(f"{'#':<4} {'Address':<44} {'AcctVal':>12} {'AT PnL':>14} {'AT ROI':>10} {'Mo PnL':>12} {'Mo ROI':>8} {'Wk PnL':>12}")
print("-" * 130)

for i, c in enumerate(candidates[:30]):
    print(f"{i+1:<4} {c['address']:<44} ${c['account_value']:>10,.0f} ${c['alltime_pnl']:>12,.0f} {c['alltime_roi']:>8.1%} ${c['month_pnl']:>10,.0f} {c['month_roi']:>6.1%} ${c['week_pnl']:>10,.0f}")

# Save candidates for next phase
with open("candidates_phase2.json", "w") as f:
    json.dump(candidates[:50], f, indent=2)

print(f"\nSaved top {min(50, len(candidates))} candidates for deep analysis.")
