"""
Phase 3: Deep audit of top candidates.
Check actual fills, positions, win rates, ETH/BTC focus.
"""
import requests
import json
import time
from collections import defaultdict

BASE = "https://api.hyperliquid.xyz"

def post_info(payload):
    for attempt in range(3):
        try:
            r = requests.post(f"{BASE}/info", json=payload, timeout=30)
            return r.json()
        except:
            time.sleep(1)
    return None

with open("candidates_phase2.json") as f:
    candidates = json.load(f)

# Deep audit top 25 candidates
print("=== Phase 3: Deep Audit - Top 25 Candidates ===\n")
print("Analyzing fills, win rates, ETH/BTC concentration...\n")

# 30-day window
now_ms = int(time.time() * 1000)
thirty_days_ago = now_ms - (30 * 24 * 60 * 60 * 1000)

audited = []

for i, c in enumerate(candidates[:25]):
    addr = c["address"]
    print(f"[{i+1}/25] Auditing {addr[:10]}...", end=" ", flush=True)

    # Get recent fills (last 30 days)
    fills = post_info({
        "type": "userFillsByTime",
        "user": addr,
        "startTime": thirty_days_ago,
        "aggregateByTime": True
    })

    if not fills or not isinstance(fills, list):
        print("NO FILLS")
        continue

    # Get current state
    state = post_info({"type": "clearinghouseState", "user": addr})

    # Analyze fills
    coin_stats = defaultdict(lambda: {
        "trades": 0, "wins": 0, "losses": 0,
        "total_pnl": 0.0, "volume": 0.0,
        "win_pnl": 0.0, "loss_pnl": 0.0
    })

    total_trades = 0
    total_wins = 0
    total_pnl = 0.0

    for fill in fills:
        coin = fill.get("coin", "")
        pnl = float(fill.get("closedPnl", "0"))
        sz = float(fill.get("sz", "0"))
        px = float(fill.get("px", "0"))
        volume = sz * px

        coin_stats[coin]["trades"] += 1
        coin_stats[coin]["volume"] += volume
        coin_stats[coin]["total_pnl"] += pnl
        total_trades += 1
        total_pnl += pnl

        if pnl > 0:
            coin_stats[coin]["wins"] += 1
            coin_stats[coin]["win_pnl"] += pnl
            total_wins += 1
        elif pnl < 0:
            coin_stats[coin]["losses"] += 1
            coin_stats[coin]["loss_pnl"] += pnl

    # Check ETH/BTC concentration
    eth_btc_trades = coin_stats.get("ETH", {}).get("trades", 0) + coin_stats.get("BTC", {}).get("trades", 0)
    eth_btc_pnl = coin_stats.get("ETH", {}).get("total_pnl", 0) + coin_stats.get("BTC", {}).get("total_pnl", 0)
    eth_btc_volume = coin_stats.get("ETH", {}).get("volume", 0) + coin_stats.get("BTC", {}).get("volume", 0)

    total_volume = sum(s["volume"] for s in coin_stats.values())
    eth_btc_pct = (eth_btc_volume / total_volume * 100) if total_volume > 0 else 0

    win_rate = (total_wins / total_trades * 100) if total_trades > 0 else 0

    # Account value and leverage info
    acct_val = c["account_value"]

    # Get current positions for leverage insight
    current_positions = []
    if state and isinstance(state, dict):
        positions = state.get("assetPositions", [])
        for p in positions:
            pos = p.get("position", {})
            if pos:
                current_positions.append({
                    "coin": pos.get("coin", ""),
                    "size": float(pos.get("szi", "0")),
                    "entry": float(pos.get("entryPx", "0") or "0"),
                    "leverage": pos.get("leverage", {}),
                    "pnl": float(pos.get("unrealizedPnl", "0")),
                })

    result = {
        "address": addr,
        "account_value": acct_val,
        "alltime_pnl": c["alltime_pnl"],
        "alltime_roi": c["alltime_roi"],
        "month_pnl": c["month_pnl"],
        "month_roi": c["month_roi"],
        "total_fills_30d": total_trades,
        "total_pnl_30d": total_pnl,
        "win_rate": win_rate,
        "eth_btc_trades": eth_btc_trades,
        "eth_btc_pnl": eth_btc_pnl,
        "eth_btc_pct": eth_btc_pct,
        "coins_traded": list(coin_stats.keys()),
        "coin_breakdown": {k: dict(v) for k, v in coin_stats.items()},
        "current_positions": current_positions,
        "total_volume_30d": total_volume,
    }

    audited.append(result)

    # Summary line
    eth_tag = "ETH" if "ETH" in coin_stats else ""
    btc_tag = "BTC" if "BTC" in coin_stats else ""
    focus = f"{eth_tag}/{btc_tag}" if eth_tag or btc_tag else "OTHER"

    print(f"fills={total_trades:>5} | WR={win_rate:>5.1f}% | PnL30d=${total_pnl:>10,.0f} | "
          f"ETH/BTC={eth_btc_pct:>5.1f}% | focus={focus} | coins={len(coin_stats)}")

    time.sleep(0.3)  # rate limit

# Now rank by our elite criteria
print("\n\n=== ELITE RANKING (ETH/BTC focused, high WR, profitable 30d) ===\n")

# Filter: must trade ETH or BTC, win rate > 55%, profitable in 30d
elite = [a for a in audited if
         a["eth_btc_pct"] > 20 and      # At least 20% ETH/BTC volume
         a["win_rate"] > 55 and          # >55% win rate
         a["total_pnl_30d"] > 0 and      # Profitable last 30 days
         a["total_fills_30d"] >= 20]      # Active (20+ fills in 30d)

elite.sort(key=lambda x: (x["win_rate"] * x["eth_btc_pct"] * x["total_pnl_30d"]), reverse=True)

print(f"{'#':<3} {'Address':<44} {'WR':>6} {'Fills':>6} {'PnL 30d':>12} {'ETH/BTC%':>9} {'AcctVal':>12} {'AT ROI':>10}")
print("-" * 110)

for i, e in enumerate(elite[:15]):
    print(f"{i+1:<3} {e['address']:<44} {e['win_rate']:>5.1f}% {e['total_fills_30d']:>5} ${e['total_pnl_30d']:>10,.0f} "
          f"{e['eth_btc_pct']:>8.1f}% ${e['account_value']:>10,.0f} {e['alltime_roi']:>8.1%}")

    # Show coin breakdown
    for coin, stats in sorted(e["coin_breakdown"].items(), key=lambda x: x[1]["volume"], reverse=True)[:3]:
        wr = (stats["wins"] / stats["trades"] * 100) if stats["trades"] > 0 else 0
        print(f"    {coin:<6} trades={stats['trades']:>4} WR={wr:>5.1f}% PnL=${stats['total_pnl']:>10,.0f}")
    print()

with open("elite_candidates.json", "w") as f:
    json.dump(elite, f, indent=2, default=str)

print(f"\nSaved {len(elite)} elite candidates for final selection.")
