"""
Phase 3b: Wide scan of full leaderboard for ETH/BTC-focused elite traders.
Pre-filter by profitability, then deep audit for ETH/BTC focus + win rate.
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

# Reload full leaderboard
print("Loading leaderboard...")
r = requests.get("https://stats-data.hyperliquid.xyz/Mainnet/leaderboard", timeout=60)
lb = r.json()
rows = lb.get("leaderboardRows", [])
print(f"Total: {len(rows)} traders\n")

# Pre-filter: profitable all-time AND this month, reasonable account size
# Broader filter than before to catch ETH/BTC specialists
prefiltered = []
for row in rows:
    addr = row.get("ethAddress", "")
    acct_val = float(row.get("accountValue", "0"))
    perfs = {w[0]: w[1] for w in row.get("windowPerformances", [])}

    alltime = perfs.get("allTime", {})
    month = perfs.get("month", {})
    week = perfs.get("week", {})

    alltime_pnl = float(alltime.get("pnl", "0"))
    alltime_roi = float(alltime.get("roi", "0"))
    month_pnl = float(month.get("pnl", "0"))
    month_roi = float(month.get("roi", "0"))
    week_pnl = float(week.get("pnl", "0"))
    month_vlm = float(month.get("vlm", "0"))

    # Broader pre-filter
    if (alltime_pnl > 100_000 and       # >$100K all-time
        month_pnl > 0 and               # Profitable this month
        week_pnl >= 0 and               # Not bleeding this week
        acct_val > 20_000 and           # Min $20K
        acct_val < 10_000_000 and       # Copyable
        month_vlm > 1_000_000):         # Active volume this month

        prefiltered.append({
            "address": addr,
            "account_value": acct_val,
            "alltime_pnl": alltime_pnl,
            "alltime_roi": alltime_roi,
            "month_pnl": month_pnl,
            "month_roi": month_roi,
            "week_pnl": week_pnl,
            "month_vlm": month_vlm,
        })

print(f"Pre-filtered: {len(prefiltered)} candidates\n")

# Sort by month ROI (recent consistency)
prefiltered.sort(key=lambda x: x["month_roi"], reverse=True)

# Deep audit top 60 by monthly performance
now_ms = int(time.time() * 1000)
thirty_days_ago = now_ms - (30 * 24 * 60 * 60 * 1000)

elite_results = []

print(f"Deep auditing top {min(60, len(prefiltered))} candidates for ETH/BTC focus...\n")

for i, c in enumerate(prefiltered[:60]):
    addr = c["address"]
    print(f"[{i+1}/60] {addr[:12]}...", end=" ", flush=True)

    fills = post_info({
        "type": "userFillsByTime",
        "user": addr,
        "startTime": thirty_days_ago,
        "aggregateByTime": True
    })

    if not fills or not isinstance(fills, list) or len(fills) < 10:
        print(f"skipped (fills={len(fills) if fills and isinstance(fills, list) else 0})")
        time.sleep(0.2)
        continue

    # Analyze: separate opening vs closing fills
    # closedPnl != 0 means it's a closing fill
    coin_stats = defaultdict(lambda: {
        "total_fills": 0, "closing_fills": 0,
        "wins": 0, "losses": 0, "breakeven": 0,
        "total_pnl": 0.0, "volume": 0.0,
        "win_pnl": 0.0, "loss_pnl": 0.0,
        "avg_size": []
    })

    for fill in fills:
        coin = fill.get("coin", "")
        pnl = float(fill.get("closedPnl", "0"))
        sz = float(fill.get("sz", "0"))
        px = float(fill.get("px", "0"))
        volume = sz * px

        coin_stats[coin]["total_fills"] += 1
        coin_stats[coin]["volume"] += volume
        coin_stats[coin]["avg_size"].append(volume)

        if pnl != 0:  # Only count closing fills for win rate
            coin_stats[coin]["closing_fills"] += 1
            coin_stats[coin]["total_pnl"] += pnl
            if pnl > 0:
                coin_stats[coin]["wins"] += 1
                coin_stats[coin]["win_pnl"] += pnl
            else:
                coin_stats[coin]["losses"] += 1
                coin_stats[coin]["loss_pnl"] += pnl

    # ETH/BTC analysis
    eth = coin_stats.get("ETH", {"closing_fills": 0, "wins": 0, "losses": 0, "total_pnl": 0, "volume": 0, "total_fills": 0})
    btc = coin_stats.get("BTC", {"closing_fills": 0, "wins": 0, "losses": 0, "total_pnl": 0, "volume": 0, "total_fills": 0})

    eth_btc_closing = eth["closing_fills"] + btc["closing_fills"]
    eth_btc_wins = eth["wins"] + btc["wins"]
    eth_btc_losses = eth["losses"] + btc["losses"]
    eth_btc_pnl = eth["total_pnl"] + btc["total_pnl"]
    eth_btc_volume = eth["volume"] + btc["volume"]
    eth_btc_fills = eth["total_fills"] + btc["total_fills"]

    total_volume = sum(s["volume"] for s in coin_stats.values())
    total_closing = sum(s["closing_fills"] for s in coin_stats.values())
    total_wins = sum(s["wins"] for s in coin_stats.values())

    eth_btc_vol_pct = (eth_btc_volume / total_volume * 100) if total_volume > 0 else 0
    eth_btc_wr = (eth_btc_wins / eth_btc_closing * 100) if eth_btc_closing > 0 else 0
    overall_wr = (total_wins / total_closing * 100) if total_closing > 0 else 0

    # Calculate profit factor (win PnL / abs(loss PnL))
    total_win_pnl = sum(s["win_pnl"] for s in coin_stats.values())
    total_loss_pnl = abs(sum(s["loss_pnl"] for s in coin_stats.values()))
    profit_factor = (total_win_pnl / total_loss_pnl) if total_loss_pnl > 0 else float('inf')

    # ETH/BTC profit factor
    eb_win = eth.get("win_pnl", 0) + btc.get("win_pnl", 0)
    eb_loss = abs(eth.get("loss_pnl", 0) + btc.get("loss_pnl", 0))
    eb_pf = (eb_win / eb_loss) if eb_loss > 0 else float('inf')

    tag = ""
    if eth_btc_vol_pct > 30 and eth_btc_wr > 55 and eth_btc_pnl > 0 and eth_btc_closing >= 10:
        tag = " *** ELITE ETH/BTC ***"
        elite_results.append({
            "address": addr,
            "account_value": c["account_value"],
            "alltime_pnl": c["alltime_pnl"],
            "alltime_roi": c["alltime_roi"],
            "month_pnl": c["month_pnl"],
            "month_roi": c["month_roi"],
            "overall_wr": overall_wr,
            "eth_btc_wr": eth_btc_wr,
            "eth_btc_pnl_30d": eth_btc_pnl,
            "eth_btc_vol_pct": eth_btc_vol_pct,
            "eth_btc_closing_fills": eth_btc_closing,
            "profit_factor": profit_factor,
            "eth_btc_pf": eb_pf,
            "total_fills_30d": len(fills),
            "total_closing_30d": total_closing,
            "coins_traded": len(coin_stats),
            "eth_stats": dict(eth) if "ETH" in coin_stats else None,
            "btc_stats": dict(btc) if "BTC" in coin_stats else None,
            "total_pnl_30d": sum(s["total_pnl"] for s in coin_stats.values()),
            "total_volume_30d": total_volume,
        })

    print(f"close={total_closing:>4} WR={overall_wr:>5.1f}% EB%={eth_btc_vol_pct:>5.1f}% "
          f"EB_WR={eth_btc_wr:>5.1f}% PnL30d=${sum(s['total_pnl'] for s in coin_stats.values()):>10,.0f} "
          f"PF={profit_factor:>5.2f}{tag}")

    time.sleep(0.3)

# Final ranking
print(f"\n\n{'='*100}")
print(f"ELITE ETH/BTC TRADERS FOUND: {len(elite_results)}")
print(f"{'='*100}\n")

elite_results.sort(key=lambda x: x["eth_btc_wr"] * x["eth_btc_pf"] * (1 if x["eth_btc_pnl_30d"] > 0 else 0), reverse=True)

for i, e in enumerate(elite_results):
    print(f"\n--- #{i+1} ---")
    print(f"Address:      {e['address']}")
    print(f"Account:      ${e['account_value']:,.0f}")
    print(f"All-time PnL: ${e['alltime_pnl']:,.0f} (ROI: {e['alltime_roi']:.1%})")
    print(f"30d PnL:      ${e['total_pnl_30d']:,.0f}")
    print(f"Overall WR:   {e['overall_wr']:.1f}% ({e['total_closing_30d']} closing fills)")
    print(f"ETH/BTC WR:   {e['eth_btc_wr']:.1f}% ({e['eth_btc_closing_fills']} fills)")
    print(f"ETH/BTC PnL:  ${e['eth_btc_pnl_30d']:,.0f}")
    print(f"ETH/BTC Vol:  {e['eth_btc_vol_pct']:.1f}% of total")
    print(f"Profit Factor: {e['profit_factor']:.2f} (ETH/BTC: {e['eth_btc_pf']:.2f})")
    print(f"Coins traded: {e['coins_traded']}")

    if e["eth_stats"]:
        s = e["eth_stats"]
        wr = (s["wins"]/(s["wins"]+s["losses"])*100) if (s["wins"]+s["losses"]) > 0 else 0
        print(f"  ETH: {s['closing_fills']} closes, WR={wr:.1f}%, PnL=${s['total_pnl']:,.0f}")
    if e["btc_stats"]:
        s = e["btc_stats"]
        wr = (s["wins"]/(s["wins"]+s["losses"])*100) if (s["wins"]+s["losses"]) > 0 else 0
        print(f"  BTC: {s['closing_fills']} closes, WR={wr:.1f}%, PnL=${s['total_pnl']:,.0f}")

with open("elite_eth_btc.json", "w") as f:
    json.dump(elite_results, f, indent=2, default=str)

print(f"\n\nResults saved to elite_eth_btc.json")
