"""
Phase 5: Deep scan of broader candidate pool.
Looking for active ETH/BTC specialists with 8+ weeks of consistent history.
Scanning candidates 25-150 from pre-filtered list.
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

# Reload leaderboard and pre-filter
print("Loading leaderboard...")
r = requests.get("https://stats-data.hyperliquid.xyz/Mainnet/leaderboard", timeout=60)
rows = r.json().get("leaderboardRows", [])

prefiltered = []
for row in rows:
    addr = row.get("ethAddress", "")
    acct_val = float(row.get("accountValue", "0"))
    perfs = {w[0]: w[1] for w in row.get("windowPerformances", [])}
    alltime = perfs.get("allTime", {})
    month = perfs.get("month", {})
    week = perfs.get("week", {})

    alltime_pnl = float(alltime.get("pnl", "0"))
    month_pnl = float(month.get("pnl", "0"))
    week_pnl = float(week.get("pnl", "0"))
    month_vlm = float(month.get("vlm", "0"))
    alltime_roi = float(alltime.get("roi", "0"))

    if (alltime_pnl > 50_000 and
        month_pnl > 0 and
        acct_val > 10_000 and
        acct_val < 10_000_000 and
        month_vlm > 500_000):
        prefiltered.append({
            "address": addr, "account_value": acct_val,
            "alltime_pnl": alltime_pnl, "alltime_roi": alltime_roi,
            "month_pnl": month_pnl, "month_vlm": month_vlm,
        })

prefiltered.sort(key=lambda x: x["alltime_pnl"], reverse=True)
print(f"Pre-filtered: {len(prefiltered)} candidates")

now_ms = int(time.time() * 1000)
ninety_days_ago = now_ms - (90 * 24 * 60 * 60 * 1000)

# Quick first pass: check account state + recent fills coin distribution
# Only deep-audit if they're active and trade ETH/BTC
elite = []
checked = 0
batch_start = 0
batch_size = 200

print(f"\nQuick-scanning candidates {batch_start}-{batch_start+batch_size}...\n")

for i, c in enumerate(prefiltered[batch_start:batch_start+batch_size]):
    addr = c["address"]
    checked += 1

    # Quick check: is account active?
    state = post_info({"type": "clearinghouseState", "user": addr})
    if not state:
        continue
    margin = state.get("marginSummary", {})
    acct_val = float(margin.get("accountValue", 0))
    if acct_val < 10_000:
        time.sleep(0.15)
        continue

    # Quick fills check
    fills = post_info({"type": "userFillsByTime", "user": addr, "startTime": ninety_days_ago, "aggregateByTime": True})
    if not fills or not isinstance(fills, list) or len(fills) < 50:
        time.sleep(0.15)
        continue

    # Fast analysis
    coin_vol = defaultdict(float)
    coin_closing = defaultdict(int)
    coin_wins = defaultdict(int)
    coin_pnl = defaultdict(float)
    coin_win_pnl = defaultdict(float)
    coin_loss_pnl = defaultdict(float)
    weekly_pnl = defaultdict(float)

    for fill in fills:
        coin = fill.get("coin", "")
        pnl = float(fill.get("closedPnl", "0"))
        sz = float(fill.get("sz", "0"))
        px = float(fill.get("px", "0"))
        vol = sz * px
        coin_vol[coin] += vol
        wk = datetime.fromtimestamp(fill.get("time", 0)/1000).strftime("%Y-W%U")

        if pnl != 0:
            coin_closing[coin] += 1
            coin_pnl[coin] += pnl
            weekly_pnl[wk] += pnl
            if pnl > 0:
                coin_wins[coin] += 1
                coin_win_pnl[coin] += pnl
            else:
                coin_loss_pnl[coin] += pnl

    total_vol = sum(coin_vol.values())
    eth_btc_vol = coin_vol.get("ETH", 0) + coin_vol.get("BTC", 0)
    eth_btc_pct = (eth_btc_vol / total_vol * 100) if total_vol > 0 else 0

    # Must have significant ETH/BTC presence
    if eth_btc_pct < 30:
        time.sleep(0.15)
        continue

    eth_closing = coin_closing.get("ETH", 0) + coin_closing.get("BTC", 0)
    eth_wins = coin_wins.get("ETH", 0) + coin_wins.get("BTC", 0)
    eth_pnl = coin_pnl.get("ETH", 0) + coin_pnl.get("BTC", 0)
    eth_wr = (eth_wins / eth_closing * 100) if eth_closing > 0 else 0

    # Must have positive ETH/BTC PnL and reasonable WR
    if eth_pnl <= 0 or eth_wr < 55 or eth_closing < 15:
        time.sleep(0.15)
        continue

    # Check weekly consistency
    weeks = sorted(weekly_pnl.keys())
    losing_wks = sum(1 for w in weeks if weekly_pnl[w] < 0)
    total_wks = len(weeks)

    total_closing = sum(coin_closing.values())
    total_wins = sum(coin_wins.values())
    overall_wr = (total_wins / total_closing * 100) if total_closing > 0 else 0
    total_pnl = sum(coin_pnl.values())

    # Profit factor
    total_wp = sum(coin_win_pnl.values())
    total_lp = abs(sum(coin_loss_pnl.values()))
    pf = (total_wp / total_lp) if total_lp > 0 else float('inf')

    eb_wp = coin_win_pnl.get("ETH", 0) + coin_win_pnl.get("BTC", 0)
    eb_lp = abs(coin_loss_pnl.get("ETH", 0) + coin_loss_pnl.get("BTC", 0))
    eb_pf = (eb_wp / eb_lp) if eb_lp > 0 else float('inf')

    # Positions
    positions = state.get("assetPositions", [])
    pos_coins = [p.get("position", {}).get("coin", "") for p in positions]

    # Score: WR * consistency * profit_factor * ETH_BTC_focus
    consistency = max(0, 1 - losing_wks / max(total_wks, 1))
    score = eth_wr * consistency * min(eb_pf, 50) * (eth_btc_pct / 100)

    entry = {
        "address": addr,
        "account_value": acct_val,
        "alltime_pnl": c["alltime_pnl"],
        "total_fills_90d": len(fills),
        "total_closing_90d": total_closing,
        "overall_wr": overall_wr,
        "total_pnl_90d": total_pnl,
        "profit_factor": pf,
        "eth_btc_closing": eth_closing,
        "eth_btc_wr": eth_wr,
        "eth_btc_pnl": eth_pnl,
        "eth_btc_pf": eb_pf,
        "eth_btc_vol_pct": eth_btc_pct,
        "losing_weeks": losing_wks,
        "total_weeks": total_wks,
        "weekly_pnl": dict(weekly_pnl),
        "open_positions": pos_coins,
        "score": score,
        "eth_detail": {"closing": coin_closing.get("ETH",0), "wins": coin_wins.get("ETH",0), "pnl": coin_pnl.get("ETH",0)},
        "btc_detail": {"closing": coin_closing.get("BTC",0), "wins": coin_wins.get("BTC",0), "pnl": coin_pnl.get("BTC",0)},
    }

    elite.append(entry)
    print(f"[{checked}] {addr[:14]}... AcctVal=${acct_val:>8,.0f} | EB_WR={eth_wr:>5.1f}% ({eth_closing} fills) | "
          f"PnL=${total_pnl:>10,.0f} | EB_PnL=${eth_pnl:>10,.0f} | EB%={eth_btc_pct:>5.1f}% | "
          f"PF={pf:.1f} | Wks={total_wks} bad={losing_wks} | Score={score:.0f}")

    time.sleep(0.25)

print(f"\n\nScanned {checked} candidates, found {len(elite)} elite ETH/BTC traders")

# Rank by composite score
elite.sort(key=lambda x: x["score"], reverse=True)

print(f"\n{'='*100}")
print("TOP ELITE ETH/BTC TRADERS - RANKED BY COMPOSITE SCORE")
print(f"{'='*100}\n")

for i, e in enumerate(elite[:10]):
    print(f"\n{'='*80}")
    print(f"RANK #{i+1} | Score: {e['score']:.0f}")
    print(f"{'='*80}")
    print(f"Address:        {e['address']}")
    print(f"Account Value:  ${e['account_value']:,.0f}")
    print(f"All-time PnL:   ${e['alltime_pnl']:,.0f}")
    print(f"90d PnL:        ${e['total_pnl_90d']:,.0f}")
    print(f"Overall WR:     {e['overall_wr']:.1f}% ({e['total_closing_90d']} closes)")
    print(f"ETH/BTC WR:     {e['eth_btc_wr']:.1f}% ({e['eth_btc_closing']} closes)")
    print(f"ETH/BTC PnL:    ${e['eth_btc_pnl']:,.0f}")
    print(f"ETH/BTC Vol %:  {e['eth_btc_vol_pct']:.1f}%")
    print(f"Profit Factor:  {e['profit_factor']:.2f} (ETH/BTC: {e['eth_btc_pf']:.2f})")
    print(f"Weeks Active:   {e['total_weeks']} (losing: {e['losing_weeks']})")
    print(f"Open Positions: {e['open_positions']}")
    print(f"  ETH: {e['eth_detail']['closing']} closes, {e['eth_detail']['wins']} wins, PnL=${e['eth_detail']['pnl']:,.0f}")
    print(f"  BTC: {e['btc_detail']['closing']} closes, {e['btc_detail']['wins']} wins, PnL=${e['btc_detail']['pnl']:,.0f}")

    print(f"  Weekly PnL:")
    for wk in sorted(e["weekly_pnl"].keys()):
        marker = " <<<" if e["weekly_pnl"][wk] < 0 else ""
        print(f"    {wk}: ${e['weekly_pnl'][wk]:>12,.0f}{marker}")

with open("top_elite_deep.json", "w") as f:
    json.dump(elite[:10], f, indent=2, default=str)
