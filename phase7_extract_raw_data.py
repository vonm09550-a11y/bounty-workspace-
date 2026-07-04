"""
Phase 7: Extract ALL raw onchain data from the elite trader.
Wallet: 0x2d99fe0f36c1aebd28a1a2c0e82e8ca13c2ea351
"""
import requests
import json
import time
from datetime import datetime

BASE = "https://api.hyperliquid.xyz"
ELITE = "0x2d99fe0f36c1aebd28a1a2c0e82e8ca13c2ea351"

def post_info(payload):
    for attempt in range(3):
        try:
            r = requests.post(f"{BASE}/info", json=payload, timeout=30)
            return r.json()
        except:
            time.sleep(1)
    return None

print(f"Extracting ALL raw data for {ELITE}")
print(f"{'='*80}\n")

now_ms = int(time.time() * 1000)
all_data = {}

# 1. Current state
print("[1/8] Current state...")
all_data["current_state"] = post_info({"type": "clearinghouseState", "user": ELITE})
time.sleep(0.2)

# 2. Portfolio
print("[2/8] Portfolio performance...")
all_data["portfolio"] = post_info({"type": "portfolio", "user": ELITE})
time.sleep(0.2)

# 3. Fees
print("[3/8] Fee information...")
all_data["fees"] = post_info({"type": "userFees", "user": ELITE})
time.sleep(0.2)

# 4. Historical orders
print("[4/8] Historical orders...")
all_data["historical_orders"] = post_info({"type": "historicalOrders", "user": ELITE})
time.sleep(0.2)

# 5. Open orders
print("[5/8] Open orders...")
all_data["open_orders"] = post_info({"type": "frontendOpenOrders", "user": ELITE})
time.sleep(0.2)

# 6. All fills - extract in chunks to get as much as possible
print("[6/8] Extracting fills in time windows...")
all_fills = []
# Start from 12 months ago, extract in 30-day chunks
start = now_ms - (365 * 24 * 60 * 60 * 1000)

chunk_start = start
chunk_size = 30 * 24 * 60 * 60 * 1000  # 30 days

while chunk_start < now_ms:
    chunk_end = min(chunk_start + chunk_size, now_ms)
    fills = post_info({
        "type": "userFillsByTime",
        "user": ELITE,
        "startTime": chunk_start,
        "endTime": chunk_end,
        "aggregateByTime": True
    })
    if fills and isinstance(fills, list):
        all_fills.extend(fills)
        if len(fills) > 0:
            start_dt = datetime.fromtimestamp(chunk_start/1000).strftime("%Y-%m-%d")
            end_dt = datetime.fromtimestamp(chunk_end/1000).strftime("%Y-%m-%d")
            print(f"  {start_dt} to {end_dt}: {len(fills)} fills")
    chunk_start = chunk_end
    time.sleep(0.3)

# Deduplicate by hash
seen = set()
unique_fills = []
for f in all_fills:
    h = f.get("hash", "") + str(f.get("time", ""))
    if h not in seen:
        seen.add(h)
        unique_fills.append(f)

all_data["fills"] = unique_fills
print(f"  Total unique fills: {len(unique_fills)}")
time.sleep(0.2)

# 7. Non-funding ledger (full history)
print("[7/8] Ledger updates...")
ledger = post_info({
    "type": "userNonFundingLedgerUpdates",
    "user": ELITE,
    "startTime": start
})
all_data["ledger"] = ledger
print(f"  Ledger entries: {len(ledger) if ledger else 0}")
time.sleep(0.2)

# 8. Funding history
print("[8/8] Funding history...")
funding = post_info({
    "type": "userFunding",
    "user": ELITE,
    "startTime": now_ms - (90 * 24 * 60 * 60 * 1000)
})
all_data["funding"] = funding
print(f"  Funding entries: {len(funding) if funding else 0}")

# Save raw data
with open("elite_raw_data.json", "w") as f:
    json.dump(all_data, f, indent=2, default=str)

print(f"\nRaw data saved to elite_raw_data.json")
print(f"Total fills extracted: {len(unique_fills)}")

# Quick summary of BTC fills specifically
btc_fills = [f for f in unique_fills if f.get("coin") == "BTC"]
print(f"\nBTC fills: {len(btc_fills)}")

# Separate BTC fills into trades (group by direction changes)
btc_closing = [f for f in btc_fills if float(f.get("closedPnl", "0")) != 0]
btc_opening = [f for f in btc_fills if float(f.get("closedPnl", "0")) == 0]

print(f"BTC opening fills: {len(btc_opening)}")
print(f"BTC closing fills: {len(btc_closing)}")

# Detailed BTC trade log
print(f"\n{'='*120}")
print("COMPLETE BTC TRADE LOG")
print(f"{'='*120}")
print(f"{'Date':<20} {'Dir':<15} {'Side':<6} {'Price':>12} {'Size':>10} {'Notional':>14} {'PnL':>12} {'StartPos':>10}")
print(f"{'-'*120}")

btc_fills.sort(key=lambda x: x.get("time", 0))
for f in btc_fills:
    ts = datetime.fromtimestamp(f.get("time", 0)/1000).strftime("%Y-%m-%d %H:%M")
    direction = f.get("dir", "")
    side = f.get("side", "")
    px = float(f.get("px", "0"))
    sz = float(f.get("sz", "0"))
    pnl = float(f.get("closedPnl", "0"))
    start_pos = float(f.get("startPosition", "0"))
    notional = sz * px
    pnl_mark = f"${pnl:>10,.2f}" if pnl != 0 else f"{'':>12}"
    print(f"{ts:<20} {direction:<15} {side:<6} ${px:>10,.2f} {sz:>9.5f} ${notional:>12,.2f} {pnl_mark} {start_pos:>9.5f}")

# Save BTC-specific data
btc_data = {
    "all_btc_fills": btc_fills,
    "btc_closing": btc_closing,
    "btc_opening": btc_opening,
}
with open("elite_btc_fills.json", "w") as f:
    json.dump(btc_data, f, indent=2, default=str)

print(f"\nBTC fill data saved to elite_btc_fills.json")
