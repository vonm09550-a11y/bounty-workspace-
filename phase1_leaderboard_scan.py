"""
Phase 1: Leaderboard Scan & Initial Filter
Queries Hyperliquid API for top traders, filters for ETH/BTC specialists.
"""
import requests
import json
import time

BASE = "https://api.hyperliquid.xyz"

def post_info(payload):
    r = requests.post(f"{BASE}/info", json=payload, timeout=30)
    return r.json()

# Step 1: Get leaderboard data via the explorer API
def get_leaderboard():
    """Fetch top traders from Hyperliquid leaderboard endpoint."""
    url = "https://stats-data.hyperliquid.xyz/Mainnet/leaderboard"
    try:
        r = requests.post(url, json={}, timeout=30)
        return r.json()
    except:
        pass

    # Alternative: try the info endpoint for clearinghouse data
    # We'll also try scraping known leaderboard paths
    endpoints = [
        {"type": "leaderboard", "timeWindow": "allTime"},
        {"type": "leaderboard", "timeWindow": "month"},
    ]
    for ep in endpoints:
        try:
            r = requests.post(f"{BASE}/info", json=ep, timeout=15)
            if r.status_code == 200:
                return r.json()
        except:
            continue
    return None

def get_user_portfolio(address):
    """Get comprehensive portfolio data."""
    return post_info({"type": "portfolio", "user": address})

def get_user_state(address):
    """Get current positions and margin."""
    return post_info({"type": "clearinghouseState", "user": address})

def get_user_fills(address):
    """Get recent fills."""
    return post_info({"type": "userFills", "user": address})

def get_user_fills_by_time(address, start_ms, end_ms=None):
    """Get fills in a time range."""
    payload = {"type": "userFillsByTime", "user": address, "startTime": start_ms}
    if end_ms:
        payload["endTime"] = end_ms
    return post_info(payload)

def get_user_fees(address):
    """Get fee/volume info."""
    return post_info({"type": "userFees", "user": address})

print("=== Phase 1: Leaderboard Scan ===\n")

# Try leaderboard
lb = get_leaderboard()
print(f"Leaderboard response type: {type(lb)}")
if lb:
    if isinstance(lb, list):
        print(f"Got {len(lb)} entries")
        if len(lb) > 0:
            print(f"Sample entry keys: {lb[0].keys() if isinstance(lb[0], dict) else type(lb[0])}")
            print(f"First entry: {json.dumps(lb[0], indent=2)[:500]}")
    elif isinstance(lb, dict):
        print(f"Keys: {lb.keys()}")
        for k, v in lb.items():
            if isinstance(v, list):
                print(f"  {k}: {len(v)} items")
                if len(v) > 0 and isinstance(v[0], dict):
                    print(f"  Sample: {json.dumps(v[0], indent=2)[:300]}")
            else:
                print(f"  {k}: {type(v)} = {str(v)[:200]}")
