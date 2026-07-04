"""
Phase 1b: Multi-source trader discovery
Uses Hyperliquid's various APIs to discover elite traders.
"""
import requests
import json
import time

BASE = "https://api.hyperliquid.xyz"

def post_info(payload):
    r = requests.post(f"{BASE}/info", json=payload, timeout=30)
    return r.json()

# 1. Try the Hyperliquid explorer/stats endpoints
endpoints_to_try = [
    ("stats leaderboard", "https://stats-data.hyperliquid.xyz/Mainnet/leaderboard"),
    ("api leaderboard", f"{BASE}/info", {"type": "leaderboard"}),
]

# 2. Check the Hyperliquid explorer API for top volume / top PnL
explorer_endpoints = [
    f"https://api.hyperliquid-testnet.xyz/info",
]

# 3. Try Hyperliquid's known public data feeds
print("=== Trying Hyperliquid API discovery endpoints ===\n")

# Try various info types
info_types = [
    "leaderboard",
    "topTraders",
    "clearinghouseLeaderboard",
    "pnlLeaderboard",
]

for t in info_types:
    try:
        r = requests.post(f"{BASE}/info", json={"type": t}, timeout=10)
        print(f"{t}: status={r.status_code}, response={str(r.text)[:200]}")
    except Exception as e:
        print(f"{t}: ERROR {e}")

print("\n=== Trying explorer endpoints ===\n")

# Hyperliquid has a stats API
explorer_urls = [
    "https://stats-data.hyperliquid.xyz/Mainnet/leaderboard",
    "https://api.hyperliquid.xyz/explorer",
]

for url in explorer_urls:
    try:
        r = requests.get(url, timeout=10)
        print(f"GET {url}: status={r.status_code}, len={len(r.text)}, preview={r.text[:300]}")
    except Exception as e:
        try:
            r = requests.post(url, json={}, timeout=10)
            print(f"POST {url}: status={r.status_code}, len={len(r.text)}, preview={r.text[:300]}")
        except Exception as e2:
            print(f"{url}: ERROR {e2}")

# Try the vault data to find top vault leaders (proxy for top traders)
print("\n=== Vaults (top performers often run vaults) ===\n")

try:
    r = requests.post(f"{BASE}/info", json={"type": "vaultSummaries"}, timeout=15)
    print(f"vaultSummaries: status={r.status_code}")
    if r.status_code == 200:
        data = r.json()
        if isinstance(data, list) and len(data) > 0:
            print(f"Got {len(data)} vaults")
            # Sort by some metric
            for v in data[:3]:
                print(json.dumps(v, indent=2)[:400])
                print("---")
except Exception as e:
    print(f"vaultSummaries error: {e}")

# Try twapHistory, etc.
print("\n=== Additional discovery ===\n")
additional_types = [
    "vaultDetails",
    "vaultSummaries",
]
for t in additional_types:
    try:
        r = requests.post(f"{BASE}/info", json={"type": t}, timeout=10)
        print(f"{t}: status={r.status_code}, preview={str(r.text)[:300]}")
    except Exception as e:
        print(f"{t}: ERROR {e}")
