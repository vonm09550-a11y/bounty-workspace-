#!/usr/bin/env python3
"""Environment check for the notdecu wallet research.

Verifies every credential and endpoint phase 2 depends on, without pulling data.
Reads keys from ~/.config/gmgn/.env (GMGN_API_KEY, HELIUS_API_KEY). Never prints keys.

    python3 research/notdecu-wallet/scripts/env_check.py
"""
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error

WALLET = "4vw54BmAogeRV3vPKWyFet5yf8DTLcREzdSzx4rw9Ud9"
PUMP_PROGRAM = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P"
PUMPSWAP_PROGRAM = "pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA"
WSOL = "So11111111111111111111111111111111111111112"


def load_env():
    path = os.path.expanduser("~/.config/gmgn/.env")
    env = {}
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"')
    env.update({k: v for k, v in os.environ.items() if k in ("GMGN_API_KEY", "HELIUS_API_KEY")})
    return env


def http(url, method="GET", body=None, timeout=30):
    # Cloudflare-fronted hosts (api.helius.xyz, dexscreener, jup.ag) return 403 to the default
    # "Python-urllib" User-Agent; any ordinary UA passes.
    req = urllib.request.Request(url, method=method,
                                 headers={"content-type": "application/json", "User-Agent": "notdecu-research/0.1"},
                                 data=json.dumps(body).encode() if body is not None else None)
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.status, json.loads(r.read().decode()), time.time() - t0


results = []


def check(name, fn):
    try:
        detail = fn()
        results.append((name, "OK", detail))
    except Exception as e:  # noqa: BLE001
        results.append((name, "FAIL", f"{type(e).__name__}: {str(e)[:160]}"))


env = load_env()
GK, HK = env.get("GMGN_API_KEY"), env.get("HELIUS_API_KEY")


def gmgn_cli():
    r = subprocess.run(["gmgn-cli", "config", "--check"], capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError(r.stderr or r.stdout)
    v = subprocess.run(["gmgn-cli", "--version"], capture_output=True, text=True).stdout.strip()
    return f"gmgn-cli {v}, key configured"


def gmgn_stats():
    r = subprocess.run(["gmgn-cli", "portfolio", "stats", "--chain", "sol", "--wallet", WALLET, "--raw"],
                       capture_output=True, text=True, timeout=45)
    if r.returncode != 0:
        raise RuntimeError(r.stderr[:200])
    d = json.loads(r.stdout)
    d = d.get("data", d)
    return f"7d buys {d['buy']} sells {d['sell']} tags {d.get('common', {}).get('tags')}"


def gmgn_holdings():
    r = subprocess.run(["gmgn-cli", "portfolio", "holdings", "--chain", "sol", "--wallet", WALLET, "--limit", "1", "--raw"],
                       capture_output=True, text=True, timeout=45)
    if r.returncode != 0:
        raise RuntimeError("needs GMGN_PRIVATE_KEY (expected while the PEM is unavailable)")
    return "critical auth works"


def helius_rpc():
    if not HK:
        raise RuntimeError("HELIUS_API_KEY missing")
    st, d, dt = http(f"https://mainnet.helius-rpc.com/?api-key={HK}", "POST",
                     {"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [WALLET]})
    return f"balance {d['result']['value'] / 1e9:.3f} SOL in {dt:.2f}s"


def helius_parse():
    st, d, dt = http(f"https://api.helius.xyz/v0/transactions?api-key={HK}", "POST",
                     {"transactions": ["2gHaoU8wk1qyxFDnjvRF5AXA1URnNqLGLvAZK1PgdbzE1aKguUfmidrG7Lqrf8LB9DUdDZsEdDyandsm5cN9H2Xz"]})
    t = d[0]
    return f"{t['type']}/{t['source']} feePayer==wallet {t['feePayer'] == WALLET} in {dt:.2f}s"


def helius_token_accounts():
    st, d, dt = http(f"https://mainnet.helius-rpc.com/?api-key={HK}", "POST",
                     {"jsonrpc": "2.0", "id": 1, "method": "getTokenAccountsByOwner",
                      "params": [WALLET, {"programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"}, {"encoding": "jsonParsed"}]})
    return f"{len(d['result']['value'])} token accounts in {dt:.2f}s"


def dexscreener():
    st, d, dt = http("https://api.dexscreener.com/latest/dex/tokens/" + WSOL)
    return f"{len(d.get('pairs') or [])} pairs for WSOL in {dt:.2f}s"


def jupiter():
    st, d, dt = http(f"https://lite-api.jup.ag/price/v3?ids={WSOL}")
    return f"SOL ${d[WSOL]['usdPrice']:.2f} in {dt:.2f}s"


def idls():
    here = os.path.dirname(os.path.abspath(__file__))
    ref = os.path.join(here, "..", "refs", "idl")
    pump = json.load(open(os.path.join(ref, "pump.json")))
    amm = json.load(open(os.path.join(ref, "pump_amm.json")))
    assert pump["address"] == PUMP_PROGRAM and amm["address"] == PUMPSWAP_PROGRAM
    return f"pump {len(pump['instructions'])} ix, pump_amm {len(amm['instructions'])} ix, addresses match"


def pylibs():
    import duckdb, pandas, websockets  # noqa: F401
    return f"duckdb {duckdb.__version__} pandas {pandas.__version__} websockets {websockets.__version__}"


for name, fn in [("python libs", pylibs), ("gmgn-cli config", gmgn_cli), ("gmgn portfolio stats", gmgn_stats),
                 ("gmgn portfolio holdings (needs PEM)", gmgn_holdings), ("helius rpc", helius_rpc),
                 ("helius parseTransactions", helius_parse), ("helius token accounts", helius_token_accounts),
                 ("dexscreener", dexscreener), ("jupiter lite price", jupiter), ("pump.fun IDLs", idls)]:
    check(name, fn)

width = max(len(n) for n, _, _ in results)
bad = 0
for n, s, d in results:
    print(f"{s:4}  {n:{width}}  {d}")
    bad += s == "FAIL" and "PEM" not in n
sys.exit(1 if bad else 0)
