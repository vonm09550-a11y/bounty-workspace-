#!/usr/bin/env python3
"""Forward collector on Bitquery realtime (retention < 1 day): discover new launches by tracked creators, pull every
trade of each launch's first 30 minutes, store in the anatomy trade-cache format. Read-only, no trading.

    python3 scripts/bitquery_collect.py [--hours 13] [--creators data/anatomy/tracked_creators.json]
Outputs: data/anatomy/live/<mint>.bq.jsonl (raw rows), data/anatomy/live/index.jsonl (one line per launch),
         data/anatomy/live/trades.parquet (cache in anatomy_cross format, rebuilt each run), live/collect.log
Points: each request costs ~5 points on the developer plan; the run logs the request count.
"""
import argparse
import datetime
import json
import os
import sys
import time
import urllib.error
import urllib.request

import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from clients import load_env  # noqa: E402

LIVE = os.path.join(HERE, "..", "data", "anatomy", "live")
os.makedirs(LIVE, exist_ok=True)
LOG = os.path.join(LIVE, "collect.log")
URL = "https://streaming.bitquery.io/graphql"
SOL_MINTS = {"So11111111111111111111111111111111111111112", "11111111111111111111111111111111"}
FIELDS = "Block{Time Slot} Transaction{Signature Signer FeePayer Fee Index} Trade{Index Account{Address Owner} Amount Price PriceInUSD Currency{MintAddress Symbol Name} Side{Type Amount Currency{MintAddress Symbol}} Dex{ProtocolName ProgramAddress} Market{MarketAddress}}"
Q_DISCOVER = """query($owners:[String!],$since:DateTime!){ Solana(dataset: realtime){ DEXTradeByTokens(
  where:{Trade:{Account:{Owner:{in:$owners}} Dex:{ProtocolName:{in:["pump","raydium_launchpad","pump_amm"]}} Side:{Type:{is:buy}}} Block:{Time:{since:$since}} Transaction:{Result:{Success:true}}}
  orderBy:[{ascending:Block_Time}] limit:{count:25000}){ %s } } }""" % FIELDS
Q_TRADES = """query($mint:String!,$since:DateTime!,$before:DateTime!,$offset:Int!){ Solana(dataset: realtime){ DEXTradeByTokens(
  where:{Trade:{Currency:{MintAddress:{is:$mint}}} Block:{Time:{since:$since, before:$before}} Transaction:{Result:{Success:true}}}
  orderBy:[{ascending:Block_Time},{ascending:Transaction_Index},{ascending:Trade_Index}] limit:{count:25000, offset:$offset}){ %s } } }""" % FIELDS
REQS = 0


def log(msg):
    line = f"{datetime.datetime.utcnow().isoformat(timespec='seconds')} {msg}"
    print(line, flush=True)
    with open(LOG, "a") as f:
        f.write(line + "\n")


def gql(query, variables, tok):
    global REQS
    req = urllib.request.Request(URL, data=json.dumps({"query": query, "variables": variables}).encode(),
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + tok, "User-Agent": "notdecu-research/0.1"})
    for i in range(3):
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                REQS += 1
                d = json.loads(r.read().decode())
            if "errors" in d:
                raise RuntimeError(json.dumps(d["errors"])[:300])
            return d["data"]["Solana"]["DEXTradeByTokens"]
        except urllib.error.HTTPError as e:
            body = e.read().decode()[:300]
            if e.code == 429:
                time.sleep(20 * (i + 1)); continue
            raise RuntimeError(f"HTTP {e.code}: {body}")
        except (urllib.error.URLError, OSError):
            time.sleep(5 * (i + 1))
    raise RuntimeError("bitquery: retries exhausted")


def iso(ts):
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%dT%H:%M:%SZ")


def ts_of(s):
    return int(datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc).timestamp())


def coin_creator(mint):
    """pump.fun coins-v2: verified creator + create time (ms). None if not a pump.fun coin or unreachable."""
    try:
        req = urllib.request.Request(f"https://frontend-api-v3.pump.fun/coins-v2/{mint}", headers={"User-Agent": "notdecu-research/0.1"})
        with urllib.request.urlopen(req, timeout=20) as r:
            d = json.loads(r.read().decode())
        return d.get("creator"), int((d.get("created_timestamp") or 0) / 1000) or None
    except Exception:  # noqa: BLE001
        return None, None


def to_cache_rows(rows, dev, creator, mint, symbol, cts):
    out = []
    for r in rows:
        tr, tx, bl = r["Trade"], r["Transaction"], r["Block"]
        side = tr["Side"]["Type"]
        quote = float(tr["Side"]["Amount"] or 0)
        qm = tr["Side"]["Currency"]["MintAddress"]
        out.append({"dev": dev, "token": mint, "symbol": symbol, "sig": tx["Signature"], "slot": int(bl["Slot"]), "ts": ts_of(bl["Time"]), "s": ts_of(bl["Time"]) - cts,
                    "wallet": tr["Account"]["Owner"] or tr["Account"]["Address"], "side": side, "tokens": float(tr["Amount"] or 0), "quote": quote,
                    "sol": quote if qm in SOL_MINTS else None, "quote_mint": qm, "fee_payer": tx["FeePayer"], "fee": int(round(float(tx["Fee"] or 0) * 1e9)),
                    "protocol": tr["Dex"]["ProtocolName"], "price": float(tr["Price"] or 0), "hit": None})
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--hours", type=float, default=13)
    ap.add_argument("--creators", default=os.path.join(HERE, "..", "data", "anatomy", "tracked_creators.json"))
    a = ap.parse_args()
    tok = load_env()["BITQUERY_TOKEN"]
    creators = json.load(open(a.creators))          # address -> {"name":..., "src":...}
    idx_p = os.path.join(LIVE, "index.jsonl")
    have = {json.loads(l)["token"] for l in open(idx_p)} if os.path.exists(idx_p) else set()
    since = time.time() - a.hours * 3600
    log(f"=== collect: {len(creators)} creators, since {iso(int(since))} ===")
    disc = gql(Q_DISCOVER, {"owners": list(creators), "since": iso(int(since))}, tok)
    first = {}
    for r in disc:
        m = r["Trade"]["Currency"]["MintAddress"]
        t = ts_of(r["Block"]["Time"])
        if m not in first or t < first[m]["t"]:
            first[m] = {"t": t, "creator": r["Trade"]["Account"]["Owner"], "symbol": r["Trade"]["Currency"]["Symbol"], "protocol": r["Trade"]["Dex"]["ProtocolName"]}
    cand = {m: v for m, v in first.items() if m not in have and v["protocol"] in ("pump", "raydium_launchpad")}
    new = {}
    for m, v in cand.items():
        cr, ct = coin_creator(m)
        if cr in creators:
            v["creator"] = cr
            if ct:
                v["t"] = ct
            new[m] = v
        else:
            with open(os.path.join(LIVE, "member_buys_not_launches.jsonl"), "a") as fo:
                fo.write(json.dumps({"token": m, "symbol": v["symbol"], "buyer": creators.get(v["creator"], {}).get("name"), "first_buy_ts": v["t"], "coin_creator": cr}) + "\n")
        time.sleep(0.2)
    log(f"  discovery: {len(disc)} tracked-wallet buys, {len(first)} mints, {len(cand)} candidates, {len(new)} verified launches by tracked creators")
    with open(idx_p, "a") as fi:
        for m, v in sorted(new.items(), key=lambda kv: kv[1]["t"]):
            cts = v["t"]
            if time.time() - cts < 1800:
                log(f"  {v['symbol']} too young ({int(time.time() - cts)} s), next run"); continue
            rows, off = [], 0
            while True:
                batch = gql(Q_TRADES, {"mint": m, "since": iso(cts - 60), "before": iso(cts + 1800), "offset": off}, tok)
                rows += batch
                if len(batch) < 25000:
                    break
                off += 25000
            with open(os.path.join(LIVE, f"{m}.bq.jsonl"), "w") as f:
                for r in rows:
                    f.write(json.dumps(r, separators=(",", ":")) + "\n")
            dev = creators[v["creator"]]["name"]
            fi.write(json.dumps({"token": m, "symbol": v["symbol"], "dev": dev, "creator": v["creator"], "create_ts": cts, "protocol": v["protocol"], "n_rows": len(rows), "collected_at": int(time.time())}) + "\n"); fi.flush()
            log(f"  {dev:12} {v['symbol']:10} {m[:8]} created {iso(cts)} rows {len(rows)}")
            time.sleep(1.0)
    # rebuild the cache
    idx = [json.loads(l) for l in open(idx_p)] if os.path.exists(idx_p) else []
    cache = []
    for e in idx:
        p = os.path.join(LIVE, f"{e['token']}.bq.jsonl")
        if os.path.exists(p):
            cache += to_cache_rows([json.loads(l) for l in open(p)], e["dev"], e["creator"], e["token"], e["symbol"], e["create_ts"])
    if cache:
        pd.DataFrame(cache).to_parquet(os.path.join(LIVE, "trades.parquet"), index=False)
    log(f"=== done: {REQS} requests, index {len(idx)} launches, cache {len(cache)} trades ===")
