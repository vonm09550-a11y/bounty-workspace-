#!/usr/bin/env python3
"""Phase 3 / D5a (offline): expectancy per dev per entry style from klines on hits AND non-hits, plus
full-walk conduct where available. Narrows the D4 top-10 to 5.

    python3 scripts/dev_deep_report.py

Styles (all with 1.25% curve fee + 1.0% slippage per side, 4.5% round trip):
  S  scalp:      enter close of minute 1; exit first close >= 1.8x entry, or first close <= 0.6x, or minute-15 close
  B  build:      enter close of minute 5; hard stop close <= 0.5x; once running high >= 1.5x, exit on close <= 0.6x running high; else 24h close
  B2 build-late: same as B but enter close of minute 15 (after the dev's exit has printed for every dev in the list)
A launch with no candle in its entry window is `skipped` (no fill possible) and excluded from the average,
but counted. EV per launch = p_hit * mean(hits) + (1 - p_hit) * mean(non-hits), p_hit from the book.
"""
import glob
import json
import os

import duckdb
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
DEVS = os.path.join(DATA, "devs")
AUDIT = os.path.join(DEVS, "audit")
DB = os.path.join(DATA, "notdecu.duckdb")
FEE = 0.0125 + 0.01
TOP10 = {"9VXuNqqqzniYYW3fRDeaCtUUtqWsEeWWn5umh3aF9h17": "CANCER", "EgJoaEBSZA3wjgpPq8am9YjkxJPLa2LpXwxaQyUzB2XY": "GrokBot",
         "5YRgrP3mjGzrzirYYN5HAQH19cTYREYwGxW6XRJQUzij": "TOAD", "BFmgjdgepMxNnEyndQZC68Db3ajPdD3V8is1bQbdj4h4": "biketyson",
         "G4krkerMkeYw7ffTUgdf7qXEXnuMGHpWUESBQpYqvtwU": "BABYTROLL", "GeBJSHK4WsGrz2HRvTbqvWGx4JRMpHfJG2ikzrYBDuwR": "SAPIJIJU",
         "FAX4qRQdiSj2iWDYvkJ21VieVCXGREtwMhEyAHSJ1aqp": "PETAH", "4LTJU2qfJdmDuEQAmWXcf5hvkpomYrLebuTBz2svwRd4": "LAYOFF",
         "CzwWvTVn39dSd4LiVc6W9gZxgu36737M2fcX4EWhquh4": "1B", "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe": "ANSEM"}


def f(x):
    return float(x) if x not in (None, "") else None


def series(c1, c15, t0):
    """Merged (minute, close) path: 1m closes for the first 100 min, then 15m closes to 24 h."""
    pts = [((c["time"] - t0) / 60000.0, f(c["close"])) for c in sorted(c1, key=lambda c: c["time"])]
    last = pts[-1][0] if pts else -1
    pts += [((c["time"] - t0) / 60000.0 + 15, f(c["close"])) for c in sorted(c15, key=lambda c: c["time"]) if (c["time"] - t0) / 60000.0 + 15 > last]
    return [(m, p) for m, p in pts if p]


def entry_at(pts, minute):
    cands = [(m, p) for m, p in pts if m <= minute]
    return cands[-1][1] if cands else None


def style_S(pts):
    e = entry_at(pts, 1)
    if e is None:
        return None
    for m, p in pts:
        if m <= 1:
            continue
        if m > 15:
            break
        if p >= 1.8 * e:
            return (p / e) * (1 - FEE) ** 2 - 1
        if p <= 0.6 * e:
            return (p / e) * (1 - FEE) ** 2 - 1
    last = entry_at(pts, 15) or e
    return (last / e) * (1 - FEE) ** 2 - 1


def style_B(pts, entry_min):
    e = entry_at(pts, entry_min)
    if e is None:
        return None
    hi = e
    for m, p in pts:
        if m <= entry_min:
            continue
        hi = max(hi, p)
        if p <= 0.5 * e:
            return (p / e) * (1 - FEE) ** 2 - 1
        if hi >= 1.5 * e and p <= 0.6 * hi:
            return (p / e) * (1 - FEE) ** 2 - 1
    last = pts[-1][1]
    return (last / e) * (1 - FEE) ** 2 - 1


rows = []
per = {}
for line in open(os.path.join(AUDIT, "kline.jsonl")):
    j = json.loads(line)
    if j["creator"] not in TOP10:
        continue
    d = per.setdefault(j["token"], {"creator": j["creator"], "ath_mc": j["ath_mc"], "from": j["from"]})
    d[j["res"]] = j["candles"]
for token, d in per.items():
    pts = series(d.get("1m") or [], d.get("15m") or [], d["from"] * 1000)
    hit = d["ath_mc"] is not None and 1e5 <= d["ath_mc"] < 5e9
    rows.append({"creator": d["creator"], "dev": TOP10[d["creator"]], "token": token, "hit": hit, "n_pts": len(pts),
                 "first_min": pts[0][0] if pts else None, "S": style_S(pts), "B": style_B(pts, 5), "B2": style_B(pts, 15)})
df = pd.DataFrame(rows)
con = duckdb.connect(DB)
con.execute("DROP TABLE IF EXISTS dev_sim")
con.execute("CREATE TABLE dev_sim AS SELECT * FROM df")
con.execute(f"COPY dev_sim TO '{os.path.join(DEVS, 'dev_sim.parquet')}' (FORMAT PARQUET)")


def show(t, q):
    print(f"\n### {t}\n")
    print(con.execute(q).df().to_string(index=False))


show("sample per dev", "SELECT dev, sum(hit::INT) hits, sum((NOT hit)::INT) nonhits, sum((n_pts=0)::INT) no_candles, sum((S IS NULL)::INT) s_skipped, sum((B IS NULL)::INT) b_skipped FROM dev_sim GROUP BY 1 ORDER BY 1")
show("per-style returns by outcome (mean / median / win%), per dev", """SELECT dev, hit, count(*) n,
 round(100*avg(S)) S_mean, round(100*median(S)) S_med, round(100*avg((S>0)::INT)) S_win,
 round(100*avg(B)) B_mean, round(100*median(B)) B_med, round(100*avg((B>0)::INT)) B_win,
 round(100*avg(B2)) B2_mean, round(100*median(B2)) B2_med, round(100*avg((B2>0)::INT)) B2_win
 FROM dev_sim GROUP BY 1,2 ORDER BY 1,2""")
con.execute("""CREATE OR REPLACE TABLE dev_ev AS
WITH p AS (SELECT creator, hits_100k * 1.0 / launches p_hit, launches, hits_100k, listed_last_30d, hits_100k_last_30d, days_since_launch FROM dev_scores),
h AS (SELECT dev, creator, avg(S) S_h, avg(B) B_h, avg(B2) B2_h, avg(least(S,5)) S_hc, avg(least(B,5)) B_hc, avg(least(B2,5)) B2_hc, count(*) n_h FROM dev_sim WHERE hit GROUP BY 1,2),
n AS (SELECT dev, creator, avg(S) S_n, avg(B) B_n, avg(B2) B2_n, count(*) n_n, avg((n_pts=0)::INT) dead_share FROM dev_sim WHERE NOT hit GROUP BY 1,2)
SELECT h.dev, round(p.p_hit,3) p_hit, p.launches, n_h, n_n, round(n.dead_share,2) dead_share,
       round(100*(p.p_hit*S_h + (1-p.p_hit)*S_n),1) EV_S_pct, round(100*(p.p_hit*B_h + (1-p.p_hit)*B_n),1) EV_B_pct, round(100*(p.p_hit*B2_h + (1-p.p_hit)*B2_n),1) EV_B2_pct,
       round(100*(p.p_hit*S_hc + (1-p.p_hit)*S_n),1) EVc_S, round(100*(p.p_hit*B_hc + (1-p.p_hit)*B_n),1) EVc_B, round(100*(p.p_hit*B2_hc + (1-p.p_hit)*B2_n),1) EVc_B2,
       round(100*S_h) S_hit, round(100*S_n) S_non, round(100*B_h) B_hit, round(100*B_n) B_non, round(100*B2_h) B2_hit, round(100*B2_n) B2_non,
       p.listed_last_30d l30, p.hits_100k_last_30d h30, p.days_since_launch dsl
FROM h JOIN n USING(dev, creator) JOIN p USING(creator) ORDER BY greatest(EV_S_pct, EV_B_pct, EV_B2_pct) DESC""")
con.execute(f"COPY dev_ev TO '{os.path.join(DEVS, 'dev_ev.parquet')}' (FORMAT PARQUET)")
show("EXPECTANCY per launch (%), weighted by the dev's book hit rate (EVc_* = single-launch return capped at +500%)", "SELECT dev, p_hit, launches, n_h, n_n, EV_S_pct, EV_B_pct, EV_B2_pct, EVc_S, EVc_B, EVc_B2, S_hit, S_non, B_hit, B_non, B2_hit, B2_non, l30, h30, dsl FROM dev_ev")

# full-walk conduct where available
fw = []
for pth in glob.glob(os.path.join(AUDIT, "score_full_*.json")):
    j = json.load(open(pth)); dev = os.path.basename(pth)[11:-5]
    sc, dg, ht, cv = (j.get(k) if isinstance(j.get(k), dict) else {} for k in ("score", "dump_gate", "his_trades", "coverage"))
    fw.append({"dev": TOP10.get(dev, dev[:8]), "total": sc.get("total"), "conduct": sc.get("conduct"), "power": sc.get("power"), "band": sc.get("band"),
               "dump_tier": dg.get("tier"), "dump_rate": dg.get("dump_rate"), "coins_with_trades": dg.get("coins_with_trades"),
               "fastest_sell_s": ht.get("fastest_first_sell_s"), "median_sell_s": ht.get("median_first_sell_s"), "pull_x": ht.get("median_pull_multiple"),
               "pages": cv.get("pages_walked"), "truncated": cv.get("trade_history_truncated")})
if fw:
    print("\n### full-walk conduct (max_pages 120)\n")
    print(pd.DataFrame(fw).to_string(index=False))
con.close()
