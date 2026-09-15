#!/usr/bin/env python3
"""Phase 3 / D4 (offline): per-dev audit tables from the D4 pulls.

    python3 scripts/dev_audit_report.py            # prints sections; writes `dev_audit`, `dev_runs` tables + parquet

Inputs: d4_shortlist / dev_scores / dev_tokens (DuckDB), data/tokens/token_info.jsonl (launch-level),
data/devs/audit/stats.jsonl (funder, tags), data/devs/audit/score_<dev>.json (conduct/power),
data/devs/audit/kline.jsonl (run shapes). Missing inputs degrade to NULL columns, never to zeros.
"""
import glob
import json
import os

import duckdb

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
DEVS = os.path.join(DATA, "devs")
AUDIT = os.path.join(DEVS, "audit")
DB = os.path.join(DATA, "notdecu.duckdb")
con = duckdb.connect(DB)


def show(t, q):
    print(f"\n### {t}\n")
    print(con.execute(q).df().to_string(index=False))


# ---- 1. launch-level table for the shortlist (token info) -------------------------------------------
con.execute(f"""CREATE OR REPLACE TEMP VIEW ti AS
    SELECT _address token, TRY_CAST(total_supply AS DOUBLE) total_supply, TRY_CAST(creation_timestamp AS BIGINT) creation_ts,
           TRY_CAST(open_timestamp AS BIGINT) open_ts, TRY_CAST(migrated_timestamp AS BIGINT) migrated_ts,
           TRY_CAST(launchpad_status AS INT) launchpad_status, launchpad_platform, TRY_CAST(holder_count AS INT) holder_count,
           TRY_CAST(ath_price AS DOUBLE) * TRY_CAST(total_supply AS DOUBLE) ath_mc_ti, TRY_CAST(migration_market_cap AS DOUBLE) migration_mcap,
           dev.creator_token_status creator_status, TRY_CAST(dev.cto_flag AS INT) cto_flag, dev.fund_from fund_from_label,
           TRY_CAST(stat.top_bundler_trader_percentage AS DOUBLE) bundler_pct, TRY_CAST(stat.top70_sniper_hold_rate AS DOUBLE) sniper_hold_rate,
           TRY_CAST(stat.top_10_holder_rate AS DOUBLE) top10_rate, TRY_CAST(stat.creator_hold_rate AS DOUBLE) creator_hold_rate,
           TRY_CAST(wallet_tags_stat.smart_wallets AS INT) smart_wallets, TRY_CAST(wallet_tags_stat.sniper_wallets AS INT) sniper_wallets,
           link.twitter_username twitter, link.website website, TRY_CAST(image_dup_count AS INT) image_dup_count,
           pool.quote_symbol quote_symbol
    FROM read_json_auto('{os.path.join(DATA, 'tokens', 'token_info.jsonl')}', union_by_name=true, maximum_object_size=8000000)""")
con.execute("""CREATE OR REPLACE TABLE dev_launches AS
    SELECT t.creator, t.token, t.symbol, t.is_open, t.ath_mc, t.holders holders_book, t.create_ts, t.bundler_rate, t.total_fee,
           ti.* EXCLUDE (token)
    FROM dev_tokens t JOIN d4_shortlist s USING(creator) LEFT JOIN ti USING(token)""")

# ---- 2. stats (funder, tags) --------------------------------------------------------------------------
stats_p = os.path.join(AUDIT, "stats.jsonl")
if os.path.exists(stats_p) and os.path.getsize(stats_p) > 0:
    con.execute(f"""CREATE OR REPLACE TABLE dev_stats AS
        SELECT _creator creator, common.fund_from_address funder, common.fund_from funder_label, common.tags tags,
               TRY_CAST(common.created_token_count AS INT) created_token_count, TRY_CAST(common.follow_count AS INT) gmgn_followers,
               TRY_CAST(common.remark_count AS INT) gmgn_remarks, common.twitter_username dev_twitter,
               TRY_CAST(native_balance AS DOUBLE) native_balance, TRY_CAST(realized_profit AS DOUBLE) realized_profit_7d,
               TRY_CAST(buy AS INT) buys_7d, TRY_CAST(sell AS INT) sells_7d
        FROM read_json_auto('{stats_p}', union_by_name=true, maximum_object_size=8000000)""")
else:
    con.execute("CREATE OR REPLACE TABLE dev_stats AS SELECT creator, NULL::VARCHAR funder, NULL::VARCHAR funder_label, NULL::VARCHAR[] tags, NULL::INT created_token_count, NULL::INT gmgn_followers, NULL::INT gmgn_remarks, NULL::VARCHAR dev_twitter, NULL::DOUBLE native_balance, NULL::DOUBLE realized_profit_7d, NULL::INT buys_7d, NULL::INT sells_7d FROM d4_shortlist")

# ---- 3. dev_score JSON --------------------------------------------------------------------------------
rows = []
for p in glob.glob(os.path.join(AUDIT, "score_*.json")):
    try:
        j = json.load(open(p))
    except Exception:  # noqa: BLE001
        continue
    dev = os.path.basename(p)[6:-5]
    sc, dg, ht, la, cw, bu, cv, fl = (j.get(k) or {} for k in ("score", "dump_gate", "his_trades", "launches", "cross_wallet", "bundler", "coverage", "flagship"))
    rows.append({"creator": dev, "scored": bool(j.get("scored")), "not_scored_reason": j.get("reason"),
                 "score_total": sc.get("total"), "score_conduct": sc.get("conduct"), "score_power": sc.get("power"), "band": sc.get("band"),
                 "dump_tier": dg.get("tier"), "dump_rate": dg.get("dump_rate"), "dumps": dg.get("dumps"), "coins_with_trades": dg.get("coins_with_trades"),
                 "dump_forced_by": dg.get("forced_by"), "fastest_first_sell_s": ht.get("fastest_first_sell_s"), "median_first_sell_s": ht.get("median_first_sell_s"),
                 "median_pull_multiple": ht.get("median_pull_multiple"), "self_snipe_rate": ht.get("self_snipe_rate"), "dumped_coins": ht.get("dumped_coins"),
                 "graduation_rate": la.get("graduation_rate"), "survival_rate": la.get("survival_rate"), "over_1m": la.get("over_1m"), "career_days": la.get("career_days"),
                 "cross_wallet_moves": len(cw.get("moves") or []), "bundler_median": bu.get("median"),
                 "flagship_status": fl.get("status"), "flagship_symbol": fl.get("symbol"), "flagship_peak": fl.get("peak_mc_usd"),
                 "trade_history_truncated": cv.get("trade_history_truncated"), "book_truncated": cv.get("book_truncated")})
con.execute("DROP TABLE IF EXISTS dev_conduct")
if rows:
    import pandas as pd
    df = pd.DataFrame(rows)
    con.execute("CREATE TABLE dev_conduct AS SELECT * FROM df")
else:
    con.execute("CREATE TABLE dev_conduct AS SELECT creator, NULL::BOOLEAN scored, NULL::VARCHAR not_scored_reason, NULL::DOUBLE score_total, NULL::DOUBLE score_conduct, NULL::DOUBLE score_power, NULL::VARCHAR band, NULL::VARCHAR dump_tier, NULL::DOUBLE dump_rate, NULL::INT dumps, NULL::INT coins_with_trades, NULL::VARCHAR dump_forced_by, NULL::DOUBLE fastest_first_sell_s, NULL::DOUBLE median_first_sell_s, NULL::DOUBLE median_pull_multiple, NULL::DOUBLE self_snipe_rate, NULL::INT dumped_coins, NULL::DOUBLE graduation_rate, NULL::DOUBLE survival_rate, NULL::INT over_1m, NULL::DOUBLE career_days, NULL::INT cross_wallet_moves, NULL::DOUBLE bundler_median, NULL::VARCHAR flagship_status, NULL::VARCHAR flagship_symbol, NULL::DOUBLE flagship_peak, NULL::BOOLEAN trade_history_truncated, NULL::BOOLEAN book_truncated FROM d4_shortlist")

# ---- 4. run shapes from klines ------------------------------------------------------------------------
kl_p = os.path.join(AUDIT, "kline.jsonl")
runs = []
if os.path.exists(kl_p) and os.path.getsize(kl_p) > 0:
    per = {}
    for line in open(kl_p):
        j = json.loads(line)
        per.setdefault(j["token"], {"creator": j["creator"], "ath_mc": j["ath_mc"], "from": j["from"]})[j["res"]] = j["candles"]
    for token, d in per.items():
        c1, c15 = d.get("1m") or [], d.get("15m") or []
        r = {"creator": d["creator"], "token": token, "ath_mc_book": d["ath_mc"], "n_1m": len(c1), "n_15m": len(c15)}
        def f(x):
            return float(x) if x not in (None, "") else None
        if c1:
            c1 = sorted(c1, key=lambda c: c["time"])
            t0 = d["from"] * 1000
            first_open = f(c1[0]["open"])
            r["first_candle_delay_min"] = (c1[0]["time"] - t0) / 60000.0
            r["open_price"] = first_open
            highs = [(f(c["high"]), (c["time"] - t0) / 60000.0) for c in c1]
            hmax, hmin = max(highs)
            r["max_mult_100m"] = hmax / first_open if first_open else None
            r["min_to_max_100m"] = hmin
            def at(m):
                cs = [c for c in c1 if (c["time"] - t0) / 60000.0 <= m]
                return f(cs[-1]["close"]) / first_open if cs and first_open else None
            r["mult_5m"], r["mult_15m"], r["mult_30m"], r["mult_60m"] = at(5), at(15), at(30), at(60)
            r["mins_ge_2x_100m"] = sum(1 for c in c1 if first_open and f(c["close"]) >= 2 * first_open)
            r["mins_le_half_100m"] = sum(1 for c in c1 if first_open and f(c["close"]) <= 0.5 * first_open)
            r["vol_usd_100m"] = sum(f(c.get("volume")) or 0 for c in c1)
        if c15 and r.get("open_price"):
            c15 = sorted(c15, key=lambda c: c["time"])
            t0 = d["from"] * 1000
            highs = [(f(c["high"]), (c["time"] - t0) / 60000.0) for c in c15]
            hmax, hmin = max(highs)
            r["max_mult_24h"] = hmax / r["open_price"]
            r["min_to_max_24h"] = hmin
            r["close_24h_mult"] = f(c15[-1]["close"]) / r["open_price"]
            r["retrace_from_high_24h"] = 1 - f(c15[-1]["close"]) / hmax if hmax else None
            r["candles_ge_2x_24h"] = sum(1 for c in c15 if f(c["close"]) >= 2 * r["open_price"])
            r["vol_usd_24h"] = sum(f(c.get("volume")) or 0 for c in c15)
        runs.append(r)
con.execute("DROP TABLE IF EXISTS dev_runs")
if runs:
    import pandas as pd
    rf = pd.DataFrame(runs)
    con.execute("CREATE TABLE dev_runs AS SELECT r.*, l.symbol, l.total_supply, r.open_price * l.total_supply open_mcap FROM rf r LEFT JOIN dev_launches l USING(token)")
else:
    con.execute("CREATE TABLE dev_runs AS SELECT creator, token, symbol, NULL::DOUBLE open_mcap, NULL::DOUBLE max_mult_100m, NULL::DOUBLE min_to_max_100m, NULL::DOUBLE mult_5m, NULL::DOUBLE mult_15m, NULL::DOUBLE mult_30m, NULL::DOUBLE mult_60m, NULL::INT mins_ge_2x_100m, NULL::INT mins_le_half_100m, NULL::DOUBLE max_mult_24h, NULL::DOUBLE min_to_max_24h, NULL::DOUBLE close_24h_mult, NULL::DOUBLE retrace_from_high_24h, NULL::INT candles_ge_2x_24h, NULL::DOUBLE vol_usd_24h, NULL::DOUBLE first_candle_delay_min FROM dev_launches WHERE false")

# ---- 5. per-dev audit table ---------------------------------------------------------------------------
con.execute("""CREATE OR REPLACE TABLE dev_audit AS
WITH l AS (
  SELECT creator, count(*) launches_listed, sum((creation_ts IS NOT NULL)::INT) with_info,
         sum((migrated_ts > 0)::INT) migrated, sum((creator_status = 'creator_hold')::INT) creator_still_holds,
         sum((creator_status LIKE '%sell%')::INT) creator_sold, sum((creator_status = 'creator_close')::INT) creator_closed,
         sum((cto_flag = 1)::INT) cto, median(bundler_pct) med_bundler_pct, median(sniper_hold_rate) med_sniper_hold,
         median(top10_rate) med_top10, median(CASE WHEN ath_mc >= 1e5 THEN holder_count END) med_holders_hits_now,
         sum((coalesce(twitter,'') <> '')::INT) with_twitter, sum((image_dup_count > 1)::INT) image_dup,
         mode(quote_symbol) quote_sym, mode(launchpad_platform) platform,
         median(CASE WHEN migrated_ts > 0 AND creation_ts > 0 THEN (migrated_ts - creation_ts) / 60.0 END) med_min_to_migrate,
         sum((create_ts >= extract(epoch FROM now()) - 7 * 86400)::INT) launches_7d,
         sum((create_ts >= extract(epoch FROM now()) - 30 * 86400)::INT) launches_30d
  FROM dev_launches GROUP BY 1),
g AS (
  SELECT creator, median(gap_h) med_gap_h FROM (
    SELECT creator, (create_ts - lag(create_ts) OVER (PARTITION BY creator ORDER BY create_ts)) / 3600.0 gap_h
    FROM dev_launches WHERE create_ts > 0) WHERE gap_h IS NOT NULL GROUP BY 1),
r AS (
  SELECT creator, count(*) runs, median(open_mcap) med_open_mcap, median(max_mult_100m) med_max_mult_100m, median(min_to_max_100m) med_min_to_max_100m,
         median(mult_15m) med_mult_15m, median(mult_60m) med_mult_60m, median(max_mult_24h) med_max_mult_24h, median(min_to_max_24h) med_min_to_max_24h,
         median(close_24h_mult) med_close_24h_mult, median(retrace_from_high_24h) med_retrace_24h,
         round(100.0 * sum((min_to_max_24h > 60)::INT) / count(*), 0) pct_peak_after_1h,
         round(100.0 * sum((close_24h_mult >= 2)::INT) / count(*), 0) pct_still_2x_at_24h,
         round(100.0 * sum((mins_le_half_100m > 0)::INT) / count(*), 0) pct_halved_in_100m,
         median(first_candle_delay_min) med_first_candle_delay_min
  FROM dev_runs GROUP BY 1)
SELECT s.creator, s.lists, s.best_rank, d.launches, d.opens, d.hits_100k, d.hits_1m, d.best_ath, d.best_symbol, d.hit_rate_100k_pct, d.days_since_launch,
       l.* EXCLUDE (creator), g.med_gap_h, st.* EXCLUDE (creator), c.* EXCLUDE (creator), r.* EXCLUDE (creator)
FROM d4_shortlist s JOIN dev_scores d USING(creator) LEFT JOIN l USING(creator) LEFT JOIN g USING(creator)
LEFT JOIN dev_stats st USING(creator) LEFT JOIN dev_conduct c USING(creator) LEFT JOIN r USING(creator)
ORDER BY s.best_rank, s.lists""")
for t in ("dev_launches", "dev_runs", "dev_audit"):
    con.execute(f"COPY {t} TO '{os.path.join(DEVS, t + '.parquet')}' (FORMAT PARQUET)")

show("coverage", "SELECT count(*) devs, sum(with_info) launches_with_info, sum(launches_listed) launches_listed, sum((funder IS NOT NULL)::INT) with_stats, sum(scored::INT) scored, sum(runs) runs FROM dev_audit")
show("A. launch hygiene per dev (token info, as of today)", "SELECT creator[1:8] dev, best_symbol, launches_listed n, migrated, creator_still_holds holds, creator_sold sold, creator_closed closed, cto, med_bundler_pct bund, med_sniper_hold snip, med_top10 top10, med_holders_hits_now holders, with_twitter tw, image_dup dup, quote_sym, platform, round(med_min_to_migrate) min_to_mig, launches_7d l7, launches_30d l30, round(med_gap_h,1) gap_h FROM dev_audit ORDER BY best_rank, lists")
show("B. funder / identity (portfolio stats)", "SELECT creator[1:8] dev, best_symbol, funder[1:10] funder, funder_label, tags, created_token_count ct_count, gmgn_followers followers, dev_twitter, round(native_balance,1) sol, round(realized_profit_7d) pnl_7d, buys_7d, sells_7d FROM dev_audit ORDER BY best_rank, lists")
show("B2. shared funders inside the shortlist", "SELECT funder, count(*) devs, string_agg(best_symbol, ', ') symbols FROM dev_audit WHERE funder IS NOT NULL AND funder <> '' GROUP BY 1 HAVING count(*) > 1")
show("C. conduct (gmgn-dev-score)", "SELECT creator[1:8] dev, best_symbol, scored, not_scored_reason reason, score_total total, score_conduct conduct, score_power power, band, dump_tier, round(dump_rate,2) dump_rate, dumps, coins_with_trades cwt, round(fastest_first_sell_s) fastest_sell_s, round(median_first_sell_s) med_sell_s, round(median_pull_multiple,2) pull_x, round(self_snipe_rate,2) self_snipe, cross_wallet_moves xw, round(bundler_median,3) bund, flagship_status FROM dev_audit ORDER BY best_rank, lists")
show("D. run shapes (klines on hit tokens)", "SELECT creator[1:8] dev, best_symbol, runs, round(med_open_mcap) open_mcap, round(med_first_candle_delay_min,1) delay_m, round(med_mult_15m,2) x15m, round(med_mult_60m,2) x60m, round(med_max_mult_100m,2) max100m, round(med_min_to_max_100m) t_max100m, round(med_max_mult_24h,2) max24h, round(med_min_to_max_24h) t_max24h, round(med_close_24h_mult,2) close24h, round(med_retrace_24h,2) retrace, pct_peak_after_1h late_pk, pct_still_2x_at_24h still2x, pct_halved_in_100m halved FROM dev_audit ORDER BY best_rank, lists")
con.close()
