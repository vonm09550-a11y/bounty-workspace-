#!/usr/bin/env python3
"""Mini-phase 2.3 (offline): reconstruct positions and profile the system from the DuckDB index.

Builds table `positions` (one row per token) and prints the tables used in 04-system-profile.md.
Cost basis is rebuilt from buy legs (average-cost and FIFO); GMGN's per-leg buy_cost_usd is
only a cross-check. All money in USD from GMGN's cost_usd on each leg.

    python3 scripts/profile.py [--section all|positions|reconcile|cadence|sizing|exits|entry|monthly]
"""
import argparse
import json
import os

import duckdb

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
DB = os.path.join(DATA, "notdecu.duckdb")
W = "4vw54BmAogeRV3vPKWyFet5yf8DTLcREzdSzx4rw9Ud9"
COMPANION = "4hQZ1GtLTvAzetszCcWrb8zxiuVvEt85Bb7y6VNzA2ve"


def show(con, title, sql, index=False):
    print(f"\n### {title}\n")
    df = con.execute(sql).df()
    print(df.to_string(index=index))
    return df


def build_positions(con):
    """FIFO + average-cost realized P&L per token, computed in Python over legs ordered by time."""
    rows = con.execute("""
        SELECT token, symbol, ts, event_type, token_amount, cost_usd, price_usd, total_supply, quote_symbol, is_open_or_close, tx_hash
        FROM activity WHERE token_amount > 0 AND cost_usd IS NOT NULL ORDER BY token, ts, event_type""").fetchall()
    tr = {}
    for token, et, ts, amt, usd in con.execute("""
        SELECT token, event_type, ts, token_amount, cost_usd FROM transfers
        WHERE to_address = ? OR from_address = ?""", [COMPANION, COMPANION]).fetchall():
        d = tr.setdefault(token, {"out_n": 0, "out_amt": 0.0, "out_usd": 0.0, "in_n": 0, "in_amt": 0.0})
        if et == "transfer_out":
            d["out_n"] += 1; d["out_amt"] += amt or 0; d["out_usd"] += usd or 0
        else:
            d["in_n"] += 1; d["in_amt"] += amt or 0
    out = []
    cur = None
    def flush():
        if cur is None:
            return
        p = cur
        fb = p["first_buy_ts"]
        p["hold_first_to_first_sell_s"] = (p["first_sell_ts"] - fb) if (p["first_sell_ts"] and fb) else None
        p["hold_first_to_last_sell_s"] = (p["last_sell_ts"] - fb) if (p["last_sell_ts"] and fb) else None
        p["accum_window_s"] = (p["last_buy_ts"] - fb) if fb else None
        p["realized_avg"] = p["sell_usd"] - p["cost_of_sold_avg"]
        p["realized_fifo"] = p["sell_usd"] - p["cost_of_sold_fifo"]
        p["sold_frac"] = p["sold_amt"] / p["bought_amt"] if p["bought_amt"] > 0 else None
        p["first_sell_frac"] = (p["first_sell_amt"] / p["bought_at_first_sell"]) if p["bought_at_first_sell"] else None
        p["max_sell_share"] = (p["max_sell_usd"] / p["sell_usd"]) if p["sell_usd"] > 0 else None
        p["roi_avg"] = (p["realized_avg"] / p["cost_of_sold_avg"]) if p["cost_of_sold_avg"] > 0 else None
        t = tr.get(p["token"], {})
        p.update({"tr_out_n": t.get("out_n", 0), "tr_out_amt": t.get("out_amt", 0.0), "tr_out_usd": t.get("out_usd", 0.0),
                  "tr_in_n": t.get("in_n", 0), "tr_in_amt": t.get("in_amt", 0.0)})
        del p["fifo"]
        out.append(p)
    for token, symbol, ts, et, amt, usd, px, supply, quote, ioc, txh in rows:
        if cur is None or cur["token"] != token:
            flush()
            cur = {"token": token, "symbol": symbol, "first_buy_ts": None, "last_buy_ts": None, "first_sell_ts": None, "last_sell_ts": None,
                   "n_buys": 0, "n_sells": 0, "bought_amt": 0.0, "sold_amt": 0.0, "buy_usd": 0.0, "sell_usd": 0.0,
                   "cost_of_sold_avg": 0.0, "cost_of_sold_fifo": 0.0, "fifo": [], "avg_cost": 0.0, "held_amt": 0.0, "held_cost": 0.0,
                   "first_sell_amt": 0.0, "bought_at_first_sell": 0.0, "max_sell_usd": 0.0, "entry_mcap": None, "entry_price": None,
                   "quote_first": quote, "n_quotes": 0, "sells_before_any_buy": 0, "buy_ioc_open": 0, "max_buy_usd": 0.0}
            cur["_quotes"] = set()
        p = cur
        p["_quotes"].add(quote); p["n_quotes"] = len(p["_quotes"])
        if et == "buy":
            if p["first_buy_ts"] is None:
                p["first_buy_ts"] = ts
                p["entry_price"] = px
                p["entry_mcap"] = (px * supply) if (px and supply and supply > 0) else None
            p["last_buy_ts"] = ts
            p["n_buys"] += 1; p["bought_amt"] += amt; p["buy_usd"] += usd; p["max_buy_usd"] = max(p["max_buy_usd"], usd)
            if ioc == 1:
                p["buy_ioc_open"] += 1
            p["held_amt"] += amt; p["held_cost"] += usd
            p["avg_cost"] = p["held_cost"] / p["held_amt"] if p["held_amt"] > 0 else 0.0
            p["fifo"].append([amt, usd / amt])
        elif et == "sell":
            if p["first_buy_ts"] is None:
                p["sells_before_any_buy"] += 1
            if p["first_sell_ts"] is None:
                p["first_sell_ts"] = ts; p["first_sell_amt"] = amt; p["bought_at_first_sell"] = p["bought_amt"]
            p["last_sell_ts"] = ts
            p["n_sells"] += 1; p["sold_amt"] += amt; p["sell_usd"] += usd; p["max_sell_usd"] = max(p["max_sell_usd"], usd)
            # average cost
            q = min(amt, p["held_amt"])
            p["cost_of_sold_avg"] += q * p["avg_cost"]
            p["held_amt"] -= q; p["held_cost"] -= q * p["avg_cost"]
            if p["held_amt"] <= 1e-9:
                p["held_amt"] = 0.0; p["held_cost"] = 0.0
            # fifo
            rem = amt
            while rem > 1e-9 and p["fifo"]:
                lot = p["fifo"][0]
                take = min(rem, lot[0])
                p["cost_of_sold_fifo"] += take * lot[1]
                lot[0] -= take; rem -= take
                if lot[0] <= 1e-9:
                    p["fifo"].pop(0)
    flush()
    for p in out:
        p.pop("_quotes", None)
    con.execute("DROP TABLE IF EXISTS positions")
    import pandas as pd
    df = pd.DataFrame(out)
    con.register("pos_df", df)
    con.execute("CREATE TABLE positions AS SELECT *, to_timestamp(first_buy_ts) AS first_buy_t FROM pos_df")
    con.unregister("pos_df")
    n = con.execute("SELECT count(*) FROM positions").fetchone()[0]
    print(f"positions built: {n:,} tokens")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--section", default="all")
    ap.add_argument("--rebuild", action="store_true")
    a = ap.parse_args()
    con = duckdb.connect(DB)
    if a.rebuild or not con.execute("SELECT count(*) FROM information_schema.tables WHERE table_name='positions'").fetchone()[0]:
        build_positions(con)
    S = a.section
    if S in ("all", "reconcile"):
        last = con.execute("SELECT max(ts) FROM activity").fetchone()[0]
        for win, days in (("7d", 7), ("30d", 30)):
            sp = os.path.join(DATA, "baseline", f"stats_{win}.json")
            s = json.load(open(sp)); s = s.get("data", s)
            # window realized: sells in window, cost basis per method — recompute via legs restricted to window is complex;
            # approximate with positions whose last sell falls in the window (GMGN attributes by sell time)
            r = con.execute(f"""SELECT round(sum(realized_avg)), round(sum(realized_fifo)), count(*) ,
                                       sum(CASE WHEN realized_avg>0 THEN 1 ELSE 0 END)
                                FROM positions WHERE last_sell_ts > {last}-{days}*86400""").fetchone()
            print(f"reconcile {win}: GMGN realized ${float(s['realized_profit']):,.0f} winrate {s['pnl_stat']['winrate']:.3f} tokens {s['pnl_stat']['token_num']} | "
                  f"ours(avg) ${r[0]:,.0f} ours(fifo) ${r[1]:,.0f} tokens-with-sell {r[2]} winners {r[3]} ({r[3]/max(r[2],1):.3f})")
        pa = json.load(open(os.path.join(DATA, "baseline", "profits_all.json"))); pa = pa.get("data", pa)["list"][0]
        r = con.execute("SELECT round(sum(realized_avg)), round(sum(realized_fifo)), round(sum(cost_of_sold_avg)), round(sum(buy_usd)), round(sum(sell_usd)) FROM positions").fetchone()
        print(f"reconcile all: GMGN realized ${float(pa['total_realized_profit']):,.0f} on cost ${float(pa['total_realized_profit_cost']):,.0f} | ours(avg) ${r[0]:,.0f} ours(fifo) ${r[1]:,.0f} cost_of_sold ${r[2]:,.0f} buy ${r[3]:,.0f} sell ${r[4]:,.0f}")
        show(con, "outcome distribution (tokens with a sell), ROI on average cost",
             """SELECT CASE WHEN roi_avg > 4 THEN 'a >5x' WHEN roi_avg > 1 THEN 'b 2-5x' WHEN roi_avg >= 0 THEN 'c 0-2x'
                            WHEN roi_avg >= -0.5 THEN 'd -50..0%' ELSE 'e <-50%' END bucket, count(*) tokens, round(sum(realized_avg)) realized_usd
                FROM positions WHERE n_sells > 0 GROUP BY 1 ORDER BY 1""")
        show(con, "where the money came from: P&L concentration",
             """WITH r AS (SELECT realized_avg FROM positions WHERE n_sells>0 ORDER BY realized_avg DESC)
                SELECT (SELECT round(sum(realized_avg)) FROM r) total,
                       (SELECT round(sum(realized_avg)) FROM (SELECT * FROM r LIMIT 10)) top10,
                       (SELECT round(sum(realized_avg)) FROM (SELECT * FROM r LIMIT 100)) top100,
                       (SELECT round(sum(realized_avg)) FROM (SELECT * FROM r LIMIT 1000)) top1000,
                       (SELECT round(sum(realized_avg)) FROM r WHERE realized_avg<0) losses,
                       (SELECT round(sum(realized_avg)) FROM r WHERE realized_avg>0) gains""")
    if S in ("all", "positions"):
        show(con, "position shape", """SELECT count(*) tokens, sum(n_sells=0) never_sold, round(100.0*sum(n_sells=0)/count(*),1) pct_never_sold,
               round(median(n_buys),1) med_buys, round(avg(n_buys),1) avg_buys, round(median(n_sells),1) med_sells, round(avg(n_sells),1) avg_sells,
               round(median(buy_usd),1) med_pos_usd, round(quantile_cont(buy_usd,0.9)) p90_pos_usd, round(max(buy_usd)) max_pos_usd,
               round(100.0*sum(n_quotes>1)/count(*),1) pct_multi_quote FROM positions""")
        show(con, "buys per position (ladder depth)", """SELECT CASE WHEN n_buys=1 THEN '1' WHEN n_buys<=3 THEN '2-3' WHEN n_buys<=10 THEN '4-10' WHEN n_buys<=30 THEN '11-30' ELSE '>30' END buys, count(*) tokens, round(sum(buy_usd)) buy_usd, round(sum(realized_avg)) realized FROM positions GROUP BY 1 ORDER BY min(n_buys)""")
        show(con, "never-sold positions: cost sunk", """SELECT count(*) n, round(sum(buy_usd)) usd, round(median(buy_usd),2) med_usd, round(quantile_cont(buy_usd,0.9),1) p90_usd, sum(tr_out_n>0) moved_to_companion FROM positions WHERE n_sells=0""")
    if S in ("all", "sizing"):
        show(con, "buy clip size (USD) distribution by month", """SELECT strftime(t,'%Y-%m') m, count(*) buys, round(quantile_cont(cost_usd,0.1),2) p10, round(median(cost_usd),2) p50, round(quantile_cont(cost_usd,0.9),1) p90, round(quantile_cont(cost_usd,0.99)) p99, round(max(cost_usd)) max FROM activity WHERE event_type='buy' GROUP BY 1 ORDER BY 1""")
        show(con, "clip-size clusters (all buys)", """SELECT CASE WHEN cost_usd<1 THEN 'a <$1' WHEN cost_usd<5 THEN 'b $1-5' WHEN cost_usd<20 THEN 'c $5-20' WHEN cost_usd<100 THEN 'd $20-100' WHEN cost_usd<300 THEN 'e $100-300' WHEN cost_usd<1000 THEN 'f $300-1k' ELSE 'g >$1k' END clip, count(*) buys, round(sum(cost_usd)) usd, round(100.0*sum(cost_usd)/(SELECT sum(cost_usd) FROM activity WHERE event_type='buy'),1) pct_usd FROM activity WHERE event_type='buy' GROUP BY 1 ORDER BY 1""")
        show(con, "position size (total buy USD per token) vs outcome", """SELECT CASE WHEN buy_usd<5 THEN 'a <$5' WHEN buy_usd<50 THEN 'b $5-50' WHEN buy_usd<300 THEN 'c $50-300' WHEN buy_usd<1000 THEN 'd $300-1k' WHEN buy_usd<3000 THEN 'e $1k-3k' ELSE 'f >$3k' END pos, count(*) tokens, round(sum(buy_usd)) buy_usd, round(sum(realized_avg)) realized, round(100.0*sum(realized_avg>0)/count(*),1) pct_win, round(median(n_buys),1) med_buys FROM positions GROUP BY 1 ORDER BY 1""")
    if S in ("all", "cadence"):
        show(con, "hour of day (UTC) share of trades, all year", """SELECT hour(t) h, count(*) n, round(100.0*count(*)/(SELECT count(*) FROM activity),1) pct FROM activity GROUP BY 1 ORDER BY 1""")
        show(con, "day of week share", """SELECT dayofweek(t) dow, count(*) n, round(100.0*count(*)/(SELECT count(*) FROM activity),1) pct FROM activity GROUP BY 1 ORDER BY 1""")
        show(con, "inter-trade gap (seconds) between consecutive transactions", """WITH t AS (SELECT DISTINCT tx_hash, ts FROM activity), g AS (SELECT ts - lag(ts) OVER (ORDER BY ts, tx_hash) gap FROM t)
              SELECT count(*) n, round(quantile_cont(gap,0.1),1) p10, round(median(gap),1) p50, round(quantile_cont(gap,0.9)) p90, sum(gap<=1) within_1s, sum(gap<=5) within_5s, round(100.0*sum(gap<=5)/count(*),1) pct_within_5s FROM g WHERE gap IS NOT NULL""")
        show(con, "active days and trades per active day by month", """SELECT strftime(t,'%Y-%m') m, count(DISTINCT date_trunc('day',t)) active_days, count(DISTINCT tx_hash) tx, round(count(DISTINCT tx_hash)*1.0/count(DISTINCT date_trunc('day',t))) tx_per_active_day, count(DISTINCT hour(t)) hours_seen FROM activity GROUP BY 1 ORDER BY 1""")
        show(con, "longest quiet gaps (>6h) count by month", """WITH t AS (SELECT DISTINCT tx_hash, ts, t FROM activity), g AS (SELECT t, ts - lag(ts) OVER (ORDER BY ts, tx_hash) gap FROM t) SELECT strftime(t,'%Y-%m') m, sum(gap>6*3600) gaps_over_6h, round(max(gap)/3600,1) max_gap_h FROM g GROUP BY 1 ORDER BY 1""")
    if S in ("all", "exits"):
        show(con, "copy window: first buy -> first sell (positions with a sell)", """SELECT count(*) n, round(quantile_cont(hold_first_to_first_sell_s,0.1)) p10_s, round(median(hold_first_to_first_sell_s)) p50_s, round(quantile_cont(hold_first_to_first_sell_s,0.75)) p75_s, round(quantile_cont(hold_first_to_first_sell_s,0.9)/60) p90_min, round(100.0*sum(hold_first_to_first_sell_s<=5)/count(*),1) pct_le_5s, round(100.0*sum(hold_first_to_first_sell_s<=60)/count(*),1) pct_le_60s, round(100.0*sum(hold_first_to_first_sell_s>3600)/count(*),1) pct_gt_1h FROM positions WHERE n_sells>0""")
        show(con, "hold time bucket vs outcome", """SELECT CASE WHEN hold_first_to_last_sell_s<60 THEN 'a <1m' WHEN hold_first_to_last_sell_s<600 THEN 'b 1-10m' WHEN hold_first_to_last_sell_s<3600 THEN 'c 10-60m' WHEN hold_first_to_last_sell_s<86400 THEN 'd 1-24h' ELSE 'e >1d' END hold_bucket, count(*) tokens, round(sum(buy_usd)) buy_usd, round(sum(realized_avg)) realized, round(100.0*sum(realized_avg>0)/count(*),1) pct_win, round(median(roi_avg)*100,1) med_roi_pct FROM positions WHERE n_sells>0 GROUP BY 1 ORDER BY 1""")
        show(con, "exit shape", """SELECT count(*) n, round(median(first_sell_frac)*100,1) med_first_sell_pct, round(100.0*sum(first_sell_frac>=0.95)/count(*),1) pct_full_exit_first_sell, round(100.0*sum(max_sell_share>=0.8)/count(*),1) pct_one_dump, round(median(n_sells),1) med_sells, round(median(sold_frac)*100,1) med_sold_frac_pct, round(100.0*sum(sold_frac>=0.99)/count(*),1) pct_fully_sold FROM positions WHERE n_sells>0""")
        show(con, "loss cutting: losers by ROI and hold", """SELECT CASE WHEN roi_avg < -0.9 THEN 'a <-90%' WHEN roi_avg < -0.5 THEN 'b -90..-50%' WHEN roi_avg < -0.2 THEN 'c -50..-20%' WHEN roi_avg < 0 THEN 'd -20..0%' ELSE 'e >=0' END roi, count(*) tokens, round(sum(realized_avg)) realized, round(median(hold_first_to_last_sell_s)) med_hold_s FROM positions WHERE n_sells>0 GROUP BY 1 ORDER BY 1""")
    if S in ("all", "entry"):
        show(con, "entry market cap (price_usd x total_supply at first buy) by month", """SELECT strftime(first_buy_t,'%Y-%m') m, count(*) n, round(quantile_cont(entry_mcap,0.25)) p25, round(median(entry_mcap)) p50, round(quantile_cont(entry_mcap,0.75)) p75, round(100.0*sum(entry_mcap<100000)/count(*),1) pct_lt_100k, round(100.0*sum(entry_mcap<30000)/count(*),1) pct_lt_30k FROM positions WHERE entry_mcap IS NOT NULL AND entry_mcap>0 GROUP BY 1 ORDER BY 1""")
        show(con, "entry mcap band vs outcome", """SELECT CASE WHEN entry_mcap<10000 THEN 'a <$10k' WHEN entry_mcap<30000 THEN 'b $10-30k' WHEN entry_mcap<60000 THEN 'c $30-60k' WHEN entry_mcap<100000 THEN 'd $60-100k' WHEN entry_mcap<300000 THEN 'e $100-300k' ELSE 'f >$300k' END band, count(*) tokens, round(sum(buy_usd)) buy_usd, round(sum(realized_avg)) realized, round(100.0*sum(realized_avg>0)/count(*),1) pct_win, round(median(buy_usd),1) med_pos FROM positions WHERE entry_mcap IS NOT NULL AND entry_mcap>0 GROUP BY 1 ORDER BY 1""")
        show(con, "quote asset of first buy vs outcome", """SELECT quote_first, count(*) tokens, round(sum(buy_usd)) buy_usd, round(sum(realized_avg)) realized, round(100.0*sum(realized_avg>0)/count(*),1) pct_win FROM positions GROUP BY 1 ORDER BY tokens DESC LIMIT 12""")
    if S in ("all", "monthly"):
        show(con, "monthly: positions opened, realized (avg cost), win rate, median hold, median entry mcap", """SELECT strftime(first_buy_t,'%Y-%m') m, count(*) opened, sum(n_sells>0) closed_any, round(sum(realized_avg)) realized, round(100.0*sum(realized_avg>0)/nullif(sum(n_sells>0),0),1) win_pct, round(median(CASE WHEN n_sells>0 THEN hold_first_to_first_sell_s END)) med_first_sell_s, round(median(entry_mcap)) med_entry_mcap, round(median(buy_usd),1) med_pos_usd, round(quantile_cont(buy_usd,0.9)) p90_pos_usd FROM positions GROUP BY 1 ORDER BY 1""")
        show(con, "companion transfers vs outcome on main", """SELECT (tr_out_n>0) moved_out, count(*) tokens, round(sum(buy_usd)) buy_usd, round(sum(sell_usd)) sell_usd_main, round(sum(realized_avg)) realized_main, round(sum(tr_out_usd)) moved_usd, round(100.0*sum(n_sells=0)/count(*),1) pct_never_sold_main FROM positions GROUP BY 1""")
    con.execute(f"COPY positions TO '{os.path.join(DATA, 'positions.parquet')}' (FORMAT PARQUET)")
    con.close()


if __name__ == "__main__":
    main()
