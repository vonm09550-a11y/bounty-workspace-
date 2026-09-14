#!/usr/bin/env python3
"""Mini-phase 2.3a: load the companion wallet's GMGN activity and analyse the main<->companion round trips."""
import glob
import os

import duckdb

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
DB = os.path.join(DATA, "notdecu.duckdb")
MAIN = "4vw54BmAogeRV3vPKWyFet5yf8DTLcREzdSzx4rw9Ud9"
COMP = "4hQZ1GtLTvAzetszCcWrb8zxiuVvEt85Bb7y6VNzA2ve"

con = duckdb.connect(DB)
bs = sorted(glob.glob(os.path.join(DATA, "activity", "companion_buy-sell_*.jsonl")))
tf = sorted(glob.glob(os.path.join(DATA, "activity", "companion_transferIn-transferOut-add-remove_*.jsonl")))
con.execute("DROP TABLE IF EXISTS activity_companion")
con.execute(f"""CREATE TABLE activity_companion AS SELECT DISTINCT tx_hash, CAST(timestamp AS BIGINT) ts, to_timestamp(CAST(timestamp AS BIGINT)) t,
    event_type, token.address token, token.symbol symbol, TRY_CAST(token_amount AS DOUBLE) token_amount, TRY_CAST(cost_usd AS DOUBLE) cost_usd,
    TRY_CAST(price_usd AS DOUBLE) price_usd, quote_token.symbol quote_symbol
    FROM read_json_auto({bs!r}, union_by_name=true, maximum_object_size=4000000)""")
con.execute("DROP TABLE IF EXISTS transfers_companion")
con.execute(f"""CREATE TABLE transfers_companion AS SELECT DISTINCT tx_hash, CAST(timestamp AS BIGINT) ts, to_timestamp(CAST(timestamp AS BIGINT)) t,
    event_type, token.address token, token.symbol symbol, TRY_CAST(token_amount AS DOUBLE) token_amount, TRY_CAST(cost_usd AS DOUBLE) cost_usd, from_address, to_address
    FROM read_json_auto({tf!r}, union_by_name=true, maximum_object_size=4000000)""")


def show(t, q):
    print(f"\n### {t}\n")
    print(con.execute(q).df().to_string(index=False))


show("companion tables", "SELECT (SELECT count(*) FROM activity_companion) trade_legs, (SELECT count(*) FROM transfers_companion) transfer_legs")
show("companion transfers by type and counterparty", f"""SELECT event_type, CASE WHEN from_address='{MAIN}' OR to_address='{MAIN}' THEN 'main' ELSE 'other' END cp,
    count(*) n, count(DISTINCT token) tokens, round(sum(cost_usd)) usd FROM transfers_companion GROUP BY 1,2 ORDER BY 1,2""")
show("companion trades by month", """SELECT strftime(t,'%Y-%m') m, sum(event_type='buy') buys, sum(event_type='sell') sells,
    round(sum(CASE WHEN event_type='buy' THEN cost_usd END)) buy_usd, round(sum(CASE WHEN event_type='sell' THEN cost_usd END)) sell_usd FROM activity_companion GROUP BY 1 ORDER BY 1""")
show("round trips main -> companion -> main, per token", f"""
WITH o AS (SELECT token, min(ts) t_out, sum(token_amount) amt_out, sum(cost_usd) usd_out FROM transfers WHERE event_type='transfer_out' AND to_address='{COMP}' GROUP BY 1),
     i AS (SELECT token, min(ts) t_in, sum(token_amount) amt_in FROM transfers WHERE event_type='transfer_in' AND from_address='{COMP}' GROUP BY 1)
SELECT count(*) tokens_out, sum(i.token IS NOT NULL) came_back, round(median(i.t_in-o.t_out)) med_s_out_to_in, round(quantile_cont(i.t_in-o.t_out,0.9)) p90_s,
       round(median(i.amt_in/o.amt_out)*100,1) med_pct_returned, round(median(o.amt_out/p.bought_amt)*100,1) med_pct_of_bag_moved,
       round(median(o.t_out-p.first_buy_ts)) med_s_after_first_buy, round(median(p.first_sell_ts-i.t_in)) med_s_in_to_first_sell,
       round(median(p.first_sell_ts-o.t_out)) med_s_out_to_first_sell
FROM o JOIN positions p USING(token) LEFT JOIN i USING(token)""")
show("what main does between out and in", f"""
WITH o AS (SELECT token, min(ts) t_out FROM transfers WHERE event_type='transfer_out' AND to_address='{COMP}' GROUP BY 1),
     i AS (SELECT token, min(ts) t_in FROM transfers WHERE event_type='transfer_in' AND from_address='{COMP}' GROUP BY 1)
SELECT a.event_type, count(*) legs, round(median(a.cost_usd),2) med_usd FROM o JOIN i USING(token) JOIN activity a ON a.token=o.token AND a.ts BETWEEN o.t_out AND i.t_in GROUP BY 1""")
show("does the companion sell the moved tokens?", f"""SELECT count(DISTINCT token) tokens_sold_on_companion, round(sum(cost_usd)) usd FROM activity_companion
    WHERE event_type='sell' AND token IN (SELECT token FROM transfers WHERE to_address='{COMP}')""")
show("outcome on main: round-trip tokens vs others (Feb-Sep 2026)", """SELECT (tr_out_n>0) round_trip, count(*) tokens, round(sum(buy_usd)) buy_usd, round(sum(realized_avg)) realized,
    round(100.0*sum(realized_avg>0)/count(*),1) pct_win, round(median(roi_avg)*100,1) med_roi, round(median(hold_first_to_first_sell_s)) med_hold_s, round(median(n_buys),1) med_buys
    FROM positions WHERE first_buy_t>='2026-02-01' GROUP BY 1""")
show("moved share of the bag and P&L on main by month", f"""
WITH o AS (SELECT token, min(ts) t_out, sum(token_amount) amt_out FROM transfers WHERE event_type='transfer_out' AND to_address='{COMP}' GROUP BY 1)
SELECT strftime(p.first_buy_t,'%Y-%m') m, count(*) moved_tokens, round(median(o.amt_out/p.bought_amt)*100,1) med_pct_bag, round(sum(p.realized_avg)) realized_main, round(100.0*sum(p.realized_avg>0)/count(*),1) pct_win
FROM o JOIN positions p USING(token) GROUP BY 1 ORDER BY 1""")
con.close()
