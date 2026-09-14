#!/usr/bin/env python3
"""Mini-phase 2.4 (offline): selection profile — what he picks, joined from `tokens` x `positions`.

    python3 scripts/selection.py
"""
import os

import duckdb

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
DB = os.path.join(DATA, "notdecu.duckdb")

con = duckdb.connect(DB, read_only=True)


def show(t, q):
    print(f"\n### {t}\n")
    print(con.execute(q).df().to_string(index=False))


con.execute("""CREATE TEMP VIEW pt AS
    SELECT p.*, t.creation_ts, t.open_ts, t.migrated_ts, t.launchpad_platform, t.launchpad_status, t.migration_mcap, t.holder_count,
           t.total_fee, t.creator, t.creator_status, t.creator_open_count, t.creator_created_count, t.cto_flag, t.image_dup_count,
           t.top10_rate, t.creator_hold_rate, t.rat_pct, t.bundler_pct, t.bot_degen_rate, t.fresh_wallet_rate, t.sniper_hold_rate,
           t.smart_wallets, t.renowned_wallets, t.sniper_wallets, t.twitter, t.website, t.telegram, t.error_code,
           p.first_buy_ts - t.creation_ts AS age_at_entry_s
    FROM positions p LEFT JOIN tokens t USING(token) WHERE p.first_buy_t >= '2026-02-01'""")

show("coverage", "SELECT count(*) positions, sum(creation_ts IS NOT NULL) with_info, sum(error_code IS NOT NULL) errors, round(100.0*sum(creation_ts IS NOT NULL)/count(*),1) pct FROM pt")
show("launchpad of picked tokens", "SELECT launchpad_platform, count(*) tokens, round(sum(buy_usd)) buy_usd, round(sum(realized_avg)) realized, round(100.0*sum(realized_avg>0)/count(*),1) pct_win FROM pt GROUP BY 1 ORDER BY tokens DESC LIMIT 10")
show("token age at his first buy (seconds since creation)", """SELECT count(*) n, round(quantile_cont(age_at_entry_s,0.1)) p10, round(quantile_cont(age_at_entry_s,0.25)) p25, round(median(age_at_entry_s)) p50, round(quantile_cont(age_at_entry_s,0.75)) p75, round(quantile_cont(age_at_entry_s,0.9)) p90,
    round(100.0*sum(age_at_entry_s<=30)/count(*),1) pct_le_30s, round(100.0*sum(age_at_entry_s<=120)/count(*),1) pct_le_2m, round(100.0*sum(age_at_entry_s<=600)/count(*),1) pct_le_10m, round(100.0*sum(age_at_entry_s>3600)/count(*),1) pct_gt_1h FROM pt WHERE age_at_entry_s IS NOT NULL AND age_at_entry_s >= 0""")
show("age at entry band vs outcome", """SELECT CASE WHEN age_at_entry_s<=15 THEN 'a <=15s' WHEN age_at_entry_s<=60 THEN 'b 15-60s' WHEN age_at_entry_s<=300 THEN 'c 1-5m' WHEN age_at_entry_s<=1800 THEN 'd 5-30m' WHEN age_at_entry_s<=86400 THEN 'e 30m-1d' ELSE 'f >1d' END age, count(*) tokens, round(sum(buy_usd)) buy_usd, round(sum(realized_avg)) realized, round(100.0*sum(realized_avg>0)/count(*),1) pct_win, round(median(roi_avg)*100,1) med_roi, round(median(entry_mcap)) med_entry_mcap FROM pt WHERE age_at_entry_s IS NOT NULL AND age_at_entry_s>=0 GROUP BY 1 ORDER BY 1""")
show("age at entry by month (median seconds)", "SELECT strftime(first_buy_t,'%Y-%m') m, count(*) n, round(quantile_cont(age_at_entry_s,0.25)) p25, round(median(age_at_entry_s)) p50, round(quantile_cont(age_at_entry_s,0.75)) p75 FROM pt WHERE age_at_entry_s IS NOT NULL AND age_at_entry_s>=0 GROUP BY 1 ORDER BY 1")
show("what became of the tokens he picked (status today)", """SELECT launchpad_status, CASE WHEN migrated_ts>0 THEN 'migrated' ELSE 'not migrated' END mig, count(*) tokens, round(100.0*count(*)/(SELECT count(*) FROM pt WHERE creation_ts IS NOT NULL),1) pct, round(sum(realized_avg)) realized, round(100.0*sum(realized_avg>0)/count(*),1) pct_win FROM pt WHERE creation_ts IS NOT NULL GROUP BY 1,2 ORDER BY tokens DESC""")
show("did he sell before or after migration (migrated tokens)", "SELECT CASE WHEN last_sell_ts < migrated_ts THEN 'sold before migration' ELSE 'held into/after migration' END w, count(*) n, round(sum(realized_avg)) realized FROM pt WHERE migrated_ts>0 AND last_sell_ts IS NOT NULL GROUP BY 1")
show("creator repeat: how many of his picks share a creator", """WITH c AS (SELECT creator, count(*) n, round(sum(realized_avg)) realized, round(100.0*sum(realized_avg>0)/count(*),1) pct_win FROM pt WHERE creator IS NOT NULL AND creator<>'' GROUP BY 1)
SELECT CASE WHEN n=1 THEN 'a creator seen once' WHEN n<=3 THEN 'b 2-3 picks' WHEN n<=10 THEN 'c 4-10 picks' ELSE 'd >10 picks' END repeat, count(*) creators, sum(n) tokens, sum(realized) realized FROM c GROUP BY 1 ORDER BY 1""")
show("top recurring creators", "SELECT creator, count(*) picks, round(sum(buy_usd)) buy_usd, round(sum(realized_avg)) realized, round(100.0*sum(realized_avg>0)/count(*),1) pct_win, max(creator_created_count) created_count, max(creator_open_count) open_count FROM pt WHERE creator IS NOT NULL AND creator<>'' GROUP BY 1 ORDER BY picks DESC LIMIT 15")
show("creator history at pick time proxies (creator_created_count / open_count are as of today)", """SELECT CASE WHEN creator_created_count<=1 THEN 'a first launch' WHEN creator_created_count<=5 THEN 'b 2-5 launches' WHEN creator_created_count<=20 THEN 'c 6-20' ELSE 'd >20 (factory)' END dev_launches, count(*) tokens, round(sum(buy_usd)) buy_usd, round(sum(realized_avg)) realized, round(100.0*sum(realized_avg>0)/count(*),1) pct_win, round(median(roi_avg)*100,1) med_roi FROM pt WHERE creator_created_count IS NOT NULL GROUP BY 1 ORDER BY 1""")
show("creator graduated before? (open_count>0 today) vs outcome", "SELECT (creator_open_count>0) creator_has_graduated_token, count(*) tokens, round(sum(realized_avg)) realized, round(100.0*sum(realized_avg>0)/count(*),1) pct_win FROM pt WHERE creator_open_count IS NOT NULL GROUP BY 1")
show("creator status today vs outcome", "SELECT creator_status, count(*) tokens, round(sum(realized_avg)) realized, round(100.0*sum(realized_avg>0)/count(*),1) pct_win FROM pt WHERE creator_status IS NOT NULL GROUP BY 1 ORDER BY tokens DESC")
show("socials present at pick (as of today) vs outcome", "SELECT (coalesce(twitter,'')<>'') has_twitter, (coalesce(website,'')<>'') has_website, count(*) tokens, round(sum(realized_avg)) realized, round(100.0*sum(realized_avg>0)/count(*),1) pct_win FROM pt WHERE creation_ts IS NOT NULL GROUP BY 1,2 ORDER BY tokens DESC")
show("quality signals (today) vs outcome: bundler share", "SELECT CASE WHEN bundler_pct IS NULL THEN 'n/a' WHEN bundler_pct=0 THEN '0' WHEN bundler_pct<0.1 THEN '<10%' WHEN bundler_pct<0.3 THEN '10-30%' ELSE '>=30%' END bundler, count(*) tokens, round(sum(realized_avg)) realized, round(100.0*sum(realized_avg>0)/count(*),1) pct_win FROM pt WHERE creation_ts IS NOT NULL GROUP BY 1 ORDER BY 1")
show("quality signals (today) vs outcome: sniper hold, rat, image dup", """SELECT round(100.0*sum(sniper_hold_rate>0.3)/count(*),1) pct_sniper_gt30, round(100.0*sum(rat_pct>0.1)/count(*),1) pct_rat_gt10, round(100.0*sum(image_dup_count>1)/count(*),1) pct_image_dup, round(100.0*sum(cto_flag=1)/count(*),1) pct_cto, round(100.0*sum(smart_wallets>0)/count(*),1) pct_any_smart_money, round(100.0*sum(renowned_wallets>0)/count(*),1) pct_any_kol FROM pt WHERE creation_ts IS NOT NULL""")
show("holders today and total fees today vs outcome", """SELECT CASE WHEN holder_count<20 THEN 'a <20' WHEN holder_count<100 THEN 'b 20-100' WHEN holder_count<500 THEN 'c 100-500' ELSE 'd >=500' END holders_now, count(*) tokens, round(sum(realized_avg)) realized, round(100.0*sum(realized_avg>0)/count(*),1) pct_win, round(median(total_fee),2) med_total_fee FROM pt WHERE holder_count IS NOT NULL GROUP BY 1 ORDER BY 1""")
show("supply bought per position vs migration: was he in tokens that later graduated?", "SELECT CASE WHEN migrated_ts>0 THEN 'graduated later' ELSE 'never graduated' END g, count(*) n, round(median(buy_usd)) med_pos, round(median(hold_first_to_first_sell_s)) med_hold_s, round(sum(realized_avg)) realized FROM pt WHERE creation_ts IS NOT NULL GROUP BY 1")
con.close()
