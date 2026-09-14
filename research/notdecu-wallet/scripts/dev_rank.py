#!/usr/bin/env python3
"""Phase 3 / D3: first ranking cut over `dev_books` x `dev_tokens` (+ decu overlap from `positions`).

    python3 scripts/dev_rank.py            # prints sections, writes `dev_scores` table + data/devs/dev_scores.parquet

Books are ordered by token ATH and capped at 101 rows, so for capped devs the listed tokens are their
BEST launches: hit counts (ATH >= 100K / 1M) are complete whenever the 101st token is below the bar
(`hits_complete`), while recency and cadence come from `last_create_ts` and are complete for everyone.
`inner_count` = launches still on the curve (not graduated) and caps at 999; launches = inner_count + open_count,
so hit rates for capped devs are upper bounds (`launches_capped`). ATH above $5B is implausible (`implausible_peaks`).
"""
import os

import duckdb

HERE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(HERE, "..", "data")
con = duckdb.connect(os.path.join(DATA, "notdecu.duckdb"))


def show(t, q):
    print(f"\n### {t}\n")
    print(con.execute(q).df().to_string(index=False))


con.execute("DROP TABLE IF EXISTS dev_scores")
con.execute("""
CREATE TABLE dev_scores AS
WITH t AS (
  SELECT creator, count(*) listed, sum(is_open::INT) listed_open,
         sum((ath_mc >= 1e5 AND ath_mc < 5e9)::INT) hits_100k, sum((ath_mc >= 1e6 AND ath_mc < 5e9)::INT) hits_1m, sum((ath_mc >= 1e7 AND ath_mc < 5e9)::INT) hits_10m,
         max(CASE WHEN ath_mc < 5e9 THEN ath_mc END) best_ath, min(ath_mc) listed_min_ath, sum((ath_mc >= 5e9)::INT) implausible_peaks,
         median(CASE WHEN is_open THEN ath_mc END) med_ath_open,
         median(CASE WHEN is_open THEN bundler_rate END) med_bundler_open,
         median(CASE WHEN is_open THEN holders END) med_holders_open,
         sum((is_open AND liq_lt_4k)::INT) open_but_dry,
         sum((create_ts >= extract(epoch FROM now()) - 30*86400)::INT) listed_last_30d,
         sum((create_ts >= extract(epoch FROM now()) - 30*86400 AND ath_mc >= 1e5)::INT) hits_100k_last_30d,
         sum((create_ts >= extract(epoch FROM now()) - 90*86400 AND ath_mc >= 1e5)::INT) hits_100k_last_90d,
         max(CASE WHEN ath_mc >= 1e5 THEN create_ts END) last_hit_ts,
         count(DISTINCT launchpad_platform) n_platforms, mode(launchpad_platform) main_platform
  FROM dev_tokens GROUP BY 1),
d AS (
  SELECT p.token, tk.creator, p.realized_avg, p.buy_usd FROM positions p JOIN tokens tk USING(token) WHERE p.first_buy_t >= '2026-02-01'),
dd AS (SELECT creator, count(*) decu_picks, round(sum(realized_avg)) decu_realized, round(100.0*sum((realized_avg>0)::INT)/count(*),1) decu_win FROM d GROUP BY 1)
SELECT b.creator, b.inner_count + b.open_count launches, b.inner_count >= 999 launches_capped, b.open_count opens, b.open_ratio, t.implausible_peaks,
       t.listed, t.listed >= 101 AND t.listed_min_ath >= 1e5 AS hits_incomplete,
       t.hits_100k, t.hits_1m, t.hits_10m, round(t.best_ath) best_ath, b.creator_ath_symbol best_symbol,
       round(t.med_ath_open) med_ath_open, t.med_bundler_open, t.med_holders_open, t.open_but_dry,
       round(100.0 * t.hits_100k / greatest(b.inner_count + b.open_count, 1), 2) hit_rate_100k_pct,
       round(100.0 * t.hits_1m / greatest(b.inner_count + b.open_count, 1), 2) hit_rate_1m_pct,
       t.listed_last_30d, t.hits_100k_last_30d, t.hits_100k_last_90d,
       round((extract(epoch FROM now()) - b.last_create_ts) / 86400.0, 1) days_since_launch,
       round((extract(epoch FROM now()) - t.last_hit_ts) / 86400.0, 1) days_since_hit,
       t.n_platforms, t.main_platform,
       dd.decu_picks, dd.decu_realized, dd.decu_win
FROM dev_books b JOIN t USING(creator) LEFT JOIN dd USING(creator)
""")
con.execute(f"COPY dev_scores TO '{os.path.join(DATA, 'devs', 'dev_scores.parquet')}' (FORMAT PARQUET)")

show("universe", """SELECT count(*) devs, sum(launches_capped::INT) capped, sum((implausible_peaks>0)::INT) implausible, sum(hits_incomplete::INT) hits_incomplete, sum((hits_100k>=1)::INT) any_100k, sum((hits_1m>=1)::INT) any_1m,
 sum((hits_1m>=3)::INT) ge3_1m, sum((hits_100k>=5)::INT) ge5_100k, sum((days_since_launch<=7)::INT) active_7d, sum((days_since_launch<=30)::INT) active_30d FROM dev_scores""")
show("hit rate by launch-count band (median dev)", """SELECT CASE WHEN launches<=5 THEN 'a <=5' WHEN launches<=20 THEN 'b 6-20' WHEN launches<=100 THEN 'c 21-100' WHEN launches<999 THEN 'd 101-998' ELSE 'e 999+' END band,
 count(*) devs, round(median(open_ratio),3) med_open_ratio, round(median(hit_rate_100k_pct),2) med_hit100k_pct, round(avg(hits_1m),2) avg_hits_1m, round(median(days_since_launch),1) med_days_since_launch,
 round(median(med_bundler_open),3) med_bundler FROM dev_scores GROUP BY 1 ORDER BY 1""")
show("does decu overlap tell anything? (devs with >=20 decu picks)", """SELECT CASE WHEN hits_1m>=3 THEN 'a >=3 hits 1M' WHEN hits_1m>=1 THEN 'b 1-2 hits 1M' WHEN hits_100k>=3 THEN 'c >=3 hits 100K' ELSE 'd weaker' END power,
 count(*) devs, sum(decu_picks) picks, sum(decu_realized) realized, round(avg(decu_win),1) avg_win FROM dev_scores WHERE decu_picks>=20 GROUP BY 1 ORDER BY 1""")
show("A. craftsman list: <=100 launches, >=2 hits >=100K, launched in last 30 d, ranked by hits_1m, hits_100k, hit rate", """SELECT creator, launches, opens, hits_100k, hits_1m, best_ath, best_symbol, hit_rate_100k_pct hr100k, med_bundler_open bund, days_since_launch dsl, days_since_hit dsh, main_platform, decu_picks
 FROM dev_scores WHERE launches<=100 AND hits_100k>=2 AND days_since_launch<=30 ORDER BY hits_1m DESC, hits_100k DESC, hit_rate_100k_pct DESC LIMIT 25""")
show("B. factory list: >100 launches, ranked by hits_1m then hits_100k in last 90 d", """SELECT creator, launches, opens, hits_100k, hits_1m, hits_10m, best_ath, best_symbol, hit_rate_100k_pct hr100k, hits_100k_last_90d h90, med_bundler_open bund, days_since_launch dsl, decu_picks
 FROM dev_scores WHERE launches>100 ORDER BY hits_1m DESC, hits_100k_last_90d DESC LIMIT 25""")
show("C. hot now: >=1 hit >=100K in last 30 d, ranked by hits_100k_last_30d, best_ath", """SELECT creator, launches, hits_100k_last_30d h30, listed_last_30d l30, hits_100k, hits_1m, best_ath, best_symbol, med_bundler_open bund, days_since_launch dsl, main_platform
 FROM dev_scores WHERE hits_100k_last_30d>=1 ORDER BY hits_100k_last_30d DESC, best_ath DESC LIMIT 25""")
con.close()
