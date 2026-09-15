# Phase 3 — dev farming: plan and mini-phases (started 2026-09-14 19:20 UTC on the user's call)

Goal: a data-driven top-dev list and, per dev, the shape of their token runs, so that later entries and
exits can be styled to match. Everything here is read-only research. No swaps, no orders, no signing.

## What "top dev" means here (working definition, to be refined by D3)

A creator address whose launches, over a long enough book, **repeatedly** reach a high market cap and
stay tradeable, with low bundling and a conduct record that does not dump at open. Four axes:

| Axis | Measured by | Source |
|---|---|---|
| Power | count and rate of launches with ATH ≥ $100K / ≥ $1M; best ATH; median ATH of graduated launches | `created-tokens` (`token_ath_mc`, `is_open`), `token info` (`ath_price`) |
| Consistency | graduation ratio (`open_ratio`), spacing between launches, share of launches that stay open with pool ≥ $4K | `created-tokens` (`inner_count`, `open_count`, `last_create_timestamp`, `pool_liquidity`) |
| Conduct | creator sell timing in own coins, `creator_token_status`, liquidity drains | `gmgn-dev-score/dev_score.py` (activity walk), trenches rows |
| Hygiene | `bundler_rate`, `top70_sniper_hold_rate`, `fund_from` cluster, twitter rename/dup counts, `cto_flag` | trenches rows, `token info`, `created-tokens` |

## Tooling leverage (from the closed pump.fun research and the GMGN skills)

| Need | Tool | Weight / cost | Notes |
|---|---|---|---|
| Every graduation, live, with creator stats | `gmgn-cli market trenches --type completed --sort-by created_timestamp` | 3 per call; polled every 5 min | 60 rows per call, spans ~14 min; rows carry `creator_created_count/open_count/open_ratio`, `fund_from_address`, `bundler_rate`, `creator_token_status`, `complete_cost_time`, `twitter_create_token_count` |
| Top-ATH tokens of the last 7 d | `market trending --order-by history_highest_market_cap --max-created 7d` (1h/6h/24h × Pump.fun/all) | 1 per call; hourly | 96 rows/call, 12 with ATH ≥ $1M at the first snapshot |
| A dev's book | `portfolio created-tokens --wallet <dev> --order-by token_ath_mc` | 2 per dev | ≤101 tokens, `inner_count` caps at 999; per token: ATH mcap, holders, is_open, create_ts, bundler_rate, total_fee, coin_creator_fee |
| A dev's conduct | `.claude/skills/gmgn-dev-score/dev_score.py sol <dev>` | ~20–60 calls per dev | only for the shortlist |
| Seed universe | 2.4 token-info cache (19.9K tokens, 7,928 creators so far) | 0 | 2,076 creators with ≥ 2 graduations |
| Live launch feed (later, when acting) | pump.fun `/coins?sort=created_timestamp` or Pump-program logs + `CreateEventBc` | 0 | `knowledge/pumpfun-stack.md` §6 |
| Per-token ATH and curve state (audit) | pump.fun `coins-v2/{mint}`; GMGN `token info`; `market kline` | 0 / 1 / 2 | kline for run shape (time to ATH, drawdown) |

Rate budget: the 2.4 pull uses ~2.3 weight/s until ~20:25 UTC; the dev pull adds ~1.3 weight/s and the
watcher < 0.05 weight/s. Measured ceiling before 429s is ~8.5 weight/s.

## Mini-phases

| # | Name | What | API | Time | Output | Gate |
|---|---|---|---|---|---|---|
| D0 ✅ | Recon | probe trenches/trending/created-tokens shapes; profile the seed universe | 6 weight | done 19:15 | this file, `data/devs/probe/` | shapes confirmed |
| D1 🔄 | Dev universe | `dev_watch.py`: trenches completed every 5 min + trending hourly, running from 19:22 UTC; union with the 2.4-cache creators into `candidates.jsonl` | ~1 weight/min | continuous; first useful cut after 24 h | `data/devs/trenches_completed.jsonl`, `trending.jsonl`, `candidates.jsonl` | ≥ 1 day of graduations captured |
| D2 🔄 | Dev books at scale | `dev_pull.py --pull`: created-tokens for every candidate (2,076 now, growing with D1), then `--load` → `dev_books`, `dev_tokens` | 2 per dev; ~2.3 s/dev | ~80 min for the seed set, then incremental | `dev_books.parquet`, `dev_tokens.parquet` | ≥ 95% of candidates fetched |
| D3 | Dev scoring | per-dev metrics on the four axes; rank; sensitivity to the seed bias (decu-picked vs live-seen devs); shortlist top 100 → top 30 | 0 | offline, half a day | `D3-dev-ranking.md`, `dev_scores` table | ranking reproducible from the tables |
| D4 ✅ | Deep audit top 28 → top 10 (`D4-top-dev-audit.md`) | `dev_score.py` conduct/power; `token info` on every launch of the top 30 (ATH, migration time, bundler, sniper, holders, fund_from); kline around each run (seconds to ATH, drawdown, how long above 2× open); wallet clustering by `fund_from_address` | ~30 × (dev_score 40 + tokens 30 + kline 2×30) ≈ 4,000 weight | 1–2 h of pulls | `D4-top-dev-audit.md`, `dev_runs` table | 10 devs with a run profile each |
| D5a ✅ | Top-10 → top-5 with loss side, full walks, tells, expectancy per style (`D5a-top5.md`) |
| D5 | Run-shape model | per dev: typical open mcap, time to ATH, ATH multiple, retrace depth, where the dev sells, holder growth curve → entry/exit style per dev (time-based, multiple-based, dev-sell-based) | 0 | offline | `D5-run-shapes.md` | rules with hit rates on the dev's own history |
| D6 | Watchlist spec | how the live feed detects a watched dev's launch (creator match on the poll/log feed), what to check in the first seconds (bundler, sniper hold, quote mint, mayhem), sizing for $50 | 0 | offline | `D6-watchlist-spec.md` | spec only; **no actions** |
| D7 | Paper replay | replay D5 rules over the last 30 days of the top-10 devs' launches with pump.fun fees and realistic entry delay | ~200 kline | half a day | `D7-paper-replay.md` | positive expectancy after fees, or back to D3 |

Later phases (live paper-trading on the feed, then a $50 test) only on the user's call.

## Standing rules

- Read-only until the user says otherwise. No swap, order, cooking, create-coin, or signing calls.
- All pulls resumable from disk; raw JSONL is gitignored, parquet and candidate lists are committed.
- Every number in a report names its table and snapshot time; live listings are re-snapshotted, never overwritten.
- Dev identity is the creator address. Multi-wallet devs are clustered by `fund_from_address` in D4, not assumed.
