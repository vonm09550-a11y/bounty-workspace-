# D6 — Launch anatomy of the Synagogue launchers: pipeline, schema, agent briefs (2026-09-15)

Goal: for each launch by a group launcher, reconstruct who did what in the first 30 minutes at
transaction level, so that the window *before* the KOL-and-copier wave can be measured, not guessed.
Read-only throughout. No agent may call any GMGN swap/order/cooking/create command or sign anything.

## Pipeline (loop 1 = slingoor 32 launches + retardmode 19)

| Phase | Runner | Parallel? | Input | Output |
|---|---|---|---|---|
| A. Raw pull | `scripts/anatomy_pull.py` (Helius, one process) | no (one key) | `data/anatomy/launches_loop1.jsonl` | `data/anatomy/loop1/<dev>/<mint>.rows.jsonl`, `.parsed.jsonl`, `.meta.json` |
| B. Anatomy | general-purpose agents, one per launcher, offline | yes | A's files + `data/anatomy/member_wallets.json` + GMGN traders tags (see brief) | `data/anatomy/loop1/anatomy_<dev>.parquet` + `SUMMARY_<dev>.md` |
| C. Cross-launch | one agent, offline, after both B | no | B's parquet | `data/anatomy/loop1/cross.parquet` + `SUMMARY_cross.md` |
| D. Judgment | me | | C's summary | `D6-anatomy-loop1.md`, next loop's targets |

Forks are not available in this session; B and C agents receive this file as their brief. They write
only under `data/anatomy/loop1/`, never commit, and end with a numeric summary.

## Fixed schema for the per-launch anatomy table (Phase B output, one row per launch)

| Column | Definition |
|---|---|
| dev, creator, token, symbol, create_ts, hit, ath_mc | from the launch list |
| n_tx_30m, n_buys_30m, n_sells_30m, n_wallets_30m | counts in the window (rows with err=false) |
| first_tx_ts, create_sig | earliest transaction (the create, if present) |
| dev_first_buy_s, dev_first_buy_sol, dev_first_buy_tokens, dev_supply_share | creator's first buy: seconds after create, SOL, tokens, share of 1e9 supply |
| dev_same_slot_buyers | number of other wallets buying in the same slot as the dev's first buy (bundle proxy) |
| dev_fee_lamports_med | median fee the creator paid on his own txs in the window (priority-fee proxy: fee − 5000 per signature) |
| dev_first_sell_s, dev_sold_share_30m | creator's first sell (s after create) and share of his bought tokens sold within the window |
| member_first_buy_s, member_first_buyer, member_buyers_n, member_buy_sol_30m | first buy by any of the 32 member wallets (excluding the creator): lag, who, how many members bought, total SOL |
| member_first_sell_s, member_sell_sol_30m | first member sell lag and total member SOL out |
| kol_first_buy_s, kol_buyers_n, kol_buy_sol_30m | same for GMGN-tagged wallets (renowned / kol / smart_degen) from `token traders` if the agent fetches them; NULL if not fetched |
| outside_first_buy_s, outside_buy_sol_5m, outside_buy_sol_30m | buys by wallets that are neither creator, member nor tagged |
| sol_in_1m, sol_in_5m, sol_in_15m, sol_in_30m | cumulative SOL spent on buys at each mark |
| peak_ts_s, peak_price_sol, peak_mult_vs_dev | minute of the highest trade price (SOL per token, from sol_spent/token_amount on buys) and its multiple over the dev's first-buy price |
| top10_wallets_share_30m | share of net tokens bought (buys − sells) held by the ten largest net buyers at the end of the window |
| n_wallets_net_long_30m | wallets still net long at the end of the window |

Prices: SOL per token = sol_spent / token_amount on buys (token_amount is in whole tokens as parsed by
Helius; supply is 1e9). Seconds are relative to `create_ts`. Every column is NULL when unmeasurable,
never 0.

## Brief for a Phase B agent (one launcher)

You are given: this file; `data/anatomy/loop1/<dev>/*.rows.jsonl` and `*.meta.json`;
`data/anatomy/member_wallets.json` (32 wallets, username, role); DuckDB `data/notdecu.duckdb`
(read-only; tables `dev_tokens`, `dev_launches`, `dev_runs` for the launch's book row and klines).
Tasks: (1) build the anatomy table above for every launch of your dev, using pandas/duckdb; (2) write it
to `data/anatomy/loop1/anatomy_<dev>.parquet`; (3) write `SUMMARY_<dev>.md` with: coverage (launches,
truncated windows), medians of every lag/size column for hits vs non-hits, the five launches with the
earliest member entry and the five with the latest, and anything that looks like a data problem.
Optional, only if under 60 GMGN calls total and sequential with a 1.5 s gap: `gmgn-cli token traders
--chain sol --address <mint> --tag renowned --limit 20 --raw` on the hits only, to fill the kol_* columns.
Never call swap/order/cooking/create. Do not commit. End your report with the numeric summary.

## Brief for the Phase C agent

Inputs: both anatomy parquet files, `member_wallets.json`, `dev_tokens`. Produce `cross.parquet` and
`SUMMARY_cross.md` with: (1) the member graph: for each member, how many of each launcher's launches
they bought, median lag, median size, whether they sold within the window; (2) launcher fingerprints:
dev first-buy share, bundle proxy, fee level, launch hour, cadence, first-sell timing, per dev; (3)
hit vs non-hit at minute 1 and minute 5: which measurable columns separate them (report the
distributions, not a model); (4) the entry window: for hits, the distribution of (member_first_buy_s,
outside_first_buy_s, peak_ts_s) and how much of the peak multiple was still ahead at 30 s, 60 s,
120 s after create. Same rules as Phase B.
