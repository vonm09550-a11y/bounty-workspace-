# 05 — Selection profile (mini-phase 2.4, the last decu run) — 2026-09-14 20:20 UTC

What he picks, from GMGN `token info` on every token he opened since 2026-02-01, joined to `positions`.
Pull: 27,902 tokens, 186.7 min, 0.42 s/token, **0 errors, 100% coverage**. Tables: `tokens`
(`data/tokens.parquet`), joined view in `scripts/selection.py`, raw output `data/selection.out`.
Token-level fields (creator counts, holders, bundler, status) are **as of today**, not as of the pick.

## 1. Where and when he buys

| Launchpad | Tokens | Buy $ | Realized $ | Win % |
|---|---|---|---|---|
| Pump.fun | 25,123 (90%) | 5.59M | 1.51M | 65.0 |
| pump_agent | 1,168 | 236K | 44K | 59.7 |
| letsbonk | 819 | 182K | 35K | 57.9 |
| stonkfun | 353 | 154K | 48K | 57.5 |
| bags, bonkers, ray_launchpad, meteora, believe | 241 | 50K | 7K | 48–66 |

Age of the token at his first buy (seconds after creation):

| p10 | p25 | p50 | p75 | p90 | ≤30 s | ≤2 min | ≤10 min | >1 h |
|---|---|---|---|---|---|---|---|---|
| 3 | 5 | 9 | 26 | 128 | 77.1% | 89.6% | 95.5% | 3.2% |

He is a **launch-second buyer**: three quarters of positions open within 30 s of the create transaction,
at a median entry mcap of ~$5K (the curve floor is ~$4K). The window widened over the year: median age
7 s in Feb–May, 12–14 s in Jun–Sep, p75 from 16 s to 58 s.

| Age band | Tokens | Realized $ | Win % | Median ROI | Median entry mcap |
|---|---|---|---|---|---|
| ≤15 s | 18,356 | 1.07M | 65.2 | 10.1% | $5.1K |
| 15–60 s | 5,098 | 292K | 62.8 | 7.5% | $7.8K |
| 1–5 min | 2,652 | 178K | 65.1 | 8.3% | $10.4K |
| 5–30 min | 746 | 53K | 63.1 | 6.7% | $12.7K |
| 30 min–1 d | 329 | 15K | 55.9 | 1.6% | $15.8K |
| >1 d | 629 | 67K | 57.6 | 3.8% | $15.7K |

Edge decays with age; anything after 30 minutes is close to break-even for him.

## 2. What became of the tokens

| Status today | Tokens | Share | Realized $ | Win % |
|---|---|---|---|---|
| never migrated (dead on the curve) | 22,612 | 81.3% | 732K | 62.0 |
| migrated to PumpSwap/Raydium | 5,188 | 18.7% | 944K | 74.9 |

The 19% that graduated produced 56% of the P&L. On those, **holding into or past migration** beat selling
on the curve: 3,018 held → $767K, 2,159 sold before → $178K. Holders today: 80% of his tokens have
< 20 holders (dead); tokens now at 20–100 holders won 77.9% of the time, 100–500 76.3%, ≥500 73.1%.

## 3. Creators

| Creator repeat among his picks | Creators | Tokens | Realized $ |
|---|---|---|---|
| seen once | 8,893 | 8,893 | 494K |
| 2–3 picks | 1,035 | 2,355 | 161K |
| 4–10 picks | 429 | 2,548 | 163K |
| >10 picks | 292 | 14,004 (50%) | 857K (51%) |

Half of his volume is from 292 creators he bought more than ten times. The top one, `bwamJ…`, has
**161,908 launches and 1,498 graduations** (0.9%); he bought 1,034 of them for $55K realized at 58.5%.
These are token factories; he buys their output because it is the bulk of the feed, not because he
selects them.

| Creator launch count (today) | Tokens | Realized $ | Win % | Median ROI |
|---|---|---|---|---|
| first launch | 4,579 | 210K | 64.7 | 8.1% |
| 2–5 launches | 1,988 | 171K | **69.5** | **13.6%** |
| 6–20 | 1,663 | 141K | 68.4 | 12.6% |
| >20 (factory) | 19,580 (70%) | 1.15M | 63.4 | 8.4% |

Other creator signals: `creator_close` (creator already sold out) on 96% of tokens; `creator_hold` on
572 tokens with 71.7% win. Whether the creator had ever graduated a token made no difference (64.0% vs
65.5% win).

## 4. Quality signals (as of today) vs his outcome

| Signal | Reading |
|---|---|
| Bundler share | 80% of tokens show 0 bundling; tokens with <10% bundling won 72.8% vs 62.3% at zero — a little organised buying at open marks a real launch, not a dead one |
| Sniper hold >30% | 1.2% of tokens |
| Rat traders >10% | 0.4% |
| Duplicate image | 35.9% |
| CTO flag | 22.6% |
| Any smart-money wallet | 53.0% |
| Any renowned wallet | 100% (artefact: his own wallet is tagged, so every token he touched counts) |
| Socials | twitter+website 65.0% win, twitter only 64.2%, none 54.1%, website only 50.3% |

## 5. What this says (for strategy 2)

1. He is a **spray-and-hold-the-graduates** operator: enter in the first seconds on nearly every launch
   his router sees, cut in ~27 s when nothing happens, and keep the 19% that migrate. Selection is
   almost absent; edge is latency plus a fixed exit rule. That confirms the strategy-1 verdict.
2. The **only selection signal that moved his win rate was creator history**: devs with 2–20 prior
   launches beat both first-timers and factories by 5–6 points of win rate and ~60% more median ROI.
   That is the seam dev farming works on, and phase 3 is built on it.
3. Age at entry ≤ 60 s is where his ROI lives. A watchlist that fires on a known dev's create event and
   enters within a minute is inside that window without a private router.
4. Migration is the payoff event. Whatever run-shape model phase 3 produces should be judged on
   graduation rate and post-migration ATH per dev, not on curve pops.

## 6. Decu track: state

2.0–2.4 complete. Remaining original items (2.5 dev filter, 2.6 micro-structure, 2.7 timeline, 2.8
copyability, 2.9 synthesis) are folded into phase 3 where relevant (2.5 → D2/D3) or parked. Roughly
85% of the system is reversed: what is left is slot-level micro-structure and follower slippage, which
matter only for copying him, which is not the plan.
