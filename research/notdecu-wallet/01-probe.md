# Mini-phase 2.0 — scope probe (2026-09-14)

Goal: confirm the numbers behind the phase 2 plan before spending the budget. All raw outputs
in `data/probe/`.

## Findings

| Question | Answer | Evidence |
|----------|--------|----------|
| Rows per GMGN activity page | 20, fixed, whatever `--limit` says | 100-page walk, 2,000 rows |
| Seconds per page via `gmgn-cli` | 1.25 s (subprocess startup dominates) | 100 pages in 124.8 s |
| Seconds per page via direct HTTP (`GET /v1/user/wallet_activity`, `X-APIKEY` + `timestamp`/`client_id` query) | **0.67 s** at 0.35 s pacing, rows identical to the CLI | 20 pages in 13.3 s, tx order equal |
| Cursor format | base64 of `<slot><8-digit index>:0::` — **a cursor can be constructed for any slot**, so the year can be pulled in independent slot-range chunks and any month re-pulled alone | `NDQ2NDg2…` → `44648602900041048:0::`; `slot_cursor(420_000_000)` → 2026-05-15 rows |
| How far back GMGN activity goes | **oldest row 2025-09-13** (slot ≈ 368M). Slots 250M–360M return 0 rows. The wallet is older (created 2024-10-26, the thread's "228d" card predates this), so GMGN keeps ~12 months. The available history is exactly the year we planned | jump probes |
| Density across the year (one page per month, rows/hour) | Oct 2025 ≈ 0 · Nov 21 · Dec 11 · Jan 1 · Feb 63 · Mar 272 (burst) · Apr 31 · May 41 · Jun 38 · Jul 46 · Aug 32 · Sep 45; the last 35 h ran at 57 | `data/probe/density_samples.json` |
| Estimated 12-month row count | ~200K–260K rows (buy+sell) ≈ 10K–13K pages ≈ **2–2.5 h** at 0.67 s/page, resumable | rows vs all-time trade counts (164K trades, multi-leg rows ≈ 1.5×) |
| Helius parse throughput | 1,000 signatures in 10 calls, 17.8 s, 100% parsed, 100% `feePayer == wallet` | `data/probe/helius_parsed.jsonl` |
| Helius credit cost per parse call | **not readable from the API** — please read "credits used" on the Helius dashboard now; 21 parse calls + ~10 RPC calls have been made since the key was created | dashboard |
| Router | `FLASHX8DrLbgeR8FcfNV1F5krxYcYMUdBkrP1EPBtxB9` on 1,000/1,000 sampled trades | parsed sample |
| Venues in the 1,000-tx sample | PumpSwap 404, pump.fun curve 200, Raydium LaunchLab 114, Jupiter 2, plus 280 legs Helius labels as plain transfers (USDC-quoted curve legs) | parsed sample |
| Quote assets in 2,000 rows | USDC 614, WSOL 421, PUMP 261, SOL 160, then a long tail: SPCX, WBTC, ZEC, wXMR, DOGE, PYTH, ANTHRP, ANSEM, tokenized stocks (SPYx, QQQx, NVDAx, MSTRx, MCDx, AMZNx, CRCLx) … 50+ distinct quote mints | walk100 |
| Launchpads in 2,000 rows | Pump.fun 1,099 · **stonkfun 553** · unlabeled 348 | walk100 |

## What changes in the plan

1. **Chunk by slot, not by cursor chain.** Twelve monthly chunks from slot 368M to 447M
   (≈6.5M slots/month), each a resumable walk with its own state file, stopped when rows cross
   the chunk's lower slot bound. A failed or banned chunk resumes alone.
2. **Direct HTTP walker** replaces the CLI for bulk pulls (`scripts/clients.py`,
   `GmgnActivity(direct=True)`); the CLI stays for spot checks.
3. **Full-life = 12 months.** There is nothing older to pull from GMGN. Earlier context comes
   only from `profits --period all` totals.
4. **Quote-asset dimension is first-class.** The system trades pump.fun / stonk.fun curves quoted
   in many assets, not SOL-only; ring A must reconstruct positions per (token, quote) and
   convert every leg to USD via `cost_usd`.
5. **Row budget ≈ 2× the first estimate** (multi-leg rows). Wall time ≈ 2.5 h for 2.1, still
   inside one session if run in the background.

## Addendum — launchpad mix and core range (same day)

**Launchpad mix, sampled 3 pages per month across the year** (`data/probe/density3.json`) and
the 35-hour, 255-token sample (`walk100.jsonl`, joined to Helius-parsed programs):

| Launchpad (GMGN label) | Share of rows across the 12 months | Underlying programs | Note |
|------------------------|-------------------------------------|---------------------|------|
| Pump.fun | ~93–100% of rows in every sampled month | pump curve `6EF8…`, PumpSwap `pAMM…` | the core |
| letsbonk (Bonk) | 0–8 rows per 60-row month sample, ≈ 2–3% | Raydium LaunchLab `LanMV9…` | minor |
| stonkfun | 0 until September 2026; 553 of 2,000 rows (27%) and $35K of $121K buys in the last 35 h | Raydium LaunchLab + PumpSwap/CLMM pools, quoted in USDC / PYTH / ANTHRP / SPYx … | **new regime**: StonkFun moved to LaunchLab on 2026-09-06 |
| bags, pump_agent | 2–5 rows in a few months | — | negligible |
| unlabeled (348 rows) | quote-asset legs (USDC↔WSOL↔ARB…) via Raydium AMM/CLMM, Meteora DLMM, Jupiter | — | routing, not picks |

So "he goes with new pairs on pump.fun" holds for the whole year; Bonk is a rounding error;
the one thing that changed is the last week, when he added StonkFun launches. The Raydium
LaunchLab IDL (`refs/idl/raydium_launchpad.json`, program `LanMV9sAd7wArD4vJFi2qDdfnVhFxYSUg6eADduJ3uj`,
events `PoolCreateEvent`/`TradeEvent`) covers both letsbonk and StonkFun, and `env_check.py`
now validates it. No separate Bonk tooling is needed.

**Row density by month** (median rows/hour of three samples → estimated rows):

| Month | rows/h | est. rows | Month | rows/h | est. rows |
|-------|--------|-----------|-------|--------|-----------|
| 2025-09 | 0.5 | 400 | 2026-04 | 31 | 22K |
| 2025-10 | 0.3 | 200 | 2026-05 | 29 | 21K |
| 2025-11 | 21 | 15K | 2026-06 | 39 | 28K |
| 2025-12 | 11 | 8K | 2026-07 | 38 | 27K |
| 2026-01 | 22 | 16K | 2026-08 | 62 | 45K |
| 2026-02 | 42 | 30K | 2026-09 (14 d) | 63 | 45K |
| 2026-03 | 209 | 150K | | | |

Rough 12-month total ≈ 400K rows (multi-leg rows ≈ 2.4× the 164K all-time trades), i.e.
~20K pages ≈ 3.7 h at 0.67 s/page. March 2026 alone is ~37% of the rows.

**Core range.** His own timeline: wallet funded 2024-10-26; "228 d" card (+$243.6K, 50% win
rate) ≈ June 2025; thread of 2026-04-30 shows $1.0M realized with an April 2026 monthly
calendar; GMGN today shows $1.91M all-time, +$350K in the last 30 days. GMGN activity begins
2025-09-13 and September–October 2025 hold < 600 rows combined. Therefore:

- **Ring A (breadth): 2025-11-01 → 2026-09-14**, ten and a half months, which is every active
  month GMGN can give us. The $250K → $1M run he advertised is roughly Nov 2025 → Apr 2026
  inside it; the +$0.9M since the thread is May → Sep 2026.
- **Rings B and C (depth): 2026-02-01 → 2026-09-14**, eight months holding ~90% of the rows,
  stratified **per calendar month** so results line up with the monthly cards he posts, with
  March 2026 (the burst) and 6–14 September 2026 (StonkFun regime) analysed as their own
  regimes rather than averaged in.

## Ready for 2.1

`scripts/clients.py` now has `slot_cursor()`, the direct walker with 429 handling
(`reset_at` aware), and the batched Helius parser. Nothing has been pulled beyond the probes.
