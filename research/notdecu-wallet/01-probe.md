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

## Ready for 2.1

`scripts/clients.py` now has `slot_cursor()`, the direct walker with 429 handling
(`reset_at` aware), and the batched Helius parser. Nothing has been pulled beyond the probes.
