# Mini-phase 2.2 — Helius enrichment of every transaction (2026-09-14 13:37–14:40 UTC)

176,482 unique signatures (156,468 trades + 20,014 transfers) parsed with Helius
`parseTransactions`, 100 per call, 63 minutes, **100% parsed, 0 failed transactions, 0 trade
signatures missing**. Tables in `data/notdecu.duckdb`: `tx` (one row per transaction),
`tx_programs` (top-level and inner program per transaction), `tx_native_out` (every SOL transfer
leaving the wallet). Raw cache `data/helius/parsed.jsonl` (1.9 GB, gitignored). Analysis script:
`scripts/analyze_tx.py`.

## 1. The execution stack, dated

| Period | Top-level router program | Notes |
|--------|--------------------------|-------|
| Sep – mid-Nov 2025 | `F5tfvbLog9VdGUPqBDTT8rgXvTTcq7e5UiGnupL1zvBq` + `BLUR9cL8HqZzu5bSaC7VRX25RCG93Hv3T6NPyKxQhWUT` (two programs per trade) | different upgrade authorities from everything later: a first bot vendor |
| from 2025-11 (285 tx), 100% by Dec 2025 | **`FLASHX8DrLbgeR8FcfNV1F5krxYcYMUdBkrP1EPBtxB9`** | 151,847 of 156,468 trades (97%); upgradeable, last upgraded slot 446,668,178 (13 Sep 2026); upgrade authority `AxDepcBgxQXcEYTQokwbyR6D8R4fxF6aAQMs8Kr2TmjW` |
| Feb – Apr 2026 (inner) | `Gz9VPiSLQYbvKyb3jZPjNfyA6n4T4qVFUuAukgL964nL` | **same upgrade authority as FLASHX8** → a module of the same vendor, retired after April |
| Jan – Aug 2026 (inner, low volume) | `ExA6GYhHAeRNMWVNLrDir1SKPJZcZA2oaPq6uriSmxfJ` | separate authority; peaks June (1,315 tx) |
| Sep 2026 | `term9YPb9mzAsABaqN71A4xdbxHmpBNZavpBiQKZzN3` (166 tx top-level) | new, coincides with the StonkFun regime |

None of these programs appear in public program-name maps; they are private bot routers. The
GMGN tags `photon` / `axiom` / `padre` describe where the wallet was *seen*, not what signs its
trades: 97% of the year is one private router.

## 2. What the router costs him

SOL leaving the wallet inside trade transactions, by recipient class:

| Recipient | Owner | Tx | SOL | Median / tx | Reading |
|-----------|-------|----|-----|-------------|---------|
| 8 rotating PDAs (`2ApLdw…`, `EqGzow…`, `ECDrSz…`, `HkJYry…`, `5vPNE6…`, `3Tu1Y9…`, `BfFX9r…`, `3Pvqoz…`) | **owned by the FLASHX8 program** | ~18K each, 144K total | **1,824 SOL ≈ $184K at $101** | 0.0135 SOL on sells, 0.0003 on buys | the router's fee: **median 1.2% of trade value on both sides** ($101K on sells, $83K on buys) |
| `6E2GiNVz…` | closed (temporary WSOL account) | 29,555 | 12,569 SOL | 0.027 | the SOL leg of buys passing through a wrap account, not a fee |
| `Hj2hjN…` | pump.fun program PDA | 34,414 | 84.5 SOL | 0.00037 | pump.fun fee |
| `AVmoTt…`, `62qc2C…`, `7hTckg…`, `7VtfL8…` (+3 more) | pump.fun fee recipients (from the pump docs) | ~11K each | ~67 SOL each | 0.00116 | pump.fun protocol fee |
| Jito tip accounts | — | 1,528 all year, 1,489 of them Nov 2025–Jan 2026 | 0.45 SOL | 0.00005 | **he does not use Jito bundles** after January |

Router fee by month (SOL): Jan 165 · Feb 218 · Mar 267 · Apr 154 · May 179 · Jun 192 · Jul
229 · Aug 301 · Sep (14 d) 118. Against GMGN's $1.91M realized all-time, the router alone took
roughly 10% of gross profit; the whole fee stack (router + pump.fun + base/priority) about 12%.

## 3. Priority-fee policy changed in March 2026

| Month | Median tx fee (lamports) | p90 |
|-------|--------------------------|-----|
| Nov 2025 – Feb 2026 | 4,005,000 – 5,005,000 (≈ 0.004–0.005 SOL, $0.40–0.50 per tx) | 5,005,000 |
| Mar – Apr 2026 | **55,000** | 4,005,000 |
| May – Jul 2026 | 130,000 – 220,000 | 635,000 – 705,000 |
| Aug – Sep 2026 | 55,000 | 705,000 / 5,005,000 |

A 70–90× cut in the typical priority fee in March 2026 with no drop in volume: either the bot
changed its landing strategy (private RPC / staked connection) or the trades stopped needing to
win the block. This is the "gas collapse" seen in `02-index.md`, now dated to the first week of
March. Trades per slot: 152,090 slots with one of his transactions, 4,215 with two, 11 with
three — no bundling.

## 4. Venues, by Helius `source` (trade transactions)

| Month | pump.fun curve | PumpSwap | Raydium LaunchLab | Jupiter | other/transfer-shaped |
|-------|----------------|----------|-------------------|---------|-----------------------|
| 2025-11 | 4,281 | 103 | 19 | 6 | 10 |
| 2025-12 | 6,918 | 203 | 240 | 0 | 111 |
| 2026-01 | 12,183 | 673 | 744 | 0 | 623 |
| 2026-02 | 15,515 | 1,331 | 49 | 0 | 224 |
| 2026-03 | 19,325 | 1,978 | 2,078 | 0 | 1,137 |
| 2026-04 | 11,644 | 1,487 | 333 | 1 | 1,210 |
| 2026-05 | 12,042 | 1,787 | 243 | 0 | 2,216 |
| 2026-06 | 9,029 | 2,111 | 293 | 0 | 2,496 |
| 2026-07 | 12,238 | 3,149 | 329 | 9 | 1,851 |
| 2026-08 | 17,210 | 4,472 | 77 | 124 | 8,092 |
| 2026-09 | 5,592 | 2,361 | 946 | 209 | 6,906 |

80% of the year's trades hit the **bonding curve itself**, i.e. pre-graduation. PumpSwap
(post-migration) grows from 2% to 20% by August. The "other" column is the non-SOL-quoted legs
(USDC/USD1/stock-quoted curves routed through Raydium CLMM, Meteora, Jupiter) that Helius parses
as transfers; it explodes in Aug–Sep 2026.

## 5. The companion wallet `4hQZ1GtLTvAzetszCcWrb8zxiuVvEt85Bb7y6VNzA2ve`

- All 3,934 outbound transfers to it are **plain Token-2022 transfer transactions signed by the
  main wallet**, sent a median 0.6 minutes *before* the last buy of that token and, for 3,653 of
  3,931 tokens, before the main wallet's first sell of it. All 4,041 inbound transfers are signed
  by `4hQZ…`, not by him.
- GMGN on `4hQZ…`: funded 2025-05-08 with 10 SOL from `H8sMJSCQ…`, tag `axiom`, no X account,
  7.07 SOL balance, **452 buys / 500 sells all-time, $758K cost basis sold, $35K realized**;
  last 30 days 21 buys / 12 sells but 1,118 "tokens" (received bags).
- So bags worth about $646K left the public wallet for a wallet that has sold $790K of tokens
  in its life. How much of the public P&L is affected is a 2.3 question; the companion's own
  activity (small: ~1K trades, ~8K transfers) will be pulled there.

## 6. The missing cost basis is not the transfers

Of 49,657 sell legs, 5,361 (11%, $1.22M of sell proceeds) carry no `buy_cost_usd`. 5,298 of
those tokens *were* bought on the main wallet before the sell, and only 17% had any inbound
transfer first. GMGN's per-leg cost field is simply unreliable; 2.3 rebuilds cost basis from
the buy legs (per token, average and FIFO) and includes the companion transfers as inventory
moves.

Also seen: median buy leg is **$2.60** (p10 $0.84, p90 $221, p99 $336, mean $75). Most buys
are tiny probes; the size distribution is a central 2.3 topic.

## Gate

98%+ parsed: **passed** (100%). Next: 2.3 system profile, offline.
