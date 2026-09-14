# Mini-phase 2.1 — full activity index (pulled 2026-09-14 10:31–12:39 UTC)

Source: GMGN `GET /v1/user/wallet_activity`, `type=buy,sell`, thirteen slot-range chunks
(368M → 447.5M), 7,969 pages, 0.82 s/page after the retry fix. Loaded by
`scripts/build_index.py` into `data/notdecu.duckdb` (`activity` table, also
`data/activity.parquet`). Raw JSONL (169 MB) is gitignored and rebuildable.

## Totals

| Metric | Value |
|--------|-------|
| Legs (rows) pulled | 159,380, of which 135 chunk-boundary duplicates removed → **159,245** |
| Distinct transactions | **156,468** |
| Distinct tokens | **36,293** |
| Span | 2025-09-17 22:12 → 2026-09-14 04:40 UTC |
| Buy legs / sell legs | 109,588 / 49,657 |
| Buy USD / sell USD | $8.21M / $10.23M |

Legs ≈ transactions everywhere except August–September 2026: the multi-leg, non-SOL-quoted
regime (USDC, USD1, PUMP, tokenized-stock quotes) is recent. Across the year 94% of legs are
quoted in SOL/WSOL; USDC 4,024, USD1 2,075, PUMP 621, then a long tail of 50+ quote mints.

## Monthly table

| Month | Legs | Tokens | Buy legs | Sell legs | Buy USD | Sell USD | Realized on sell legs* | Gas USD |
|-------|------|--------|----------|-----------|---------|----------|------------------------|---------|
| 2025-09 (from 17th) | 97 | 30 | 51 | 46 | 9.1K | 9.8K | 0.7K | 332 |
| 2025-10 | 264 | 77 | 144 | 120 | 18.9K | 22.0K | 3.1K | 743 |
| 2025-11 | 4,414 | 1,534 | 2,545 | 1,869 | 327.8K | 360.2K | 32.2K | 6,330 |
| 2025-12 | 7,424 | 2,660 | 4,080 | 3,344 | 564.0K | 641.3K | 73.4K | 5,870 |
| 2026-01 | 14,073 | 4,094 | 8,659 | 5,414 | 956.9K | 1,195.0K | 213.8K | 11,176 |
| 2026-02 | 16,991 | 4,535 | 11,063 | 5,928 | 812.2K | 1,059.2K | 236.0K | 7,218 |
| 2026-03 | 23,652 | 5,057 | 17,342 | 6,310 | 1,051.9K | 1,276.3K | 189.3K | 5,327 |
| 2026-04 | 13,748 | 2,934 | 9,939 | 3,809 | 574.7K | 710.8K | 110.6K | 1,710 |
| 2026-05 | 14,780 | 3,263 | 10,376 | 4,404 | 693.8K | 860.7K | 127.7K | 1,145 |
| 2026-06 | 12,784 | 2,895 | 8,609 | 4,175 | 601.2K | 745.8K | 115.4K | 269 |
| 2026-07 | 16,159 | 3,254 | 11,471 | 4,688 | 782.6K | 974.9K | 144.5K | 823 |
| 2026-08 | 22,312 | 4,340 | 16,016 | 6,296 | 1,147.3K | 1,451.2K | 214.2K | 978 |
| 2026-09 (to 14th) | 12,547 | 1,675 | 9,293 | 3,254 | 665.2K | 925.0K | 99.5K | 1,094 |

\* `cost_usd − buy_cost_usd` summed over sell legs that carry a cost basis — see reconciliation.

Observations that shape 2.3 (facts, not conclusions):
- The ramp is Nov 2025 → Jan 2026 (4K → 14K legs/month), a plateau of 13K–24K legs/month
  since, peaks in March and August 2026. The density sampling had overestimated March 6×; the
  real month count is 23.6K legs.
- Buy legs outnumber sell legs 2.2:1 all year: many buys per position, fewer, larger exits.
  `is_open_or_close`: 38,350 buys open a position, 71,238 add to one; 38,667 sells close a
  position, 10,990 reduce.
- Gas spend collapsed from ~$6–11K/month (Nov–Feb) to ~$0.3–1K/month (Jun–Sep) while volume
  rose: the execution stack changed early 2026. Router/fee mapping in 2.2/2.3 will date it.
- Distinct tokens per month: 1.5K–5K. Ring B (Feb–Sep) universe ≈ 28K tokens.

## Reconciliation against GMGN's own stats

| Window | GMGN buys / sells | Ours (tx, token) buys / sells | Δ |
|--------|-------------------|-------------------------------|---|
| 7d | 5,175 / 1,809 | 5,803 / 2,040 | +12% / +13% — our window ends at pull time (04:40 UTC) and GMGN's at query time 09:33 UTC on a different day boundary; the 30d figure is the fair test |
| 30d | 18,210 / 6,927 | 18,581 / 7,069 | **+2.0% / +2.1%** — passes the gate |

Realized P&L does **not** reconcile from per-leg fields and must not be read from them:

| Window | GMGN `realized_profit` | Σ (`cost_usd − buy_cost_usd`) over sell legs | Why |
|--------|------------------------|----------------------------------------------|-----|
| 7d | $94.2K | $54.6K | 936 of 2,040 sell legs (46%) have **no `buy_cost_usd`** and drop out of the sum |
| 30d | $350.1K | $233.5K | 2,125 of 7,072 sell legs (30%) without cost basis |
| all | $1.91M | $1.56M | same |

So 2.3 reconstructs cost basis itself from the buy legs (per token, per quote, FIFO and
average) and then re-checks against GMGN's 7d/30d/all-time realized figures. `buy_cost_usd`
is kept only as a cross-check where present.

## Transfer and liquidity legs (pulled 12:39–13:22 UTC, 2,808 pages)

GMGN returned 279,828 rows for `transferIn/transferOut/add/remove`, but only **21,529 are
distinct**: the transfer cursor repeats pages ~13×, so the loader dedupes on the full row. No
`add`/`remove` (liquidity) legs exist: he never adds or pulls liquidity. `transfers` table in
DuckDB, `data/transfers.parquet`.

| Type | Distinct legs | Tokens | Counterparties |
|------|---------------|--------|----------------|
| transfer_in | 17,391 | 13,844 | 5,503 senders |
| transfer_out | 4,138 | 3,692 | 13 recipients |

Monthly: inbound drops explode in Aug–Sep 2026 (7,119 and 5,783 legs, most of them unsolicited
dust from thousands of senders; only 3,825 of the 13,844 inbound tokens were ever traded).
Outbound starts in earnest in March 2026.

**Two counterparties dominate and look like companion wallets of the same operator** (lead
for 2.3 and 2.6, not a conclusion):

| Address | Out legs / tokens / USD | In legs / tokens | Active |
|---------|-------------------------|------------------|--------|
| `4hQZ1GtLTvAzetszCcWrb8zxiuVvEt85Bb7y6VNzA2ve` | 3,934 / 3,674 / $646K | 4,041 / 3,696 | 2026-02-21 → today |
| `9k4kV6mHCcnTbqLrudMH8kQyKeMYJye62WaraHaGAqr5` | 124 / 114 / $15K | 1,370 / 1,295 | 2025-12-13 → today |

3,689 of the tokens he bought have an outbound transfer: bags move to `4hQZ…` and (mostly)
come back. Whether that wallet sells, sweeps dust, or stages positions decides how his public
P&L should be read, so 2.3 reconciles positions with these legs included and 2.2 parses the
transfer transactions too.

Gate: **passed** (row counts within 2% on the 30-day window). Next: 2.2 Helius enrichment of
156,468 signatures (~1,565 parse calls, ~15 min).
