# Mini-phase 2.3 — system profile (offline, from the 2.1 index + 2.2 enrichment)

Source tables: `activity` (159,245 trade legs), `positions` (36,293 tokens, built by
`scripts/profile.py` with cost basis rebuilt from buy legs, average-cost and FIFO), `tx*`
(Helius). Full printout: `data/profile.out`. Everything below is measured behaviour of the
public wallet; the companion wallet is covered in 2.3a below.

## 0. Reconciliation of the rebuilt P&L against GMGN

| Window | GMGN realized | Ours (avg cost) | Ours (FIFO) | Note |
|--------|---------------|-----------------|-------------|------|
| all-time | $1,914,604 on $9.89M cost | **$2,037,409** | $2,038,345 | +6%; GMGN's cost base is $1.7M higher (it appears to count fees and the quote-asset legs) |
| 30 d | $350,052 | $458,888 | $459,767 | our window attributes by last sell and includes the quote-asset legs GMGN nets out |
| 7 d | $94,164 | $183,379 | $184,160 | same, plus a 5-hour window offset |

The all-time figure agrees to within 6%, win rate agrees (GMGN 59–62% vs ours 64.8% overall,
61–72% by month), and FIFO ≈ average cost because positions live for seconds. Everything below
uses the average-cost figures.

## 1. What the system does, in one paragraph

It buys freshly launched pump.fun tokens on the bonding curve at a median market cap of
$5.5K–8K, with a **fixed clip of 1.4 → 2.9 SOL** (stepped up over the year), then fires
**$1–2 "bump" buys every ~25 seconds** while the token moves, and **sells the entire position
in one transaction a median 27 seconds after the first buy**. 75% of positions are closed
within 60 seconds and 99.9% are closed. Losers are cut in 16–23 seconds. The router charges
1.2% per side. It runs 17–21 hours a day, every day, with a fixed daily 6–7 hour quiet window
(06:00–13:00 UTC). Profit is turnover: 36K positions, 65% winners, median winner +4% to +23%
depending on hold, no single token above $55K of the $2.0M.

## 2. Entry

| Metric | Value |
|--------|-------|
| Entry market cap (price × supply at first buy), p25 / p50 / p75 | $4.2K / **$5.6K–7.3K** / $8–11K depending on month |
| Entries under $30K mcap | 95–99% every month |
| Venue at entry | pump.fun bonding curve (80% of all trades), PumpSwap post-migration rising to 20% by Aug 2026 |
| Quote asset of first buy | SOL 32,408 tokens ($7.0M, 65.5% win), WSOL 2,212, USD1 598, USDC 511, PUMP 85, then tokenized stocks and majors from Aug 2026 |
| Positions per month | 1.5K (Nov) → 4–5K (Jan–Mar, Aug); 428–763 transactions per active day |

Entry band vs outcome (all year):

| Entry mcap | Tokens | Buy USD | Realized | Win % |
|------------|--------|---------|----------|-------|
| < $10K | 28,387 | $5.76M | **$1,604K** | 66.6 |
| $10–30K | 6,851 | $1.93M | $337K | 57.8 |
| $30–60K | 530 | $190K | $21K | 53.4 |
| $60–300K | 288 | $135K | $10K | 40 |
| > $300K | 145 | $196K | $56K | 62.1 (the quote-asset legs) |

The edge is concentrated below $10K market cap, i.e. within the first minutes of a curve's life.

## 3. Sizing: a fixed clip plus bumps

| Month | Median main clip (SOL) | p25–p75 (SOL) | Median main clip (USD) |
|-------|------------------------|---------------|------------------------|
| Nov 2025 | 1.369 | 1.36–1.52 | $190 |
| Dec 2025 – Jan 2026 | 1.447 | 1.45–1.96 | $185–201 |
| Feb – May 2026 | **1.956** | 1.55–2.93 | $159–173 |
| Jun 2026 | 2.151 | 1.96–2.93 | $158 |
| Jul – Sep 2026 | **2.933** | 1.96–2.93 | $216–292 |

The SOL amounts are discrete (1.369, 1.447, 1.956, 2.933 SOL), i.e. bot configuration values,
not hand-typed sizes. 85% of all buy USD is in $100–300 clips; positions total $50–300 for 87%
of tokens (median $189, p90 $330, max $33K on the PUMP quote asset).

**Bumps.** 55,423 buys are under $5 (median $0.9–2.5). They are not probes: the sequence is
`buy $162 → buy $1 → buy $1 …`, the first dust buy lands a median 9–30 s after the main clip
and further ones every 25 s (p25 7 s, p75 51 s). Only 128 of 55,423 dust buys are followed by a
dust sell; 2,162 by a second main clip. The share of positions that get bumps rose from 20–30%
(Nov–Dec 2025) to 60–74% (Feb–May 2026) and 53–64% since.

Bumps and outcome, Feb–Sep 2026:

| Bumps after the clip | Tokens | Buy USD | Realized | Win % | Median ROI | Median hold |
|----------------------|--------|---------|----------|-------|------------|-------------|
| none | 10,674 | $2.11M | $99K | 52.7 | +1.3% | 13 s |
| 1–2 | 11,176 | $2.40M | $430K | 64.9 | +9% | 32 s |
| 3–5 | 4,083 | $1.08M | $477K | 80.7 | +33% | 73 s |
| > 5 | 1,877 | $0.73M | **$670K** | **92.9** | **+77%** | 159 s |

Two readings are consistent with this and ring C (2.6) is designed to separate them: (a) the
bumps *cause* the move, by keeping the token at the top of pump.fun's "bumping" feed and
re-triggering the copy-trade bots that follow this wallet (the spam swarm seen in 2.0); or (b)
the bot bumps *while* the token is already moving and stops when it stalls, so bump count is a
proxy for momentum that was there anyway. Either way, no-bump positions are close to
break-even and the money is made on the 16% of positions that get three or more bumps.

## 4. Exit

| Metric | Value |
|--------|-------|
| First buy → first sell, p10 / p50 / p75 / p90 | 8 s / **27 s** / 59 s / 2 min |
| Closed within 5 s / 60 s / held > 1 h | 5.1% / 75.4% / 0.1% |
| First sell = full exit | 83.2% of positions; 79.2% sell ≥ 80% of proceeds in one transaction |
| Sells per position | median 1 |
| Fully sold | 98.8% of positions; only 26 tokens ($663) never sold |
| Losers: hold before cut | ROI −20..0%: 23 s · −50..−20%: 20 s · −90..−50%: 16 s · < −90%: 4 tokens |

Outcome by hold time:

| Hold (first buy → last sell) | Tokens | Realized | Win % | Median ROI |
|------------------------------|--------|----------|-------|------------|
| < 1 min | 25,038 | $524K | 59.0 | +4.3% |
| 1–10 min | 9,819 | **$1,035K** | 76.3 | +23% |
| 10–60 min | 944 | $292K | 84.2 | +41% |
| 1–24 h | 250 | $118K | 84.8 | +57% |
| > 1 day | 216 | $69K | 83.3 | +15% |

The exit rule reads as time-and-momentum, not price target: hold while it moves (bumping),
dump on the first stall. Winners are held longer than losers, and the long tail is tiny.

## 5. Outcome distribution and where the money came from

| ROI bucket (avg cost) | Tokens | Realized |
|-----------------------|--------|----------|
| > 5x | 130 | $202K |
| 2–5x | 2,730 | $1,019K |
| 0–2x | 20,505 | $1,338K |
| −50–0% | 12,337 | −$459K |
| < −50% | 565 | −$63K |

Gains $2.57M, losses −$0.53M. Top 10 tokens = $54K (2.7% of profit), top 100 = 11%, top 1,000
= 40%. In the skill's vocabulary this is a ⚙️ **turnover grind**: no lucky coin, no pick-and-size.

## 6. Cadence and schedule

- 152,090 slots hold one of his transactions, 4,215 hold two, 11 hold three: one order at a
  time, no bundles.
- Inter-transaction gap: p10 4 s, median 20 s, p90 206 s; 14.5% of transactions land within 5 s
  of the previous one.
- Every month has 28–33 gaps longer than 6 hours and a maximum gap of 15–17 hours: **one daily
  pause**, 06:00–13:00 UTC (share of trades per hour: 0.0–1.7% from 06 to 13 UTC, 7–8% per hour
  from 17 to 22 UTC). Weekends are slightly busier than weekdays (15–16% vs 13–14% per day).
- Trades per active day: 152 (Nov) → 763 (Mar) → 715 (Aug), 18–21 distinct hours a day.

The schedule matches a bot that is switched on when the operator is awake (US evening peak)
rather than a fully unattended process, and it never idles more than one sleep cycle.

## 7. Drift over the year (positions opened per month)

| Month | Opened | Realized | Win % | Median first sell | Median entry mcap | Median position |
|-------|--------|----------|-------|-------------------|-------------------|-----------------|
| 2025-11 | 1,534 | $32K | 58.5 | 22 s | $7.3K | $204 |
| 2025-12 | 2,660 | $91K | 63.0 | 22 s | $6.6K | $189 |
| 2026-01 | 4,090 | $225K | 69.1 | 24 s | $7.1K | $207 |
| 2026-02 | 4,534 | $247K | 71.6 | 24 s | $5.6K | $163 |
| 2026-03 | 5,056 | $224K | 64.0 | 20 s | $5.6K | $176 |
| 2026-04 | 2,930 | $136K | 63.0 | 23 s | $5.2K | $168 |
| 2026-05 | 3,253 | $167K | 61.1 | 27 s | $5.4K | $179 |
| 2026-06 | 2,888 | $144K | 63.6 | 37 s | $6.2K | $190 |
| 2026-07 | 3,191 | $191K | 60.9 | 38 s | $6.9K | $228 |
| 2026-08 | 4,320 | $328K | 61.5 | 34 s | $7.3K | $239 |
| 2026-09 (14 d) | 1,638 | $241K | 71.1 | 59 s | $8.0K | $308 |

Three regimes: **ramp** (Nov–Jan: clip 1.4 SOL, 20–30% of positions bumped, fee-heavy
execution), **peak grind** (Feb–May: clip 1.96 SOL, 60–74% bumped, 20-second exits, priority
fee cut in March), **larger and slower** (Jun–Sep: clip 2.9 SOL, holds 34–59 s, entry mcap
drifting up to $8K, StonkFun and stock-quoted curves added in September).

## 8. Quote-asset legs

The exotic quote assets are a September 2026 development and small in P&L: PUMP as quote
$10.8K, DOGE $3.3K, SPYx $1.9K, NVDAx $1.4K; ARB, LINK, PYTH near zero. They are routing
legs of stock-quoted curves, not a second strategy. 89% of positions show two quote symbols
only because GMGN labels the buy side `SOL` and the sell side `WSOL`.

## 2.3a — the companion wallets: a bag-parking loop, not a hidden exit

GMGN activity for `4hQZ1GtLTvAzetszCcWrb8zxiuVvEt85Bb7y6VNzA2ve` (12 months): **197 trade
legs** and 9,687 transfer legs. It barely trades; it holds. `scripts/companion.py`, output
`data/companion.out`. Note: the GMGN transfer endpoint ignores the slot cursor, so one chunk
already holds everything (the 13-chunk pull was stopped after confirming identical rows).

The loop, measured on 3,674 tokens (Feb–Sep 2026):

| Step | Timing / size |
|------|---------------|
| Main wallet buys the clip | t = 0 |
| Main sends **47% of the bag** to the companion | median **8 s** after the first buy |
| Main keeps bumping ($2.28 median buys, 10,348 legs while parked) | |
| Companion sends **100% of it back** | median **47 s** after it left (p90 4.6 min); 3,673 of 3,674 came back |
| Main sells everything | median **2 s** after it returns |
| Companion sells the token itself | 3 tokens, $305, i.e. never |

Why park half the bag for a minute: he buys a median **4.8% of supply** (p90 6.7%), which
would put the wallet at the top of every holders panel his buyers look at (his own thread tells
followers to inspect holders). Parking 2.3% of supply in a second wallet keeps each address
near 2.3–2.5% during the bump phase, and the bag is reunited only for the single dump
transaction. Whatever the intent, the effect on the public numbers is nil: nothing is sold
elsewhere, so the wallet's P&L is complete and GMGN's `wash_trader` tag is not explained by
this loop. Round-trip tokens are his committed trades: 77.6% win rate and +22.6% median ROI
versus 62.4% and +7.2% for the rest, held 62 s vs 24 s, 4 buys vs 2.

A third wallet, `9k4kV6mHCcnTbqLrudMH8kQyKeMYJye62WaraHaGAqr5`, receives 1,222 transfers from
the companion ($119K, 1,186 tokens, since March 2026) and 124 from the main wallet, and sends
1,370 back to the main wallet; `6yCLZ7XW…` sees 56–59 transfers each way. Their role (a second
parking slot when the bag is larger, or a dust sink) is left to 2.6, which will parse their
transactions; at $126K total moved it cannot change the P&L picture.

## 9. What 2.3 leaves to the next mini-phases

- **Causality of the bumps** (2.6, slot-level): do other wallets buy in the seconds after his
  clip and each bump, and how much of his sell fills against them.
- **Selection** (2.4): which of the ~5K curves per month he picks and why (creator, age at
  entry, launch metadata) — entry mcap alone says "first minutes of the curve".
- **Companion wallet** (2.3a, in progress): 3,674 tokens moved to `4hQZ…`; on the public
  wallet those tokens show $920K bought, $1.38M sold, $463K realized, so the main wallet sells
  more than it bought on them — inventory comes back from the companion. Appended below once
  its activity is loaded.
