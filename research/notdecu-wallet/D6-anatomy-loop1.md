# D6 — Launch anatomy, loop 1: slingoor and retardmode at transaction level (2026-09-15 16:00 UTC)

Every transaction in the first 30 minutes of 51 launches (slingoor 32, retardmode 19), pulled from
Helius on the bonding-curve account, the AMM pool account, and for TOAD a block-by-block scan.
Trades re-derived from token-balance changes (not the fee payer), so router-paid and non-SOL-quoted
trades are included. Phase B tables: `data/anatomy/loop1/anatomy_<dev>.parquet`; Phase C:
`cross_*.parquet/csv`, `SUMMARY_cross.md`. Scripts: `anatomy_pull.py`, `anatomy_blockscan.py`,
`anatomy_build.py`, `anatomy_cross.py`. Read-only; nothing traded. All rules below are **in-sample**
on 14 + 4 hits.

## 1. The reading

1. **Both devs buy in their own create transaction, every time** (28/28, 19/19). Nothing is visible
   earlier than that buy; the next visible thing, seconds later, is whether the dev sells into the
   first buyers.
2. **The miss is a dump, the hit is a hold.** slingoor dumped 11 of 14 misses within 5–217 s (median
   17 s); retardmode 12 of 15 within seconds (median 7.5 s) and none of his 4 hits. Misses peak at
   4–50 s; hits peak at 15–25 minutes.
3. **Size of the self-buy is the second tell.** Hits: slingoor 58% of supply (30 SOL), retardmode 42%
   (20 SOL). Misses: 39% and 10%. Size alone is not enough: slingoor's misses also carry 39% and
   three of retardmode's misses carried 38–43% and were dumped in 5–73 s.
4. **Outsiders are first, members are late.** Outside wallets buy in the create slot on every launch;
   the first group-member buy on a hit comes at a median 184 s (earliest 38 s). Only 14 of 32
   members ever bought a loop-1 launch. The group is not the first wave; the dev's own crowd is.
5. **Two members carry the group's participation**: ibuycoin (owner) bought 11 launches, 10 hits,
   median entry 115 s; trenchdigger bought 12, 10 hits, median entry 235 s. Both enter at 6× and
   13× the dev's average price, i.e. after the first leg, and exit only partly inside the window.
6. **There is still a run after the group is in.** From the price at 60 s, the best price still to
   come inside the window was a median 3.6× on hits (slingoor 3.6×, retardmode 5.1×); from 120 s
   2.6×; from 300 s 2.3×. Four hits peaked in the last five minutes of the window, so these are
   lower bounds on the run and upper bounds on what a perfect exit could take.
7. **slingoor's curve is a formality.** 18 of 28 launches graduate the bonding curve within 60 s
   (median 4 s) on hits and misses alike; the bundle fills it. Graduation speed is his habit, not a
   signal. retardmode's hits graduate in 8–20 minutes and only one miss ever graduates.
8. **Priority fee is a weak third tell on slingoor**: 72K lamports on the create tx of hits vs 35K on
   misses. On retardmode fees are small and uninformative; his tell is the 01 UTC hour (7 of 19).

## 2. Rules measured on the data (in-sample)

| Launcher | Rule, decidable by | Hits caught | Misses passed |
|---|---|---|---|
| slingoor | dev share ≥ 35% and no dev sell by 60 s | 7 of 13 | 1 of 12 |
| slingoor | + at least 2 other buyers in the dev's slot | 6 of 13 | 0 of 12 |
| slingoor | no dev sell by 300 s (alone) | 11 of 13 | 2 of 12 |
| slingoor | no dev sell by 300 s and ≥ 200 wallets by 5 min | 9 of 13 | 1 of 12 |
| retardmode | dev share ≥ 35% and no dev sell by 60 s | 3 of 4 | 1 of 15 (dumped at 73 s) |
| retardmode | dev share ≥ 35% and no dev sell by 120 s | 3 of 4 | 0 of 15 |
| retardmode | no dev sell by 300 s (alone) | 4 of 4 | 3 of 15 |

The miss that passes the 60-second rule on each dev is the one he dumped between 60 and 217 s;
waiting to 120 s removes it on retardmode and costs nothing on slingoor. The hit no rule catches is
retardmode's PEACE (12.5% self-buy, peaked after the window).

## 3. What an entry at each mark had ahead of it (hits, price relative to the dev's average price)

| Mark | slingoor: price at mark | best still ahead (median) | retardmode: price at mark | best still ahead |
|---|---|---|---|---|
| 30 s | 8–13× | 4.1× | 1.0–2.4× | 12× (n=4) |
| 60 s | 5–122× (median ~13×) | 3.6× (n=12) | 1.3–4.0× | 5.1× (n=4) |
| 120 s | | 2.6× | | 4.9× |
| 300 s | | 2.3× | | |

Reading: on slingoor the dev's bundle bought at the curve floor and the price at 60 s is already
5–120× his cost, so his profit is not available to anyone; what is available is the 2–4× that still
formed over the next 10–25 minutes. On retardmode the price at 60 s is close to his cost and the
run ahead is larger, which is why his conduct score and expectancy were the best in D5a.

## 4. Members on these launches

| Member | Launches bought | Hits | Median entry | Entry price vs dev | Sold in window |
|---|---|---|---|---|---|
| ibuycoin (owner) | 11 | 10 | 115 s (min 38 s) | 6× | partly; realized −13 SOL, marked +24 |
| trenchdigger | 12 | 10 | 235 s (min 24 s) | 13× | partly; realized −9 SOL, marked +18 |
| stellanyang | 3 | 3 | ~1,000 s | | |
| bsol_x, waynecapital, badattrading, LowiqdegN, mitch, TMH, ibuyrunners, slingoor (on retardmode), others | 1–2 each | | 60–1,100 s | | |
| 18 members | 0 | | | | |

The two heavy members pick hits (10 of 11, 10 of 12): they see the same tell we measure, or they
know. Either way their entry comes after it, at 40–235 s, and they hold through the window.

## 5. Launcher fingerprints

| | slingoor | retardmode |
|---|---|---|
| Launches / span | 32 in 75 d, median gap 14 h | 19 in 314 d |
| Launch hours | spread; clusters 02–05 and 15–22 UTC | 7 of 19 in the 01 UTC hour |
| Self-buy on hits / misses | 58% / 39% of supply; 30 / 16 SOL | 42% / 10%; 20 / 3 SOL |
| Same-slot co-buyers on hits / misses | 5 / 1 | 0–5 either way |
| Create-tx priority fee, hits / misses | 72K / 35K lamports | 11–20K, flat |
| Curve graduation | within 60 s on 18/28 (median 4 s) | hits 8–20 min; misses never |
| Quote | 8 of 32 non-SOL (6 stonkfun/LaunchLab, 5 of them misses) | 4 of 19 non-SOL |
| Wallets in minute 1, hits / misses | 1,289 / 126 (30-min: 1,289 / 99) | 18 / — |

## 6. Caveats

- In-sample rules on 14 + 4 hits. The 60-s and 120-s thresholds must be replayed on loop 2 (0xkgc,
  mitch, jester, gampsito, hashbergers) before they are treated as a filter.
- Three slingoor hits are truncated at 30,000 tx (427–881 s); three LaunchLab launches end at
  migration (3–7 s) with no pool pull; four MPN rows have no trades and are excluded.
- KOL wallets were not tagged (no GMGN call), so "outside" includes KOLs and bots. RETARDIO carried
  15,066 fee-only no-op transactions from three bot wallets, excluded from trade counts.
- Prices are in quote units per token; SOL conversion for non-SOL quotes uses the window's own
  router rate.

## 7. Loop 2

1. Same pipeline on 0xkgc (7 hits + 40 misses), mitch and jester (top 20 by peak each), gampsito
   and hashbergers (top 10 + 10 misses): ~120 launches, 3–4 h of pulls. Tests whether the "hold at
   120 s" rule generalises across the group's launchers.
2. KOL tagging: one `token traders --tag renowned` pass on the 18 loop-1 hits (~20 GMGN calls) to
   split "outside" into KOL vs crowd and time the KOL leg against the member leg.
3. Callouts: the user's screenshots of the Callouts tab with timestamps, placed against
   `cross_entry.csv`, to see whether calls precede or follow the member buys.
4. A live detector spec (D6 feed): create event from a tracked wallet → read the self-buy share
   from the create tx → watch the dev's wallet for a sell for 120 s → decide. All read-only inputs
   exist already (pump.fun feed for creates, Helius parse for the create tx, the activity feed or
   program logs for the dev's sell).

---

## 8. Backtest v2 on loop 1 (in-sample), explicit cost model — 2026-09-15 16:40 UTC

`scripts/backtest_v2.py`. Costs charged per trade: pump.fun fee by venue and market-cap tier (curve
1.25%; pool 1.25% below 420 SOL mcap, stepping down to 1.00% at 4,420 SOL and 0.30% above 98,240 SOL),
base fee 5,000 lamports per signature, **empirical priority fee** (median paid by buyers in the 10 s
after the mark on that launch, floor 20,000 lamports), rent for the volume accumulator and ATA, price
impact from constant-product liquidity (curve: 30 SOL virtual + raised; pool: 85 SOL + net inflow),
and a 0.5% sandwich allowance per side. $50 per trigger at $100/SOL. Measured on the 51 launches:
priority fees at the mark were 0.0001–0.0004 SOL, impact 0.05–0.5%, so the fee that matters is the
1.0–1.25% pump.fun fee per side.

Base rule (self-buy ≥ 35%, hold at 60/120 s, trail 40%, hard stop 50%, 30-min window): 10 triggers,
7 wins, **+$1,120** (+$245 without PQ), worst −$28.

Grid (324 configs; `backtest_v2_grid.csv`): what moved the result, in order of robustness:

| Change | Effect on loop 1 |
|---|---|
| Enter at **180 s** instead of 60/120 s | fewer misses entered (the dev has dumped by then), peaks still 12–22 min away; ex-best P&L +$326 to +$761 vs +$245 |
| Self-buy floor **20%** instead of 35% | catches TOAD and OFFICIAL (12 of 18 hits vs 9) at the cost of 2–4 misses |
| Take-profit at **5×** | banks the big runners (PQ, RETARDIO) instead of riding them down |
| Trailing 50% vs 40% | slightly better; the runs are noisy |
| Hard stop 40% vs 50% | no difference |
| Time stop 15 min | cuts the worst loss to −$17 with 8 of 10 wins |

Best by P&L excluding the single best trade: mark 180 s, floor 20%, trail 50%, TP 5×, 14 triggers,
10 wins, +$4,049 (+$761 ex-best). Best by win rate: mark 180 s, floor 35%, trail 50%, TP 5×, time stop
15 min, 10 triggers, 8 wins, +$526 (+$326 ex-best), worst −$17.

**These are 324 configurations fitted to 18 hits.** Loop 2 (113 launches, five other launchers,
pulling now) is the out-of-sample test and nothing above is a rule until it survives that.
