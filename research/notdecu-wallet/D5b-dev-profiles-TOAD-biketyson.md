# D5b — Surface profiles: the TOAD dev (slingoor) and the biketyson dev (0xkgc) — 2026-09-15 11:05 UTC

Sources: pump.fun user and balance endpoints (`/users/{wallet}`, `/balance/summary/{wallet}`), GMGN
`portfolio stats` 7 d and 30 d, the created-tokens book, `token info` per launch, and the D4/D5a klines.
Raw JSON in `data/devs/profiles/`. Read-only.

## 1. Identity

| | TOAD dev | biketyson dev |
|---|---|---|
| Wallet | `5YRgrP3mjGzrzirYYN5HAQH19cTYREYwGxW6XRJQUzij` | `BFmgjdgepMxNnEyndQZC68Db3ajPdD3V8is1bQbdj4h4` |
| pump.fun username | **slingoor** | **0xkgc** |
| X (Twitter) | **@slingoorio** | **@0xkgc** |
| pump.fun bio | "be patient for the perfect opportunity // nfa" | "i deploy ideas, the market decides if theyre wanted / nfa" |
| pump.fun followers / following | **124,644** / 1 | 3,917 / 297 |
| pump.fun group | "Synagogue" — **admin** | "Synagogue" — member |
| GMGN tags | arbitrager, axiom, **top_dev**, top_renamed, top_followed | arbitrager, padre |
| GMGN followers / remarks | 5,923 / 6,894 | 123 / 139 |
| Wallet first seen by GMGN | 2026-06-24 | 2026-06-09 |
| Funded from | `EnAbM9Be…` (unlabelled) | `HWBL4PAu…` (unlabelled) |

They are connected: same pump.fun group (slingoor runs it), and one of 0xkgc's tokens links to
@slingoorio. 0xkgc looks like a member of slingoor's circle rather than an independent operator; if
slingoor's crowd is what moves both devs' launches, their runs are not independent bets.

## 2. Live since, and how much they trade

| | slingoor | 0xkgc |
|---|---|---|
| First listed launch | 2026-06-29 | 2026-08-26 (book lists 100 of 141 launches; the unlisted 41 are his lowest-ATH ones and may be older) |
| Last launch | 2026-09-12 16:27 UTC | 2026-09-14 13:50 UTC |
| Span of the listed book | 74 days | 18 days |
| Launches (book counters) | 28 (32 listed) | 141 (100 listed) |
| pump.fun portfolio value today | **$636K** across 43 tokens, 0.05 SOL free | $92.5K across 26 tokens, 157 SOL free |
| Portfolio unrealized | +$58K on $578K cost (+10%) | −$3.7K on $96K cost (−4%) |
| GMGN 30 d trading: buys / sells | 6,567 / 5,629 | 592 / 379 |
| 30 d cost deployed | $4.03M | $84K |
| **30 d realized P&L** | **+$831K (+22%)** | +$11.5K (+18%) |
| 7 d realized P&L | −$66K (−6%) on $1.31M | +$5.3K (+16%) on $25K |
| 30 d tokens traded / win rate | 2,057 / **19.5%** | 292 / **50.6%** |
| 30 d outcome buckets (loss >50% / 0–2× / 2–5× / >5×) | 678 / 981 / 5 / 4 | 12 / 174 / 4 / 1 |
| Avg holding period | ~5.3 days | ~2.4 days |

Reading: slingoor is first a **whale trader** (2,000 tokens a month, $4M deployed, +$831K realized in
30 days with a 19% win rate, i.e. a few large winners paying for hundreds of small losses) and a launcher
second. 0xkgc is a **small, disciplined trader** (50% win rate, few large losses) who launches at high
cadence. Neither wallet's launch fee income is meaningful next to the trading: the book shows ~$4.0K
(slingoor) and ~$0.6K (0xkgc) of `total_fee`.

## 3. Launch record (wins and losses as a dev)

Hit = launch reached $100K market cap at any time; graduated = left the bonding curve; dead = fewer than
20 holders today.

| | slingoor | 0xkgc |
|---|---|---|
| Listed launches | 32 | 100 (of 141) |
| Graduated | 22 (69%) | 9 |
| Hits ≥ $100K | **14** (50% of launches) | 7 (5% of 141) |
| Hits ≥ $1M | **4**: TOAD $23.6M, OFFICIAL $3.8M, sling $1.2M, LIZARD $1.1M | 1: biketyson $11.5M |
| Dead today | 12 (38%) | 78 (78%) |
| Creator status today | sold out on 27, holds 1 | sold out on 94, holds 6 |
| Own conduct in own coins (full walk) | 8 dumps / 27 traded coins, median first sell **11 min**, sells at ~1.2× | **0 dumps / 66 traded coins**, median first sell 22 min |
| Median hit shape (D4) | first minute $38K → 2.7× at 15 min → peak 5.4× at 33 min → 24 h close 0.56× | first minute $6K → 3.8× at 15 min → peak 7.2× at 19 min, 24 h peak 17× at ~10 h → 24 h close 2.5× |
| Scalp expectancy per launch (D5a, with Twitter tell) | +33% (80% hit rate on tell launches) | +93% (September sample) |

### Weekly timeline (launches / hits / graduated)

| Week | slingoor | 0xkgc |
|---|---|---|
| W27 (Jun 29) | 5 / 1 / 4 | — |
| W31–W32 (Jul 27–Aug 9) | 5 / 4 / 4 (TOAD on Aug 8) | — |
| W34 (Aug 17) | **5 / 5 / 5** | — |
| W35 (Aug 24) | 3 / 2 / 3 | 36 / 0 / 1 |
| W36 (Aug 31) | 3 / 1 / 2 | 44 / 2 / 3 (biketyson on Sep 3) |
| W37 (Sep 7) | **11 / 1 / 4** | 19 / 5 / 4 |
| W38 (Sep 14) | — | 1 / 0 / 1 |

slingoor's cadence changed in week 37: 11 launches in a week (his previous max was 5) with one hit.
That is the "fading" in D5a and it coincides with his 7-day trading loss. 0xkgc went from 0 hits in
36 launches to 5 hits in 19 launches as his volume dropped; his best week is his most selective one.

### What they launch

- slingoor: his own brand (TOAD, sling, OFFICIAL, LIZARD) plus reaction tokens; tokens link to
  @slingoorio and assorted meme accounts. Launch hours spread across the day, clusters at 02–05 and
  15–22 UTC.
- 0xkgc: reaction tokens to X posts (Elon Musk posts twice, @blknoiz06 i.e. Ansem, @aislop_), a
  pump.fun community link, and the biketyson brand. Launch hours peak at 05–07 and 19–21 UTC.

## 4. What this means for tracking

- **slingoor is the tracked dev, 0xkgc is the scalp.** slingoor's edge is his 124K-follower crowd:
  a launch with a Twitter link hit 80% of the time. The risk is his own state: he is on an 11-launch,
  1-hit week and a −$66K trading week; if week 38 looks like week 37, the crowd is thinning.
- **0xkgc's edge is entry price**, not audience: a $6K first minute on a dev whose launches reliably
  pop to 3–4× by minute 15. His hit rate is low (5%) but his misses still paid on a scalp in September.
  A second month is needed before treating that as a property rather than a streak.
- **Correlation**: same group, same circle. A watchlist of both is closer to one bet on slingoor's
  audience than to two devs. Size accordingly.
- Follow-on checks that need only public feeds: @slingoorio and @0xkgc post history around each launch
  (does the post precede the create event, and by how much); the "Synagogue" group's member list for
  other launchers in the circle.
