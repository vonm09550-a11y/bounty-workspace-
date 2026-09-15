# D4 — Deep audit of the 28 shortlisted devs (2026-09-15)

Read-only research. Inputs: `token info` on all 2,088 listed launches, `portfolio stats` per dev,
`gmgn-dev-score/dev_score.py` per dev (conduct + power from the dev's own trades in his own coins), and
1-minute + 15-minute klines on the 394 launches that reached $100K. Script: `scripts/dev_audit.py`
(pulls) and `scripts/dev_audit_report.py` (tables `dev_launches`, `dev_conduct`, `dev_stats`, `dev_runs`,
`dev_audit`; raw output `data/devs/audit_report.out`). All "today" fields are as of the pull (08:33–09:40 UTC).

## 0. What D4 changes versus D3

D3 ranked devs by *power* (how often their launches reached $100K / $1M). D4 adds *conduct* (what the dev
does with his own supply at open), *identity* (funding wallet, GMGN tags), *launch hygiene* (creator status,
CTO, bundling, holders on the hits today) and *run shape* (what a hit actually looked like minute by
minute). Conduct reorders the list more than anything else: most factories that top the power ranking
dump their own bag within seconds on nearly every launch.

## 1. Conduct — the dev's own trades in his own coins (dev_score)

`dump_rate` = share of his coins with trades where he sold into the open; `sys` tier = systematic dumper;
`fastest_sell` = seconds from open to his first sell on any coin; `pull_x` = median multiple at which he
sells; `self_snipe` = share of launches where he bought in the creation block.

| Dev | Best | Band | Total | Conduct | Power | Dump tier | Dump rate | Fastest sell | Median sell | Pull × | Self-snipe |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `4LTJ…wRd4` | LAYOFF | **buyable** | 98.8 | 98.5 | 51.3 | rare | 0.06 | 8 s | 239 s | 1.08 | 0.94 |
| `EgJo…B2XY` | GrokBot | **buyable** | 91.1 | 86.3 | 65.9 | rare | 0.10 | 5 s | 305 s | 1.35 | 0.97 |
| `CzwW…quh4` | 1B | **buyable** | 79.6 | 77.0 | 63.0 | none | 0.00 | 1 s | 60 s | 0.37 | 1.00 |
| `9VXu…9h17` | CANCER | **buyable** | 79.4 | 79.4 | 49.3 | rare | 0.29 | 5 s | 37 s | 1.58 | 1.00 |
| `FzaK…T4Dw` | Bepe | mixed | 74.4 | 74.4 | 44.9 | rare | 0.25 | 1 s | 2 s | 1.29 | 1.00 |
| `FAX4…1aqp` | PETAH | mixed | 72.1 | 72.1 | 40.0 | rare | 0.17 | 10 s | 53 s | 1.56 | 1.00 |
| `HLez…ajhU` | S&P 500 | mixed | 65.5 | 65.0 | 52.7 | often_unproven | 0.00 (3 coins) | 115 s | 6,800 s | 1.53 | 0.33 |
| `GeBJ…Duwr` | SAPIJIJU | mixed | 63.7 | 58.2 | 68.4 | rare | 0.23 | 0 s | 27 s | 1.22 | 0.94 |
| `yHCx…6PRe` | ANSEM | mixed | 51.8 | 40.7 | 87.1 | rare | 0.26 | 7 s | 36 s | 1.59 | 0.96 |
| `5YRg…Uzij` | TOAD | avoid | 49.0 | 45.0 | 70.2 | sys | 0.20 | 5 s | 3,559 s | 0.96 | 0.90 |
| `G4kr…vtwU` | BABYTROLL | avoid | 45.2 | 45.0 | 51.0 | sys | 0.29 | 3 s | 12 s | 0.41 | 1.00 |
| `BY4h…Gtqc` | ICEMAN | avoid | 43.6 | 42.1 | 55.1 | sys | 0.97 | 0 s | 2 s | 2.54 | 1.00 |
| `96hq…3Cda` | Dancedoge | avoid | 45.0 | 45.0 | 47.8 | sys | 0.75 | 1 s | 2 s | 1.99 | 1.00 |
| `8gxN…jRsW` | FRANK | avoid | 45.2 | 45.0 | 51.2 | sys | 0.77 | 0 s | 1 s | 1.79 | 1.00 |
| `gVDX…dAkx` | MACRODUCK | avoid | 43.1 | 42.1 | 55.0 | sys | 0.82 | 0 s | 2 s | 1.82 | 0.98 |
| `7d3m…R2hw` | RAMEN | avoid | 45.0 | 45.0 | 38.9 | sys | 0.70 | 0 s | 6 s | 1.76 | 1.00 |
| `4Drt…kU2s` | MASK | avoid | 35.8 | 32.8 | 64.8 | often | 0.60 | 3 s | 5 s | 1.62 | 1.00 |
| `4QwJ…bDQs` | BUTT | avoid | 31.4 | 31.4 | 48.8 | sys | 0.90 | 1 s | 2 s | 2.26 | 0.99 |
| `Bmts…PiUU` | Morty | avoid | 45.2 | 45.0 | 50.9 | sys | 0.18 | 0 s | 2 s | 1.22 | 1.00 |
| `BFmg…j4h4` | biketyson | avoid | 45.3 | 45.0 | 53.5 | sys (forced) | 0.00 | 28 s | 1,298 s | 1.11 | 0.97 |
| `9VHB…x6T9` | IGW | avoid | 45.0 | 45.0 | 45.4 | sys | 0.91 | 3 s | 4 s | 2.60 | 1.00 |
| `Hr5e…tq1N` | LeMonke | avoid | 45.0 | 45.0 | 33.9 | sys | 0.35 | 1 s | 6 s | 1.36 | 0.96 |
| `AbVk…8aT9` | Pappy | avoid | 43.7 | 43.7 | 40.4 | sys | 0.93 | 2 s | 3 s | 3.40 | 1.00 |
| `9ChW…bH9q` | sami | avoid | 37.0 | 37.0 | 39.4 | often | 0.70 | 1 s | 3 s | 2.03 | 1.00 |
| `D8n8…anS4` | Stock | stay_away | 24.5 | 24.5 | 48.6 | sys | 0.82 | 1 s | 4 s | 2.92 | 1.00 |
| `49nS…YdLa` | popedoll | stay_away | 25.1 | 25.1 | 43.3 | often | 0.61 | 12 s | 16 s | 2.05 | 1.00 |
| `HyYN…nMFF` | Fartcoin | stay_away | 14.5 | 0.0 | 98.5 | often | 0.42 | 3 s | 15 s | 2.72 | 1.00 |
| `7ufm…VsmL` | maxxing | not scored | — | — | — | peak_implausible | — | — | — | — | — |

Reading:

- **Self-snipe is universal** (0.94–1.00): every dev on this list buys his own launch in the creation
  block. The difference is what he does next.
- **The factories with the highest hit counts are systematic dumpers**: ICEMAN, FRANK, MACRODUCK, BUTT,
  Pappy, Stock sell 75–97% of the time, within 1–4 seconds of open, at a median 1.8–3.4× the open. Their
  "hits" are the coins where the crowd outran the dump. Buying their opens means buying the dev's exit.
- **The buyable four** hold for minutes, not seconds: GrokBot sells at a median 305 s and 1.35×, LAYOFF at
  239 s and 1.08×, CANCER at 37 s and 1.58×. `1B` records zero dumps but a 0.37× median pull, i.e. he sells
  *below* open (he averages down or exits losers), and his book and trade history are both truncated.
- **ANSEM and SAPIJIJU** are the two factories whose conduct is only "rare" dumping (0.23–0.26) despite
  hundreds of launches; the score is held down by a factory penalty (34–45 points), not by conduct. Both
  move 70–88% of the supply of some coins to other wallets (`cross_wallet`), which is a bundling or
  team-wallet pattern and must be treated as an unknown, not a dump.
- **TOAD and BABYTROLL** fail on a mix of a systematic tier and, for BABYTROLL, a 0.41× median pull (sells
  under open). TOAD's median first sell is 59 minutes, so the "sys" tier comes from a handful of
  early exits; conduct is closer to the mixed band than the label suggests.
- `maxxing` was not scored: a reported peak above $50B on one coin invalidates the data, not the dev.

## 2. Identity and funding (portfolio stats)

| Dev | Best | Funded from | GMGN tags | Created (GMGN) | GMGN followers | SOL balance | 7-d realized |
|---|---|---|---|---|---|---|---|
| GrokBot | `6UWsi9…` (unlabelled) | arbitrager, **top_dev** | 32 | 894 | 0.1 | +$4.2K |
| Fartcoin | `39azUY…` (Pump.fun) | app_smart_money, smart_degen, top_followed | 497 | 25,531 | 276.9 | −$0.1K |
| ANSEM | `AWLDsA…` (HTX) | **top_dev**, top_followed, arbitrager | 868 | 15,140 | 100.4 | +$185.5K |
| TOAD | `EnAbM9…` (unlabelled) | **top_dev**, top_followed, arbitrager | 28 | 5,913 | 10.7 | −$65.0K |
| SAPIJIJU | `8xjigA…` (unlabelled) | **top_dev** | 376 | 1,545 | 107.3 | +$1.31M |
| BABYTROLL | `8RtiGu…` (unlabelled) | **top_dev**, arbitrager | 42 | 737 | 6.4 | +$1.9K |
| S&P 500 | `JDd3hy…` (unlabelled) | **top_dev**, padre | 9 | 27 | 0.4 | +$0.4K |
| CANCER | `5tzFki…` (Binance) | — | 69 | 1,435 | 0.1 | 0 |
| 1B | `ACj8Km…` (unlabelled) | gmgn, gmgn_go, arbitrager | 184 | 1,220 | 0.0 | +$79.1K |
| LAYOFF | `3vSW14…` (unlabelled) | arbitrager | 18 | 159 | 0.4 | +$0.3K |
| MACRODUCK | `u6PJ8D…` (Gate.io) | arbitrager | 350 | 2,199 | 23.1 | +$46.7K |
| maxxing | `GJRs4F…` (Coinbase) | gmgn_go, launchpad_smart; twitter `hubzify` | 353 | 2,793 | 249.0 | +$84.9K |

Six of the 28 were funded from the same Binance hot wallet (`5tzFki…`: ICEMAN, CANCER, FRANK, BUTT,
popedoll, LeMonke) and two from a Pump.fun wallet. Exchange hot wallets fund thousands of users, so this
is **not** evidence of a shared operator. No two shortlist devs share an unlabelled funder, so no
wallet-farm cluster exists inside the shortlist. GMGN's own `top_dev` tag lands on 7 of the 28.

## 3. Launch hygiene (token info on every listed launch, as of today)

| Dev | Launches listed | Migrated | Creator still holds | CTO | Median holders on hits | Twitter set | Duplicate image | Median gap between launches |
|---|---|---|---|---|---|---|---|---|
| GrokBot | 32 | 21 | 0 | 9 | 430 | 30 | 23 | 2.0 h |
| LAYOFF | 18 | 2 | 0 | 2 | 2,009 | 2 | 3 | 1.3 h |
| CANCER | 69 | 17 | 0 | 17 | 216 | 69 | 18 | 17 h |
| 1B | 100 | 55 | 0 | 28 | 108 | 100 | 28 | 15 h |
| S&P 500 | 12 | 3 | 1 | 1 | 1,289 | 3 | 6 | 0.1 h (batch) |
| Bepe | 76 | 9 | 6 | 28 | 530 | 76 | 16 | 3.2 h |
| PETAH | 90 | 22 | 0 | 61 | 225 | 90 | 16 | 14 h |
| SAPIJIJU | 100 | 88 | 1 | 31 | 31 | 97 | 37 | 3.1 h |
| ANSEM | 101 | 100 | 1 | 45 | 38 | 97 | 42 | 4.2 h |
| TOAD | 32 | 22 | 1 | 11 | 228 | 16 | 11 | 14 h |
| BABYTROLL | 44 | 29 | 16 | 29 | 652 | 37 | 10 | 33 h |
| Fartcoin | 101 | 84 | 8 | 67 | 128 | 85 | 19 | 25 h |

Observations:

- **CTO is the norm on the strong books**: 28–67% of the launches of ANSEM, SAPIJIJU, Fartcoin, PETAH,
  Bepe were taken over by their communities. These devs launch, sell early (see §1) and leave; the run,
  when it comes, is carried by holders. That is compatible with buying the launch *after* the dev's
  exit, not with buying the open.
- **Bundling and sniper hold are ~0 on every dev today**; those fields decay as tokens die and say
  nothing about the first minutes. The run shapes in §4 replace them.
- **Duplicate images** on 20–40% of launches for most factories: they recycle art, which is a cheap
  sign of a spray rather than a build.
- **S&P 500 dev** launched 12 tokens in one batch (median gap 6 minutes) on a `SPYx` stock quote; 3 of 12
  ran, all 5 days ago. Too young to be a record.

## 4. Run shapes — what a hit looked like, minute by minute (394 hits, klines)

Definitions: price reference is the **open of the first 1-minute candle** (median 0.3–0.7 min after the
create transaction, i.e. after the dev's own creation-block buy). `open mcap` = that price × supply.
`x15m` / `x60m` = close at 15 / 60 min over the reference; `peak` = highest 1-minute high in the first
100 min or 15-minute high in 24 h, with the minute it occurred; `24h close` = close of the 24th hour over
the reference; `still 2×` = share of hits still ≥ 2× at 24 h; `halved` = share that traded ≤ 0.5× at some
point in the first 100 min. **These are hits only** (launches that reached $100K); the non-hit launches
are not in this sample, so nothing here is an expected value. Devs with < 5 runs are shown but not read.

| Dev | Runs | Open mcap | x15m | x60m | Peak 100 min (min) | Peak 24 h (min) | 24h close | Retrace | Peak after 1 h | Still 2× | Halved |
|---|---|---|---|---|---|---|---|---|---|---|---|
| GrokBot | 11 | $80K | 1.94 | 0.76 | 2.36× (10) | 2.19× (15) | 0.07 | 98% | 36% | 18% | 45% |
| Fartcoin dev | 65 | $56K | 0.92 | 0.97 | 2.28× (9) | 2.34× (30) | 0.20 | 90% | 37% | 18% | 57% |
| ANSEM | 75 | $91K | 0.55 | 0.28 | 1.79× (2) | 1.24× (9) | 0.17 | 85% | 15% | 1% | 83% |
| SAPIJIJU | 71 | $98K | 0.88 | 0.39 | 2.08× (3) | 1.72× (11) | 0.19 | 87% | 23% | 4% | 70% |
| TOAD | 14 | $38K | 2.73 | 2.10 | 5.44× (33) | 6.68× (101) | 0.56 | 89% | 57% | 36% | 29% |
| BABYTROLL | 19 | $41K | 1.41 | 1.66 | 2.77× (65) | 4.25× (97) | 0.19 | 96% | 68% | 26% | 21% |
| ICEMAN | 10 | $9K | 0.62 | 0.43 | 1.42× (1) | 178× (381) | 0.53 | 95% | 50% | 20% | 60% |
| CANCER | 7 | $9K | 1.79 | 1.76 | 7.49× (53) | 12.5× (811) | **5.20** | 59% | 100% | **86%** | 14% |
| Dancedoge | 6 | $7K | 1.05 | 1.20 | 2.47× (26) | 87.9× (648) | 4.23 | 74% | 67% | 50% | 17% |
| FRANK | 6 | $9K | 2.73 | 9.20 | 14.4× (57) | 18.0× (65) | 2.90 | 84% | 50% | 50% | 33% |
| MACRODUCK | 10 | $17K | 2.34 | 0.77 | 5.35× (9) | 8.14× (7) | 0.89 | 88% | 20% | 30% | 40% |
| RAMEN | 5 | $7K | 1.46 | 4.36 | 7.58× (31) | 14.6× (42) | 2.34 | 69% | 40% | 60% | 20% |
| Stock | 12 | $11K | 3.93 | 1.21 | 11.7× (12) | 11.7× (12) | 0.40 | 98% | 17% | 25% | 33% |
| 1B | 10 | $23K | 1.40 | 1.86 | 5.84× (35) | 8.25× (50) | 0.37 | 92% | 50% | 20% | 50% |
| BUTT | 8 | $15K | 2.14 | 0.50 | 7.83× (24) | 8.63× (22) | 0.21 | 98% | 25% | 13% | 63% |
| biketyson | 7 | $6K | 3.79 | 3.18 | 7.17× (19) | 17.3× (629) | 2.52 | 62% | 86% | **71%** | **0%** |
| popedoll | 7 | $13K | 3.20 | 3.00 | 7.71× (52) | 22.9× (106) | 1.64 | 79% | 71% | 43% | 0% |
| maxxing | 7 | $10K | 2.01 | 1.09 | 12.7× (11) | 12.7× (12) | 0.39 | 95% | 14% | 29% | 43% |
| Pappy | 10 | $17K | 2.35 | 1.24 | 9.09× (19) | 11.1× (64) | 0.28 | 97% | 50% | 30% | 40% |
| PETAH | 8 | $8K | 1.56 | 3.93 | 8.60× (95) | 23.3× (126) | 0.98 | 96% | 88% | 38% | 0% |
| sami | 7 | $13K | 4.36 | 3.08 | 16.6× (25) | 22.1× (37) | 1.25 | 93% | 29% | 29% | 43% |
| MASK, LAYOFF, LeMonke, IGW, Bepe, Morty, S&P 500 | 2–4 | — | — | — | — | — | — | — | — | — | not read |

Two shapes, and the dev's conduct predicts which one:

**Shape 1 — bundled spike (GrokBot, ANSEM, SAPIJIJU, Fartcoin dev, Stock, BUTT, maxxing, Pappy).**
The first minute already prints at $50K–$100K (10–25× the curve floor), because the dev's creation-block
buy and the crowd that follows him are in before the first candle closes. The peak comes at minute 2–15,
the 24-hour close is 0.07–0.4× of the first minute, and 45–83% of the hits halve within 100 minutes.
ANSEM and SAPIJIJU peak in 2–3 minutes; only GrokBot (peak at 10–15 min, +94% at 15 min) leaves a window
a human can act in. These are the *top_dev*-tagged accounts with the biggest followings: the run is the
following arriving, and it is over before an outsider without a router is filled.

**Shape 2 — post-exit build (CANCER, biketyson, PETAH, popedoll, TOAD, BABYTROLL, FRANK, Dancedoge,
RAMEN).** The first minute prints at $6K–$40K, the dev sells his creation-block bag within seconds (§1),
and the hit forms *afterwards*: peak after 1 hour in 57–100% of cases, median peak at 1.5–13 hours,
24-hour close 2–5× the first minute, and 0–29% of hits ever halve in the first 100 minutes. CANCER's hits
were still 5.2× at 24 h and 86% of them were ≥ 2×; biketyson's 71% with none halving. For these devs the
dev's "dump" is toxic flow leaving, not the end of the trade.

Everything above conditions on the launch having become a hit. The hit rates from D3 (CANCER 10%,
biketyson 5%, PETAH 9%, TOAD 50%, BABYTROLL 45%, FRANK 6%, GrokBot 34%) are the other half of the
expectancy and need the non-hit klines (D5/D7) before any sizing.

## 5. Verdict — top 10 to track, with the style each one implies

Ordering weighs conduct (§1) first, then per-launch hit rate and recency (D3), then run shape (§4).

| # | Dev | Why | Style implied |
|---|---|---|---|
| 1 | `9VXuNqqqzniYYW3fRDeaCtUUtqWsEeWWn5umh3aF9h17` CANCER | buyable (79), 10% hit rate over 69 launches, hits peak at 13 h and hold (5.2× at 24 h, 86% still ≥ 2×), 24-day quiet spell is the risk | post-exit build: enter after minute 5, hold hours, exit on retrace from a multi-hour high |
| 2 | `EgJoaEBSZA3wjgpPq8am9YjkxJPLa2LpXwxaQyUzB2XY` GrokBot | buyable (91), GMGN top_dev, 34% hit rate, 5 hits ≥ $1M, launches every 2 h, but spike shape: peak at 10–15 min, dead by 24 h | scalp: in within 60 s, out at 10–15 min or +80%, never hold |
| 3 | `5YRgrP3mjGzrzirYYN5HAQH19cTYREYwGxW6XRJQUzij` TOAD | top_dev, 50% hit rate, 4 hits ≥ $1M, peak at 100 min, 36% still 2× at 24 h; dev's median first sell 59 min (the "sys" label comes from a few fast exits) | post-exit build with a 2-hour horizon |
| 4 | `BFmgjdgepMxNnEyndQZC68Db3ajPdD3V8is1bQbdj4h4` biketyson | best hold profile on the list (peak at 10 h, 71% still 2×, none halved), 100 launches in 30 d, 7 hits in 30 d; 5% hit rate and holding his own bag on 6 coins | post-exit build, hours |
| 5 | `G4krkerMkeYw7ffTUgdf7qXEXnuMGHpWUESBQpYqvtwU` BABYTROLL | top_dev, 45% hit rate, peak at 97 min; dev dumps at 12 s below open, so entries after his exit are clean; still holds 16 coins | post-exit build, 1–2 h |
| 6 | `GeBJSHK4WsGrz2HRvTbqvWGx4JRMpHfJG2ikzrYBDuwR` SAPIJIJU | top_dev, 19% hit rate, 8 hits ≥ $1M, 71 hits in 90 d, launches every 3 h, rare dumping; spike shape peaks at 3 min | watch only until we have a sub-minute feed; not tradeable by hand |
| 7 | `FAX4qRQdiSj2iWDYvkJ21VieVCXGREtwMhEyAHSJ1aqp` PETAH | mixed (72), 9% hit rate, peak at 2 h, none halved, 61/90 CTO (community carries) | post-exit build |
| 8 | `4LTJU2qfJdmDuEQAmWXcf5hvkpomYrLebuTBz2svwRd4` LAYOFF | best conduct on the list (98.5), both graduations went ≥ $1M with multi-day runs; only 18 launches, 2 graduated, batch launcher | small size, hold |
| 9 | `CzwWvTVn39dSd4LiVc6W9gZxgu36737M2fcX4EWhquh4` 1B | buyable (80), 44% graduation, peak at 50 min; sells below open (0.37×) and both records truncated | post-exit build, 1 h; verify with a full walk |
| 10 | `yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe` ANSEM | most power on the list ($449M flagship, 310 graduations), rare dumping, but hits peak at 2 min and 83% halve | watch only; a feed-and-router problem, not a selection problem |

Dropped from the D3 shortlist after the audit, with the reason:

- **Systematic dumpers at open** (sell 75–97% of the time within 1–4 s): ICEMAN, FRANK, MACRODUCK,
  Dancedoge, RAMEN, BUTT, Pappy, Stock, popedoll, sami, LeMonke, IGW. Some (FRANK, Dancedoge, RAMEN,
  popedoll) have a good post-exit shape and could re-enter via a "buy only after the dev's sell prints"
  rule in D5, but not as tracked devs.
- **Fartcoin dev**: conduct 0, dumps at 3 s, 15 days quiet.
- **MASK**: often-dumper (0.60), 4 runs.
- **S&P 500, Bepe, Morty**: 3 or fewer runs; S&P 500 is 5 days old.
- **maxxing**: unscored (implausible peak in the data).

## 6. What D4 did not settle, and what D5 needs

1. **Base rates**: every run shape above is conditional on a hit. D5 pulls the same klines on a random
   sample of each top-10 dev's *non-hit* launches (~300 calls) to get the loss side and a first
   expectancy per style.
2. **Sub-minute entry cost**: for shape-1 devs the first candle is already 10–25× the floor; the question
   is whether minute-1 entry with a 1.25% curve fee and $50 size has positive expectancy at all. D5.
3. **Dev sell detection in real time**: shape-2 entries key off the dev's own sell. The activity feed
   lags; the Pump program logs decoded with `TradeEventBc` (creator == dev) do not. D6 spec item.
4. **Coverage**: 1B, ANSEM, SAPIJIJU, TOAD, BABYTROLL, PETAH have truncated trade walks (25 pages); a
   full walk for the top 5 is ~200 weight each.
5. The watcher continues; a dev not seen in the first cut can enter through the weekly re-rank.
