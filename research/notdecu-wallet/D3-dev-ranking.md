# D3 — Dev ranking, first cut (draft, 2026-09-14 20:35 UTC)

Source: `dev_books` × `dev_tokens` for 2,075 devs (seed = creators with ≥ 2 graduations among decu's
picks; the 617 devs seen by the watcher are being fetched and will be merged in the next cut).
Script: `scripts/dev_rank.py` → table `dev_scores`, `data/devs/dev_scores.parquet`, raw `data/devs/rank.out`.
Read-only research; no actions.

## 0. Definitions and caveats

- **launches** = `inner_count` (still on curve) + `open_count` (graduated). `inner_count` caps at 999
  (452 devs), so their hit rates are upper bounds.
- **hit** = a launch whose all-time-high market cap (GMGN `token_ath_mc`) reached ≥ $100K; **big hit** ≥ $1M.
  Books list the dev's top-101 tokens by ATH, so hit counts are complete for every dev in this cut
  (`hits_incomplete` = 0). 10 devs carry an implausible ATH ≥ $5B; those rows are excluded from hits.
- **Seed bias**: every dev here launched at least one token decu bought. That over-samples high-cadence
  devs (he buys the feed) and under-samples rare launchers. The watcher sample corrects this over time.
- Conduct (does the dev sell into his own open) is **not** measured yet; that is D4.

## 1. Universe

| Devs | Launches capped | Any hit ≥ $100K | Any hit ≥ $1M | ≥ 3 hits ≥ $1M | ≥ 5 hits ≥ $100K | Launched in last 7 d | last 30 d |
|---|---|---|---|---|---|---|---|
| 2,075 | 452 | 1,611 | 521 | 18 | 111 | 750 | 1,134 |

Hit rate by dev size (median dev in each band):

| Launches | Devs | Graduation ratio | Hit rate ≥ $100K | Avg big hits | Days since last launch |
|---|---|---|---|---|---|
| ≤ 5 | 87 | 0.667 | 25.0% | 0.18 | 48 |
| 6–20 | 307 | 0.231 | 6.7% | 0.18 | 49 |
| 21–100 | 500 | 0.094 | 2.5% | 0.19 | 30 |
| 101–998 | 729 | 0.018 | 0.28% | 0.29 | 16 |
| 999+ | 452 | 0.008 | 0.05% | 0.54 | 3 |

The pattern is monotonic: the more a dev launches, the lower the chance any one launch runs. Factories
produce the most big hits in absolute terms only because they launch thousands. For a small account
that has to pick launches one at a time, **per-launch hit rate is the number that matters**, so the
craftsman band (≤ 100 launches) is the primary pool and factories are a separate, conditional list.

Decu overlap adds nothing: his win rate on a dev's launches is 62–65% regardless of the dev's power, which
is consistent with 2.4 (he does not select on dev).

## 2. List A — craftsmen (≤ 100 launches, ≥ 2 hits, launched in the last 30 days), top 15

| # | Creator | Launches | Grads | Hits ≥ $100K | ≥ $1M | Best ATH | Best | Hit rate | Bundler (med) | Days since launch / since hit |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `EgJoaEBSZA3wjgpPq8am9YjkxJPLa2LpXwxaQyUzB2XY` | 32 | 21 | 11 | 5 | $11.4M | GrokBot | 34.4% | 0 | 0.7 / 0.8 |
| 2 | `5YRgrP3mjGzrzirYYN5HAQH19cTYREYwGxW6XRJQUzij` | 28 | 22 | 14 | 4 | $23.6M | TOAD | 50.0% | 0 | 2.2 / 4.0 |
| 3 | `G4krkerMkeYw7ffTUgdf7qXEXnuMGHpWUESBQpYqvtwU` | 42 | 29 | 19 | 2 | $2.8M | BABYTROLL | 45.2% | 0 | 0.7 / 0.7 |
| 4 | `9VXuNqqqzniYYW3fRDeaCtUUtqWsEeWWn5umh3aF9h17` | 69 | 17 | 7 | 2 | $2.9M | CANCER | 10.1% | 0.0002 | 14.1 / 121 |
| 5 | `8gxNUi3uDnqPdpVciCAf8EDD6Bc1e5spQijXBzwGjRsW` | 99 | 17 | 6 | 2 | $4.2M | FRANK | 6.1% | 0 | 6.3 / 37 |
| 6 | `7d3mQnXjc76v9ZKZQ5T7LU2d3JyaKXfBvnhtfUAiR2hw` | 43 | 15 | 5 | 2 | $2.7M | RAMEN | 11.6% | 0 | 4.7 / 26 |
| 7 | `4DrtsW86GarGJJeYrBwYCjoyMgDPG95QWSGhFHvCkU2s` | 79 | 14 | 4 | 2 | $34.0M | MASK | 5.1% | 0.00005 | 0.2 / 77 |
| 8 | `FzaKKXhhU7ba76NJ9fffoa5Gt4LhSnME1rcMxrrwT4Dw` | 76 | 9 | 3 | 2 | $1.7M | Bepe | 3.9% | 0.0002 | 2.6 / 18 |
| 9 | `9VHB7HHU7msVHzd6BjMhHPbL2E92XPRiV2R7fg1Xx6T9` | 14 | 3 | 2 | 2 | $7.8M | IGW | 14.3% | 0.0043 | 2.7 / 458 |
| 10 | `4LTJU2qfJdmDuEQAmWXcf5hvkpomYrLebuTBz2svwRd4` | 18 | 2 | 2 | 2 | $4.2M | LAYOFF | 11.1% | 0.024 | 0.0 / 199 |
| 11 | `Hr5eg6WFy1TNLrDUYasMgu1Y94AL2fNCUg9sWC7Qtq1N` | 26 | 2 | 2 | 2 | $1.5M | LeMonke | 7.7% | 0.0097 | 13.9 / 18 |
| 12 | `AbVkRUfynaEo6PMWyBCihRcirKbu3GkiyEoH5vny8aT9` | 99 | 34 | 10 | 1 | $7.5M | Pappy | 10.1% | 0.00035 | 0.8 / 16 |
| 13 | `FAX4qRQdiSj2iWDYvkJ21VieVCXGREtwMhEyAHSJ1aqp` | 90 | 22 | 8 | 1 | $1.5M | PETAH | 8.9% | 0.00025 | 4.8 / 138 |
| 14 | `9ChWUUbP2NgvmzCS419FAhV6XiUG7ggU6U5QtS32bH9q` | 50 | 14 | 7 | 1 | $1.4M | sami | 14.0% | 0.0013 | 7.1 / 24 |
| 15 | `5a1kLJrDxg2X3u4Zu5p72xWSdEB8p8cfVTNWvEs6AVT6` | 15 | 6 | 6 | 1 | $1.3M | BTCX | 40.0% | 0.019 | 0.6 / 5 |

The first three are the profile the strategy wants: 28–42 launches, more than half of them graduate,
a third to a half reach $100K, multiple $1M+ runs, no bundling, and a launch within the last 3 days.
Rows 9–11 have two big hits but a last hit 200–450 days ago: past power, unproven now.

## 3. List B — factories (> 100 launches), top 10 by big hits then recent hits

| # | Creator | Launches | Grads | Hits ≥ $100K | ≥ $1M | ≥ $10M | Best ATH | Best | Hit rate | Hits last 90 d | Days since launch |
|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | `HyYNVYmnFmi87NsQqWzLJhUTPBKQUfgfhdbBa554nMFF` | 497 | 263 | 65 | 14 | 2 | $1.69B | Fartcoin | 13.1% | 5 | 14.7 |
| 2 | `GeBJSHK4WsGrz2HRvTbqvWGx4JRMpHfJG2ikzrYBDuwR` | 376 | 139 | 71 | 8 | 0 | $9.7M | SAPIJIJU | 18.9% | 71 | 0.2 |
| 3 | `BY4hmLWBGWQ1Z6bn6s1sy4a4wHqnDKR2AjPY5wjvGtqC` | 174 | 25 | 10 | 6 | 2 | $27.3M | ICEMAN | 5.8% | 10 | 0.2 |
| 4 | `H6zpaY14WgkEmB3MJTvC7Wb5PQJkBVLd4KwLD2ktVgop` | 2,568 | 120 | 44 | 4 | 0 | $5.3M | KIRK | 1.7% | 41 | 3.0 |
| 5 | `AxqXBbPab4iRUMpUiCxKmkawUk77TR5mRVsTFDiUTsh` | 2,360 | 130 | 11 | 4 | 1 | $82.9M | FURRY | 0.5% | 11 | 4.7 |
| 6 | `96hq1rUo5qQk26NAP7wK6VtcnZXPKbkHpdVsdGwe3Cda` | 294 | 35 | 6 | 4 | 1 | $32.4M | Dancedoge | 2.0% | 6 | 4.0 |
| 7 | `yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe` | 868 | 310 | 75 | 3 | 1 | $449M | ANSEM | 8.6% | 75 | 3.0 |
| 8 | `ARW9NzhpuBVYaYBZo6fW1P1U6LTNwUY6jfi7XC37Sa97` | 189 | 99 | 24 | 3 | 0 | $3.8M | Tate | 12.7% | 24 | 5.2 |
| 9 | `4q4GKBpVmXGhXYNaR4DetQjf5WjHEHhbJ9Wgybt7F8Yu` | 159 | 52 | 23 | 3 | 1 | $16.2M | FINNBAGS | 14.5% | 23 | 72 |
| 10 | `gVDXhoGbePACvSqN7CZBtQXFW9eyJwsgudPEwSydAkx` | 340 | 104 | 10 | 3 | 0 | $7.4M | MACRODUCK | 2.9% | 10 | 0.7 |

Two of these behave like craftsmen at scale: `GeBJ…` (376 launches, 19% hit rate, 71 hits in the last
90 days) and `yHCx…` (868 launches, 310 graduations, 75 hits, 31 of them in the last 30 days). Both
launch daily. `HyYN…` is the Fartcoin creator address as GMGN records it; its recent record (5 hits in
90 days, quiet for 15 days) is much weaker than its history. The 2,000+ launch rows (KIRK, FURRY) are
sprayers with a 0.5–1.7% hit rate and belong on no watchlist.

## 4. List C — hot now (hits ≥ $100K in the last 30 days), top 10

| # | Creator | Hits last 30 d | Launches last 30 d | Hit rate (30 d) | All-time hits | Best | Days since launch |
|---|---|---|---|---|---|---|---|
| 1 | `yHCx…6PRe` (ANSEM) | 31 | 35 | 89% | 75 | $449M | 3.0 |
| 2 | `H6zp…tVgop` (KIRK) | 19 | 22 listed (of many more) | n/a, capped | 44 | $5.3M | 3.0 |
| 3 | `ARW9…Sa97` (Tate) | 18 | 64 | 28% | 24 | $3.8M | 5.2 |
| 4 | `GeBJ…Duwr` (SAPIJIJU) | 14 | 23 | 61% | 71 | $9.7M | 0.2 |
| 5 | `AxqX…UTsh` (FURRY) | 11 | 101 listed | ≤ 11% | 11 | $82.9M | 4.7 |
| 6 | `EgJo…B2XY` (GrokBot) | 11 | 32 | 34% | 11 | $11.4M | 0.7 |
| 7 | `BY4h…Gtqc` (ICEMAN) | 10 | 100 listed | ≤ 10% | 10 | $27.3M | 0.2 |
| 8 | `gVDX…dAkx` (MACRODUCK) | 10 | 100 listed | ≤ 10% | 10 | $7.4M | 0.7 |
| 9 | `D8n8…anS4` (Stock) | 10 | 66 | 15% | 12 | $2.9M | 0.1 |
| 10 | `5YRg…Uzij` (TOAD) | 9 | 22 | 41% | 14 | $23.6M | 2.2 |

"Launches last 30 d" counts listed tokens only; for capped books (100–101 listed) it is a floor and the
30-day hit rate is an upper bound.

## 5. Shortlist for D4 (deep audit), 30 devs

Union, in order: List A rows 1–15, List B rows 1–3, 7–10, List C rows 1, 4, 9, plus the next five
craftsmen by hit rate with ≥ 3 hits (`39ZP…2Rac` POB, `YvEs…PnuX` TJR, `9ChW…bH9q` sami is already in,
`FzaK…T4Dw` in, `CfkaA…shxB` "67", `5ZJQ…uTVD` pwease). Exact list is materialised by
`scripts/dev_rank.py` in the next cut as `d4_shortlist`.

D4 measures what this cut cannot: conduct (creator sells in own coins, timing of the first sell,
liquidity drains) via `dev_score.py`; per-launch open mcap, time to ATH, ATH multiple and retrace via
`token info` + `market kline`; and wallet clustering via `fund_from_address` so that a "craftsman" is
not just one face of a factory.

## 6. Next cut

- Merge the 617 watcher-sourced devs (running) and re-rank; report how many of the top 30 survive.
- Add the watcher's second and third day so recency is measured on live graduations, not on books.
