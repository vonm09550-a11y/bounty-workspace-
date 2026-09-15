# D5a — Top-10 deepened, narrowed to 5 (2026-09-15 10:30 UTC)

Read-only research. Adds to D4: the **loss side** (1m + 15m klines on the newest 40 non-hit launches per
dev, 289 tokens), **full trade walks** (120+ pages) for the six devs whose D4 conduct was truncated, a
**per-launch expectancy per entry style**, and the **tells** that separate a dev's hits from his misses.
Scripts: `scripts/dev_deep.py` (pulls), `scripts/dev_deep_report.py` (tables `dev_sim`, `dev_ev`); raw
`data/devs/deep_report.out`.

## 1. Method

Three mechanical entry styles simulated on every sampled launch (hits and non-hits), fees 1.25% curve +
1.0% slippage per side (4.5% round trip):

| Style | Entry | Exit |
|---|---|---|
| S scalp | close of minute 1 | first close ≥ 1.8× entry, or ≤ 0.6×, else minute-15 close |
| B build | close of minute 5 | hard stop ≤ 0.5×; after running high ≥ 1.5×, exit on close ≤ 0.6× of the high; else 24-h close |
| B2 build-late | close of minute 15 | same as B |

Expectancy per launch = p(hit) × mean return on hits + (1 − p(hit)) × mean return on non-hits, with p(hit)
from the dev's full book (D3) and single-launch returns capped at +500% so one outlier cannot carry a
dev. Devs whose book is capped at 101 (biketyson, SAPIJIJU, ANSEM, 1B, PETAH) have their non-hit sample
drawn from the newest launches only; that is flagged where it matters.

## 2. Expectancy per launch, all launches vs launches carrying the tells

Tells (from D5a §3): a Twitter link on the token **and** a launch hour outside 06–12 UTC.

| Dev | p(hit) book | Hit % with tells / without | EV scalp all | EV scalp, tells | EV build all | EV build, tells | Conduct (full walk) |
|---|---|---|---|---|---|---|---|
| biketyson | 5% | 40 / 8 | **+52%** | **+93%** | +7% | +21% | 0 dumps on 66 traded coins; "sys" label forced by one drained pool (`letgo`) |
| TOAD | 50% | 80 / 15 | **+20%** | **+33%** | +3% | +5% | 8 dumps / 27, median first sell 11 min; label forced by one drained pool |
| BABYTROLL | 45% | 56 / 10 | +6% | +6% (≈ +10% at the tell hit rate) | −3% | 0% | 12 dumps / 41, sells at 12 s below open; label forced by one drained pool |
| CANCER | 10% | 13 / 19 | −1% | −2% | +5% | **+12%** | buyable (79), rare dumping |
| LAYOFF | 11% | 100 / 0 (2 hits) | +14% | n/a (2 tell launches) | +8% | n/a | buyable (98.5) |
| PETAH | 9% | 18 / 14 | 0% | −3% | −2% | −2% | mixed (71), rare dumping |
| 1B | 5% | 20 / 0 | −2% | −4% | −24% | −25% | buyable (80) but sells below open |
| GrokBot | 34% | 37 / 20 | −11% | −5% | −21% | −21% | buyable (91) |
| SAPIJIJU | 19% | 72 / 67 | −17% | −19% | −19% | −21% | mixed (64), rare dumping |
| ANSEM | 9% | 74 / 75 | −22% | −22% | −45% | −47% | mixed (54), rare dumping |

The "EV, tells" column still uses the book hit rate; with the tell-conditioned hit rate instead, the
three leaders read biketyson ≈ +97%, TOAD ≈ +42%, BABYTROLL ≈ +11% on a scalp.

Reading:

- **Conduct and expectancy are different things.** GrokBot, 1B and ANSEM have clean or acceptable
  conduct and *negative* expectancy for us: their launches open too high (first minute at $80K–$90K,
  D4 §4) and their misses lose 25–40% in 15 minutes. A dev being safe to buy does not make his launches
  worth buying.
- **The three positive devs open low** (first-minute mcap $6K–$40K) and their launches pop in the first
  minutes even when they do not become hits: biketyson's non-hits still returned +49% on a scalp with
  a 74% win rate, TOAD's +9% with the tells.
- **Build style pays only for CANCER** (+12% with tells) and only on his hits, which stopped in May.

## 3. The tells

| Dev | Twitter on hits / non-hits | Website on hits / non-hits | Reused image on hits / non-hits | Median launch hour UTC (hits) |
|---|---|---|---|---|
| biketyson | 71% / 24% | 43% / 14% | 0% / 18% | 11 |
| TOAD | 86% / 29% | 50% / 43% | 43% / 36% | 18 |
| BABYTROLL | 100% / 78% | 37% / 13% | 16% / 30% | 14 |
| LAYOFF | 100% / 0% | 100% / 19% | 50% / 13% | 20 |
| CANCER | 100% / 100% | 57% / 27% | 43% / 24% | 13 |
| 1B | 100% / 100% | 40% / 8% | 10% / 30% | 16 |
| GrokBot | 100% / 90% | 73% / 57% | 64% / 76% | 4 |
| SAPIJIJU, ANSEM, PETAH | ≥ 96% on both | small gap | none | 8 / 17 / 3 |

Pooled over the ten: launches at 06–12 UTC hit 20% of the time vs 34–36% in every other window. Names:
ANSEM's, SAPIJIJU's and BABYTROLL's hits are almost all named after crypto-Twitter personalities
(Ansem, Murad, Mert, Toly, mdudas, pmarca, Cupsey, Jimothy); their launches are reactions to those
accounts' posts, which is a tell that needs a Twitter feed to use.

## 4. Month by month (complete for uncapped books; capped books list only their top-101 by ATH)

| Dev | Jun | Jul | Aug | Sep (to 15th) | Read |
|---|---|---|---|---|---|
| BABYTROLL | 4/12 | 6/14 | 7/13 | 1/3 | consistent 45% for four months |
| biketyson | — | — | 0/48 | 7/52 (1 ≥ $1M) | new; one good month |
| TOAD | 1/2 | 0/3 | 12/15 (4 ≥ $1M) | 1/12 | one great month, fading |
| GrokBot | — | — | 10/18 (5 ≥ $1M) | 1/14 | one great month, fading |
| CANCER | 0/12 | 0/3 | 0/9 | 0 | no hit since May |
| PETAH | — | — | 0/27 | 0/4 | no hit since April |
| LAYOFF | — | — | — | 0/10 (batch) | 2 hits ever (Jan, Feb) |
| 1B | 1/43 | 5/48 | 3/7 | 1/2 | low rate, slowing |
| SAPIJIJU (capped) | — | 47/62 | 18/30 | 6/8 | steady factory |
| ANSEM (capped) | 1/1 | 30/39 | 38/55 | 6/6 | steady factory |

## 5. Verdict — the five

Ranked by expectancy with the tells, then consistency, then conduct. Style is what the simulation
found positive, not a preference.

| # | Dev | Address | Style | Condition | Risk to state plainly |
|---|---|---|---|---|---|
| 1 | biketyson | `BFmgjdgepMxNnEyndQZC68Db3ajPdD3V8is1bQbdj4h4` | scalp: in at minute 1, out at +80% / −40% / minute 15 | Twitter link present, not 06–12 UTC | one month of history; the +49% on non-hits is a September sample and may not hold; 100 launches a month means many small trades |
| 2 | TOAD | `5YRgrP3mjGzrzirYYN5HAQH19cTYREYwGxW6XRJQUzij` | scalp, same rule | Twitter link present (80% hit rate with it, 15% without) | September is 1/12; if the next 10 tell-launches hit < 40%, demote |
| 3 | BABYTROLL | `G4krkerMkeYw7ffTUgdf7qXEXnuMGHpWUESBQpYqvtwU` | scalp with tells, small size | Twitter link present, not 06–12 UTC | scalp edge shrank from +48% (Jun) to −30% (Aug) on non-hits; hits still pay; the dev sells at 12 s so minute-1 entry is after his exit |
| 4 | CANCER | `9VXuNqqqzniYYW3fRDeaCtUUtqWsEeWWn5umh3aF9h17` | build: in at minute 5, trail 40% off the high, else 24 h | only if he launches again with a website | dormant 14 days, no hit since May; kept for conduct (buyable) and the only positive build profile |
| 5 | LAYOFF | `4LTJU2qfJdmDuEQAmWXcf5hvkpomYrLebuTBz2svwRd4` | hold: small size, exit on trail | Twitter link present (both hits had one, none of the misses) | 2 hits in 18 launches; the September batch of 10 had none; thinnest record on the list |

Cut, with the number that cut them:

- **GrokBot**: −5% to −11% scalp EV even with tells; misses lose 39% in 15 minutes. Powerful, not profitable for a follower.
- **SAPIJIJU**, **ANSEM**: −17% to −22% scalp, worse on build; hits peak at 2–3 minutes and the first
  minute is already $90K+. Feed-and-router plays, not selection plays.
- **1B**: −24% build, −2% scalp; sells below open.
- **PETAH**: ≈ 0% everywhere and no hit since April.

## 6. What this list is and is not

- It is a **research shortlist with implied rules**, backtested on the dev's own history with a simple
  exit. It is not a live signal and nothing has been traded.
- The expectancies are per launch before position sizing; at $50 a launch, a +30% edge is $15 per trade
  and each dev gives 1–5 launches a day. The number that matters next is how many of those launches
  a hand-driven entry actually catches at minute 1 (D6 feed spec, D7 replay with realistic delay).
- Re-rank weekly from the watcher: the top of this list is decided by the last 30 days, and both
  leaders have a single strong month.
