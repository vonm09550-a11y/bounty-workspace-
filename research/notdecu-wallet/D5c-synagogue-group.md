# D5c — The "Synagogue" pump.fun group (from the user's screenshots, 2026-09-15 ~12:50 local)

Screenshots in `refs/synagogue/` (15 images of the group page: header, 30D/7D/1D P&L, open positions
sorted by size). The API could not read this page (members endpoint needs a login); the screenshots can.

## 1. What the group is

A pump.fun **group**: a shared portfolio view over its members' wallets, with "Callouts" (members
posting a call on a coin) and "Replies". Tagline: "The loot was promised to us 3000 years ago."

| Field | Value |
|---|---|
| Members / followers | **32** / 1.6K |
| Unique coins traded by members | **29.9K** |
| Combined open portfolio | **$1,585,281** |
| 30-day P&L | **+$466,836 (+16.9%)** |
| 7-day P&L | **−$441,820 (−15.8%)** |
| 1-day P&L | −$61,325 (−2.9%) |
| Admin | slingoor (the TOAD dev, 124K pump.fun followers) |
| Member seen | 0xkgc (the biketyson dev) |
| Image owner | ibuycoin |

Reading: 32 wallets, $1.6M of open positions, and 30K distinct coins traded is a **coordinated trading
circle**, not a fan club. The 7-day drawdown of −$442K is the same week slingoor lost $66K and went
11 launches / 1 hit; the group's fortunes and his are one series.

## 2. The group holds its own members' launches

Largest open positions (from the size-sorted list) and their P&L:

| Position | Size | P&L | Note |
|---|---|---|---|
| NotInEmployment | $239K | +$71K | |
| **LMAO!** | $193K | +$33K, callout "Higher" 6 d ago | **slingoor's launch of Sep 12** (ATH $99K in our book; the group's position is bigger than the coin's ATH mcap in our data, so the group is a large share of the float or the ATH is stale) |
| The Black … | $149K | +$70K | |
| Anonymous ZC | $141K | +$195K (+240%) | |
| Minirouter.sh | $102K | −$10K | |
| flybrain | $79K | −$137K | |
| **BIKE TYSON** | $65K | +$6K | **0xkgc's $11.5M launch**, still held |
| WSOP | $54K | +$22K | |
| Xavier | $44K | −$0.5K | |
| Shrek, Market Dominance, Chill House, 混混猫, AI, RETARDIO, Tung Tung, swarm, Suica, Agent Worm, NearKat | $11K–$23K | mixed | Chill House = the CHILLHOUSE dev from our factory list |
| **TOAD** | $10K | −$49K | slingoor's flagship, held through a 27% drawdown |
| Zcash, Kintara, NA, glorp, Jotchua, YOYO, HODL, NUDES | $5K–$7K | mixed | ZEC = 0xkgc's Sep 12 launch |
| Lizardmax, Tyse Bike (BIKESON), baton, sling, Melon Musk, KET, STONK, FLORK, emberc, … | $2K–$5K | | LIZARD, sling = slingoor; BIKESON, MelonMusk = 0xkgc; baton = the ANSEM / S&P 500 devs |

Cross-match of the group's holdings against the 28 audited devs' books (symbol match, so some rows
are namesakes): **8 of slingoor's launches** (TOAD, OFFICIAL, sling, LIZARD, WINNIE, nothing,
Chairman, LMAO!) and **4 of 0xkgc's** (biketyson, BIKESON, ZEC, MelonMusk) sit in the group's open
book, all still open. Also present: GrokBot's PUMPCAT, MACRODUCK's monke and HODL, Morty's Doggo,
maxxing's Swarm/Flork/bean, and baton (launched by both the ANSEM dev and the S&P 500 dev on Sep 9).

## 3. What this changes

1. **The "dev edge" for slingoor and 0xkgc is the group's buying.** A launch by a member is bought by
   32 wallets with $1.6M behind them, and the callouts tell the 1.6K followers to buy too. That is why
   a slingoor launch with a Twitter link hit 80% of the time and why 0xkgc's misses still popped 3–4× in
   15 minutes. We are not detecting a talented creator; we are detecting a coordinated bid.
2. **Our five is mostly one bet.** slingoor, 0xkgc, and by symbol overlap several devs we cut (GrokBot,
   MACRODUCK, Morty, maxxing, CHILLHOUSE) are in or around the same circle. Correlated risk: when the
   group has a bad week (−$442K), every member's launch fades at once.
3. **The trade that exists** is riding the group's own flow: enter after the group's first wave (the
   minute-1 scalp in D5a) and exit before it rotates. The group's positions show they hold their own
   launches through deep drawdowns (TOAD −27%, flybrain −$137K), so the exit timing has to be ours.
4. **The trade that does not exist** is holding to the group's target: their callouts ("Higher") are
   for their own bags.
5. **Watchlist input**: the group page itself is a signal source. New callouts and new positions in a
   fresh member launch precede the public run. This is readable only from a logged-in pump.fun session,
   so it is a manual feed unless the user's own session is used.

## 4. Open questions for the user (only the page can answer)

- Members tab: the other 30 wallets. Any of our 28 audited devs there would confirm the cluster.
- Callouts tab: timestamps of the "Higher"-type calls versus each coin's chart, to measure the lead
  the group gives itself before the crowd.

---

## 5. Members (from the Members tab screenshots, 1D/7D/30D P&L per member, 2026-09-15 ~12:55 local)

All 32 usernames resolved to wallets through pump.fun's user endpoint (`data/devs/profiles/
synagogue_members.json`); GMGN 30-day stats per wallet in `synagogue_members_stats.json`. The two
P&L columns disagree in places because they measure different things: pump.fun's figure is the
member's group-view P&L (includes open positions marked to market), GMGN's is realized only.

| Member | Role | pump.fun followers | X | pump.fun P&L 30D / 7D / 1D | GMGN 30d realized | GMGN win rate | Launches (book) | Hits ≥ $100K / ≥ $1M | Note |
|---|---|---|---|---|---|---|---|---|---|
| lvvpumpy | | 9,758 | — | **+$468K** / +$166K / −$8K | +$58K | 30% | 0 | — | the group's 30-day P&L is essentially his |
| retardmode | | 3,883 | — | +$98K / +$104K / −$13K | **+$373K (+79%)** | 52% | 19 | 4 / 1 (PEACE $1.7M) | GMGN top_dev; 1,133 SOL; launched WOJAK today (graduated) |
| hoeleeshiet | | 717 | @hoeleeshiett | +$95K / +$7K / +$9K | +$0.2K | 34% | 0 | — | |
| pumpguy__ | | 3,764 | @pumpguy__ | +$95K / −$15K / +$3K | +$3K | 33% | 2 | 1 / 0 (USEFUL) | |
| kanpai | | 1,035 | @kanpai | +$73K / −$15K / −$1K | +$8K | 28% | 0 | — | 502 SOL |
| trenchdigger | | 39,367 | @gilldurn | +$44K / +$13K / −$3K | +$29K | 43% | 7 | 0 | 7,135 buys in 30 d, $1.29M deployed; funded from Robinhood |
| usurp | | 231 | — | +$12K / −$13K / −$1K | +$1K | 38% | 0 | — | |
| **0xkgc** | | 3,937 | @0xkgc | +$11K / +$3K / +$9K | +$13K | 51% | 141 | 7 / 1 (biketyson $11.5M) | our #1 scalp dev |
| trenchdiga | | 502 | — | +$9K / −$3K / +$0.3K | −$1K | 22% | 40 | 0 | |
| MidCurveMortal | Admin | 760 | — | +$9K / −$19K / −$2K | +$3K | 36% | 6 | 0 | |
| waynecapital | | 891 | @onchainscammer | +$6K / −$0.7K / −$0.03K | +$3K | 33% | 37 | 0 | tagged smart_degen |
| badattrading | | 12,726 | — | +$3K / +$3K / −$7K | +$15K | 35% | 1 | 1 / 0 (SOBAT $888K) | tagged smart_degen, top_followed |
| hashbergers | | 57,667 | @Hashbergers | +$3K / +$27K / −$0.03K | +$2K | 42% | 115 | 5 / 1 (PINU $1.2M) | tagged **sandwich_bot** |
| ibuycoin | **Owner** | 864 | @ibuycoins | +$3K / −$0.04K / −$4K | +$3K | 33% | 31 | 0 | funded from Coinbase |
| b69 | | 344 | @B69___ | +$1K / +$2K / +$3K | +$4K | 33% | 0 | — | |
| agentpuffle | Admin | 290 | @AgentPuffle | ≈ 0 | ≈ 0 | 17% | 4 | 0 | |
| Fabricci | | 61 | @0xFabricci | −$0.2K | −$0.1K | 0% | 0 | — | |
| TMH | | 1,040 | @thememeshunterx | −$0.3K / +$0.2K / +$0.4K | −$1K | 25% | 1 | 0 | |
| SleepyyMike | | 203 | — | −$0.6K | −$1K | 30% | 0 | — | |
| rohwhale | Admin | 225 | @rowhale | −$0.9K | −$2K | 35% | 0 | — | |
| ibuyrunners | | 305 | — | −$1K | −$0.1K | 17% | 6 | 0 | |
| 0xPromiser | | 207 | — | −$1K | +$3K | 25% | 13 | 0 | |
| baseddom | | 1,717 | @based_d0m | −$2K / −$3K / +$0.1K | −$0.2K | 21% | 17 | 1 / 1 (NiggaButt $611K) | |
| LowiqdegN | | 413 | — | −$6K / −$0.4K / +$0.9K | −$5K | 27% | 1 | 0 | |
| moonpie666 | | 1,037 | @mushmoonz | −$8K / −$7K / −$0.6K | −$25K | 29% | 0 | — | |
| jester | | 30,429 | @thejester | −$8K / −$4K / −$0.1K | +$5K | 22% | 165 | 18 / 7 | tagged **kol** and **wash_trader**; best DIRECTOR (reported $2.0B, implausible) |
| gampsito | | 1,125 | @gampsito | −$11K / −$3K / −$0.6K | +$15K | 27% | 294 | 6 / 4 (Dancedoge $32M) | **the Dancedoge dev from D4** (systematic dumper, 0.75) |
| bsol_x | Admin | 5,631 | @bsol_x | −$13K / +$4K / +$1K | −$17K | 20% | 0 | — | |
| stellanyang | | 812 | — | −$19K / −$14K / −$2K | −$18K | 25% | 0 | — | |
| **slingoor** | Admin | 124,796 | @slingoorio | **−$192K / −$570K / −$4K** | **+$831K (+22%)** | 19.5% | 28 | 14 / 4 | the two sources disagree by $1M: GMGN counts realized sells, pump.fun marks his open bags |
| mitch | Admin | **562,005** | — | −$197K / −$100K / −$39K | +$8K | 17% | 176 | 16 / 2 (MITCH $42.6M) | the largest account in the group, 4.5× slingoor's following |
| alpha_co | | 305 | @alpha_co | (blank) | −$1K | 24% | 0 | — | |

Totals across the 32 wallets, GMGN 30 d: **$8.79M deployed, +$1.31M realized**; 20 of 32 have launched
tokens; combined pump.fun following ≈ 830K, of which mitch 562K and slingoor 125K.

### 5.1 What the member list says

1. **Two engines, not one.** The trading P&L is concentrated in lvvpumpy (+$468K group view) and
   retardmode (+$373K realized, 79% on cost, 52% win rate, 1,133 SOL). The audience is concentrated
   in mitch (562K followers) and slingoor (125K). The launches come from slingoor, mitch, jester,
   gampsito, hashbergers, 0xkgc, retardmode. Money, reach and supply are held by different members,
   which is what a coordinated group looks like.
2. **Five of our audited devs are in the room.** slingoor (TOAD), 0xkgc (biketyson), gampsito
   (Dancedoge, cut in D4 as a systematic dumper), plus mitch and jester whose books we had not pulled:
   mitch 176 launches / 16 hits / MITCH $42.6M; jester 165 launches / 18 hits / 7 ≥ $1M. Both are now
   in `candidates.jsonl` (source `synagogue`) and their books are cached.
3. **GMGN's own tags mark the group's character**: retardmode and slingoor `top_dev`; jester `kol`
   and `wash_trader`; hashbergers `sandwich_bot`; waynecapital and badattrading `smart_degen`. A
   sandwich bot and a wash-trader sit next to the two top devs.
4. **The 7-day drawdown is slingoor's.** Group −$442K; slingoor −$570K, mitch −$100K, offset by
   lvvpumpy +$166K and retardmode +$104K. He is carrying open bags in his own coins (LMAO! $193K, TOAD
   held through −27%). GMGN still shows him +$831K realized because it counts what he sold, not what
   he holds. Both are true.
5. **Small accounts lose.** 20 of 32 members are negative on the 30-day group view; the median member
   is roughly flat to −$1K. Being in the room is not the edge; being the one who launches or the one
   who buys first is.

### 5.2 For the plan

- Track all 32 wallets as creators: any create event from one of them is a group launch and gets the
  group's bid. The watcher already records creators of every graduation; `candidates.jsonl` now tags
  these as `synagogue`, so a group launch can be flagged at creation from the pump.fun feed.
- The three launchers worth a D5a-style pass next: **retardmode** (4 hits in 19, top_dev, the best
  trader in the group), **mitch** (176 launches, the biggest audience), **jester** (18 hits but kol +
  wash_trader tags and an implausible $2B peak; treat as a bundler until the klines say otherwise).
- Keep the exit rule ours. The group holds its own launches through 27–50% drawdowns; the first wave
  is theirs, the second wave is the followers, and the 24-hour close on their hits is 0.2–0.6× of the
  first minute for the spike-shape devs.
