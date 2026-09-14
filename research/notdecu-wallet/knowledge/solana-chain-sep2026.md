# Solana chain snapshot — September 2026 (written 2026-09-14)

Purpose: the "top chain volume and metadata as of this month" item from the strategy-2 recon list.
Two kinds of numbers: **measured** here (Helius RPC and pump.fun HTTP, 18:53 UTC today) and **published**
(web sources, cited). Published numbers disagree with each other in places; where they do, the measured
value wins and the disagreement is noted.

## 1. Network (measured, Helius mainnet RPC)

| Metric | Value | How |
|---|---|---|
| Slot / epoch | 447,049,698 / 1034 | `getSlot`, `getEpochInfo` |
| Slot time | 319 ms (3.13 slots/s) | `getRecentPerformanceSamples(10)` |
| TPS total / non-vote | 4,307 / 2,190 | same (non-vote = user transactions, ~189M/day at this rate) |
| Priority fee on the Pump program, last 150 slots | median 0, p90 735K, max 2.0M µlamports/CU | `getRecentPrioritizationFees([pump])` — the p90 is what a launch-second buy competes against |
| SOL/USD | $103.44 | pump.fun `/sol-price` (not stale) |

The 2.0M µlamports/CU spikes on the Pump program are launch-second sniper auctions: at 120K CU a buy at
that fee pays 0.24 SOL (~$25) in priority alone. Our own wallet-of-study paid a flat 0.0005–0.002 SOL and
still filled in the first slot 50%+ of the time, because it entered *after* the sniper window (median age
at entry was measured in 2.4, see `05-selection-profile.md`).

## 2. Network (published)

| Metric | Value | Source |
|---|---|---|
| Daily fee payers | ~2.2M avg (Q1 2026) | [Solana Compass](https://solanacompass.com/) via search; [Token Terminal daily active addresses](https://tokenterminal.com/explorer/projects/solana/metrics/active-addresses-daily) |
| Daily non-vote transactions | 112.6M avg (Q1 2026, +50% q/q) | same; our measured 2,190 non-vote TPS implies ~189M/day today |
| Active addresses | 2.4–5.1M/day | [The Block on-chain metrics](https://www.theblock.co/data/on-chain-metrics/solana) |
| Fees vs revenue | ~$4.3B annualised fees, ~$28.7M protocol revenue | [DefiLlama Solana](https://defillama.com/chain/solana), [Messari](https://solana.messari.io/performance) |
| Uptime | 100% over 90 days as of 2026-07-23; no full halt since 2024-02-06 | [Chainspect](https://chainspect.app/chain/solana) |
| SOL price | one source says $72.91 with "Fear" sentiment | [CoinStats analysis](https://coinstats.app/ai/a/investment-analysis-solana) — **conflicts with the measured $103.44; treat the CoinStats figure as stale/unreliable** |

## 3. DEX and memecoin volume (published)

| Metric | Value | Source |
|---|---|---|
| Solana 24h DEX volume, 2026-09-12 | $3.25B ($530M ahead of Robinhood Chain) | [CoinStats](https://coinstats.app/ai/a/investment-analysis-solana) |
| Solana share of memecoin market | 85% (Aug 2026), ahead of Robinhood and BNB Chain | [edgeX news](https://pro.edgex.exchange/en-US/news/article/solana-reclaims-85-memecoin-market-share) |
| Solana spot DEX market share | 29% → 33% in Q1 2026 while industry volume fell 30% q/q | [Step Data Q1 report](https://stepdata.substack.com/p/solana-dex-volume-q1-report) |
| Solana memecoin market cap | $5.1B → ~$6.7B YTD; daily volume $850M → $2.57B | [BingX](https://bingx.com/en/learn/article/top-solana-meme-coins) (promotional source, directional only) |
| Memecoin share of Solana DEX volume | fell to ~10% at one point in 2026 | [SolanaFloor](https://solanafloor.com/news/memecoin-dex-volume-share-drops-10-solana-defi-maturing) |
| Competing venue | prediction markets doubled to $4.3B while Solana memecoin trading slumped | [CryptoSlate](https://cryptoslate.com/new-degen-trenches-prediction-markets-double-volume-to-4-3b-as-solana-memecoin-trading-slumps/) |
| Raydium share of Solana DEX volume | 49.2% (Q1 2025, historical) | Step Data |

Reading: the chain is bigger than a year ago in users and transactions, but memecoin *trading* is a
smaller and more concentrated slice of it. That concentration is on pump.fun, which is the point for us.

## 4. pump.fun this month (published + measured)

| Metric | Value | Source |
|---|---|---|
| Launches per day | 35,183–49,530 per daily cohort (late Aug 2026) | [Solana Compass](https://solanacompass.com/news/pumpfun-launched-42000-tokens-in-one-day-fewer-than-2-will-ever-reach-a-dex), [Step Data showdown](https://stepdata.substack.com/p/solana-launchpad-showdown-pumpfun) |
| Launches per day (measured) | ~42K (200 newest coins in 6.8 min) | pump.fun `/coins?sort=created_timestamp` |
| Graduation rate | ~2.7% (late-Aug cohorts); broke down to 1.15% at the low | Step Data; [Cryptopolitan](https://www.cryptopolitan.com/pump-fun-graduating-tokens-break-to-1-15-of-new-launches/) |
| Share of all Solana graduations | 95% | [CoinMarketCap Academy](https://coinmarketcap.com/academy/article/pumpfun-controls-95percent-of-token-graduation-market) |
| Bonding-curve volume, first week of Sept | ~$1.14B quote-side across ~323K distinct tokens | Step Data |
| Revenue | ~$3M/day in September; ~$1M/day cited in a slower period | [The Block](https://www.theblock.co/post/375352/pump-fun-dominates-token-launches-1-million-daily-despite-market-slowdown), [Tokenomics.com](https://tokenomics.com/articles/pumpfun-tokenomics-how-pump-distributes-45m-monthly-to-holders) |
| Graduated-token volume on Raydium/PumpSwap | daily series available | [The Block data](https://www.theblock.co/data/decentralized-finance/launchpads/pump-fun-graduated-tokens-volume-daily) |
| Quote mints at launch (measured) | 80% SOL, 6.5% PUMP, 3% USDC, rest exotic | `/coins` newest 200 |
| Socials at launch (measured) | 43% twitter, 19% website | same |

Implications for dev farming (numbers only; no tactics yet):

- ~42K launches/day and ~2.7% graduation means ~1,100 graduations/day. A top-dev list has to be
  selected from the creators of those ~1,100/day, not from the 42K. GMGN `token info` gives
  `creator_created_count` / `creator_open_count` per token, which is the cheapest first filter.
- $1.14B/week on the curve over 323K tokens is ~$3.5K average curve volume per token; the median is
  far lower. Whatever list we build must be judged on the tail (tokens that reach $100K+ mcap), which
  the ATH fields (`coins-v2.ath_market_cap`, GMGN `ath_price`) expose directly.
- Priority-fee auctions at launch are 0.7–2.0M µlamports/CU. A $50 account cannot win those; the entry
  style that fits is post-sniper (seconds to minutes after creation), which is also where the studied
  wallet lived.
- Competitor launchpads (LetsBonk on Raydium LaunchLab, others) are below 5% of graduations combined
  this month, so the SOL + pump.fun scope decision stands.

## 5. Source reliability

- Measured values: reproducible with `scripts/env_check.py` style probes; keep re-measuring monthly.
- Step Data, The Block, Solana Compass, DefiLlama, Token Terminal, Messari: data publishers, cite freely.
- CoinStats (AI-generated page), BingX and KuCoin blogs, edgeX news: secondary or promotional; used only
  where no primary source surfaced, and flagged above.
