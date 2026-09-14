# Digest — wallet-side GMGN skills (read in full)

Covers: gmgn-wallet-analysis (+ analyze.py), gmgn-wallet-score, gmgn-portfolio, gmgn-dev-score
(+ dev_score.py references), gmgn-token, gmgn-track, gmgn-holder-analysis, CLAUDE.md,
docs/cli-usage.md. Numbers below are copied from the skills, not invented.

## Commands and exact flags

```bash
gmgn-cli config --check                         # exit 0 = key configured
gmgn-cli portfolio stats   --chain sol --wallet W --period 7d|30d --raw        # w3, key only
gmgn-cli portfolio profits --chain sol --wallet W [--wallet W2 …≤100] --period 1d|7d|30d|all --raw   # w3
gmgn-cli portfolio activity --chain sol --wallet W [--token T] [--limit n] [--cursor c] \
        [--type buy --type sell --type transferIn --type transferOut --type add --type remove] --raw # w3, 20 rows/page hard cap
gmgn-cli portfolio holdings --chain sol --wallet W --limit ≤50 --order-by usd_value|last_active_timestamp|realized_profit|unrealized_profit|total_profit|history_bought_cost|history_sold_income \
        --direction desc --hide-closed false --hide-airdrop true --raw          # w5, NEEDS GMGN_PRIVATE_KEY
gmgn-cli portfolio created-tokens --chain sol --wallet W [--order-by market_cap|token_ath_mc] [--migrate-state migrated|non_migrated] --raw  # w2
gmgn-cli portfolio token-balance --chain sol --wallet W --token T --raw          # w1
gmgn-cli token info     --chain sol --address T --raw     # w1  (flag is --address, not --token)
gmgn-cli token security --chain sol --address T --raw     # w1
gmgn-cli token pool     --chain sol --address T --raw     # w1
gmgn-cli token holders  --chain sol --address T --limit ≤100 --order-by amount_percentage|profit|unrealized_profit|buy_volume_cur|sell_volume_cur --tag smart_degen|renowned|fresh_wallet|dev|sniper|rat_trader|bundler|transfer_in|dex_bot|bluechip_owner --raw  # w5
gmgn-cli token traders  --chain sol --address T (same flags as holders) --raw   # w5
gmgn-cli track kol        --chain sol --limit ≤200 [--side buy|sell] --raw      # w1 (side is client-side)
gmgn-cli track smartmoney --chain sol --limit ≤200 [--side buy|sell] --raw      # w1
gmgn-cli track follow-tokens --chain sol --wallet W --raw                       # w3, key only
gmgn-cli market kline --chain sol --address T --resolution 30s|1m|5m|15m|1h|4h|1d [--from unix] [--to unix] --raw
```

Env: `GMGN_RATE_LIMIT_AUTO_RETRY_MAX_WAIT_MS=90000` lets the CLI absorb a 429 ban using the
server's `x-ratelimit-reset` header. Empty stdout with exit 0 = soft rate limit, not "no data".
Retrying at/before the reset instant extends a ban by 5 s each time (max 5 min). Never run calls
in parallel; ~0.35 s gap sequential is the pacing dev_score.py uses.

## Response shapes (envelopes differ per route)

| Route | Rows live at |
|-------|--------------|
| stats | bare object; `pnl_stat{token_num, winrate, pnl_lt_nd5_num, pnl_nd5_0x_num, pnl_0x_2x_num, pnl_2x_5x_num, pnl_gt_5x_num, avg_holding_period}`, `common{tags, twitter_username, followers_count, follow_count, created_token_count, created_at, fund_from_address, fund_amount}`, `buy`, `sell`, `bought_cost`, `sold_income`, `bought_fee`, `sold_fee`, `realized_profit`, `realized_profit_pnl`, `native_balance`, `last_timestamp` |
| profits | `{"list":[row]}`; row has `realized_profit`, `realized_profit_cost`, `buy`, `sell`, `unrealized_profit`, `total_realized_profit`, `total_realized_profit_cost`, `total_profit`, `total_cost` |
| activity | `{"activities":[…], "next": cursor}`; row: `tx_hash`, `timestamp`, `event_type` (buy/sell/transfer_in/transfer_out/launch/claim_fee/burn/add/remove — note filter is camelCase `transferOut`, response is snake_case), `token{address,symbol,total_supply}`, `token_amount`, `quote_amount`, `cost_usd`, `buy_cost_usd` (on sells: cost basis of what was sold → `cost_usd − buy_cost_usd` is that exit's realized P&L), `price_usd`, `price`, `is_open_or_close`, `quote_token`, `from_address`, `to_address`, `gas_native`, `gas_usd`, `priority_fee`, `tip_fee`, `launchpad`, `launchpad_platform` |
| holdings | `{"list":[…], "next"}`; row: `token{token_address, symbol, is_honeypot, launchpad_platform, launchpad, liquidity, total_supply, creation_timestamp}`, `balance`, `usd_value`, `accu_cost`, `history_bought_cost`, `history_sold_income`, `realized_profit`, `unrealized_profit`, `total_profit`, `total_profit_pnl`, `history_total_buys`, `history_total_sells`, `start_holding_at`, `end_holding_at`, `wallet_token_tags` |
| created-tokens | bare: `inner_count`, `open_count`, `open_ratio`, `creator_ath_info{ath_mc, ath_token, token_symbol}`, `tokens[]` (≤~101 rows, newest first) with `token_address`, `is_open`, `pool_liquidity`, `token_ath_mc`, `market_cap`, `holders`, `create_timestamp`, `launchpad_platform`, `bundler_rate`, `cto_flag`, `total_fee`, `coin_creator_fee` |
| token info | `address, symbol, total_supply, circulating_supply, price{price, price_1m…24h, buys_/sells_/volume_/swaps_{1m,5m,1h,6h,24h}, hot_level}, liquidity, holder_count, creation_timestamp, open_timestamp, launchpad, launchpad_status (0 not open/1 live/2 migrated), launchpad_progress, launchpad_platform, migrated_pool, migration_market_cap, ath_price, dev{creator_address, creator_token_balance, creator_token_status (creator_hold/creator_sell*/creator_close), creator_open_count, cto_flag, fund_from, dexscr_*, ath_token_info{ath_mc…}}, link{twitter_username, website, telegram, description}, stat{top_10_holder_rate, dev_team_hold_rate, creator_hold_rate, top_rat_trader_percentage, top_bundler_trader_percentage, fresh_wallet_rate, bot_degen_rate}, wallet_tags_stat{smart_wallets, renowned_wallets, sniper_wallets, rat_trader_wallets, bundler_wallets, whale_wallets, fresh_wallets}, fee_distribution{launchpad, platform_data}` |
| token security | `is_honeypot` (EVM only), `renounced_mint`, `renounced_freeze_account`, `buy_tax`, `sell_tax`, `top_10_holder_rate`, `creator_balance_rate`, `creator_token_status`, `suspected_insider_hold_rate`, `rug_ratio` (0–1), `is_wash_trading`, `rat_trader_amount_rate`, `bundler_trader_amount_rate`, `sniper_count`, `burn_status` |
| trending / trenches items | `address, symbol, price, volume, liquidity, market_cap, initial_liquidity, history_highest_market_cap, swaps, buys, sells, holder_count, top_10_holder_rate, open_timestamp, creation_timestamp, launchpad, launchpad_platform, launchpad_status, exchange, creator, creator_token_status, rug_ratio, sniper_count, smart_degen_count, renowned_count, rat_trader_amount_rate, bundler_trader_amount_rate, is_wash_trading, cto_flag, image_dup, twitter_rename_count, hot_level, total_fee` |

## gmgn-wallet-analysis — the four gates (analyze.py)

Data plan (weights): stats_7d 3 → profits_all 3 → holdings 5 (=11, verdict decidable) →
activity ×3 pages 9 (=20) → stats_30d 3, profits_1d 3 (=26) → created-tokens 2 only if launcher.

| Gate | Fails when |
|------|-----------|
| G1 Authenticity | `wash_trader` tag AND `conviction_share < 0.5`; or launcher (`created_token_count > 0.5 × token_num`); or `token_num < 5`; or one-coin (realized>0, ≤1 token above 2x, ≥8 tokens, losers > 50%) |
| G2 Currency | roi_7d ≤ −10% while roi_all > +10%; or 7d and 30d both negative; or never worked |
| G3 Reachability | median copy window < 3 × latency (default 3 s); or median entry mcap < $30k; or `sandwich_bot`/`mev_bot` tag; or ≥10k followers while trading sub-$1M caps; or gas ≥ 25% of profit; or avg buy < $50; or > 100 trades/day |
| G4 Survivability | ≥2 live honeypots (refuted if `history_total_sells > 0`); or ≥35% of tokens down >50%; or ≥3 positions down 90%+ with zero sells |

Metric definitions used (reuse these in phase 2):
- copy window = median(first sell ts − first buy ts) per token, from activity
- entry mcap = `price_usd × token.total_supply` on buy rows; p25/p50/p75; share < $100k
- flip5 rate = round trips with first sell ≤ 5 s after first buy (needs ≥10 round trips)
- dump share = tokens where the largest sell ≥ 80% of sold USD (needs ≥10 sellers)
- top3 buy share = top-3 tokens' share of buy USD (needs ≥5 tokens)
- hour peak share = best 6-hour window's share of trades (needs ≥20 ts, span ≥12 h)
- posture 24h: distributing if sells > 2× buys, accumulating if buys > 2× sells, else rotating
- conviction share = realized gains from positions with `realized_profit ≥ accu_cost` or ≥ $1k per exit, ÷ all gains (needs ≥3 gainers) — the wash-trader corroboration
- profit concentration = largest winner ÷ sum of winners (trusted only with ≥3 winners over ≥8 positions)
- size cap = half the wallet's own average buy
- form: 💀 broken (all > 0.1 and 7d ≤ −0.1), 🔥 heating (7d > max(0.1, all)), ➡️ steady (|7d−all| ≤ 0.15), ❄️ cooling (7d < all − 0.15), ⚫ never worked
- profit engine: 🕸️ spray-and-hit vs ⚙️ turnover grind vs 🎯 pick-and-size, from per_day × top-3 winners' share

Tag severities: `wash_trader` veto G1 only if corroborated; `sandwich_bot`/`mev_bot` veto G3;
`kol`, `top_followed`, `top_renamed`, `sniper`, `rat_trader`, `bundler`, `insider`, `dev`,
`fresh_wallet` warn; `smart_money`, `bluechip_owner` good; `photon`, `bullx`, `gmgn`, `maestro`,
`pepeboost` neutral order-channel provenance.

Run: `python3 .claude/skills/gmgn-wallet-analysis/analyze.py <WALLET> sol en [--latency 3] [--size usd] [--brief]`

## gmgn-wallet-score — formulas

Inputs: stats 7d, activity sample (default 200 rows, max 400), created-tokens + token security
only if dev wallet.

Track-record score (0–100) = 100 × Σ w·factor, factors clamped 0–1:
- stop-loss discipline 0.34: `1 − lt_n50/token_num`
- profit share 0.28: `(gt5 + x2_5 + x0_2)/token_num`
- capital ROI 0.16: `clamp((roi + 0.05)/0.35)` (−5%→0, +30%→1)
- win rate 0.10: `clamp(winrate/0.5)`
- sample size 0.12: `clamp((token_num − 20)/300)`

Copy-tradeability score (0–100):
- entry 0.22: `clamp(0.12 + (1 − entry_under_100k))`
- profit per trade 0.22: `clamp(realized_profit/sell_count / 80)`
- hold vs latency 0.20: `clamp((1 − 1.6·flip5) × clamp(avg_hold_s/172800 + 0.15))`
- feasibility 0.18: `clamp(1 − trades/2500)`
- edge type 0.18: `clamp(1 − 0.6·entry_under_100k − 0.6·flip5)`

Backtest: `copy_pct = wallet_pct − latency·0.015·(0.3 + 0.7·entry_under_100k) − 2·slippage − gas/avg_buy`,
defaults latency 3 s, slippage 5%, gas $0.2.

Style tags: 🤖 trades ≥ 2000/7d; ⚡ flip5 ≥ 0.3; 🎯 entry_under_100k ≥ 0.8; 💎 hold ≥ 5 d and
< 200 trades; 🐋 avg buy ≥ $5k; 🏆 winrate ≥ 0.65 and ≥ 15 trades; 🐇 avg hold < 1 h; 🔦
median entry < $30k; 📈 realized > $20k and big_loss ≤ 5%; 🎰 winrate < 0.35 with hits; 🐌 < 60
trades.

Verdict: dev & score<40 🔴; dev 🟡; track ≥65 & copy <35 ⚠️; track ≥60 & copy ≥55 🟢; track <40 🔴; else 🟡.

## gmgn-dev-score — for the "track dev wallets" hypothesis

Run: `python3 .claude/skills/gmgn-dev-score/dev_score.py sol <creator_address> [max_pages]` → JSON.
- Resolve creator from a token: `token info` → `dev.creator_address`.
- dump = pulled out ≥ 1.5× what he put in AND first sell ≤ 30 s after launch.
- severity per coin = `clamp((mult−1)/3) × clamp((120 − first_sell_s)/120)`.
- CONDUCT raw = `100 − 55·mean_severity − 10·clamp((cto_rate−0.3)/0.7)`, shrunk toward 60 by
  `w = min(1, coins_with_trades/5) × min(1, career_days/30)` when raw > 60; factory penalty
  `−45·clamp((log10(max(20,inner)) − log10 20)/(log10 500 − log10 20))`; unaccounted exit −15 and cap 74.
- POWER = min(100, B1 peak `clamp((log10(ath)−5)/4)·60` + B2 repeat `min(25, 11+5·log2(successes ≥ $1M))`
  + B3 flagship alive 10 + B4 book quality `10·(0.5·survival + 0.3·graduation + 0.2·(1−drawdown))·min(1, sampled/5)`).
- TOTAL = CONDUCT + `max(0, min(1, successes/3) × (POWER−50)/50 × 15)`; dump-gate caps: systematic 45/49, frequent −20 & cap 74, unproven cap 65/74.
- Bands: ≥75 buyable, ≥50 mixed, ≥30 avoid, else stay_away.
- created-tokens `tokens[]` is newest-first and capped ~101; `N = max(inner+open, len(tokens))`.

## gmgn-token — quick scoring card (his likely safety filter)

✅/⚠️/🚫: `rug_ratio` <0.10 / 0.10–0.30 / >0.30; `top_10_holder_rate` <0.20 / 0.20–0.50 / >0.50;
`sniper_count` <5 / 5–20 / >20; `renounced_mint` & `renounced_freeze_account` true; `creator_token_status`
creator_close ✅ vs creator_hold 🚫; `smart_wallets` ≥3 ✅, 0 bearish. Honeypot = hard stop.
`market cap = price.price × circulating_supply`. Wallet `--tag dex_bot` covers Axiom, Photon,
BullX, Trojan, GMGN, Drops, PepeBoost, Padre.

## gmgn-holder-analysis — thresholds (float-based, top-100 holders)

Rating 🔴 if rat traders >5% or largest wallet >10% or dev sock puppet; ⚠️ if ≥2 of {dev holding
>1%, airdrop >20%, risk wallets >35%, linked >15%}; 🟡 exactly one; ✅ none. Top10 >60% 🔴 / >40%
🟡; top20 >75% / >55%; risk wallets >35% / >15%; linked funding >25% / >10% (escalate to 🟡 if any
group funded within 60 s). Run: `python3 .claude/skills/gmgn-holder-analysis/analyze.py <TOKEN> sol en`.

## gmgn-track — signal reading

`is_open_or_close`: kol/smartmoney 0 = open/add, 1 = close/reduce (follow-wallet is inverted).
Cluster signal = ≥3 distinct wallets same direction within ~30 min. `price_change` is a ratio
since the trade (6.66 = +566%).
