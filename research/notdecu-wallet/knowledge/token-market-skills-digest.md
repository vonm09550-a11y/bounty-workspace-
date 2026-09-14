# Digest — token / market / execution GMGN skills and workflow docs

> **Correction note (live-verified):** a live `gmgn-cli token security --chain sol` call confirms `rug_ratio`, `is_wash_trading`, `sniper_count`, `creator_token_status`, `bundler_trader_amount_rate` and `rat_trader_amount_rate` are all **null on sol** in the `token security` response. Those fields are only present on `market trending` / `market trenches` / `market hot-searches` rank rows. Wherever a workflow doc or gmgn-swap below says to read them from `token security`, treat that as wrong for sol and use the listing rows instead.

Source root: `/tmp/claude-0/-home-user-bounty-workspace-/16aeee2d-76bd-5537-b1d4-404318c120c6/scratchpad/gmgn-skills/`

Files read in full: contract-dd 915 lines, cooking 696, heat-rank 633, kline-pattern 272, narrative 129 + 2 refs, swap 848, token-buy 229 + 4 refs, market 1341, and all 9 workflow docs.

## Global facts (apply to every command)

- Preamble every skill runs: `gmgn-cli config --check` (exit 0 ok; exit 1 → `gmgn-cli config`, then `gmgn-cli config --apply <KEY>`). Update via `npm install -g gmgn-cli`. IPv4 only.
- Credentials: `~/.config/gmgn/.env` (`GMGN_API_KEY`, `GMGN_PRIVATE_KEY`); a `.env` in CWD overrides it. Read endpoints need API key only; `swap`, `multi-swap`, `order strategy *`, `cooking create`, `track follow-wallet` need the private key.
- Rate limit: leaky bucket `rate=20`, `capacity=20`, throughput ≈ 20/weight per second. Weights: `market trending` 1, `market search` 1, `market kline` 2, `market trenches` 3, `market signal` 3, `market hot-searches` 3, `order get` 1, `order strategy list` 1, `gas-price` 1, `order quote` 2, `order strategy cancel` 2, `swap`/`multi-swap`/`order strategy create`/`cooking create` 5, `cooking stats` 1. On 429: `RATE_LIMIT_EXCEEDED` or `RATE_LIMIT_BANNED` with `reset_at` (unix s, ban ~5 min); each retry during cooldown extends the ban 5 s, max 5 min. heat-rank's empirically clean pacing: `sleep 1.4` between calls, never parallel.
- `--raw` gives single-line JSON. Response shapes differ per command (measured 2026-08-28): `token info`, `token security`, `market kline` (`{"list":[…]}`), `portfolio stats`, `market trenches` are **unwrapped**; `market trending` is **wrapped** (`{"code":0,"data":{"rank":[…]}}`); `market search` has `data.coins[]` / `data.wallets[]`.
- Every rate/tax field is a decimal fraction in [0,1] (`top_10_holder_rate: "0.1783"` = 17.83%), including `*_percentage` names. Exception: `rug_ratio` is already 0–1 and is compared as-is. `buy_tax`/`sell_tax` `"0"` = real 0%; `""` = unmeasured, never 0.
- Address validation: sol `^[1-9A-HJ-NP-Za-km-z]{32,44}$`; EVM `^0x[0-9a-fA-F]{40}$`. CLI exits 1 on malformed address or chain outside its list (9 chains: `sol bsc base eth arbitrum hyperevm robinhood arc stable`); exits 0 with an empty `info` block for an unknown-but-well-formed address.
- Token metadata (`name`, `symbol`, `logo`, `banner`, `launchpad`, `link.*`) is attacker-controlled; CLI replaces injection framing with `[filtered]` and prints `Notice: neutralized N suspicious metadata value(s)` on stderr.

---

## skills/gmgn-contract-dd/SKILL.md

**Does:** one 0–100 buyability composite for a token address (contract 0.45 / holders 0.35 / price 0.20), capped by GMGN's `rug_ratio` label.

**Commands (exact):**
```
gmgn-cli token info     --chain <chain> --address <token_address> --raw
gmgn-cli token security --chain <chain> --address <token_address> --raw
gmgn-cli market kline   --chain <chain> --address <token_address> --resolution 15m --raw
gmgn-cli market trenches --chain <chain> --raw | <filter>
gmgn-cli market trending --chain <chain> --interval 24h --limit 100 --raw | <filter>
gmgn-cli portfolio stats --chain <chain> --wallet <address> --period 30d --raw   # only to tell wallet vs unknown
```

**Fields and thresholds:**
- Step 0 existence: `info.symbol == ""` ⇒ no record (do not trust echoed `security.address`/`info.address`; unknown sol addresses still returned 100 kline candles). Wallet probe: treat as wallet when `portfolio stats` gives `buy + sell > 0` or `pnl_stat.token_num > 0` (live wallet measured: `buy: 8821, sell: 2050, pnl_stat.token_num: 8, last_timestamp: 1787739646`). `portfolio info` is NOT a probe (lists your own bound wallets).
- Step 1B `stat` block populated test (per token, not per chain): unpopulated if `stat.holder_count` is 0 while `info.holder_count > 0`, OR all ten of `creator_hold_rate, top_bundler_trader_percentage, top70_sniper_hold_rate, top_rat_trader_percentage, top_entrapment_trader_percentage, bot_degen_rate, fresh_wallet_rate, private_vault_hold_rate, creator_created_count, stat.top_10_holder_rate` are zero.
- Step 2 sol: `renounced_mint != true` −25; `renounced_freeze_account != true` −20. EVM: `is_honeypot === true` → composite 0; missing `is_honeypot`/`is_open_source` on a populated block → cap 79; `is_open_source === false` −15; `is_renounced === false` −8; `is_blacklist === true` −20.
- Step 3 contract (worst matching tier only, per field): `max(buy_tax, sell_tax)` >10% −25 / >5% −10; LP not locked (`lock_summary.is_locked === false` and on sol `burn_status` present and ≠ `"burn"`) −12 (on bsc/base/eth/robinhood/arc/stable the lock half alone fires −12 and caps at 79; skipped on arbitrum/hyperevm); liquidity (`info.liquidity` or `pool.liquidity`, non-zero one) <$10K −15 / <$50K −6; `pool.liquidity / pool.initial_liquidity` <0.5 −10 (`initial_liquidity: 0` = unavailable); `stat.creator_created_count` ≥500 −18 / ≥200 −14 / ≥50 −10 / ≥10 −6 / ≥3 −3; `info.image_dup_count > 0` −6; `len(kline.list)` <8 −12, 8–23 −6.
- Step 4 holders: `top_10_holder_rate` (take non-zero of `security.` vs `stat.`) >50% −25 / >30% −14 / >20% −6; `info.holder_count` <200 −12 / <500 −5; `stat.creator_hold_rate` >5%/>2% −20/−10; `stat.top_bundler_trader_percentage` >30/>15/>5% −20/−10/−4; `stat.top70_sniper_hold_rate` >15/>5% −15/−6; `stat.top_rat_trader_percentage` >5/>1% −12/−5; `stat.top_entrapment_trader_percentage` >50/>20/>5% −22/−16/−10; `stat.bot_degen_rate` >70/>50% −12/−6; `stat.fresh_wallet_rate` >50% −8; `stat.private_vault_hold_rate` >5% −8.
- Step 5 price, window W = last min(96, n) candles (default call returns exactly 100 candles; every field is a string; `time` is ms): `drawdown = 1 − C[-1]/max(H)` >70/50/30% −30/−18/−8; worst candle `(C−O)/O` < −50/−30% −14/−7; `float(info.price.price)/float(info.price.price_24h) < 0.5` −10 (`price_24h` is the price 24h ago, not a % change; `info.price` is a dict holding `price, price_1m/5m/1h/6h/24h, buys_24h, sells_24h, volume_24h, buy_volume_24h, sell_volume_24h, swaps_24h`); `vol_ratio = mean(V[-20:])/mean(V[-40:-20]) < 0.20` −18 (needs ≥40 candles).
- Step 5B `rug_ratio` cap: ≥0.50 → cap 59; 0.30–0.50 → cap 79; <0.30 nothing; key absent = unavailable (not 0). `rug_ratio` is **absent from `token info`, `token security`, `token pool`** — only on trenches/trending rows. Bucket keys in raw trenches output: `completed`, `near_completion`, `new_creation` (top-level); trending rows at `data.rank`. Trenches rows carry `created_timestamp`; trending rows carry `open_timestamp`. On bsc 176/180 and base 147/180 trenches rows lack `rug_ratio`; sol trenches and all trending listings always carry it. 302/400 trending rows read exactly 0 (population default).
- Step 6: clamp sections 0–100, renormalize over sections with data (price dropped → 0.5625/0.4375), take lowest cap, coverage = executed/(executed+skipped) against inventory 23 (sol) / 25 (EVM); ≥80% "evidence sufficient", ≥50% "coverage low", <50% "insufficient". Grades ≥80 buyable / ≥60 with conditions / ≥40 not advised / <40 do not buy.
- Step 7 honeypot exemption requires `info.price.sells_24h > 500`, `sell_volume_24h > $100K`, `sell/buy volume` 0.3–3.0, no tax, and `security.privileges` present-and-empty (it was `null` on every response, so Step 7 never fires).

**Gotchas / costs:** `market trenches --chain sol --raw` = 757,598 bytes; `market trending --interval 24h --limit 100 --raw` = 233,821 bytes; `token info` ~5 KB; 100-candle kline ~15 KB. Filter in shell (the two python3 pipelines in Step 5B, with `export ADDR=`). `--limit` on trenches caps rows per category at 80.

**RE-relevant:** market cap = `float(info.price.price) * float(info.circulating_supply)` (no `market_cap` key; verified against `dev.ath_token_info.ath_mc`); `ath_price` exists. Creator data: `dev.creator_address`, `dev.creator_token_balance`, `dev.creator_token_status` (`creator_close`/`creator_hold`), `stat.creator_created_count`, `dev.twitter_name_change_history`, `dev.twitter_del_post_token_count`, `wallet_tags_stat.sniper_wallets`. `stat.bot_degen_count / stat.bot_degen_rate` gives the analysed-trader cohort size (1068/0.5416 = 1972 on a 20,930-holder token). Launchpad: `info.launchpad` vocabulary is endpoint-dependent (`openfour` from `token info` vs `flap`/`fourmeme` from trenches; on sol trending: `pump` 55, `ray_launchpad` 28, `stonkfun` 11, `meteora_virtual_curve` 6 of 100). BSC address suffix is a launchpad marker: every flap launch ends `7777` (137/137), four.meme ends `ffff` (openfour mode) or `4444`. Firing-rate table: on 25 live tokens the permission rows (`renounced_*`, `is_honeypot`, taxes) fired 0/25; discriminating rows are liquidity, `creator_created_count`, pool shrink, drawdown, worst candle, top10, holder count, bundler.

---

## skills/gmgn-cooking/SKILL.md

**Does:** deploys tokens on launchpads (`cooking create`, private key, typed `yes` on `/dev/tty` or `GMGN_ALLOW_AUTOMATED_TRADES=1` + `--yes`) or returns per-launchpad creation counts (`cooking stats`).

**Commands:** `gmgn-cli cooking stats [--raw]` → `[{launchpad, token_count}]`. `gmgn-cli cooking create --chain <sol|bsc|base|robinhood> --dex <id> --from <addr> --name --symbol --buy-amt <human units> (--image <b64> | --image-url <url>) (--slippage 0-100 | --auto-slippage) [--raised-token USDC|USD1|USDT] [--priority-fee] [--tip-fee] [--gas-price wei] [--anti-mev sol only] [--is-mayhem|--is-cashback|--is-buy-back pump only] [--pump-fee-share-list json] [--bags-fee-share-list json] [--flap-rate-conf json] [--fourmeme-rate-conf json] [--buy-wallets json ≤12 pump/≤3 fourmeme] [--snip-buy-wallets json ≤10] [--sell-configs json] [--buy-trade-config|--sell-trade-config json] [--dev-wallet-bps] ...`. Poll `gmgn-cli order get --chain <chain> --order-id <id>` every 2 s up to 30 s; mint address is `report.output_token` when `state = 30`, `status = "successful"`.

**RE-relevant:** the `--dex` vocabulary is the canonical launchpad id set: sol `pump`, `bonk`, `bags`; bsc `fourmeme`, `flap`; base `klik`, `clanker`; robinhood `trench`, `pons`. `--sell-configs` shows how GMGN-launched devs automate exits: `{"sell_type":"delay_sell"|"limit_order","delay_sec"|"delay_mili_sec","sell_ratio":"0.5","check_price":"<USD mcap>","wallet_addresses":[...]}` — a bundle of wallets buying at create then dumping N seconds later or at a mcap trigger is a recognisable on-chain signature. Bonding-curve concept: graduation to Raydium (sol) / PancakeSwap (bsc).

---

## skills/gmgn-heat-rank/SKILL.md

**Does:** sweeps 7 chains × 3 windows of `market trending`, gates and scores 0–100, lists ≤10 names.

**Commands (verbatim loop):**
```
gmgn-cli market trending --chain "$ch" --interval "$iv" --limit 100 --min-marketcap 500000 --min-liquidity 100000 --max-created 7d "${F[@]}" --raw
# F: sol → --filter renounced --filter frozen --filter not_wash_trading
#    bsc|base|eth → --filter not_honeypot --filter verified --filter renounced
#    robinhood|arc|stable → no --filter (server defaults)
# intervals 24h first, then 1h, 6h; sleep 1.4 between calls
```

**Thresholds (script constants):** `MIN_LIQ 100_000, MIN_VOL24 800_000, MIN_TURN 0.05, MAX_TOP10 0.30, MAX_BOT 0.85, MIN_VOL1H 20_800, MIN_POS 0.20, MIN_HOLDERS 500, HARD_POS 0.10, MAX_RUG 0.15, MAX_DEV 0.05, YOUNG_D 2.0, MAX_AGE_D 7.0, Y_VOL1H 150_000, Y_LIQ 200_000, MIN_LMC 0.015, Y_TOP10 0.25, Y_ATH 0.45, Y_HOLD 800, Y_SM 20, Y_KOL 10, E_HARD 1.0, U_IMBAL 0.35, U_LIQ 250_000, U_TOP10 0.25, U_SNIPER 0.30, U_SCORE_ADD 8, TOP_N 10, MIN_SCORE 60, V0 3_000_000`. Bundler ceiling = max(0.60, per-chain leave-one-out p90). Score = 100×(0.14 vacc + 0.22 size + 0.08 pos + 0.15 grow + 0.13 smart + 0.14 qual + 0.08 heat + 0.06 fresh), percentiles over the pool. Reads `volume, market_cap, liquidity, holder_count, smart_degen_count, renowned_count, visiting_count, buys, sells, swaps, open_timestamp, creation_timestamp, history_highest_market_cap, price_change_percent, bot_degen_rate, bundler_rate, rug_ratio, dev_team_hold_rate, top_10_holder_rate, top70_sniper_hold_rate, entrapment_ratio, bluechip_owner_percentage, insider_rate, rat_trader_amount_rate, is_wash_trading, is_honeypot, creator_token_status`.

**Gotchas (measured on 569 unfiltered 24h rows) — field availability, share of rows non-zero:**

| field | sol | bsc | robinhood | base | eth | arc | stable |
|---|---|---|---|---|---|---|---|
| `bot_degen_rate` | 100% | 100% | 100% | 0% | 0% | 2% | 5% |
| `bundler_rate` | 92% | 70% | 62% | 0% | 0% | 2% | 0% |
| `rug_ratio` | 95% | 0% | 0% | 18% | 0% | 0% | 0% |
| `bluechip_owner_percentage` | 38% | 0 | 0 | 0 | 0 | 0 | 0 |
| `visiting_count` | 97% | 95% | 96% | 49% | 21% | 10% | 21% |
| `dev_team_hold_rate` | 38% | 10% | 17% | 5% | 8% | 12% | 21% |

`insider_rate` is never sent despite the `--min-insider-rate` flag. An unrecognised `--filter` tag is silently ignored and an all-unrecognised list disables server defaults (`--filter is_out_market` alone admitted honeypots). `price_change_percent` under 1 day of age is measured off launch price. `history_highest_market_cap` is corrupt on some rows (guard: `hh>1e10 or hh>50*mc`). Holder counts not comparable across chains. `buy_tax`/`sell_tax` arrive as strings; bsc has a real 1–3% sell tax on 93% of rows; `lock_percent` is 0.95 by default on bsc/robinhood.

**RE-relevant:** For a sol pump.fun trencher the rug gates work (95% coverage on sol); on any other chain `rug_ratio == 0` means "no model", not clean.

---

## skills/gmgn-kline-pattern/SKILL.md

**Does:** classifies a kline series into a named pattern and scores 0–100 from six hand-computed numbers.

**Command:** `gmgn-cli market kline --chain <chain> --address <address> --resolution <1m|5m|15m|30m|1h|4h|1d> --raw` (default 15m). Response `{"list":[{time(ms), open, high, low, close, volume(USD), amount(tokens), source}]}`, all strings; sort by `time` ascending; drop candles with close/high/low ≤0; <8 candles → stop.

**Formulas:** `trend_up` = mean(last 9 closes) vs mean(last 21) (three-valued); `slope` = if N≥24 `(mean(C[-5:]) − mean(C[-24:-19]))/mean(C[-24:-19])` else `(C[-1]−C[0])/C[0]`; `volatility` = mean over last 14 of `(high−low)/close`; `drawdown` = `(max(highs) − C[-1])/max(highs)`; `vol_ratio` = `V[-1]/mean(V[-21:-1])`; `up_from_low` = `(C[-1] − min(lows))/min(lows)`.
Patterns (first match): Vertical run-up `slope>0.25 & dd<0.12`; Uptrend channel `slope>0.08 & dd<0.25`; Breakdown `dd>0.55 & slope<−0.10`; Bounce off lows `dd>0.55 & slope>0.02`; Distribution at highs `dd>0.35 & |slope|<0.08`; Slow bleed `slope<−0.20`; Basing `|slope|<0.05 & vol<0.05 & up_from_low<0.20`; Wide chop `|slope|<0.08 & vol>0.08`; else Bullish/Bearish/Sideways consolidation by `trend_up`.
Score from 50: trend up/down ±12; slope >0.15 +15, 0.02–0.15 +6, <−0.15 −15, −0.15…−0.02 −6; `vol_ratio>3` green +8 / red −10; `vol_ratio<0.3` −5; dd>0.60 −15, 0.30–0.60 −6, dd<0.05 +8; divergence (N>40, new 20-bar high on volume <0.7×) −10. Clamp 0–100.

**RE-relevant:** market-cap candles are not exposed by the CLI — derive from price × supply. Use `volume` (USD) not `amount`.

---

## skills/gmgn-narrative/SKILL.md (+ references/interfaces.md, patterns.md)

**Does:** writes a story/spread card from `token info` plus an external social-search provider (`SOCIAL_SEARCH_PROVIDER=x_api|grok_api`) — no scoring thresholds.

**Commands:** `gmgn-cli token info --chain <chain> --address <address>`; optionally `gmgn-cli token security`.

**Fields read (the canonical `token info` creator/social set):** `symbol, name, dev.creator_address, dev.creator_open_count, dev.creator_token_status, dev.cto_flag, dev.ath_token_info, dev.twitter_name_change_history, link.website, link.twitter_username, fee_distribution, launchpad, launchpad_platform`, plus `is_honeypot/buy_tax/sell_tax/is_renounced` from security.

**RE-relevant:** `launchpad` and `launchpad_platform` are two distinct fields that can disagree (one may record settlement infra rather than the branded platform). `fee_distribution` shows who receives creator-reward share. `dev.creator_open_count` = prior launches that graduated. Generic website generators keyed by token address are a copycat tell; creator address repeating across several hyped tokens in a session = same operator.

---

## skills/gmgn-token-buy/SKILL.md (+ references/fields.md, pitfalls.md, resolution.md, thresholds.md)

**Does:** name → unique contract, three hard gates (volume/depth/security) + one execution gate (direction), then an order card handed to gmgn-swap. Fixed 4 requests per token.

**Commands:**
```
gmgn-cli market search -q <CA> --raw                                   # Step 0, no --chain
gmgn-cli market search -q <name|symbol|CA> [--chain <chain>] --order-by weight --raw
gmgn-cli token info     --chain <chain> --address <CA> --raw
gmgn-cli token security --chain <chain> --address <CA> --raw
gmgn-cli gas-price --chain <chain> --raw
```

**Fields:** `market search` → judge hits by `len(coins)` only (`wallets` is padded: a fake address returned 0 coins / 11 wallets). `coins[]`: `chain, address, name, symbol, liquidity` (**two-sided sum ≈ 2× depth**), `volume_24h, volume_1h, swaps_5m/1h/6h/24h, mcp, ath_market_cap` (garbage on new tokens, seen $345T), `holder_count, created_at` (unix s, may be 0), `buy_tax/sell_tax/total_buy_tax/total_sell_tax, is_honeypot, twitter_rename_count, twitter_change_flag, cto_flag, kol_count, is_og, creator, launchpad_platform, launchpad_status, progress`. `coins[]` numbers are byte-identical to `token info`. `--order-by weight` drops honeypots server-side; `--chain all` is rewritten to no chain.
`token info`: depth = `min(pool.base_reserve_value, pool.quote_reserve_value)` if both >0 else `pool.liquidity/2` (BONK's base side was `"0"` while `base_reserve` held 14.7B tokens); `pool.liquidity` always = 2× one side; `biggest_pool_address ≠ pool.pool_address` means depth is a lower bound; `pool.exchange` (`uniswap_v4`, `pancake_v2`, `meteora_dlmm`…); `price.price / price_5m / price_1h / price_24h` are **window start prices** (change = `price/price_5m − 1`); `price.buy_volume_5m/1h/24h`, `sell_volume_*`; `price.sells_24h > 0` = honeypot layer 4; `stat.creator_hold_rate` (dev holding — NOT `dev.top_10_holder_rate`); `stat.top_entrapment_trader_percentage, top_bot_degen_percentage, fresh_wallet_rate, top_rat_trader_percentage, top_bundler_trader_percentage, top70_sniper_hold_rate`; `wallet_tags_stat.bundler_wallets/smart_wallets/whale_wallets/fresh_wallets` are **counts** (`fresh_wallets` caps at 1000); `creation_timestamp` (0 = unknown; BONK has 0 for both `creation_timestamp` and `open_timestamp`); `circulating_supply`.
`token security`: honeypot 4 layers `is_honeypot` → `honeypot` int (0/1/−1 untested) → `can_not_sell=1` → info `sells_24h>0`; EVM-only `is_renounced`/`renounced`, `is_open_source`; sol-only `renounced_mint`, `renounced_freeze_account` (always `false` on EVM, meaningless); `lock_summary.is_locked` + `lock_percent` + `lock_detail[].is_blackhole` (MEME: `is_locked=true`, `lock_percent="0"`, `lock_detail[0]` 95% to `0x000…0`); `lp_holders` max 10 rows, mixes NFT positions. CLMM/DLMM pools (`_v3/_v4/clmm/dlmm`) → lock check not applicable.

**Thresholds:** 24h volume ≥$50,000; 1h swaps ≥10; volume/pool ratio bands: pool <$100K 0.30–15, $100K–1M 0.15–12, ≥$1M 0.05–30 (above cap with ≥150 holders = breakout, allowed); depth ≥$30,000; price impact ≤3%; LP: single external address ≥50% unlocked = fail; direction: 5m drop ≥10% = only hard stop, 5–10% or all three windows (5m/1h/24h) sell>buy = execution downgrade; limit trigger = `price × (1 − |5m drawdown|)`; ≥100× in 24h with negative 24h net flow = warning. Security red flags: honeypot, mintable, freezable/blacklist, tax >10%, upgradeable proxy with owner. Warnings (≥2 = fail): top10 >50%, `stat.creator_hold_rate` >5%, not open source, age <24h, rat >15%, holders <200, entrapment >30%, bot >60%, `bundler_wallets/holder_count` >5%, fresh >30%; mcap ≥$1M with <100 holders = fail. Slippage = `2% + tax + impact×1.5 + |5m change|×0.5`, cap 15%, +3% inside 1h of launch. Candidate score = geometric mean of depth, 24h vol, `min(mcap, max(depth,vol)×50)`, `min(holders, 50000)`; age prior ≤4.1×; auto-lock only if unique qualifier or leader ≥5× second. Gas: use `low/average/high` directly (P2 default), `*_prio_fee_mixed` for priority (`*_prio_fee` is `1` on sol), `native_token_usd_price`, `*_estimate_time`; sol `auto` 0.00025 SOL, `auto_mev` 0.001 SOL Jito tip; EVM gas units v2 150K / v3 180K / v4 200K.

**RE-relevant:** `market search -q <wallet>` returns `wallets[]` with `wallet_tags` (smart money/KOL) and `twitter_username` — a quick way to see how GMGN labels the target wallet. `coins[].creator`, `launchpad_platform`, `launchpad_status` (0 = on curve, 1 = migrated), `progress` (bonding-curve progress) come from a single call.

---

## skills/gmgn-swap/SKILL.md

**Does:** executes swaps, multi-wallet swaps, quotes, order polling, gas price, and limit/strategy orders (private key).

**Commands:** `gmgn-cli swap --chain <sol|bsc|base|eth|robinhood|arc|stable> --from <wallet> --input-token <addr> --output-token <addr> (--amount <smallest unit> | --percent <n>) [--slippage 0-100 | --auto-slippage] [--min-output] [--anti-mev sol/bsc/eth] [--priority-fee sol ≥0.00001] [--tip-fee sol ≥0.00001 / bsc ≥0.000001] [--gas-price gwei] [--gas-level low|average|high eth] [--auto-fee eth] [--max-fee-per-gas] [--max-priority-fee-per-gas] [--condition-orders json ≤10] [--sell-ratio-type buy_amount|hold_amount] [--yes]`; `gmgn-cli multi-swap --chain --accounts a,b (--input-amount json | --input-amount-bps json | --output-amount json) ...` (≤100 wallets); `gmgn-cli order quote --chain --from --input-token --output-token --amount --slippage`; `gmgn-cli order get --chain <chain> --order-id <id>`; `gmgn-cli gas-price --chain <eth|bsc|base|sol>`; `gmgn-cli order strategy create --chain --from --base-token --quote-token --order-type <limit_order|smart_trade> --sub-order-type <buy_low|buy_high|stop_loss|take_profit|mix_trade> [--check-price] [--open-price] (--amount-in | --amount-in-percent) [--sell-param json] [--buy-param json] [--condition-orders json] [--expire-in] [--limit-price-mode exact|slippage] ...`; `gmgn-cli order strategy list --chain --group-tag <LimitOrder|STMix> [--type open|history] [--from] [--base-token] [--page-token] [--limit]`; `gmgn-cli order strategy cancel --chain --from --order-id [--order-type] [--close-sell-model]`.

**Fields:** currency addresses: SOL `So11111111111111111111111111111111111111112`, sol USDC `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v`, EVM native `0x000…0`, bsc USDC `0x8ac76a51cc950d9822d68b83fe1ad97b32cd580d`, base USDC `0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913`. `--amount` is smallest unit (1 SOL = 1e9). `--percent` only when input is not a currency. Condition orders: `order_type profit_stop|loss_stop|profit_stop_trace|loss_stop_trace`, `side "sell"`, `price_scale` (gain % or drop %), `sell_ratio`, `drawdown_rate`. Status `pending → processed → confirmed | failed | expired`; `report.*` only at `state=30`. Pre-swap check reads `token security` for `is_honeypot == "yes"` (abort) and `rug_ratio` (>0.3 red; risk bands <0.1 / 0.1–0.3 / >0.3). Note: contract-dd verified (and the live sol call in the note at the top confirms) `rug_ratio` is not in `token security` — this doc's check is inconsistent with that measurement. EIP-1559 minimums bsc 50,000,000 wei, base/eth 200,000 wei. `swap` also has an error-count limiter (`ERROR_RATE_LIMIT_BLOCKED`, e.g. repeated `40003701` insufficient balance).

**RE-relevant:** `order strategy list --type history --group-tag STMix` fields (`open_price, close_price, record_high_price, drawdown_rate, profit_stop, loss_stop, order_statistic.buy_usdt_price/usdt_profit/success_sell_num, reason_code`) describe exactly what a GMGN-managed TP/SL/trailing strategy looks like — but only for your own API-bound wallet, not a third-party wallet.

---

## skills/gmgn-market/SKILL.md

**Does:** kline, trending ranks, trenches (launchpad lifecycle lists), signal feed, hot-searches, search.

**Commands and flags:**
- `gmgn-cli market kline --chain <c> --address <a> --resolution <30s|1m|5m|15m|1h|4h|1d> [--from <unix s>] [--to <unix s>] --raw` (weight 2; `--from/--to` seconds, CLI converts to ms).
- `gmgn-cli market trending --chain <c> --interval <1m|5m|1h|6h|24h> [--limit ≤100] [--order-by default|swaps|marketcap|history_highest_market_cap|liquidity|volume|holder_count|smart_degen_count|renowned_count|gas_fee|price|change1m|change5m|change1h|creation_timestamp] [--direction asc|desc] [--filter <tag>...] [--platform <name>...] [--min-/--max- volume|liquidity|marketcap|history-highest-marketcap|swaps|holder-count|gas-fee|renowned-count|smart-degen-count|bot-degen-count|visiting-count|price-change-percent|insider-rate|bundler-rate|entrapment-ratio|top10-holder-rate|top70-sniper-hold-rate|dev-team-hold-rate] [--min-created/--max-created 30m|6h|7d] --raw`. Default filters when `--filter` omitted: sol `renounced frozen`; EVM `not_honeypot verified renounced`. Sol filter tags: `renounced frozen burn token_burnt has_social not_social_dup not_image_dup dexscr_update_link not_wash_trading is_internal_market is_out_market`; EVM: `not_honeypot verified renounced locked token_burnt has_social not_social_dup not_image_dup dexscr_update_link is_internal_market is_out_market`. Sol `--platform` values: `Pump.fun pump_mayhem pump_mayhem_agent pump_agent letsbonk bonkers bags memoo liquid bankr zora surge anoncoin moonshot_app wendotdev heaven sugar token_mill believe trendsfun trends_fun jup_studio Moonshot boop xstocks ray_launchpad meteora_virtual_curve pool_ray pool_meteora pool_pump_amm pool_orca`.
- `gmgn-cli market trenches --chain <c> [--type new_creation|near_completion|completed ...] [--launchpad-platform <p>...] [--limit ≤80] [--filter-preset safe|smart-money|strict] [--sort-by smart_degen_count|renowned_count|volume_24h|volume_1h|swaps_24h|swaps_1h|rug_ratio|holder_count|usd_market_cap|created_timestamp] [--direction] [--min-/--max- volume-24h|net-buy-24h|swaps-24h|buys-24h|sells-24h|visiting-count|progress|marketcap|liquidity|created|holder-count|top-holder-rate|rug-ratio|bundler-rate|insider-ratio|entrapment-ratio|private-vault-hold-rate|top70-sniper-hold-rate|bot-count|bot-degen-rate|fresh-wallet-rate|total-fee|smart-degen-count|renowned-count|creator-balance-rate|creator-created-count|creator-created-open-count|creator-created-open-ratio|x-follower|twitter-rename-count|tg-call-count] --raw`. Presets: `safe` = `max_rug_ratio 0.3 + max_bundler_rate 0.3 + max_insider_ratio 0.3`; `smart-money` = `min_smart_degen_count 1`; `strict` = safe + smart-money + `min_volume_24h 1000`; explicit flags override presets. `--max-created` here takes `30s`/`0.5m`/`30m` (bare number = minutes). Response keys documented as `data.new_creation`, `data.pump` (= near_completion), `data.completed`; contract-dd's measured raw output instead has top-level `completed`, `near_completion`, `new_creation` — check the actual shape before parsing.
- `gmgn-cli market signal --chain <sol|bsc|robinhood|arc|stable> [--signal-type n ...] [--mc-min/--mc-max] [--trigger-mc-min/--trigger-mc-max] [--total-fee-min/--total-fee-max] [--min-create-or-open-ts/--max-create-or-open-ts] [--groups '<json>'] --raw`. Types 1–21 (6 PriceUp, 7 ATH, 10 BundlerSell, 11 CTO, 12 SmartDegenBuy, 13 PlatformCall, 18 PumpClaims, 20 KOLBuy…); 14/15/16 in a filter → 400. Max 50 per group. Fields `token_address, signal_type, trigger_at, trigger_mc, first_trigger_mc, market_cap, ath, signal_times, cur_data.{top_10_holder_rate, holder_count, liquidity}`.
- `gmgn-cli market hot-searches [--chain c ...] [--interval] [--limit 500] [--filter ...] [--min-*/--max-*] [--params json] --raw`; ranked by `visiting_count`; own tag vocabulary (`launching`/`migrated`, `not_risk`, `distribed`, `is_burnt`, `img_not_duplicate`, `social_not_duplicate`, `creator_hold`, `creator_close`, `locked` = lock ≥0.5, `hide_b20`).
- `gmgn-cli market search --query|-q <q> [--chain c] [--launchpad-platform p ...≤50] [--is-og true|false] [--is-launched true|false] [--order-by weight] --raw`; `coins[]` (`mcp` = market cap), `wallets[]` (≤50; `address, chain, twitter_username, wallet_tags`).

**Rank-row fields (trending/hot-searches; trenches shares most):** `address, symbol, name, chain, total_supply, creator, launchpad_platform, exchange, open_timestamp, creation_timestamp, rank, hot_level, price, market_cap, liquidity, volume, history_highest_market_cap, initial_liquidity, price_change_percent[1m|5m|1h], swaps, buys, sells, holder_count, gas_fee, renounced_mint, renounced_freeze_account, is_honeypot, is_open_source, is_renounced, buy_tax, sell_tax, burn_status, top_10_holder_rate, rug_ratio, is_wash_trading, rat_trader_amount_rate, bundler_rate, entrapment_ratio, sniper_count, bot_degen_count, bot_degen_rate, dev_team_hold_rate, top70_sniper_hold_rate, lock_percent, creator_token_status, creator_close, dev_token_burn_ratio, smart_degen_count, renowned_count, bluechip_owner_percentage, twitter_username, website, telegram, cto_flag, dexscr_ad, dexscr_update_link, dexscr_trending_bar, dexscr_boost_fee`. Trenches-specific: `usd_market_cap, created_timestamp, complete_timestamp, complete_cost_time, swaps_1m/1h/24h, volume_1h/24h, buys_24h, sells_24h, net_buy_24h, bundler_trader_amount_rate, suspected_insider_hold_rate, open_source ("yes"/"no"/"unknown"), owner_renounced, creator_balance_rate, has_at_least_one_social, x_user_follower, instagram, tiktok`.

**Quality criteria:** Pass `smart_degen_count ≥3`, `rug_ratio <0.1`, `creator_close`, `top_10_holder_rate <0.20`, `liquidity >$50k`; skip if `rug_ratio >0.3` or `is_wash_trading` or `is_honeypot = 1`. Lifecycle stages: Early (<1h, 0 smart money), Breakout (`smart_degen_count ≥3` rising, `price_change_percent1h >20%`, `swaps_1h` vs `swaps_24h/24`), Distribution (`creator_close`, KOLs entering), Decline.

**RE-relevant:** `--min-total-fee/--max-total-fee` (trenches "total fee") and `--total-fee-min/--total-fee-max` (signal "total fees paid USD") plus rank field `gas_fee` / `--min-gas-fee` are the only "fee" filters exposed — this is presumably what "global fees" maps to (total fees paid on the token, a pump.fun heat proxy). `complete_cost_time` (creation → bonding-curve completion seconds) and `progress` characterize how fast a curve filled. `--platform Pump.fun` (trending) vs `--launchpad-platform pump` (search) vs `pump` (`info.launchpad`) are three vocabularies for the same launchpad.

---

## docs/workflow-*.md (thresholds only where they add something)

- **daily-brief:** `market trending --interval 1h|6h --order-by volume --limit 20`; `track smartmoney --chain`; `track kol --chain`; `market trenches --type near_completion|completed` quick filter `smart_degen_count ≥1`, `rug_ratio <0.2`; `token security` flags `top_10_holder_rate >0.5`, `creator_hold`, `is_wash_trading`.
- **early-project-screening:** trenches with `--filter-preset safe|strict --sort-by smart_degen_count` or manual `--max-rug-ratio 0.3 --max-bundler-rate 0.3 --max-insider-ratio 0.3 --min-smart-degen-count 1 --min-volume-24h 1000`; discard if `rug_ratio >0.3`, wash, `bundler_rate >0.3`, `rat_trader_amount_rate >0.3`, or no SM/KOL and volume <$10k; security hard stops `is_honeypot "yes"`, sol renounced flags false, `rug_ratio >0.3`, `sell_tax >0.10`, `top_10_holder_rate >0.6`; then `token holders --tag smart_degen --order-by buy_volume_cur --direction desc --limit 10`, `token traders --order-by profit --direction desc --limit 10` (holder fields `buy_30m`, `buy_1h`, `last_active_timestamp`, `profit`).
- **market-opportunities:** `market trending --chain <c> --interval 1h --order-by volume --limit 50 --filter not_honeypot --filter has_social --raw`; weights SM high, bluechip/volume/momentum/liquidity medium, age low (<1h avoided).
- **project-deep-report:** 15-point score (fundamentals 3, security 4, liquidity 2, smart money 4, price 2); hard stops `rug_ratio >0.5`, both sol renounced false, `sell_tax >0.15`; `token pool` (`is_on_curve`, `exchange`, `creation_timestamp`); `market kline --resolution 4h`; trending lookup via `jq '.data.rank[] | select(.address == "<addr>")'`; holder fields `buy_volume_cur, sell_volume_cur, unrealized_profit, realized_profit, amount_percentage`; ≥11 buy, 7–10 watch, <7 skip.
- **risk-warning:** danger table (`rug_ratio >0.3`, top10 >0.5, `creator_hold`, `sell_tax >0.10`, `bundler_rate >0.3`, `rat_trader_amount_rate >0.3`); liquidity drop >30%; top 1–3 wallets >20%; `track smartmoney` `is_open_or_close`, `price_change`.
- **smart-money-profile / wallet-analysis (the wallet-side toolkit):** `portfolio stats --chain <c> --wallet <a> [--wallet <b> ...] --period 7d|30d` → `winrate` (>0.6 strong), `pnl` (= realized_profit/total_cost), `realized_profit`, `buy_count/sell_count`, `token_num`; `portfolio activity --chain --wallet --limit 100` → per-event `timestamp`/`last_active_timestamp`, `amount_usd`, buy/sell events to pair into round trips (hold time <1h scalper, 1–24h day trader, 1–7d swing, >7d position); `portfolio holdings --chain --wallet --order-by usd_value --direction desc --limit 50` → `usd_value, cost, unrealized_profit, profit_change`; `track follow-wallet --chain --wallet` (private key) → live feed with `is_open_or_close`, `price_change`; leaderboard weights winrate 40% / pnl 40% / token_num 10% / 7d-vs-30d improvement 10%.
- **token-due-diligence / token-research:** `token info` → `token security` (thresholds: taxes 0 / 0.01–0.05 / >0.10, top10 <0.20 / 0.20–0.50 / >0.50, rug <0.10 / 0.10–0.30 / >0.30, `sniper_count` <5 / 5–20 / >20) → `token pool` → trending membership check → `token holders --tag smart_degen --order-by buy_volume_cur` and `token traders --tag renowned --order-by profit`.

---

## How to reverse-engineer a pump.fun trencher with these tools

1. **Wallet history:** `portfolio activity --chain sol --wallet <W> --limit 100` (paginate) for every buy/sell with timestamps and USD; `portfolio stats --period 7d|30d` for winrate/pnl/token_num; `portfolio holdings` for open bags; `market search -q <W>` for GMGN's `wallet_tags`. (`gmgn-wallet-analysis` / `gmgn-portfolio` skills exist in the repo but were outside this read.)
2. **Per traded token — launchpad and creator:** `token info` → `launchpad`, `launchpad_platform`, `dev.creator_address`, `dev.creator_open_count`, `dev.creator_token_status`, `dev.cto_flag`, `dev.ath_token_info.ath_mc`, `stat.creator_created_count`, `creation_timestamp`, `open_timestamp`; cheaper alternative `market search -q <CA> --raw` → `coins[0].{creator, launchpad_platform, launchpad_status, progress, created_at}`. Expect `pump` / `ray_launchpad` / `stonkfun` / `meteora_virtual_curve` on sol.
3. **Entry-time context:** `market kline --chain sol --address <CA> --resolution 1m --from <entry_ts−1800> --to <entry_ts+1800> --raw`; `time` is ms, prices strings; market cap at entry = close × `total_supply` (from a rank row) or `circulating_supply` (token info). Zero candles = GMGN tracks no pool (common for tokens that never graduated).
4. **What the wallet's candidate pool looked like:** `market trenches --chain sol --type new_creation --type near_completion --type completed --limit 80 --raw` (huge; filter in shell), with `--max-created`, `--min-progress`, `--min-total-fee`, `--min-smart-degen-count`, `--max-rug-ratio`; `market signal --chain sol --signal-type 12|20|18` for smart-money/KOL/pump-claim events with `trigger_at`/`trigger_mc`; `market trending --interval 1m|5m --platform Pump.fun --order-by volume`.
5. **Rug/quality gates the wallet may be applying:** `rug_ratio` (sol only, listings only), `bundler_rate`, `rat_trader_amount_rate`, `entrapment_ratio`, `sniper_count`, `top70_sniper_hold_rate`, `dev_team_hold_rate`/`creator_balance_rate`, `creator_token_status`, `renounced_mint`/`renounced_freeze_account`, `burn_status`, `is_wash_trading`, `dexscr_*`, `has_at_least_one_social`, `x_user_follower`, `tg_call_count`, `creator_created_open_ratio` — all available as `--min-/--max-` server filters on trenches, so a hypothesised rule set can be replayed as a filter and compared against the wallet's actual buys.

---

## Reference table: every gmgn-cli subcommand encountered

| Subcommand | Flags seen (exact) | Auth | Weight |
|---|---|---|---|
| `config` | `--check`, `--apply <KEY>` | — | — |
| `token info` | `--chain`, `--address`, `--raw` | key | ? |
| `token security` | `--chain`, `--address`, `--raw` | key | ? |
| `token pool` | `--chain`, `--address`, `--raw` | key | ? |
| `token holders` | `--chain`, `--address`, `--tag smart_degen`, `--order-by buy_volume_cur\|amount_percentage`, `--direction asc\|desc`, `--limit`, `--raw` | key | ? |
| `token traders` | `--chain`, `--address`, `--tag renowned`, `--order-by profit`, `--direction`, `--limit`, `--raw` | key | ? |
| `market kline` | `--chain`, `--address`, `--resolution 30s\|1m\|5m\|15m\|30m\|1h\|4h\|1d`, `--from <s>`, `--to <s>`, `--raw` | key | 2 |
| `market trending` | `--chain`, `--interval 1m\|5m\|1h\|6h\|24h`, `--limit ≤100`, `--order-by`, `--direction`, `--filter <tag>` (rep.), `--platform <name>` (rep.), `--min-*/--max-*`, `--min-created/--max-created`, `--raw` | key | 1 |
| `market trenches` | `--chain`, `--type` (rep.), `--launchpad-platform` (rep.), `--limit ≤80`, `--filter-preset safe\|smart-money\|strict`, `--sort-by`, `--direction`, `--min-*/--max-*` (see list above), `--raw` (examples also show `--exclude-wash-trading`, `--min-smart-degen`, `--min-holders`, `--min-swaps`) | key | 3 |
| `market signal` | `--chain sol\|bsc\|robinhood\|arc\|stable`, `--signal-type` (rep., 1–21 not 14–16), `--mc-min/--mc-max`, `--trigger-mc-min/--trigger-mc-max`, `--total-fee-min/--total-fee-max`, `--min-create-or-open-ts/--max-create-or-open-ts`, `--groups <json>`, `--raw` | key | 3 |
| `market hot-searches` | `--chain` (rep.), `--interval`, `--limit 500`, `--filter` (rep.), `--min-*/--max-*`, `--params <json>`, `--raw` | key | 3 |
| `market search` | `--query/-q`, `--chain`, `--launchpad-platform` (rep. ≤50), `--is-og`, `--is-launched`, `--order-by weight`, `--raw` | key | 1 |
| `portfolio stats` | `--chain`, `--wallet` (rep. ≤10), `--period 7d\|30d`, `--raw` | key | ? |
| `portfolio holdings` | `--chain`, `--wallet`, `--order-by usd_value`, `--direction desc`, `--limit 50` | key | ? |
| `portfolio activity` | `--chain`, `--wallet`, `--limit 100` | key | ? |
| `portfolio info` | (lists wallets bound to the API key; ignores `--address`) | key | ? |
| `track smartmoney` | `--chain` | key | ? |
| `track kol` | `--chain` | key | ? |
| `track follow-wallet` | `--chain`, `--wallet` | key + private key | ? |
| `gas-price` | `--chain eth\|bsc\|base\|sol`, `--raw` (top-level command) | key | 1 |
| `swap` | `--chain`, `--from`, `--input-token`, `--output-token`, `--amount` \| `--percent`, `--slippage` \| `--auto-slippage`, `--min-output`, `--anti-mev`, `--priority-fee`, `--tip-fee`, `--gas-price`, `--gas-level`, `--auto-fee`, `--max-fee-per-gas`, `--max-priority-fee-per-gas`, `--condition-orders <json>`, `--sell-ratio-type buy_amount\|hold_amount`, `--yes` | key + pk | 5 |
| `multi-swap` | `--chain`, `--accounts a,b`, `--input-token`, `--output-token`, `--input-amount <json>` \| `--input-amount-bps <json>` \| `--output-amount <json>`, plus the same fee/slippage/condition flags as `swap` | key + pk | 5 |
| `order quote` | `--chain`, `--from`, `--input-token`, `--output-token`, `--amount`, `--slippage` | key | 2 |
| `order get` | `--chain`, `--order-id` | key (+pk per swap doc) | 1 |
| `order strategy create` | `--chain`, `--from`, `--base-token`, `--quote-token`, `--order-type limit_order\|smart_trade`, `--sub-order-type buy_low\|buy_high\|stop_loss\|take_profit\|mix_trade`, `--check-price`, `--open-price`, `--amount-in` \| `--amount-in-percent`, `--limit-price-mode exact\|slippage`, `--expire-in`, `--sell-ratio-type`, `--quote-investment`, `--sell-param <json>`, `--buy-param <json>`, `--slippage`/`--auto-slippage`, `--priority-fee`, `--tip-fee`, `--auto-fee`, `--gas-price`, `--gas-level`, `--max-fee-per-gas`, `--max-priority-fee-per-gas`, `--anti-mev`, `--condition-orders <json>`, `--yes` | key + pk | 5 |
| `order strategy list` | `--chain`, `--group-tag LimitOrder\|STMix`, `--type open\|history`, `--from`, `--base-token`, `--page-token`, `--limit` | key + pk | 1 |
| `order strategy cancel` | `--chain`, `--from`, `--order-id`, `--order-type`, `--close-sell-model` | key + pk | 2 |
| `cooking stats` | `--raw` | key | 1 |
| `cooking create` | `--chain sol\|bsc\|base\|robinhood`, `--dex pump\|bonk\|bags\|fourmeme\|flap\|klik\|clanker\|trench\|pons`, `--from`, `--name`, `--symbol`, `--buy-amt`, `--image` \| `--image-url`, `--slippage` \| `--auto-slippage`, `--description`, `--website`, `--twitter`, `--telegram`, `--fee`, `--priority-fee`, `--tip-fee`, `--gas-price`, `--max-fee-per-gas`, `--max-priority-fee-per-gas`, `--anti-mev`, `--anti-mev-mode off\|normal\|secure`, `--raised-token`, `--dev-wallet-bps`, `--dev-gas`, `--dev-priority`, `--dev-tip`, `--dev-max-fee-per-gas`, `--approve-vision v1\|v2`, `--source`, `--is-mayhem`, `--is-cashback`, `--is-buy-back`, `--pump-fee-share-list`, `--flap-rate-conf`, `--fourmeme-rate-conf`, `--bags-fee-share-list`, `--bonk-model`, `--buy-wallets`, `--snip-buy-wallets`, `--buy-trade-config`, `--sell-trade-config`, `--sell-configs`, `--yes` | key + pk | 5 |

"?" = weight not stated in the files read. Weights for `token *`, `portfolio *`, and `track *` live in the `gmgn-token`, `gmgn-portfolio`, and `gmgn-track` skill files, which were not in scope.

**Contradictions worth knowing before trusting any single file:** (a) the workflow docs and gmgn-swap read `rug_ratio`, `creator_token_status`, `sniper_count` from `token security`, but contract-dd verified `rug_ratio` is absent from `token info`/`security`/`pool`, and the live sol call in the note at the top confirms all six listing-only fields are null there; (b) gmgn-market documents trenches rows under `data.new_creation/data.pump/data.completed`, contract-dd's tested pipeline reads top-level `completed/near_completion/new_creation`; (c) trenches `--max-created` accepts seconds/minutes while trending's accepts `m/h/d`.
