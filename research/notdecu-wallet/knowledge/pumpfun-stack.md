# pump.fun developer stack — map of tools and data sources (2026-09-14)

Everything pump.fun exposes to builders, tested from this environment, and what each piece is
for in our two tracks (research on the notdecu wallet; strategy 2 recon). Probes were read-only:
a GET on each endpoint and one unsigned transaction build. Nothing was signed or sent.

## 1. The pieces

| Piece | What it is | Link | Version / state |
|-------|------------|------|-----------------|
| `@pump-fun/pump-sdk` | official TypeScript SDK for the bonding-curve program: create/buy/sell instruction builders, quoting, PDAs, state fetchers, event decoders, quote-mint and fee logic | https://www.npmjs.com/package/@pump-fun/pump-sdk | 2.0.0, 13 Sep 2026, MIT, 132 releases; source repo URL is 404, npm is the artifact |
| `@pump-fun/pump-swap-sdk` | official SDK for PumpSwap (post-graduation AMM): `PumpAmmSdk`, `PumpAmmInternalSdk`, swap/deposit/withdraw builders and quoting | https://www.npmjs.com/package/@pump-fun/pump-swap-sdk | 1.20.0, 10 Sep 2026, MIT |
| `@pump-fun/agent-payments-sdk` | payments/invoices for "tokenized agents" | bundled with pump-sdk | not relevant to us |
| `pump-rust-client` | Rust equivalent: instruction builders, quoting, PDAs | https://crates.io/crates/pump-rust-client | 0.1.13, 9 Sep 2026 |
| `pump-fun/pump-public-docs` | program docs (pump, PumpSwap, fee program, creator fees, fee sharing, holder rewards, CPI, FAQ), per-instruction docs (BUY, SELL, COIN_CREATION, COLLECT_CREATOR_FEE, CREATOR_FEE_SHARING) and the IDLs (`pump`, `pump_amm`, `pump_fees`, JSON + TS) | https://github.com/pump-fun/pump-public-docs | cloned; IDLs copied to `refs/idl/` |
| `pump-fun/pump-fun-skills` | four Agent Skills by pump.fun: `swap`, `create-coin`, `coin-fees`, `tokenized-agents`, each with runnable Node scripts | https://github.com/pump-fun/pump-fun-skills | installed as `.claude/skills/pump-*` (package-locks stripped) |
| Agents API `https://fun-block.pump.fun` | **server-side transaction builder** used by the official skills: `POST /agents/swap`, `/agents/create-coin`, `/agents/collect-fees`, `/agents/sharing-config`. Detects curve vs AMM, resolves accounts, sets compute budget, returns an unsigned base64 `VersionedTransaction` for the wallet to sign | documented only inside the skills | **live**: a 0.001 SOL buy build returned HTTP 201 with `pumpMintInfo` (hasGraduated, expectedOutAmount, tokenProgram, isMayhemMode, poolCoinCreator) |
| Coin API `https://frontend-api-v3.pump.fun/coins-v2/{mint}` | per-coin state: creator, created_timestamp, complete, bonding_curve, pump_swap_pool, virtual/real reserves, quote_mint, market_cap_usd, **ath_market_cap**, boost_mode, is_holder_reward, security_verdict, is_banned, nsfw, reply_count, last_trade_timestamp, socials | used by the official skills; undocumented otherwise | **live**, HTTP 200, no key; CORS-blocked so server-side only |
| `https://frontend-api-v3.pump.fun/sol-price` | SOL/USD with timestamp and staleness flag | same | live |
| Profile API `https://profile-api.pump.fun/balance/summary/{wallet}` and `/balance/tokens/{wallet}` | wallet native + token balances, token_count, portfolio P&L | same | **live** on the target wallet: 993.8 SOL, 1,588 tokens, $103.8K value, cost basis $96.1K |
| Third-party reverse-engineered spec | 483 endpoints incl. `advanced-api-v2`, livestream, mayhem, communities | https://github.com/BankkRoll/pumpfun-apis | unsupported; convenience only |
| Third-party streams | PumpPortal websocket (new tokens, migrations free; trades metered) | https://pumpportal.fun/data-api/real-time/ | tested in 2.0 |

What pump.fun does **not** provide: a documented public REST/websocket data API with SLAs, historical
trades or OHLCV, or wallet analytics beyond the profile balance endpoints. Those stay with GMGN
(analytics), Helius (chain history), and our own decoding of `TradeEvent`/`CreateEvent`.

## 2. Program IDs and constants (from the skills and SDK)

| Name | Value |
|------|-------|
| Pump (bonding curve) | `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` |
| PumpSwap AMM | `pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA` |
| Pump fee program | `pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ` (seen inner on 148K of his tx) |
| Mayhem program | exported as `MAYHEM_PROGRAM_ID` in the SDK |
| Mainnet address lookup table used by the app | `7mFD2mUtRS65XstiSAvCJuYmdesZoQwCwRJhq1p3eRMe` |
| Compute units the app uses | bonding buy/sell 120,000 · AMM buy/sell 200,000 · create 270,000 |
| Priority fee policy in the skills | `getPriorityFeeEstimate` (Helius-style RPC method), floor 100,000 µlamports, cap 5,000,000 |
| Jito | 8 tip accounts, default tip 0.0001 SOL, send only to block-engine endpoints when protection is on |
| Token program | pump coins are **Token-2022** (`TokenzQd…`) — matches the 153,933 inner Token-2022 calls in his history. Always read the mint owner on-chain; the skill warns `coins-v2.token_program` can be stale |
| Decimals | tokens 6, SOL 9; slippage in the bonding SDK is a **percent**, not bps |

## 3. SDK surface that matters for us (exact export names, pump-sdk 2.0.0)

- **Read state:** `OnlinePumpSdk` → `fetchGlobal`, `fetchBuyState`, `fetchSellState`, `fetchFeeConfig`; `bondingCurvePda`, `bondingCurveMarketCap`, `Global`, `BondingCurve` (fields incl. `isMayhemMode`, `isCashbackCoin`, `isHolderReward`).
- **Quote:** `getBuyTokenAmountFromSolAmount`, `getBuySolAmountFromTokenAmount`, `getSellSolAmountFromTokenAmount`, `computeFeesBps`, `calculateFeeTier`, `getFee`.
- **Build:** `PUMP_SDK.buyInstructions(...)`, `PUMP_SDK.sellInstructions(...)`, `createV2Instruction`, `createV2AndBuyV2Instructions`.
- **Decode events:** `CreateEventBc`, `TradeEventBc`, `CompleteEventBc`, `BuyEventAmm`, `SellEventAmm`, plus fee/CTO events. This is the basis for a launch-and-trade feed from raw logs.
- **Quote mints:** `SOL_LIKE_QUOTE_MINTS`, `STABLE_QUOTE_MINTS`, `isExoticQuoteMint`, `QuoteControl` — the mechanism behind the ARB/USDC/stock-quoted curves in his September trades.
- **Creator economics:** `creatorVaultPda`, `feeSharingConfigPda`, `hasCoinCreatorMigratedToSharingConfig`, `holderRewardsPda`, `admin_cto` events. Fee configuration is on-chain and one-time locked, so it is a readable dev-quality signal.

## 4. How the pieces map to our tracks

| Need | Best source | Fallback |
|------|-------------|----------|
| His history, P&L, tags (research) | GMGN activity + Helius parse (done) | — |
| Live launch feed for strategy 2 | own RPC log subscription on the Pump program decoded with `CreateEventBc`; or PumpPortal `subscribeNewToken` | `coins-v2` polling (no list endpoint tested) |
| Curve state at second resolution | `OnlinePumpSdk.fetchBuyState` + `bondingCurveMarketCap` | `coins-v2` (`virtual_*_reserves`, `market_cap_usd`) |
| Fee cost of a trade at a given mcap | `computeFeesBps` / `calculateFeeTier` (Project Ascend dynamic fees) | docs `FEE_PROGRAM_README.md` |
| Creator quality | `coins-v2.creator` → GMGN `created-tokens` / `dev_score.py`; on-chain fee-sharing config; `is_holder_reward`; `security_verdict` | — |
| Building a buy/sell for a $50 test | `fun-block.pump.fun /agents/swap` (zero code, returns unsigned tx) or `PUMP_SDK.buyInstructions` for full control | GMGN `swap` (needs the missing PEM), PumpPortal trade API (+0.5%) |
| Anti-sniper protection when we act | Jito tip via the skill's `jito.mjs`; note **he** stopped using Jito in Jan 2026 | — |

## 5. Gotchas found

- `coins-v2` returns `created_timestamp` in **milliseconds** (GMGN uses seconds).
- `is_mayhem_mode` is `null` on `coins-v2` for the probed coin; the on-chain `BondingCurve.isMayhemMode` is authoritative.
- The skills' default RPC (`rpc.solanatracker.io/public`) is a public endpoint; we use Helius.
- The skill scripts pin `@pump-fun/pump-sdk ^1.33`; the current SDK is 2.0.0 with `create_v2` changes (cashback deprecated, holder-reward coins). Trading instructions are unchanged across the bump.
- `fun-block.pump.fun` is undocumented outside the skills; treat its availability as best-effort.

## 6. Close-out: list and discovery endpoints (probed 2026-09-14 18:55 UTC) — tooling research CLOSED

The open question from §4 was "is there a list endpoint, or do we need a log subscription for a launch
feed?". Answer: the frontend API has two working list endpoints, so a polling feed is possible without
any chain decoding. All probes were plain GETs with a custom User-Agent, no key.

| Endpoint (`https://frontend-api-v3.pump.fun`) | Result | Shape / notes |
|---|---|---|
| `GET /coins?offset=N&limit=50&sort=created_timestamp&order=DESC&includeNsfw=false` | **200** | array of coin objects: `mint, creator, created_timestamp (ms), bonding_curve, virtual_*_reserves, real_*_reserves, market_cap_usd, quote_mint, quote_decimals, program, protocol, boost_mode, is_holder_reward, is_cashback_enabled, is_currently_live, twitter, website, reply_count, complete, is_banned, nsfw, token_program`. `limit` up to 50 works, offset paging works. |
| `GET /coins/currently-live?offset=0&limit=50&includeNsfw=false` | **200** | same fields plus `ath_market_cap`, `ath_market_cap_timestamp`, `last_trade_timestamp`, `description` — coins with an active livestream |
| `GET /coins-v2/{mint}` | 200 | per-coin detail (see §1) |
| `GET /sol-price` | 200 | `{solPrice, asOfTimestamp, stale}` |
| `GET /coins/user-created-coins/{wallet}` | 404 | creator history is **not** exposed here; use GMGN `created-tokens` (weight 2) or index `CreateEvent` by creator |
| `GET /coins/latest`, `/coins/king-of-the-hill`, `/trades/latest/{mint}`, `/candlesticks/{mint}` | 404 | gone in v3 |
| `https://advanced-api-v2.pump.fun/...` | 530 | origin down; the third-party spec lists it, do not rely on it |

Measured from the newest 200 coins (18:53 UTC):

| Metric | Value |
|---|---|
| Launch rate | 200 coins in 6.8 min = ~1,760/h = ~42K/day |
| Quote mint | 160 SOL, 13 PUMP, 6 USDC, 3 other (exotic-quote curves are ~20% of launches) |
| `boost_mode` | 198 NONE, 2 IN_PROGRESS |
| `is_holder_reward` | 0 of 200 |
| Socials at launch | 87 twitter, 38 website |
| `is_mayhem_mode` | null on the list endpoint (on-chain `BondingCurve.isMayhemMode` remains authoritative) |

Consequences for the dev-farming track (strategy 2, not started):

1. **Launch feed**: poll `/coins?sort=created_timestamp` every ~10 s (50 rows covers ~100 s of launches at
   the current rate) or subscribe to Pump-program logs and decode `CreateEventBc`. Polling is enough for
   research; the log subscription is only needed when we act (sub-second entry).
2. **Creator lookup**: the feed gives `creator` for every launch, so a dev watchlist is a set-membership
   check on each new row. Creator history itself comes from GMGN `created-tokens` + `token info`, not
   from pump.fun.
3. **Curve state and ATH**: `coins-v2` (per mint) has `ath_market_cap`; the list endpoint does not, so
   an outcome table per token needs one `coins-v2` call or GMGN `token info` (which we already cache).
4. **Cost**: zero. All of this is unauthenticated HTTP; rate limits were not hit at 4 calls in 2 s.
   Treat it as best-effort (undocumented, CORS-blocked, can change without notice).

Rating of the pump.fun-side tools for the next track (1 = use first):

| Rank | Tool | Why |
|---|---|---|
| 1 | `frontend-api-v3 /coins` list + `coins-v2` | free launch feed with creator, quote mint, socials, curve state, ATH |
| 2 | `@pump-fun/pump-sdk` event decoders + `OnlinePumpSdk` | exact curve state and second-resolution trade feed when we go live; fee tier math for sizing |
| 3 | `fun-block.pump.fun /agents/swap` | unsigned tx builder for a $50 test buy without writing instruction code |
| 4 | `profile-api` balance endpoints | quick dev-wallet balance/P&L check |
| 5 | PumpPortal websocket | only if polling proves too coarse; trades are metered |
