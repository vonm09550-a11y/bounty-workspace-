# pump.fun program + SDK digest (from pump-public-docs and @pump-fun/pump-sdk 2.0.0 source)

Written by a reading pass over the docs repo, the IDLs and the shipped SDK source. Where the SDK
README is stale the shipped `src/*.ts` was used. Items marked *inference* were derived from the
constants rather than stated in a doc.

## Digest (docs repo + `@pump-fun/pump-sdk@2.0.0` source)

Sources: `pump-public-docs/` (README, docs/*.md, docs/instructions/*.md, idl/*.json, docs/fees.png) and the installed SDK (`README.md` plus shipped `src/*.ts`, which I used where the README was stale). Everything here is from those files unless marked *inference*.

## 1) Program map, accounts, PDAs

| Program | Address |
|---|---|
| Pump (bonding curve) | `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P` (mainnet + devnet) |
| PumpSwap AMM | `pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA` |
| Pump Fees | `pfeeUxB6jkeY1Hxd7CsFCAjcbHA9rWtchMGdZ6VojVZ` |
| Mayhem | `MAyhSmzXzV1pTf7LsNkrNwkWKTo4ougAJ1PPg47MD4e` |

Pump PDAs (seeds, all under the Pump program unless noted):
- `Global` = `["global"]` → `4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf`
- `BondingCurve` = `["bonding-curve", mint]`; `bonding-curve-v2` = `["bonding-curve-v2", mint]` (passed as remaining account on legacy `buy`)
- `associated_bonding_curve` = ATA(mint, owner=bonding_curve, base token program)
- `creator_vault` = `["creator-vault", bonding_curve.creator]` (lamport vault for SOL coins)
- `holder_rewards` = `["holder-rewards", mint]`
- `pool-authority` = `["pool-authority", mint]` → this is `Pool.creator` of the canonical PumpSwap pool; canonical pool = PumpSwap `["pool", index=0 (u16), pool_authority, mint, quote_mint]`
- `user_volume_accumulator` = `["user_volume_accumulator", user]`; `global_volume_accumulator` = `["global_volume_accumulator"]`
- `mint-authority` = `["mint-authority"]`; `quote-control` = `["quote-control"]`; event authority = `["__event_authority"]`
- Pump Fees: `fee_config` = `["fee_config", PUMP_PROGRAM_ID]`; `sharing_config` = `["sharing-config", mint]`
- PumpSwap: `GlobalConfig` = `["global_config"]` → `ADyA8hdefvWN2dbGGWFotbzWxrAvLW83WG6QCVXvJKqw`; AMM creator vault authority = `["creator_vault", coin_creator]` (underscore, vs hyphen on Pump)

`BondingCurve` layout (8-byte disc `[23,183,248,55,96,216,172,96]`, then): `virtual_token_reserves u64, virtual_quote_reserves u64, real_token_reserves u64, real_quote_reserves u64, token_total_supply u64, complete bool, creator pubkey, is_mayhem_mode bool, is_cashback_coin bool, quote_mint pubkey, creator_fee_bps u64, can_edit_creator_fee bool, is_holder_reward bool`. Sizes: 115 → 124 → 125 (`BONDING_CURVE_SIZE`); `extend_account` grows to 151. Short accounts must be read with trailing fields as 0/false/default. `quote_mint == Pubkey::default()` means SOL. `virtual_quote_reserves == 0` means migrated.

IDL `pump.json` instruction names: `add_quote_control_mint, add_quote_mint, admin_cto, admin_set_idl_authority, admin_update_token_incentives, buy, buy_exact_quote_in_v2, buy_exact_sol_in, buy_v2, claim_cashback, claim_cashback_v2, claim_token_incentives, close_user_volume_accumulator, collect_creator_fee, collect_creator_fee_v2, create, create_v2, distribute_creator_fees, distribute_creator_fees_v2, distribute_fee_to_holders, extend_account, get_minimum_distributable_fee, init_user_volume_accumulator, initialize, initialize_quote_control, migrate, migrate_bonding_curve_creator, migrate_v2, remove_quote_control_mint, remove_quote_mint, sell, sell_v2, set_creator, set_mayhem_virtual_params, set_metaplex_creator, set_params, set_quote_control_admin, set_reserved_fee_recipients, set_virtual_quote_reserves, sync_user_volume_accumulator, toggle_cashback_enabled, toggle_create_v2, toggle_mayhem_mode, update_buyback_config, update_creator_fee_config, update_global_authority, update_holder_reward_config`. Accounts: `BondingCurve, FeeConfig, Global, GlobalVolumeAccumulator, QuoteControl, SharingConfig, UserVolumeAccumulator`.

Instruction discriminators: `buy` `[102,6,61,18,1,218,235,234]`, `sell` `[51,230,133,164,1,127,131,173]`, `buy_v2` `[184,23,238,97,103,197,211,61]`, `sell_v2` `[93,246,130,60,231,233,64,178]`, `create` `[24,30,200,40,5,28,7,119]`, `create_v2` `[214,144,76,236,95,139,49,180]`. Args: `buy(amount u64, max_sol_cost u64, track_volume OptionBool)`, `sell(amount, min_sol_output)`, `buy_v2(amount, max_sol_cost)`, `sell_v2(amount, min_sol_output)`, `buy_exact_quote_in_v2(spendable_quote_in, min_tokens_out)`. `buy_v2` takes 27 accounts, `sell_v2` 26 (full tables in `docs/instructions/BUY.md`/`SELL.md`); legacy `buy` = 18 accounts after appending `bonding-curve-v2` and a buyback fee recipient.

`pump_amm.json` instructions: `admin_cto_pool, admin_update_token_incentives, boost_buy_and_burn, buy, buy_exact_quote_in, claim_cashback, claim_token_incentives, close_user_volume_accumulator, collect_coin_creator_fee, create_config, create_pool, deposit, disable, extend_account, init_boost, init_user_volume_accumulator, migrate_pool_coin_creator, sell, set_boost_authority, set_coin_creator, set_reserved_fee_recipients, sync_user_volume_accumulator, toggle_boost, toggle_cashback_enabled, toggle_mayhem_mode, transfer_creator_fees_to_pump, transfer_creator_fees_to_pump_v2, update_admin, update_buyback_config, update_creator_fee_config, update_fee_config, withdraw`.

## 2) Bonding-curve math

Global initial parameters (mainnet, from `PUMP_PROGRAM_README.md`):
- `initial_virtual_token_reserves` = 1,073,000,000,000,000 (1.073B tokens, 6 decimals)
- `initial_virtual_sol_reserves` = 30,000,000,000 (30 SOL)
- `initial_real_token_reserves` = 793,100,000,000,000 (793.1M tokens sellable on the curve)
- `token_total_supply` = 1,000,000,000,000,000 (1B)
- `real_sol_reserves` starts at 0. Coin mints have `decimals = 6`.

Constant product on virtual reserves, k = vT·vSOL = 3.219e25. Buys add the same lamports to virtual and real SOL and remove the same tokens from virtual and real token reserves; sells reverse it. `complete` flips true at the end of the buy that drives `real_token_reserves` to 0; then permissionless `migrate` creates the canonical PumpSwap pool and burns LP.

Exact SDK quote functions (`src/bondingCurve.ts`), all integer BN:
- tokens for quote-in (no fee): `tokens = inputAmount * vT / (vSOL + inputAmount)`, capped at `realTokenReserves`
- SOL cost for exact tokens (no fee): `cost = amount * vSOL / (vT - amount) + 1`
- SOL out for selling tokens (no fee): `out = amount * vSOL / (vT + amount)`
- Buy given a total SOL budget: `inputAmount = (amount - 1) * 10000 / (totalFeeBps + 10000)`, then tokens formula above. Total buy cost = `cost + ceil(cost*protocolBps/10000) + ceil(cost*creatorBps/10000)`. Sell proceeds = `out - ceil(out*protocolBps/10000) - ceil(out*creatorBps/10000)`. Creator fee is charged only if `bondingCurve.creator != Pubkey::default()` (or it's a brand-new curve).

Price and market cap:
- spot price (lamports per base unit) = vSOL / vT; per whole token in SOL = (vSOL/1e9)/(vT/1e6). Initial: 30/1.073e9 ≈ 2.796e-8 SOL/token.
- `bondingCurveMarketCap = virtualQuoteReserves * mintSupply / virtualTokenReserves` (lamports). For fee-tier purposes the SDK passes `mintSupply = 1e15` (`ONE_BILLION_SUPPLY`) for non-mayhem coins, the actual mint supply for mayhem coins. Initial mcap ≈ 27.96 SOL.
- Progress to graduation = `1 - real_token_reserves / 793.1e12`, equivalently `real_sol_reserves / ~85.005e9`.

*Inference from the constants*: at completion vT = 1.073e15 − 7.931e14 = 2.799e14, vSOL = k/vT ≈ 115.005 SOL, so ~85.005 SOL of real SOL is raised and graduation mcap ≈ 410.9 SOL — which matches the fee table's first PumpSwap tier boundary "0–420 SOL". The ~206.9M unsold tokens plus the real SOL (less `pool_migration_fee` = 15,000,001 lamports) seed the pool. `CompleteEvent`, then `CompletePumpAmmMigrationEvent(user, mint, mint_amount, sol_amount, pool_migration_fee, bonding_curve, timestamp, pool, quote_mint)` mark this.

PumpSwap pricing uses `effective_quote_reserves = pool_quote_token_account.amount + Pool.virtual_quote_reserves` (i128, currently 0 everywhere); pool mcap = `quoteReserve * baseMintSupply / baseReserve`.

## 3) Fee schedule (all numbers)

Fees live on-chain in `FeeConfig` (`fee_tiers: Vec<FeeTier{market_cap_lamports_threshold u128, fees{lp_fee_bps, protocol_fee_bps, creator_fee_bps}}>`, `stable_fee_tiers`, `flat_fees`, `exotic_flat_fees`). Tier selection: if mcap < tiers[0].threshold → tiers[0]; else the highest tier whose threshold ≤ mcap. Dynamic fees apply only to bonding curves and *canonical* PumpSwap pools (`Pool.creator == pump_pool_authority_pda(mint)`); other pools pay `flatFees`. Schedule by quote mint: SOL-like (zero key, WSOL, Token-2022 native) → `feeTiers`; mainnet USDC `EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v` → `stableFeeTiers`; anything else → `exoticFlatFees` (README example admin value: protocol 300 bps, creator 25). Fallback when `FeeConfig` is null: `Global.fee_basis_points` (100) + `Global.creator_fee_basis_points`.

Published tiers (docs/fees.png, effective 1 Sept 2025 20:00 UTC; verify live values from `FeeConfig`):

| mcap (SOL) | creator | protocol | LP | total |
|---|---|---|---|---|
| Bonding curve (any) | 0.30% | 0.95% | 0% | **1.25%** |
| 0–420 (PumpSwap) | 0.30% | 0.93% | 0.02% | 1.25% |
| 420–1470 | 0.95% | 0.05% | 0.20% | 1.20% |
| 1470–2460 | 0.90% | 0.05% | 0.20% | 1.15% |
| 2460–3440 | 0.85% | 0.05% | 0.20% | 1.10% |
| 3440–4420 | 0.80% | 0.05% | 0.20% | 1.05% |
| 4420–9820 | 0.75% | 0.05% | 0.20% | 1.00% |
| 9820–14740 | 0.70% | | | 0.95% |
| 14740–19650 | 0.65% | | | 0.90% |
| 19650–24560 | 0.60% | | | 0.85% |
| 24560–29470 | 0.55% | | | 0.80% |
| 29470–34380 | 0.50% | | | 0.75% |
| 34380–39300 | 0.45% | | | 0.70% |
| 39300–44210 | 0.40% | | | 0.65% |
| 44210–49120 | 0.35% | | | 0.60% |
| 49120–54030 | 0.30% | | | 0.55% |
| 54030–58940 | 0.275% | | | 0.53% |
| 58940–63860 | 0.25% | | | 0.50% |
| 63860–68770 | 0.225% | | | 0.48% |
| 68770–73681 | 0.20% | | | 0.45% |
| 73681–78590 | 0.175% | | | 0.43% |
| 78590–83500 | 0.15% | | | 0.40% |
| 83500–88400 | 0.125% | | | 0.38% |
| 88400–93330 | 0.10% | | | 0.35% |
| 93330–98240 | 0.075% | | | 0.33% |
| 98240+ | 0.05% | 0.05% | 0.20% | 0.30% |

(Blank cells = 0.05% protocol / 0.20% LP.) Practical consequence for a sniper: since a bonding curve's mcap never exceeds ~411 SOL, **every curve trade pays 0.95% protocol + 0.30% creator = 1.25% of the pre-fee SOL amount** (1.25% round-trip cost each way, i.e. ~2.5% total plus curve slippage). Legacy PumpSwap `GlobalConfig` constants (`lp 20 bps, protocol 5 bps`) are the pre-tier fallback.

Buyback: `Global.buyback_basis_points` and `TradeEvent.buyback_fee(_basis_points)` exist and a `buyback_fee_recipient` is mandatory, but no doc defines the rate, and the SDK's `getFee` sums only protocol + creator — so *inference*: buyback (and cashback, on legacy cashback coins) is carved out of the protocol/creator fees rather than added on top. Confirm from `TradeEvent.fee + creator_fee + buyback_fee` on real trades.

Per-coin override: `BondingCurve.creator_fee_bps` (only storable on QuoteControl "exotic" quotes; ignored on SOL/USDC), gated by `Global.creator_fee_configurable` and `max_configurable_creator_fee_bps`.

## 4) Events and decoding

Events are emitted via Anchor `#[event_cpi]` (the `event_authority` + `program` accounts): a self-CPI whose instruction data is the 8-byte Anchor event-CPI marker, the 8-byte event discriminator, then the borsh struct. Parse inner instructions targeting `6EF8…` (also works from `Program data:` logs where present). The SDK decoders (`PUMP_SDK.decodeCreateEventBc / decodeTradeEventBc / decodeCompleteEventBc`) take the borsh body with the discriminator stripped and pad short (older-layout) events with zero bytes so trailing fields decode as defaults; do the same.

Discriminators: `CreateEvent` `[27,114,169,77,222,235,99,118]` (hex `1b72a94ddeeb6376`), `TradeEvent` `[189,219,127,211,78,230,97,238]` (`bddb7fd34ee661ee`), `CompleteEvent` `[95,114,97,156,212,46,152,8]` (`5f72619cd42e9808`); PumpSwap `BuyEvent` `[103,244,82,31,44,245,119,119]`, `SellEvent` `[62,47,55,10,165,3,220,42]`.

Borsh: string = u32 LE length + UTF-8; pubkey 32 bytes; u64/i64 8 bytes LE; bool 1 byte; `Vec<Shareholder>` = u32 count + n × (pubkey 32 + `share_bps` u16).

`CreateEvent` fields in order: `name string, symbol string, uri string, mint pubkey, bonding_curve pubkey, user pubkey, creator pubkey, timestamp i64, virtual_token_reserves u64, virtual_sol_reserves u64, real_token_reserves u64, token_total_supply u64, token_program pubkey, is_mayhem_mode bool, is_cashback_enabled bool, quote_mint pubkey, virtual_quote_reserves u64, creator_fee_bps u64, is_holder_reward bool`.

`TradeEvent`: `mint pubkey, sol_amount u64, token_amount u64, is_buy bool, user pubkey, timestamp i64, virtual_sol_reserves u64, virtual_token_reserves u64, real_sol_reserves u64, real_token_reserves u64, fee_recipient pubkey, fee_basis_points u64, fee u64, creator pubkey, creator_fee_basis_points u64, creator_fee u64, track_volume bool, total_unclaimed_tokens u64, total_claimed_tokens u64, current_sol_volume u64, last_update_timestamp i64, ix_name string, mayhem_mode bool, cashback_fee_basis_points u64, cashback u64, buyback_fee_basis_points u64, buyback_fee u64, shareholders Vec<Shareholder>, quote_mint pubkey, quote_amount u64, virtual_quote_reserves u64, real_quote_reserves u64, holder_rewards_bps u64, holder_rewards u64`. Reserves are post-trade, so price/mcap/progress follow directly from section 2. `fee` = protocol lamports, `creator_fee` = creator lamports; `sol_amount` is the pre-fee curve amount (*inference from the SDK math*); `ix_name` tells `buy`/`buy_v2`/`sell`/etc.

`CompleteEvent`: `user pubkey, mint pubkey, bonding_curve pubkey, timestamp i64, quote_mint pubkey`.

PumpSwap `BuyEvent`: `timestamp i64, base_amount_out, max_quote_amount_in, user_base_token_reserves, user_quote_token_reserves, pool_base_token_reserves, pool_quote_token_reserves, quote_amount_in, lp_fee_basis_points, lp_fee, protocol_fee_basis_points, protocol_fee, quote_amount_in_with_lp_fee, user_quote_amount_in (all u64), pool, user, user_base_token_account, user_quote_token_account, protocol_fee_recipient, protocol_fee_recipient_token_account, coin_creator (pubkeys), coin_creator_fee_basis_points, coin_creator_fee, track_volume bool, total_unclaimed_tokens, total_claimed_tokens, current_sol_volume u64, last_update_timestamp i64, min_base_amount_out u64, ix_name string, cashback_fee_basis_points, cashback, buyback_fee_basis_points, buyback_fee u64, virtual_quote_reserves i128, can_boost bool, base_supply u64, holder_rewards_bps, holder_rewards u64`. `SellEvent` is the same shape with `base_amount_in, min_quote_amount_out, … quote_amount_out, … quote_amount_out_without_lp_fee, user_quote_amount_out` and no `track_volume`/volume-accumulator/`min_base_amount_out`/`ix_name` fields.

## 5) SDK usage for buy/sell (v2.0.0)

Split: `PumpSdk` (offline builders; singleton `PUMP_SDK`) and `OnlinePumpSdk(connection)` (RPC fetchers). **The README "Usage" section is stale**: it shows `new PumpSdk(connection)` and positional `getBuyTokenAmountFromSolAmount(global, bondingCurve, solAmount)`; in the shipped source `fetchGlobal/fetchFeeConfig/fetchBuyState/fetchSellState` live on `OnlinePumpSdk` and the quote functions take an object.

README snippets (verbatim):
```ts
const global = await sdk.fetchGlobal();
const { bondingCurveAccountInfo, bondingCurve, associatedUserAccountInfo } =
    await sdk.fetchBuyState(mint, user);
const solAmount = new BN(0.1 * 10 ** 9); // 0.1 SOL
const instructions = await sdk.buyInstructions({
    global, bondingCurveAccountInfo, bondingCurve, associatedUserAccountInfo,
    mint, user, solAmount,
    amount: getBuyTokenAmountFromSolAmount(global, bondingCurve, solAmount),
    slippage: 1,
});
```
```ts
const { bondingCurveAccountInfo, bondingCurve } = await sdk.fetchSellState(mint, user);
const amount = new BN(15_828);
const instructions = await sdk.sellInstructions({
    global, bondingCurveAccountInfo, bondingCurve, mint, user, amount,
    solAmount: getSellSolAmountFromTokenAmount(global, bondingCurve, amount),
    slippage: 1,
});
```
Real signatures from source:
- `OnlinePumpSdk.fetchBuyState(mint, user, tokenProgram = TOKEN_PROGRAM_ID, quoteMint?)` → `{bondingCurveAccountInfo, bondingCurve, associatedUserAccountInfo, quoteMint, quoteTokenProgram}`; `fetchSellState` same minus `associatedUserAccountInfo` (throws if the user ATA is missing).
- `getBuyTokenAmountFromSolAmount({global, feeConfig, mintSupply, bondingCurve, amount, quoteMint, quoteControl?, creatorFeeBps?})`; `getBuySolAmountFromTokenAmount(same)`; `getSellSolAmountFromTokenAmount({global, feeConfig, mintSupply, bondingCurve, amount})`. Pass `feeConfig = await onlineSdk.fetchFeeConfig()` or fees fall back to `Global` bps.
- `PUMP_SDK.buyInstructions({global, bondingCurveAccountInfo, bondingCurve, associatedUserAccountInfo, mint, user, amount, solAmount, slippage, tokenProgram = TOKEN_PROGRAM_ID})` builds legacy `buy(amount, max_sol_cost, track_volume=[true])`, prepends an idempotent ATA create, picks random fee/buyback recipients, and sets `max_sol_cost = solAmount * (1 + slippage*10/1000)` — `slippage: 1` means 1%. `sellInstructions({... amount, solAmount, slippage, tokenProgram, mayhemMode, cashback?})` sets `min_sol_output = solAmount * (1 − slippage/100)`.
- Unified path: `PUMP_SDK.buyV2Instructions({global, bondingCurveAccountInfo, bondingCurve, associatedUserAccountInfo, mint, user, amount, quoteAmount, slippage, tokenProgram = TOKEN_2022_PROGRAM_ID, quoteTokenProgram = TOKEN_PROGRAM_ID})`, `sellV2Instructions`, and raw builders `getBuyV2InstructionRaw({user, mint, creator, amount, quoteAmount, tokenProgram, quoteMint, quoteTokenProgram, feeRecipient, buybackFeeRecipient})` / `getSellV2InstructionRaw` (see BUY.md/SELL.md). For SOL coins pass `quoteMint = NATIVE_MINT` (`So111…112`), `quoteTokenProgram = TOKEN_PROGRAM_ID`; `create_v2` coins have Token-2022 base mints, legacy `create` coins SPL Token.
- Helpers: `getFeeRecipient(global, mayhemMode)`, `getStaticRandomFeeRecipientForBuyback()`, `PUMP_SDK.decodeBondingCurve(accountInfo)` (handles all lengths), `bondingCurvePda`, `creatorVaultPda`, `holderRewardsPda`, `canonicalPumpPoolPda`.

## 6) Creator economics (dev-quality signals)

- Creator fee on the curve = 0.30% of every trade, paid to `creator_vault(BondingCurve.creator)`; on PumpSwap it peaks at 0.95% in the 420–1470 SOL tier and decays to 0.05% above 98,240 SOL. Collected via permissionless `collect_creator_fee(_v2)` / AMM `collect_coin_creator_fee`; SDK `collectCoinCreatorFeeInstructions(creator)`, `getCreatorVaultBalanceBothPrograms(creator)`.
- `CreateEvent.user` vs `creator`: they differ in the "free coin creation" flow where the first buyer creates on-chain; `creator` is who earns fees. `BondingCurve.creator` is set from `create`'s `creator` arg (or backfilled via `set_metaplex_creator`/`set_creator`).
- Fee sharing: `create_fee_sharing_config` re-points `BondingCurve.creator` (and `Pool.coin_creator`) to the `["sharing-config", mint]` PDA (owned by Pump Fees); `update_fee_shares_v2` sets ≤10 shareholders summing to 10,000 bps and is **one-shot/locked**. `TradeEvent.shareholders` is populated for such coins. Detect: `creator` account owner == `pfee…`, or `isCreatorUsingSharingConfig`.
- Holder-reward coins: `is_holder_reward = true`, `creator == holderRewardsPda(mint)`; fee is set aside and distributed by pump.fun via `distribute_fee_to_holders` (signed by `Global.holder_reward_claim_authority`). Permanent. `TradeEvent.holder_rewards(_bps)` mirrors `creator_fee`.
- Cashback coins (`is_cashback_coin`) are deprecated (creation rejected, 6082); legacy ones route creator fee to buyers.
- CTO: `admin_cto` (signed by `Global.admin_set_creator_authority`) reassigns creator (paying the old one out first) or converts to holder-reward; can set `creator_fee_bps` only on exotic quotes; mayhem coins cannot be CTO'd. Emits `AdminCtoEvent`.
- Mayhem mode: `is_mayhem_mode` flag, separate "reserved" fee recipients, and the fee-tier mcap uses the real mint supply — the docs never define its mechanics beyond that.

## 7) Gotchas

1. Field renames: `virtual_sol_reserves`→`virtual_quote_reserves`, `real_sol_reserves`→`real_quote_reserves` in the account; `TradeEvent` carries both old and new names.
2. Every account/event is append-only; decode with zero-padding for short data (curve 115/124/125 bytes; `Global` 1045/1054/1087).
3. Curve completion-guard: `buy.amount` must be ≤ `real_token_reserves`; the SDK caps tokens at `realTokenReserves`. A buy completing the curve costs slightly more CU.
4. Fee recipients: 8 normal, 8 reserved (mayhem), 8 buyback (`FEE_RECIPIENTS.md`); `buy_v2/sell_v2` require one of each; legacy `buy` needs `bonding-curve-v2` PDA + buyback recipient appended.
5. First-ever trade per wallet pays ~0.0018444 SOL rent for `user_volume_accumulator` plus ATA rents.
6. CU: FAQ recommends a static 100k limit for legacy buy/sell (bump seeds vary per mint); v2 with Token-2022 quote 250–300k; docs' Rust examples use 400k.
7. Slippage must be applied to the SOL side (`max_sol_cost`/`min_sol_output`); no token-side slippage on the curve.
8. Devnet USDC is not a listed stable and pays the exotic schedule; Token-2022 quote ATAs are 170–182 bytes.
9. `CompleteEvent`/`complete=true` ≠ migrated: check `virtual_token_reserves == 0` (SDK's "migrated" test) or the canonical pool's existence.
10. Sharing-config coins fail `collect_creator_fee*`; use `distribute_creator_fees_v2`.
