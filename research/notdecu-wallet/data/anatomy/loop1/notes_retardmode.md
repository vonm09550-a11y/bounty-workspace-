## Data problems and reading notes (hand-written, retardmode)

Conventions used in the table:
- Seconds are relative to `meta.create_ts`. Lags of events that never happened are NULL; genuine zeros (no member
  bought, dev sold nothing) are 0. `dev_sold_share_30m` = creator tokens sold / creator tokens bought in the window.
- `n_tx_30m` counts every err=false transaction (as the schema says); `n_buys/n_sells/n_wallets` count trades
  re-derived from account-level balance changes; `x_n_noop_tx_30m` is how many transactions moved no tokens.
- `peak_*` is the highest 1-second buy VWAP with >= 0.01 SOL in that second (dust and fee-sized "buys" excluded);
  `peak_ts_s` is that second, not a minute. `peak_mult_vs_dev` divides by the creator's first-buy price.
- `top10_wallets_share_30m` and `n_wallets_net_long_30m` are computed from window flows only (buys - sells, dust < 1
  token ignored). The creator is included in "wallets". A launch where nobody is net long gets NULL share.
- `dev_same_slot_buyers` = distinct other wallets with a buy in the same slot as the creator's first buy. For all 19
  launches the creator's first buy is the create transaction itself (slot of the mint).

Problems found in the inputs:
1. `*.parsed.jsonl` and `*.rows.jsonl` are not time-ordered (the first line of yoohoo is at +9 s). Everything here is
   sorted by (timestamp, slot, signature); rows inside one second are only ordered by slot.
2. Four launches are pump.fun launches quoted in another token, not SOL: GMONAD (quote CrAr4RRJ...), PQ (quote
   GkyPYa7N...pump = CHILLHOUSE in dev_tokens), GIGAY (63LfDmNb...), WOJAK (5UUH9RTD...). The compact rows show
   ~0.001 SOL "sol_spent" for every buy on these (only rent/tip lamports), so the compact rows are unusable for them.
   All SOL columns for these four are converted from quote units with the per-minute median SOL<->quote rate seen in
   the window's own router legs (GMONAD ~4.3k/SOL, GIGAY ~46.4k, WOJAK ~2.16k, PQ 39.7k drifting to 34.2k over the
   window). Sanity check: ath_mc / (peak_price_sol * 1e9) gives an implied SOL price of ~100-120 USD for these four,
   in line with the SOL-quoted launches whose peak fell inside the window.
3. MRHATE's create transaction is labelled SWAP/RAYDIUM by Helius (the creator swapped 1,519 USDC to SOL and bought
   in the same transaction); it is recognised as the create because the curve receives the initial supply in it.
4. RETARDIO: 15,066 of 18,849 window transactions move no tokens; they are fee-only transactions from three bot
   wallets (6ojY451y..., 8JjVNyj6..., 3ct4z3q2...) hammering the AMM pool between minutes 5 and 20. GOOSE and BIRD have
   the same pattern at a smaller scale (159/295 and 101/192). `n_tx_30m` therefore overstates activity for those;
   use `x_n_trade_tx_30m`.
5. The compact rows attribute a trade to the fee payer and label it 'other' when the fee payer is not the trader
   (routers, gasless/sponsored swaps, arb bots paying for several accounts). This hides ~12% of RETARDIO's, ~17% of
   PQ's and ~11% of WOJAK's trades, and in particular hides stellanyang's MRHATE/PQ buys and ibuyrunners' RETARDIO
   buys, which go through a sponsor fee payer. `sol_received` is 0 on almost every compact sell for the same reason
   (the curve pays the seller with a lamport transfer that Helius does not list under nativeTransfers). The table
   here uses account-level balance changes instead and is not affected.
6. PEACE (hit, ath 1.69M) graduated after the window: the meta has a pool but no `curve_last_s`/`pool_pages` (older
   pull), and all 286 window transactions are on the curve. Its run (and MRHATE's, RETARDIO's) happened after minute 30:
   the in-window peak multiple is 3.9x for PEACE vs an ATH ~100x above the window peak.
7. MRHATE: the pool phase covers only the last ~60 s of the window (curve_last_s = 1737), so `x_pool_phase` is True
   but essentially the whole window is curve trading.
8. `dev_launches` and `dev_runs` have no rows for this creator; only `dev_tokens` does (19 rows, ath_mc and create_ts
   agree with the launch list). No kline-derived run shape is available for retardmode from DuckDB.
9. Only 6 of 19 launches have any member buy, so the "five earliest" and "five latest" member-entry lists overlap
   (the 6 launches are RETARDIO 38 s, WOJAK 139 s, PQ 265 s, yoohoo 269 s, GIGAY 417 s, MRHATE 1095 s). Only 8 of the
   31 non-creator member wallets ever appear: stellanyang, ibuycoin, ibuyrunners, trenchdigger, TMH, mitch, slingoor,
   baseddom. Member SOL in the window is small (24.6 SOL for stellanyang, < 10 SOL for everyone else); no member is
   ever in the create slot or the first minute. The earliest member entry on a hit is ibuycoin at 38 s on RETARDIO.
10. `symbol` values are stripped ("yoohoo " has a trailing space in the launch list).
11. `kol_*` columns are NULL by design (GMGN was not called), so `outside_*` = everyone except the creator and the
    31 member wallets, including any KOL/smart-money wallets.

Reading of the dev's own pattern (retardmode, 19 launches):
- He always buys in the create transaction (dev_first_buy_s = 0 on 19/19).
- On the 4 hits his first buy is large (12.5%, 35%, 48%, 57% of supply; 3.9-47 SOL) and he does not sell at all in
  the first 30 minutes (0/4). On the 15 misses he sells within seconds in 12/15 (median 7.5 s after create, median
  sold share 0.9) and his first buy is smaller (median 9.7% of supply, 3 SOL), although WOJAK (38.5%), SPOON (42.5%)
  and LEMON (35%) show that a big first buy alone does not identify a hit: he dumped those at 73 s, 5 s and 5 s.
- Priority fee: median 20.5k lamports on hits vs 9.1k on misses; the early Nov-2025 launches used 125k-645k.
- The same-slot bundle proxy is weak: 0-5 other buyers in the create slot, no higher on hits (0, 0, 1, 2).
