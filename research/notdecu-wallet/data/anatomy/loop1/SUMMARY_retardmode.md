# SUMMARY_retardmode — launch anatomy, loop 1 (Phase B, offline)

Built by `scripts/anatomy_build.py` from `data/anatomy/loop1/retardmode/*.parsed.jsonl`. Trades are re-derived from Helius account-level token balance changes (see the script docstring); SOL figures are the curve/pool-side amounts (fees and tips excluded); non-SOL-quoted launches are converted to SOL at the window's own router rate. `kol_*` columns are NULL (GMGN not called).

## Coverage

- launches: 19 (hits 4, non-hits 15)
- truncated windows (>30,000 tx): 0
- launches with an AMM pool phase inside the window: 4 (MRHATE, RETARDIO, PQ, WOJAK)
- launches quoted in a non-SOL token: 4 (GIGAY, GMONAD, PQ, WOJAK)
- launches with no member buy in the window: 13
- launches with no dev sell in the window: 7
- transactions in windows: 28654, of which trades 13134, no-op/fee-only 15520, wallet-to-wallet transfers 0

## Medians, hits vs non-hits (every lag/size column; n = launches with a value)

| column | hits median | n | non-hits median | n |
|---|---|---|---|---|
| n_tx_30m | 1,640.5 | 4 | 295 | 15 |
| n_buys_30m | 975 | 4 | 66 | 15 |
| n_sells_30m | 654.5 | 4 | 75 | 15 |
| n_wallets_30m | 554 | 4 | 61 | 15 |
| dev_first_buy_s | 0 | 4 | 0 | 15 |
| dev_first_buy_sol | 19.621 | 4 | 2.969 | 15 |
| dev_first_buy_tokens | 4.18e+08 | 4 | 9.66e+07 | 15 |
| dev_supply_share | 0.418 | 4 | 0.097 | 15 |
| dev_same_slot_buyers | 0.5 | 4 | 2 | 15 |
| dev_fee_lamports_med | 20,500 | 4 | 9,079 | 15 |
| dev_first_sell_s | NULL | 0 | 7.5 | 12 |
| dev_sold_share_30m | 0 | 4 | 0.895 | 15 |
| member_first_buy_s | 265 | 3 | 269 | 3 |
| member_buyers_n | 2 | 4 | 0 | 15 |
| member_buy_sol_30m | 9.313 | 4 | 0 | 15 |
| member_first_sell_s | 1,266 | 1 | 306 | 1 |
| member_sell_sol_30m | 0 | 4 | 0 | 15 |
| outside_first_buy_s | 0.5 | 4 | 0 | 15 |
| outside_buy_sol_5m | 48.39 | 4 | 39.345 | 15 |
| outside_buy_sol_30m | 551.388 | 4 | 51.122 | 15 |
| sol_in_1m | 36.057 | 4 | 46.352 | 15 |
| sol_in_5m | 68.505 | 4 | 49.126 | 15 |
| sol_in_15m | 201.046 | 4 | 52.065 | 15 |
| sol_in_30m | 575.755 | 4 | 54.091 | 15 |
| peak_ts_s | 1,466.5 | 4 | 4 | 15 |
| peak_price_sol | 8.29e-07 | 4 | 9.15e-08 | 15 |
| peak_mult_vs_dev | 16.776 | 4 | 2.612 | 15 |
| top10_wallets_share_30m | 0.748 | 4 | 1 | 14 |
| n_wallets_net_long_30m | 180 | 4 | 7 | 15 |

## Member entry: five earliest

| symbol | hit | member_first_buy_s | member_first_buyer | member_buyers_n | member_buy_sol_30m | dev_first_buy_s | peak_ts_s | peak_mult_vs_dev |
|---|---|---|---|---|---|---|---|---|
| RETARDIO | True | 38 | ibuycoin | 3 | 20.235 | 0 | 833 | 29.642 |
| WOJAK | False | 139 | trenchdigger | 5 | 18.146 | 0 | 745 | 11.828 |
| PQ | True | 265 | trenchdigger | 4 | 15.728 | 0 | 1663 | 86.554 |
| yoohoo | False | 269 | TMH | 1 | 0.988 | 0 | 4 | 3.701 |
| GIGAY | False | 417 | baseddom | 1 | 0.049 | 0 | 91 | 4.134 |

## Member entry: five latest

| symbol | hit | member_first_buy_s | member_first_buyer | member_buyers_n | member_buy_sol_30m | dev_first_buy_s | peak_ts_s | peak_mult_vs_dev |
|---|---|---|---|---|---|---|---|---|
| MRHATE | True | 1095 | stellanyang | 1 | 2.897 | 0 | 1270 | 3.642 |
| GIGAY | False | 417 | baseddom | 1 | 0.049 | 0 | 91 | 4.134 |
| yoohoo | False | 269 | TMH | 1 | 0.988 | 0 | 4 | 3.701 |
| PQ | True | 265 | trenchdigger | 4 | 15.728 | 0 | 1663 | 86.554 |
| WOJAK | False | 139 | trenchdigger | 5 | 18.146 | 0 | 745 | 11.828 |

No member buy in the window: CARDAMOM, NIGGERMAS, HANUKKAH, clappy, Chazerei, PEACE, YGIG, GOOSE, BIRD, GMONAD, MERCURY, LEMON, SPOON

## The dev's own pattern

| group | first-buy share median | first-buy SOL median | first-sell s median (n sold) | sold share median | fee med (lamports − 5000) |
|---|---|---|---|---|---|
| hits | 0.418 | 19.621 | NULL (0/4) | 0 | 20,500 |
| non-hits | 0.097 | 2.969 | 7.5 (12/15) | 0.895 | 9,079 |

| symbol | hit | dev_first_buy_s | dev_supply_share | dev_first_buy_sol | dev_same_slot_buyers | dev_fee_lamports_med | dev_first_sell_s | dev_sold_share_30m | x_dev_sell_sol_30m |
|---|---|---|---|---|---|---|---|---|---|
| CARDAMOM | False | 0 | 0.034 | 0.989 | 0 | 125,000 | 97 | 1 | 1.744 |
| NIGGERMAS | False | 0 | 0.034 | 0.989 | 2 | 125,000 | 48 | 1 | 1.413 |
| HANUKKAH | False | 0 | 0.034 | 0.989 | 4 | 125,000 | 7 | 1 | 0.987 |
| clappy | False | 0 | 0.034 | 0.989 | 1 | 645,000 | NULL | 0 | 0 |
| Chazerei | False | 0 | 0.066 | 1.975 | 3 | 40,000 | NULL | 0 | 0 |
| PEACE | True | 0 | 0.125 | 3.948 | 0 | 40,000 | NULL | 0 | 0 |
| YGIG | False | 0 | 0.035 | 1.002 | 0 | 8,500 | NULL | 0 | 0 |
| yoohoo | False | 0 | 0.152 | 4.944 | 0 | 7,000 | 8 | 0.5 | 6.63 |
| GOOSE | False | 0 | 0.097 | 2.969 | 2 | 4,000 | 7 | 1 | 4.531 |
| BIRD | False | 0 | 0.097 | 2.969 | 3 | 7,000 | 6 | 0.5 | 2.248 |
| MRHATE | True | 0 | 0.353 | 14.691 | 1 | 10,000 | NULL | 0 | 0 |
| RETARDIO | True | 0 | 0.483 | 24.551 | 2 | 30,000 | NULL | 0 | 0 |
| GIGAY | False | 0 | 0.197 | 9.653 | 1 | 9,079 | 96 | 0.761 | 23.234 |
| GMONAD | False | 0 | 0.2 | 9.781 | 1 | 377,391.5 | 124 | 1 | 10.906 |
| PQ | True | 0 | 0.573 | 47.291 | 0 | 11,000 | NULL | 0 | 0 |
| WOJAK | False | 0 | 0.385 | 23.65 | 2 | 83,185 | 73 | 0.895 | 61.013 |
| MERCURY | False | 0 | 0.152 | 4.944 | 0 | 4,000 | 6 | 0.823 | 13.071 |
| LEMON | False | 0 | 0.354 | 14.78 | 5 | 4,000 | 5 | 0.94 | 20.079 |
| SPOON | False | 0 | 0.425 | 19.673 | 3 | 7,000 | 5 | 1 | 21.039 |

## Data problems (auto-detected)

- CARDAMOM: 6 trades where the trader is not the fee payer (compact rows label these 'other')
- PEACE: 2 trades where the trader is not the fee payer (compact rows label these 'other')
- PEACE: meta has no curve_last_s although the token graduated later (older pull); whole window is curve phase
- YGIG: 2 trades where the trader is not the fee payer (compact rows label these 'other')
- yoohoo: 2 trades where the trader is not the fee payer (compact rows label these 'other')
- GOOSE: 159 of 295 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- GOOSE: 2 trades where the trader is not the fee payer (compact rows label these 'other')
- BIRD: 101 of 192 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- BIRD: 4 trades where the trader is not the fee payer (compact rows label these 'other')
- MRHATE: 21 trades where the trader is not the fee payer (compact rows label these 'other')
- RETARDIO: 15066 of 18849 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- RETARDIO: 550 trades where the trader is not the fee payer (compact rows label these 'other')
- GIGAY: quoted in 63LfDmNb3MQ8mw9MtZ2To9bEA2M71kZUUGq5tiJxcqj9 (not SOL); SOL columns converted at ~46,388.606 quote/SOL
- GIGAY: 27 trades where the trader is not the fee payer (compact rows label these 'other')
- GMONAD: quoted in CrAr4RRJMBVwRsZtT62pEhfA9H5utymC2mVx8e7FreP2 (not SOL); SOL columns converted at ~4,283.118 quote/SOL
- GMONAD: 5 trades where the trader is not the fee payer (compact rows label these 'other')
- PQ: quoted in GkyPYa7NnCFbduLknCfBfP7p8564X1VZhwZYJ6CZpump (not SOL); SOL columns converted at ~35,720.51 quote/SOL
- PQ: 370 trades where the trader is not the fee payer (compact rows label these 'other')
- WOJAK: quoted in 5UUH9RTDiSpq6HKS6bp4NdU9PNJpXRXuiw6ShBTBhgH2 (not SOL); SOL columns converted at ~2,157.469 quote/SOL
- WOJAK: 172 trades where the trader is not the fee payer (compact rows label these 'other')
- MERCURY: 10 trades where the trader is not the fee payer (compact rows label these 'other')
- LEMON: 14 trades where the trader is not the fee payer (compact rows label these 'other')
- SPOON: 7 trades where the trader is not the fee payer (compact rows label these 'other')

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
