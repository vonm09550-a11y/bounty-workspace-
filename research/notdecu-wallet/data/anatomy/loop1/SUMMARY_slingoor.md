# SUMMARY_slingoor — launch anatomy, loop 1 (Phase B, offline)

Built by `scripts/anatomy_build.py` from `data/anatomy/loop1/slingoor/*.parsed.jsonl`. Trades are re-derived from Helius account-level token balance changes (see the script docstring); SOL figures are the curve/pool-side amounts (fees and tips excluded); non-SOL-quoted launches are converted to SOL at the window's own router rate. `kol_*` columns are NULL (GMGN not called).

## Coverage

- launches: 32 (hits 14, non-hits 18)
- truncated windows (>30,000 tx): 3
- launches with an AMM pool phase inside the window: 17 (FibFrog, 78, 💀, catcall, OFFICIAL, Chairman, TOAD, sling, WINNIE, HOODWARTS, LIZARD, DIDDY, 🐺, INSANE, nothing, link, SEXY)
- launches quoted in a non-SOL token: 2 (MARVIN, SEXY)
- launches with no member buy in the window: 20
- launches with no dev sell in the window: 22
- transactions in windows: 138797, of which trades 90190, no-op/fee-only 135835, wallet-to-wallet transfers 2772

## Medians, hits vs non-hits (every lag/size column; n = launches with a value)

| column | hits median | n | non-hits median | n |
|---|---|---|---|---|
| n_tx_30m | 9,680 | 11 | 307.5 | 18 |
| n_buys_30m | 2,686 | 11 | 137 | 13 |
| n_sells_30m | 1,978 | 11 | 111 | 13 |
| n_wallets_30m | 1,289 | 11 | 99 | 13 |
| dev_first_buy_s | 0 | 14 | 0 | 13 |
| dev_first_buy_sol | 30.125 | 14 | 16.298 | 13 |
| dev_first_buy_tokens | 5.76e+08 | 14 | 3.85e+08 | 13 |
| dev_supply_share | 0.576 | 14 | 0.385 | 13 |
| dev_same_slot_buyers | 5 | 14 | 1 | 13 |
| dev_fee_lamports_med | 76,434.5 | 14 | 48,592 | 18 |
| dev_first_sell_s | 14 | 2 | 13 | 8 |
| dev_sold_share_30m | 0 | 11 | 1 | 13 |
| member_first_buy_s | 138 | 11 | 24 | 1 |
| member_buyers_n | 1 | 11 | 0 | 13 |
| member_buy_sol_30m | 1.98 | 11 | 0 | 13 |
| member_first_sell_s | 200 | 9 | 26 | 1 |
| member_sell_sol_30m | 0.957 | 11 | 0 | 13 |
| outside_first_buy_s | 0 | 14 | 0 | 13 |
| outside_buy_sol_5m | 633.909 | 14 | 104.149 | 13 |
| outside_buy_sol_30m | 1,660.958 | 11 | 106.461 | 13 |
| sol_in_1m | 369.328 | 14 | 95.204 | 13 |
| sol_in_5m | 650.283 | 14 | 104.892 | 13 |
| sol_in_15m | 1,025.359 | 11 | 107.204 | 13 |
| sol_in_30m | 1,689.888 | 11 | 107.204 | 13 |
| peak_ts_s | 849 | 13 | 4 | 9 |
| peak_price_sol | 2.6e-06 | 13 | 3.75e-07 | 9 |
| peak_mult_vs_dev | 55.038 | 13 | 6.137 | 9 |
| top10_wallets_share_30m | 0.747 | 11 | 1 | 13 |
| n_wallets_net_long_30m | 367 | 11 | 9 | 13 |

## Member entry: five earliest

| symbol | hit | member_first_buy_s | member_first_buyer | member_buyers_n | member_buy_sol_30m | dev_first_buy_s | peak_ts_s | peak_mult_vs_dev |
|---|---|---|---|---|---|---|---|---|
| INSANE | False | 24 | trenchdigger | 1 | 8.891 | 0 | 14 | 18.384 |
| HOODWARTS | True | 38 | ibuycoin | 2 | 7.014 | 0 | 4 | 13.806 |
| LIZARD | True | 60 | bsol_x | NULL | NULL | 0 | 824 | 106.313 |
| WINNIE | True | 62 | ibuycoin | 3 | 5.438 | 0 | 5 | 58.692 |
| DIDDY | True | 70 | hashbergers | 3 | 34.91 | 0 | 849 | 52.308 |

## Member entry: five latest

| symbol | hit | member_first_buy_s | member_first_buyer | member_buyers_n | member_buy_sol_30m | dev_first_buy_s | peak_ts_s | peak_mult_vs_dev |
|---|---|---|---|---|---|---|---|---|
| nothing | True | 1431 | trenchdigger | 1 | 0.99 | 0 | 1046 | 46.065 |
| TOAD | True | 1207 | badattrading | 1 | 1.98 | 0 | 1743 | 71.64 |
| MARVIN | True | 406 | ibuycoin | 1 | 2.876 | 0 | 1268 | 10.93 |
| Chairman | True | 307 | trenchdigger | 4 | 10.045 | 0 | 1365 | 78.272 |
| sling | True | 229 | trenchdigger | NULL | NULL | 0 | 118 | 167.998 |

No member buy in the window: FibFrog, 78, 💀, BEGFI, dontbuy, 🐺, Graped, donotbuy, link, MPN, SEXY, MPN, MPN, ETH, GRND, MPN, LMAO!, USDC, GREEN, DAMN

## The dev's own pattern

| group | first-buy share median | first-buy SOL median | first-sell s median (n sold) | sold share median | fee med (lamports − 5000) |
|---|---|---|---|---|---|
| hits | 0.576 | 30.125 | 14 (2/14) | 0 | 76,434.5 |
| non-hits | 0.385 | 16.298 | 13 (8/18) | 1 | 48,592 |

| symbol | hit | dev_first_buy_s | dev_supply_share | dev_first_buy_sol | dev_same_slot_buyers | dev_fee_lamports_med | dev_first_sell_s | dev_sold_share_30m | x_dev_sell_sol_30m |
|---|---|---|---|---|---|---|---|---|---|
| MARVIN | True | 0 | 0.247 | 17.026 | 5 | 87,149 | NULL | 0 | 0 |
| FibFrog | False | 0 | 0.391 | 17.187 | 7 | 80,049 | 14 | 1 | 35.448 |
| 78 | False | 0 | 0.582 | 35.557 | 2 | 165,242 | 38 | 1 | 36.692 |
| 💀 | False | 0 | 0.385 | 16.792 | 0 | 62,184 | 11 | 1 | 25.838 |
| BEGFI | False | 0 | 0.413 | 18.767 | 4 | 804,637 | 10 | 1 | 23.543 |
| catcall | True | 0 | 0.065 | 1.932 | 3 | 5,255 | NULL | NULL | 0 |
| dontbuy | False | 0 | 0.026 | 0.742 | 4 | 805,442.5 | 217 | 1 | 1.211 |
| OFFICIAL | True | 0 | 0.343 | 14.076 | 0 | 157,056.5 | NULL | 0 | 0 |
| Chairman | True | 0 | 0.61 | 39.508 | 6 | 513,520.5 | NULL | 0 | 0 |
| TOAD | True | 0 | 0.201 | 6.915 | 21 | 112,553 | NULL | 0 | 0 |
| sling | True | 0 | 0.716 | 60.249 | 2 | 555,441 | NULL | NULL | 0 |
| WINNIE | True | 0 | 0.533 | 29.631 | 7 | 148,383 | 13 | 1 | 149.83 |
| HOODWARTS | True | 0 | 0.667 | 49.384 | 2 | 20,395 | 15 | 1 | 84.638 |
| LIZARD | True | 0 | 0.712 | 59.261 | 10 | 65,720 | NULL | NULL | 0 |
| DIDDY | True | 0 | 0.61 | 39.508 | 0 | 918,459 | NULL | 0 | 0 |
| 🐺 | True | 0 | 0.727 | 62.997 | 5 | 10,190 | NULL | 0 | 0 |
| INSANE | False | 0 | 0.199 | 6.818 | 22 | 4,000 | 17 | 0.887 | 50.417 |
| nothing | True | 0 | 0.542 | 30.619 | 10 | 27,617 | NULL | 0 | 0 |
| Graped | True | 0 | 0.472 | 23.577 | 8 | 10,000 | NULL | 0 | 0 |
| donotbuy | False | 0 | 0.378 | 16.298 | 0 | 14,752 | 12 | 1 | 44.05 |
| link | False | 0 | 0.483 | 24.551 | 13 | 7,000 | 5 | 1 | 74.387 |
| MPN | False | NULL | NULL | NULL | NULL | 90,177 | NULL | NULL | NULL |
| SEXY | False | 0 | 0.571 | 48.183 | 0 | 11,000 | NULL | 0 | 0 |
| MPN | False | NULL | NULL | NULL | NULL | 168,947 | NULL | NULL | NULL |
| MPN | False | NULL | NULL | NULL | NULL | 96,510 | NULL | NULL | NULL |
| ETH | True | 0 | 0.639 | 0.002 | 1 | 35,000 | NULL | 0 | 0 |
| GRND | False | 0 | 0.613 | 0.002 | 1 | 35,000 | NULL | 0 | 0 |
| MPN | False | NULL | NULL | NULL | NULL | 246,068 | NULL | NULL | NULL |
| LMAO! | False | 0 | 0.032 | 9.05e-05 | 1 | 35,000 | NULL | 0 | 0 |
| USDC | False | 0 | 0.251 | 0.000715 | 1 | 20,817.5 | NULL | 0 | 0 |
| GREEN | False | 0 | 0.223 | 0.000634 | 1 | 4,483 | NULL | 0 | 0 |
| DAMN | False | NULL | NULL | NULL | NULL | 3,010 | NULL | NULL | NULL |

## Data problems (auto-detected)

- MARVIN: quoted in EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v (not SOL); SOL columns converted at ~75.471 quote/SOL
- MARVIN: 12 trades where the trader is not the fee payer (compact rows label these 'other')
- MARVIN: meta has no curve_last_s although the token graduated later (older pull); whole window is curve phase
- catcall: 399 trades where the trader is not the fee payer (compact rows label these 'other')
- catcall: window truncated at 427 s; *_30m columns NULL
- dontbuy: 7 trades where the trader is not the fee payer (compact rows label these 'other')
- OFFICIAL: 4792 of 9680 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- OFFICIAL: 575 trades where the trader is not the fee payer (compact rows label these 'other')
- Chairman: 10095 of 15850 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- Chairman: 533 trades where the trader is not the fee payer (compact rows label these 'other')
- TOAD: 7254 of 14672 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- TOAD: 566 trades where the trader is not the fee payer (compact rows label these 'other')
- sling: 572 trades where the trader is not the fee payer (compact rows label these 'other')
- sling: window truncated at 872 s; *_30m columns NULL
- WINNIE: 13786 of 23381 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- WINNIE: 1585 trades where the trader is not the fee payer (compact rows label these 'other')
- HOODWARTS: 202 trades where the trader is not the fee payer (compact rows label these 'other')
- LIZARD: 587 trades where the trader is not the fee payer (compact rows label these 'other')
- LIZARD: window truncated at 881 s; *_30m columns NULL
- DIDDY: 21278 of 27129 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- DIDDY: 1008 trades where the trader is not the fee payer (compact rows label these 'other')
- 🐺: 18778 of 23530 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- 🐺: 808 trades where the trader is not the fee payer (compact rows label these 'other')
- INSANE: 349 trades where the trader is not the fee payer (compact rows label these 'other')
- nothing: 3452 of 6897 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- nothing: 446 trades where the trader is not the fee payer (compact rows label these 'other')
- Graped: meta has no curve_last_s although the token graduated later (older pull); whole window is curve phase
- donotbuy: 8 trades where the trader is not the fee payer (compact rows label these 'other')
- link: 61 trades where the trader is not the fee payer (compact rows label these 'other')
- MPN: no create transaction found in the window (create_ts later than the mint?)
- MPN: creator never bought in the window
- SEXY: quoted in XsDoVfqeBukxuZHWhdvWHBhgEHjGNst4MLodqsJHzoB (not SOL); SOL columns converted at ~0.276 quote/SOL
- SEXY: 55 trades where the trader is not the fee payer (compact rows label these 'other')
- MPN: no create transaction found in the window (create_ts later than the mint?)
- MPN: creator never bought in the window
- MPN: no create transaction found in the window (create_ts later than the mint?)
- MPN: creator never bought in the window
- ETH: no create transaction found in the window (create_ts later than the mint?)
- ETH: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- ETH: meta has no curve_last_s although the token graduated later (older pull); whole window is curve phase
- GRND: no create transaction found in the window (create_ts later than the mint?)
- GRND: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- GRND: meta has no curve_last_s although the token graduated later (older pull); whole window is curve phase
- MPN: no create transaction found in the window (create_ts later than the mint?)
- MPN: creator never bought in the window
- LMAO!: no create transaction found in the window (create_ts later than the mint?)
- LMAO!: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- LMAO!: meta has no curve_last_s although the token graduated later (older pull); whole window is curve phase
- USDC: no create transaction found in the window (create_ts later than the mint?)
- USDC: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- GREEN: no create transaction found in the window (create_ts later than the mint?)
- GREEN: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- GREEN: meta has no curve_last_s although the token graduated later (older pull); whole window is curve phase
- DAMN: no create transaction found in the window (create_ts later than the mint?)
- DAMN: creator never bought in the window
