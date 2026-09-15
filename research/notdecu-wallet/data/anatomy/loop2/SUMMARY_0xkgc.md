# SUMMARY_0xkgc — launch anatomy, loop 1 (Phase B, offline)

Built by `scripts/anatomy_build.py` from `data/anatomy/loop1/0xkgc/*.parsed.jsonl`. Trades are re-derived from Helius account-level token balance changes (see the script docstring); SOL figures are the curve/pool-side amounts (fees and tips excluded); non-SOL-quoted launches are converted to SOL at the window's own router rate. `kol_*` columns are NULL (GMGN not called).

## Coverage

- launches: 47 (hits 7, non-hits 40)
- truncated windows (>30,000 tx): 0
- launches with an AMM pool phase inside the window: 3 (ducknana, thewok, Hunter)
- launches quoted in a non-SOL token: 4 (fries, CRIME, dump, ZEC)
- launches with no member buy in the window: 39
- launches with no dev sell in the window: 23
- transactions in windows: 61237, of which trades 52579, no-op/fee-only 3722, wallet-to-wallet transfers 4936

## Medians, hits vs non-hits (every lag/size column; n = launches with a value)

| column | hits median | n | non-hits median | n |
|---|---|---|---|---|
| n_tx_30m | 2,712 | 7 | 732 | 40 |
| n_buys_30m | 1,667 | 7 | 364 | 40 |
| n_sells_30m | 1,053 | 7 | 294.5 | 40 |
| n_wallets_30m | 797 | 7 | 257.5 | 40 |
| dev_first_buy_s | 0 | 7 | 0 | 40 |
| dev_first_buy_sol | 0.992 | 7 | 0.992 | 40 |
| dev_first_buy_tokens | 6.64e+07 | 7 | 3.43e+07 | 40 |
| dev_supply_share | 0.066 | 7 | 0.034 | 40 |
| dev_same_slot_buyers | 1 | 7 | 1.5 | 40 |
| dev_fee_lamports_med | 400,000 | 7 | 452,500 | 40 |
| dev_first_sell_s | 528 | 3 | 738 | 21 |
| dev_sold_share_30m | 0 | 7 | 0.23 | 40 |
| member_first_buy_s | 79 | 1 | 335 | 7 |
| member_buyers_n | 0 | 7 | 0 | 40 |
| member_buy_sol_30m | 0 | 7 | 0 | 40 |
| member_first_sell_s | 409 | 1 | 436 | 5 |
| member_sell_sol_30m | 0 | 7 | 0 | 40 |
| outside_first_buy_s | 0 | 7 | 0 | 40 |
| outside_buy_sol_5m | 26.222 | 7 | 19.612 | 40 |
| outside_buy_sol_30m | 417.25 | 7 | 96.379 | 40 |
| sol_in_1m | 19.523 | 7 | 13.745 | 40 |
| sol_in_5m | 27.213 | 7 | 20.604 | 40 |
| sol_in_15m | 226.043 | 7 | 92.908 | 40 |
| sol_in_30m | 420.127 | 7 | 97.37 | 40 |
| peak_ts_s | 1,008 | 5 | 505 | 35 |
| peak_price_sol | 3.33e-07 | 5 | 9.68e-08 | 35 |
| peak_mult_vs_dev | 10.17 | 5 | 3.257 | 35 |
| top10_wallets_share_30m | 0.41 | 7 | 0.923 | 39 |
| n_wallets_net_long_30m | 261 | 7 | 30 | 40 |

## Member entry: five earliest

| symbol | hit | member_first_buy_s | member_first_buyer | member_buyers_n | member_buy_sol_30m | dev_first_buy_s | peak_ts_s | peak_mult_vs_dev |
|---|---|---|---|---|---|---|---|---|
| ats | False | 48 | 0xPromiser | 2 | 19.951 | 0 | 317 | 5.26 |
| SlowRogan | False | 60 | 0xPromiser | 1 | 0.099 | 0 | 298 | 3.257 |
| Hunter | True | 79 | 0xPromiser | 1 | 0.01 | 0 | 1249 | 17.734 |
| CRIME | False | 169 | slingoor | 3 | 18.739 | 0 | 705 | 12.528 |
| fries | False | 335 | 0xPromiser | 2 | 3.636 | 0 | 1198 | 8.57 |

## Member entry: five latest

| symbol | hit | member_first_buy_s | member_first_buyer | member_buyers_n | member_buy_sol_30m | dev_first_buy_s | peak_ts_s | peak_mult_vs_dev |
|---|---|---|---|---|---|---|---|---|
| 1trump | False | 852 | trenchdigger | 1 | 0.988 | 0 | 932 | 8.428 |
| duve | False | 769 | 0xPromiser | 1 | 0.889 | 0 | 902 | 7.15 |
| ktw | False | 516 | SleepyyMike | 2 | 1.975 | 0 | 609 | 6.406 |
| fries | False | 335 | 0xPromiser | 2 | 3.636 | 0 | 1198 | 8.57 |
| CRIME | False | 169 | slingoor | 3 | 18.739 | 0 | 705 | 12.528 |

No member buy in the window: OG, tradoor, 1LEFT, missooor, madeitup, topbuyer, 1minute, few, SOLMOG, ducknana, SOLONLY, happyegg, ETH, swingdog, biip, BOT, initials, GOAT, biketyson, GAPE, oversold, IBRN, Catiban, MAC, ZUPERCYCLE, MelonMusk, thewok, BABYLMAO, AAPLTOP, Keanu, fleaman, dump, CUM, UNC, BIKESON, K-Train, COMMUNISM, ZEC, RIPASS

## The dev's own pattern

| group | first-buy share median | first-buy SOL median | first-sell s median (n sold) | sold share median | fee med (lamports − 5000) |
|---|---|---|---|---|---|
| hits | 0.066 | 0.992 | 528 (3/7) | 0 | 400,000 |
| non-hits | 0.034 | 0.992 | 738 (21/40) | 0.23 | 452,500 |

| symbol | hit | dev_first_buy_s | dev_supply_share | dev_first_buy_sol | dev_same_slot_buyers | dev_fee_lamports_med | dev_first_sell_s | dev_sold_share_30m | x_dev_sell_sol_30m |
|---|---|---|---|---|---|---|---|---|---|
| OG | False | 0 | 0.034 | 0.992 | 0 | 452,500 | 211 | 1 | 1.169 |
| tradoor | False | 0 | 0.034 | 0.992 | 0 | 452,500 | 224 | 1 | 1.003 |
| 1LEFT | False | 0 | 0.038 | 1.09 | 3 | 452,500 | 753 | 0.223 | 0.79 |
| missooor | False | 0 | 0.034 | 0.992 | 3 | 452,500 | 1611 | 1 | 1.017 |
| madeitup | False | 0 | 0.034 | 0.992 | 0 | 505,000 | NULL | 0 | 0 |
| topbuyer | False | 0 | 0.034 | 0.992 | 1 | 505,000 | NULL | 0 | 0 |
| 1minute | False | 0 | 0.034 | 0.989 | 2 | 514,120 | 802 | 1 | 1.159 |
| 1trump | False | 0 | 0.034 | 0.989 | 1 | 400,000 | 738 | 1 | 3.913 |
| few | False | 0 | 0.034 | 0.989 | 1 | 400,000 | 763 | 1 | 2.93 |
| SOLMOG | False | 0 | 0.034 | 0.992 | 2 | 505,000 | NULL | 0 | 0 |
| ducknana | False | 0 | 0.034 | 0.992 | 1 | 400,000 | 777 | 0.437 | 2.507 |
| SOLONLY | False | 0 | 0.034 | 0.992 | 1 | 505,000 | NULL | 0 | 0 |
| happyegg | False | 0 | 0.034 | 0.992 | 5 | 452,500 | 873 | 1 | 1.309 |
| ETH | False | 0 | 0.034 | 0.992 | 1 | 452,500 | 685 | 1 | 1.219 |
| swingdog | False | 0 | 0.034 | 0.992 | 2 | 452,500 | 703 | 1 | 1.151 |
| biip | False | 0 | 0.034 | 0.992 | 2 | 505,000 | NULL | 0 | 0 |
| BOT | False | 0 | 0.034 | 0.989 | 3 | 502,500 | 36 | 1 | 1.479 |
| initials | False | 0 | 0.034 | 0.989 | 3 | 1e+06 | NULL | 0 | 0 |
| GOAT | False | 0 | 0.034 | 0.992 | 1 | 452,500 | 1298 | 1 | 1.05 |
| biketyson | True | 0 | 0.034 | 0.992 | 2 | 400,000 | 428 | 0.719 | 6.215 |
| GAPE | False | 0 | 0.034 | 0.992 | 4 | 752,500 | 343 | 1 | 1.014 |
| oversold | False | 0 | 0.034 | 0.992 | 3 | 452,500 | 784 | 1 | 1.313 |
| IBRN | False | 0 | 0.034 | 0.992 | 4 | 505,000 | NULL | 0 | 0 |
| Catiban | False | 0 | 0.034 | 0.992 | 3 | 752,500 | 915 | 1 | 1.041 |
| MAC | False | 0 | 0.047 | 0.000167 | 1 | 35,000 | NULL | 0 | 0 |
| ZUPERCYCLE | False | 0 | 0.058 | 0.000205 | 1 | 20,086 | NULL | 0 | 0 |
| MelonMusk | True | 0 | 0.066 | 1.981 | 1 | 452,500 | 528 | 0.156 | 3.461 |
| thewok | True | 0 | 0.034 | 0.991 | 2 | 505,000 | NULL | 0 | 0 |
| BABYLMAO | False | 0 | 0.09 | 0.00032 | 1 | 17,852.5 | NULL | 0 | 0 |
| Hunter | True | 0 | 0.066 | 1.981 | 0 | 452,500 | 1146 | 0.145 | 3.81 |
| duve | False | 0 | 0.034 | 0.991 | 6 | 452,500 | 387 | 0.25 | 1.039 |
| AAPLTOP | False | 0 | 0.091 | 0.000321 | 1 | 3,370 | NULL | 0 | 0 |
| Keanu | False | 0 | 0.06 | 1.778 | 6 | 42,173.5 | NULL | 0 | 0 |
| fries | False | 0 | 0.048 | 1.96 | 0 | 306,781 | NULL | 0 | 0 |
| CRIME | False | 0 | 0.049 | 2.039 | 0 | 605,000 | 555 | 0.461 | 3.738 |
| fleaman | False | 0 | 0.051 | 1.486 | 0 | 505,000 | NULL | 0 | 0 |
| dump | False | 0 | 0.036 | 1.455 | 0 | 605,000 | NULL | 0 | 0 |
| CUM | False | 0 | 0.066 | 1.981 | 11 | 400,000 | 278 | 0.237 | 2.739 |
| ats | False | 0 | 0.066 | 1.981 | 13 | 252,500 | NULL | 0 | 0 |
| UNC | True | 0 | 0.091 | 0.000321 | 1 | 20,429 | NULL | 0 | 0 |
| ktw | False | 0 | 0.097 | 2.969 | 6 | 400,000 | 320 | 0.375 | 2.223 |
| BIKESON | True | 0 | 0.114 | 0.000323 | 1 | 35,000 | NULL | 0 | 0 |
| SlowRogan | False | 0 | 0.082 | 2.475 | 6 | 505,000 | NULL | 0 | 0 |
| K-Train | False | 0 | 0.057 | 1.684 | 12 | 505,000 | NULL | 0 | 0 |
| COMMUNISM | False | 0 | 0.066 | 1.956 | 1 | 396,706.5 | 1169 | 0.5 | 2.731 |
| ZEC | True | 0 | 0.071 | 2.878 | 2 | 11,000 | NULL | 0 | 0 |
| RIPASS | False | 0 | 0.088 | 0.000251 | 1 | 35,000 | NULL | 0 | 0 |

## Data problems (auto-detected)

- tradoor: 2 trades where the trader is not the fee payer (compact rows label these 'other')
- 1LEFT: 138 trades where the trader is not the fee payer (compact rows label these 'other')
- missooor: 30 trades where the trader is not the fee payer (compact rows label these 'other')
- madeitup: 54 trades where the trader is not the fee payer (compact rows label these 'other')
- topbuyer: 70 trades where the trader is not the fee payer (compact rows label these 'other')
- 1minute: 41 trades where the trader is not the fee payer (compact rows label these 'other')
- 1trump: 387 trades where the trader is not the fee payer (compact rows label these 'other')
- few: 305 trades where the trader is not the fee payer (compact rows label these 'other')
- SOLMOG: 184 trades where the trader is not the fee payer (compact rows label these 'other')
- ducknana: 2055 of 6741 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- ducknana: 830 trades where the trader is not the fee payer (compact rows label these 'other')
- SOLONLY: 18 trades where the trader is not the fee payer (compact rows label these 'other')
- happyegg: 111 trades where the trader is not the fee payer (compact rows label these 'other')
- ETH: 82 trades where the trader is not the fee payer (compact rows label these 'other')
- swingdog: 111 trades where the trader is not the fee payer (compact rows label these 'other')
- biip: 29 trades where the trader is not the fee payer (compact rows label these 'other')
- BOT: 2 trades where the trader is not the fee payer (compact rows label these 'other')
- initials: 119 trades where the trader is not the fee payer (compact rows label these 'other')
- GOAT: 8 trades where the trader is not the fee payer (compact rows label these 'other')
- biketyson: 580 trades where the trader is not the fee payer (compact rows label these 'other')
- GAPE: 68 of 176 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- GAPE: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- oversold: 72 trades where the trader is not the fee payer (compact rows label these 'other')
- IBRN: 96 trades where the trader is not the fee payer (compact rows label these 'other')
- Catiban: 4 trades where the trader is not the fee payer (compact rows label these 'other')
- MAC: no create transaction found in the window (create_ts later than the mint?)
- MAC: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- ZUPERCYCLE: no create transaction found in the window (create_ts later than the mint?)
- ZUPERCYCLE: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- MelonMusk: 786 trades where the trader is not the fee payer (compact rows label these 'other')
- thewok: 38 trades where the trader is not the fee payer (compact rows label these 'other')
- BABYLMAO: no create transaction found in the window (create_ts later than the mint?)
- BABYLMAO: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- Hunter: 992 trades where the trader is not the fee payer (compact rows label these 'other')
- duve: 353 trades where the trader is not the fee payer (compact rows label these 'other')
- AAPLTOP: no create transaction found in the window (create_ts later than the mint?)
- AAPLTOP: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- Keanu: 289 trades where the trader is not the fee payer (compact rows label these 'other')
- fries: quoted in XsqE9cRRpzxcGKDXj1BJ7Xmg4GRhZoyY1KpmGSxAWT2 (not SOL); SOL columns converted at ~0.394 quote/SOL
- fries: 186 trades where the trader is not the fee payer (compact rows label these 'other')
- CRIME: quoted in pumpCmXqMfrsAkQ5r49WcJnRayYRqmXz6ae8H7H9Dfn (not SOL); SOL columns converted at ~23,783.239 quote/SOL
- CRIME: 214 trades where the trader is not the fee payer (compact rows label these 'other')
- fleaman: 147 trades where the trader is not the fee payer (compact rows label these 'other')
- dump: quoted in 7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs (not SOL); SOL columns converted at ~0.041 quote/SOL
- dump: 108 trades where the trader is not the fee payer (compact rows label these 'other')
- CUM: 337 trades where the trader is not the fee payer (compact rows label these 'other')
- ats: 149 trades where the trader is not the fee payer (compact rows label these 'other')
- UNC: no create transaction found in the window (create_ts later than the mint?)
- UNC: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- ktw: 244 trades where the trader is not the fee payer (compact rows label these 'other')
- BIKESON: no create transaction found in the window (create_ts later than the mint?)
- BIKESON: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- SlowRogan: 122 trades where the trader is not the fee payer (compact rows label these 'other')
- K-Train: 71 trades where the trader is not the fee payer (compact rows label these 'other')
- COMMUNISM: 258 trades where the trader is not the fee payer (compact rows label these 'other')
- ZEC: quoted in A7bdiYdS5GjqGFtxf17ppRHtDKPkkRqbKtR27dxvQXaS (not SOL); SOL columns converted at ~0.09 quote/SOL
- ZEC: 337 trades where the trader is not the fee payer (compact rows label these 'other')
- RIPASS: no create transaction found in the window (create_ts later than the mint?)
- RIPASS: 1 trades where the trader is not the fee payer (compact rows label these 'other')
