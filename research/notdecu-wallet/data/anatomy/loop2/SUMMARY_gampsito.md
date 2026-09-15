# SUMMARY_gampsito — launch anatomy, loop 1 (Phase B, offline)

Built by `scripts/anatomy_build.py` from `data/anatomy/loop1/gampsito/*.parsed.jsonl`. Trades are re-derived from Helius account-level token balance changes (see the script docstring); SOL figures are the curve/pool-side amounts (fees and tips excluded); non-SOL-quoted launches are converted to SOL at the window's own router rate. `kol_*` columns are NULL (GMGN not called).

## Coverage

- launches: 16 (hits 6, non-hits 10)
- truncated windows (>30,000 tx): 1
- launches with an AMM pool phase inside the window: 4 (Polycat, Biz, Dancedoge, ok)
- launches quoted in a non-SOL token: 1 (BTD)
- launches with no member buy in the window: 15
- launches with no dev sell in the window: 0
- transactions in windows: 31103, of which trades 19394, no-op/fee-only 41709, wallet-to-wallet transfers 0

## Medians, hits vs non-hits (every lag/size column; n = launches with a value)

| column | hits median | n | non-hits median | n |
|---|---|---|---|---|
| n_tx_30m | 1,132 | 5 | 1,325 | 10 |
| n_buys_30m | 641 | 5 | 171.5 | 10 |
| n_sells_30m | 491 | 5 | 167.5 | 10 |
| n_wallets_30m | 351 | 5 | 128 | 10 |
| dev_first_buy_s | 0 | 6 | 0 | 10 |
| dev_first_buy_sol | 4.94 | 6 | 5.928 | 10 |
| dev_first_buy_tokens | 1.52e+08 | 6 | 1.77e+08 | 10 |
| dev_supply_share | 0.152 | 6 | 0.177 | 10 |
| dev_same_slot_buyers | 7 | 6 | 5.5 | 10 |
| dev_fee_lamports_med | 90,480.5 | 6 | 55,087.25 | 10 |
| dev_first_sell_s | 3 | 6 | 2 | 10 |
| dev_sold_share_30m | 1 | 5 | 1 | 10 |
| member_first_buy_s | 402 | 1 | NULL | 0 |
| member_buyers_n | 0 | 5 | 0 | 10 |
| member_buy_sol_30m | 0 | 5 | 0 | 10 |
| member_first_sell_s | 409 | 1 | NULL | 0 |
| member_sell_sol_30m | 0 | 5 | 0 | 10 |
| outside_first_buy_s | 0 | 6 | 0 | 10 |
| outside_buy_sol_5m | 176.667 | 6 | 69.802 | 10 |
| outside_buy_sol_30m | 265.004 | 5 | 75.156 | 10 |
| sol_in_1m | 109.51 | 6 | 70.448 | 10 |
| sol_in_5m | 181.607 | 6 | 75.73 | 10 |
| sol_in_15m | 291.514 | 6 | 76.086 | 10 |
| sol_in_30m | 270.932 | 5 | 80.59 | 10 |
| peak_ts_s | 421 | 6 | 5 | 10 |
| peak_price_sol | 1.82e-07 | 6 | 7.24e-08 | 10 |
| peak_mult_vs_dev | 5.528 | 6 | 2.162 | 10 |
| top10_wallets_share_30m | 0.348 | 3 | 1 | 8 |
| n_wallets_net_long_30m | 30 | 5 | 2.5 | 10 |

## Member entry: five earliest

| symbol | hit | member_first_buy_s | member_first_buyer | member_buyers_n | member_buy_sol_30m | dev_first_buy_s | peak_ts_s | peak_mult_vs_dev |
|---|---|---|---|---|---|---|---|---|
| Biz | True | 402 | trenchdigger | NULL | NULL | 0 | 1063 | 28.62 |

## Member entry: five latest

| symbol | hit | member_first_buy_s | member_first_buyer | member_buyers_n | member_buy_sol_30m | dev_first_buy_s | peak_ts_s | peak_mult_vs_dev |
|---|---|---|---|---|---|---|---|---|
| Biz | True | 402 | trenchdigger | NULL | NULL | 0 | 1063 | 28.62 |

No member buy in the window: PP, petcat, Polycat, Dancedoge, ok, mlem, looong, Shrekt, HeHa, OrgyInu, hats, Chimpi, blep, yap, BTD

## The dev's own pattern

| group | first-buy share median | first-buy SOL median | first-sell s median (n sold) | sold share median | fee med (lamports − 5000) |
|---|---|---|---|---|---|
| hits | 0.152 | 4.94 | 3 (6/6) | 1 | 90,480.5 |
| non-hits | 0.177 | 5.928 | 2 (10/10) | 1 | 55,087.25 |

| symbol | hit | dev_first_buy_s | dev_supply_share | dev_first_buy_sol | dev_same_slot_buyers | dev_fee_lamports_med | dev_first_sell_s | dev_sold_share_30m | x_dev_sell_sol_30m |
|---|---|---|---|---|---|---|---|---|---|
| PP | True | 0 | 0.152 | 4.94 | 8 | 1e+06 | 1 | 0.972 | 14.582 |
| petcat | True | 0 | 0.177 | 5.928 | 6 | 1e+06 | 1 | 1 | 14.755 |
| Polycat | True | 0 | 0.152 | 4.94 | 6 | 81,861 | 4 | 0.989 | 10.836 |
| Biz | True | 0 | 0.125 | 3.953 | 7 | 52,275 | 2 | NULL | 9.615 |
| Dancedoge | True | 0 | 0.201 | 6.916 | 7 | 51,429 | 5 | 1 | 9.203 |
| ok | True | 0 | 0.152 | 4.94 | 9 | 99,100 | 4 | 1 | 5.863 |
| mlem | False | 0 | 0.152 | 4.94 | 6 | 35,251 | 3 | 1 | 8.183 |
| looong | False | 0 | 0.177 | 5.928 | 8 | 46,050 | 2 | 1 | 14.431 |
| Shrekt | False | 0 | 0.201 | 6.916 | 18 | 67,999 | 1 | 1 | 14.365 |
| HeHa | False | 0 | 0.152 | 4.94 | 2 | 50,441 | 1 | 1 | 7.379 |
| OrgyInu | False | 0 | 0.177 | 5.928 | 2 | 69,400 | 1 | 1 | 12.182 |
| hats | False | 0 | 0.152 | 4.94 | 4 | 94,925 | 1 | 1 | 6.299 |
| Chimpi | False | 0 | 0.177 | 5.928 | 12 | 59,437.5 | 2 | 1 | 8.173 |
| blep | False | 0 | 0.177 | 5.928 | 5 | 115,630 | 4 | 1 | 13.381 |
| yap | False | 0 | 0.177 | 5.928 | 12 | 50,737 | 5 | 1 | 7.337 |
| BTD | False | 0 | 0.086 | 3.744 | 3 | 14,925 | 4 | 1 | 4.791 |

## Data problems (auto-detected)

- PP: 47 trades where the trader is not the fee payer (compact rows label these 'other')
- petcat: 13 trades where the trader is not the fee payer (compact rows label these 'other')
- Polycat: 7865 of 12832 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- Polycat: 610 trades where the trader is not the fee payer (compact rows label these 'other')
- Biz: 528 trades where the trader is not the fee payer (compact rows label these 'other')
- Biz: window truncated at 1070 s; *_30m columns NULL
- Dancedoge: 212 of 269 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- ok: 341 of 396 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- mlem: 325 of 490 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- looong: 121 trades where the trader is not the fee payer (compact rows label these 'other')
- Shrekt: 1441 of 1932 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- Shrekt: 8 trades where the trader is not the fee payer (compact rows label these 'other')
- HeHa: 1059 of 1185 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- OrgyInu: 909 of 1465 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- OrgyInu: 12 trades where the trader is not the fee payer (compact rows label these 'other')
- hats: 991 of 1178 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- Chimpi: 833 of 926 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- blep: 1013 of 1539 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- yap: 239 of 335 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- BTD: quoted in XsqE9cRRpzxcGKDXj1BJ7Xmg4GRhZoyY1KpmGSxAWT2 (not SOL); SOL columns converted at ~0.385 quote/SOL
- BTD: 205 trades where the trader is not the fee payer (compact rows label these 'other')
