# SUMMARY_hashbergers — launch anatomy, loop 1 (Phase B, offline)

Built by `scripts/anatomy_build.py` from `data/anatomy/loop1/hashbergers/*.parsed.jsonl`. Trades are re-derived from Helius account-level token balance changes (see the script docstring); SOL figures are the curve/pool-side amounts (fees and tips excluded); non-SOL-quoted launches are converted to SOL at the window's own router rate. `kol_*` columns are NULL (GMGN not called).

## Coverage

- launches: 12 (hits 2, non-hits 10)
- truncated windows (>30,000 tx): 0
- launches with an AMM pool phase inside the window: 2 (SCRAP, PINU)
- launches quoted in a non-SOL token: 0 
- launches with no member buy in the window: 11
- launches with no dev sell in the window: 2
- transactions in windows: 12852, of which trades 9165, no-op/fee-only 3687, wallet-to-wallet transfers 0

## Medians, hits vs non-hits (every lag/size column; n = launches with a value)

| column | hits median | n | non-hits median | n |
|---|---|---|---|---|
| n_tx_30m | 5,884.5 | 2 | 37 | 10 |
| n_buys_30m | 2,293.5 | 2 | 18 | 10 |
| n_sells_30m | 1,758 | 2 | 18.5 | 10 |
| n_wallets_30m | 1,257.5 | 2 | 18 | 10 |
| dev_first_buy_s | 0 | 2 | 0 | 10 |
| dev_first_buy_sol | 13.121 | 2 | 0.989 | 10 |
| dev_first_buy_tokens | 2.51e+08 | 2 | 3.42e+07 | 10 |
| dev_supply_share | 0.251 | 2 | 0.034 | 10 |
| dev_same_slot_buyers | 5.5 | 2 | 1 | 10 |
| dev_fee_lamports_med | 313,194 | 2 | 146,860 | 10 |
| dev_first_sell_s | NULL | 0 | 10 | 10 |
| dev_sold_share_30m | 0 | 2 | 1 | 10 |
| member_first_buy_s | 38 | 1 | NULL | 0 |
| member_buyers_n | 1 | 2 | 0 | 10 |
| member_buy_sol_30m | 1.98 | 2 | 0 | 10 |
| member_first_sell_s | 65 | 1 | NULL | 0 |
| member_sell_sol_30m | 0.678 | 2 | 0 | 10 |
| outside_first_buy_s | 0 | 2 | 0 | 10 |
| outside_buy_sol_5m | 296.696 | 2 | 6.5 | 10 |
| outside_buy_sol_30m | 1,239.233 | 2 | 7.449 | 10 |
| sol_in_1m | 120.496 | 2 | 6.053 | 10 |
| sol_in_5m | 310.806 | 2 | 10.199 | 10 |
| sol_in_15m | 828.318 | 2 | 11.251 | 10 |
| sol_in_30m | 1,254.334 | 2 | 11.251 | 10 |
| peak_ts_s | 1,342 | 2 | 7.5 | 10 |
| peak_price_sol | 1.84e-06 | 2 | 3.75e-08 | 10 |
| peak_mult_vs_dev | 40.284 | 2 | 1.218 | 10 |
| top10_wallets_share_30m | 0.531 | 2 | 1 | 4 |
| n_wallets_net_long_30m | 475 | 2 | 0 | 10 |

## Member entry: five earliest

| symbol | hit | member_first_buy_s | member_first_buyer | member_buyers_n | member_buy_sol_30m | dev_first_buy_s | peak_ts_s | peak_mult_vs_dev |
|---|---|---|---|---|---|---|---|---|
| PINU | True | 38 | trenchdigger | 2 | 3.96 | 0 | 1781 | 55.556 |

## Member entry: five latest

| symbol | hit | member_first_buy_s | member_first_buyer | member_buyers_n | member_buy_sol_30m | dev_first_buy_s | peak_ts_s | peak_mult_vs_dev |
|---|---|---|---|---|---|---|---|---|
| PINU | True | 38 | trenchdigger | 2 | 3.96 | 0 | 1781 | 55.556 |

No member buy in the window: SCRAP, RAPEHIM, PVE, PENGU, OBESE, AMIGA, OARFISH, KINDA, FLOAT, COMPUTA, piss

## The dev's own pattern

| group | first-buy share median | first-buy SOL median | first-sell s median (n sold) | sold share median | fee med (lamports − 5000) |
|---|---|---|---|---|---|
| hits | 0.251 | 13.121 | NULL (0/2) | 0 | 313,194 |
| non-hits | 0.034 | 0.989 | 10 (10/10) | 1 | 146,860 |

| symbol | hit | dev_first_buy_s | dev_supply_share | dev_first_buy_sol | dev_same_slot_buyers | dev_fee_lamports_med | dev_first_sell_s | dev_sold_share_30m | x_dev_sell_sol_30m |
|---|---|---|---|---|---|---|---|---|---|
| SCRAP | True | 0 | 0.000706 | 0.022 | 0 | 191,924 | NULL | 0 | 0 |
| RAPEHIM | False | 0 | 0.003 | 0.08 | 0 | 216,753 | 13 | 1 | 0.081 |
| PVE | False | 0 | 0.034 | 0.989 | 0 | 196,038.5 | 9 | 1 | 1.203 |
| PENGU | False | 0 | 0.034 | 0.989 | 0 | 206,848 | 8 | 1 | 1.012 |
| OBESE | False | 0 | 0.06 | 1.779 | 3 | 372,788.5 | 17 | 1 | 3.28 |
| AMIGA | False | 0 | 0.285 | 10.866 | 0 | 34,398 | 9 | 1 | 10.864 |
| OARFISH | False | 0 | 0.034 | 0.989 | 1 | 62,551 | 12 | 1 | 1.176 |
| KINDA | False | 0 | 0.034 | 0.989 | 3 | 75,000 | 10 | 1 | 1.178 |
| FLOAT | False | 0 | 0.034 | 0.989 | 1 | 97,681.5 | 10 | 1 | 1.019 |
| COMPUTA | False | 0 | 0.034 | 0.989 | 1 | 200,483 | 9 | 1 | 1.015 |
| piss | False | 0 | 0.034 | 0.989 | 3 | 50,000 | 24 | 1 | 2.203 |
| PINU | True | 0 | 0.5 | 26.22 | 11 | 434,464 | NULL | 0 | 0 |

## Data problems (auto-detected)

- SCRAP: 99 trades where the trader is not the fee payer (compact rows label these 'other')
- OBESE: 4 trades where the trader is not the fee payer (compact rows label these 'other')
- OARFISH: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- KINDA: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- PINU: 3680 of 8713 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- PINU: 547 trades where the trader is not the fee payer (compact rows label these 'other')
