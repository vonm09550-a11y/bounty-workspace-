# SUMMARY_mitch — launch anatomy, loop 1 (Phase B, offline)

Built by `scripts/anatomy_build.py` from `data/anatomy/loop1/mitch/*.parsed.jsonl`. Trades are re-derived from Helius account-level token balance changes (see the script docstring); SOL figures are the curve/pool-side amounts (fees and tips excluded); non-SOL-quoted launches are converted to SOL at the window's own router rate. `kol_*` columns are NULL (GMGN not called).

## Coverage

- launches: 11 (hits 2, non-hits 9)
- truncated windows (>30,000 tx): 0
- launches with an AMM pool phase inside the window: 9 (glown, SOSA, BCC, mitch, XXX, HARD, fagua, RNT, JDS)
- launches quoted in a non-SOL token: 0 
- launches with no member buy in the window: 11
- launches with no dev sell in the window: 10
- transactions in windows: 19822, of which trades 607, no-op/fee-only 234, wallet-to-wallet transfers 18981

## Medians, hits vs non-hits (every lag/size column; n = launches with a value)

| column | hits median | n | non-hits median | n |
|---|---|---|---|---|
| n_tx_30m | 52 | 2 | 1,936 | 9 |
| n_buys_30m | 29.5 | 2 | 34 | 9 |
| n_sells_30m | 22.5 | 2 | 10 | 9 |
| n_wallets_30m | 27 | 2 | 34 | 9 |
| dev_first_buy_s | 0 | 1 | 0 | 4 |
| dev_first_buy_sol | 84.682 | 1 | 26.501 | 4 |
| dev_first_buy_tokens | 7.92e+08 | 1 | 4.98e+08 | 4 |
| dev_supply_share | 0.792 | 1 | 0.498 | 4 |
| dev_same_slot_buyers | 1 | 1 | 0 | 4 |
| dev_fee_lamports_med | 45,000 | 2 | 321,971 | 6 |
| dev_first_sell_s | 39 | 1 | NULL | 0 |
| dev_sold_share_30m | 0 | 1 | 0 | 4 |
| member_first_buy_s | NULL | 0 | NULL | 0 |
| member_buyers_n | 0 | 2 | 0 | 9 |
| member_buy_sol_30m | 0 | 2 | 0 | 9 |
| member_first_sell_s | NULL | 0 | NULL | 0 |
| member_sell_sol_30m | 0 | 2 | 0 | 9 |
| outside_first_buy_s | 0 | 2 | 1 | 9 |
| outside_buy_sol_5m | 73.944 | 2 | 155.529 | 9 |
| outside_buy_sol_30m | 75.189 | 2 | 157.319 | 9 |
| sol_in_1m | 112.614 | 2 | 77.409 | 9 |
| sol_in_5m | 116.285 | 2 | 155.529 | 9 |
| sol_in_15m | 116.285 | 2 | 174.547 | 9 |
| sol_in_30m | 117.53 | 2 | 174.547 | 9 |
| peak_ts_s | 19 | 2 | 157 | 9 |
| peak_price_sol | 2.29e-07 | 2 | 4.11e-07 | 9 |
| peak_mult_vs_dev | 1.591 | 1 | 5.9 | 4 |
| top10_wallets_share_30m | 1 | 2 | 0.854 | 9 |
| n_wallets_net_long_30m | 5 | 2 | 29 | 9 |

## Member entry: five earliest

| symbol | hit | member_first_buy_s | member_first_buyer | member_buyers_n | member_buy_sol_30m | dev_first_buy_s | peak_ts_s | peak_mult_vs_dev |
|---|---|---|---|---|---|---|---|---|

## Member entry: five latest

| symbol | hit | member_first_buy_s | member_first_buyer | member_buyers_n | member_buy_sol_30m | dev_first_buy_s | peak_ts_s | peak_mult_vs_dev |
|---|---|---|---|---|---|---|---|---|

No member buy in the window: kai, glown, SOSA, BCC, mitch, XXX, HARD, fagua, RNT, JDS, MITCH

## The dev's own pattern

| group | first-buy share median | first-buy SOL median | first-sell s median (n sold) | sold share median | fee med (lamports − 5000) |
|---|---|---|---|---|---|
| hits | 0.792 | 84.682 | 39 (1/2) | 0 | 45,000 |
| non-hits | 0.498 | 26.501 | NULL (0/9) | 0 | 321,971 |

| symbol | hit | dev_first_buy_s | dev_supply_share | dev_first_buy_sol | dev_same_slot_buyers | dev_fee_lamports_med | dev_first_sell_s | dev_sold_share_30m | x_dev_sell_sol_30m |
|---|---|---|---|---|---|---|---|---|---|
| kai | False | 0 | 0.098 | 3.001 | 0 | 85,000 | NULL | 0 | 0 |
| glown | False | 0 | 0.442 | 21.001 | 0 | 30,000 | NULL | 0 | 0 |
| SOSA | False | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 |
| BCC | False | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 |
| mitch | True | NULL | NULL | NULL | NULL | 60,000 | 39 | NULL | 59.275 |
| XXX | False | NULL | NULL | NULL | NULL | 500,000 | NULL | NULL | 0 |
| HARD | False | 0 | 0.731 | 64.001 | 0 | 838,334 | NULL | 0 | 0 |
| fagua | False | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 |
| RNT | False | 0 | 0.554 | 32.001 | 0 | 143,942 | NULL | 0 | 0 |
| JDS | False | NULL | NULL | NULL | NULL | 500,000 | NULL | NULL | 0 |
| MITCH | True | 0 | 0.792 | 84.682 | 1 | 30,000 | NULL | 0 | 0 |

## Data problems (auto-detected)

- glown: 2 trades where the trader is not the fee payer (compact rows label these 'other')
- SOSA: no create transaction found in the window (create_ts later than the mint?)
- SOSA: creator never bought in the window
- SOSA: 2 trades where the trader is not the fee payer (compact rows label these 'other')
- BCC: no create transaction found in the window (create_ts later than the mint?)
- BCC: creator never bought in the window
- BCC: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- mitch: creator never bought in the window
- mitch: 5 trades where the trader is not the fee payer (compact rows label these 'other')
- XXX: no create transaction found in the window (create_ts later than the mint?)
- XXX: creator never bought in the window
- XXX: 10 trades where the trader is not the fee payer (compact rows label these 'other')
- HARD: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- fagua: no create transaction found in the window (create_ts later than the mint?)
- fagua: creator never bought in the window
- fagua: 3 trades where the trader is not the fee payer (compact rows label these 'other')
- RNT: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- JDS: no create transaction found in the window (create_ts later than the mint?)
- JDS: creator never bought in the window
- JDS: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- MITCH: 1 trades where the trader is not the fee payer (compact rows label these 'other')
