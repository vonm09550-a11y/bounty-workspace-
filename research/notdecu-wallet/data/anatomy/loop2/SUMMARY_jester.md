# SUMMARY_jester — launch anatomy, loop 1 (Phase B, offline)

Built by `scripts/anatomy_build.py` from `data/anatomy/loop1/jester/*.parsed.jsonl`. Trades are re-derived from Helius account-level token balance changes (see the script docstring); SOL figures are the curve/pool-side amounts (fees and tips excluded); non-SOL-quoted launches are converted to SOL at the window's own router rate. `kol_*` columns are NULL (GMGN not called).

## Coverage

- launches: 27 (hits 7, non-hits 20)
- truncated windows (>30,000 tx): 0
- launches with an AMM pool phase inside the window: 6 (SNEAKERS, WATERFALL, COBSON, CREAMUS, it, all/in)
- launches quoted in a non-SOL token: 4 (ALBERT, COBSON, SEKOLAH, ISRAELI)
- launches with no member buy in the window: 20
- launches with no dev sell in the window: 8
- transactions in windows: 20822, of which trades 18572, no-op/fee-only 1658, wallet-to-wallet transfers 592

## Medians, hits vs non-hits (every lag/size column; n = launches with a value)

| column | hits median | n | non-hits median | n |
|---|---|---|---|---|
| n_tx_30m | 626 | 7 | 279 | 20 |
| n_buys_30m | 365 | 7 | 109 | 20 |
| n_sells_30m | 259 | 7 | 96 | 20 |
| n_wallets_30m | 214 | 7 | 80.5 | 20 |
| dev_first_buy_s | 0 | 7 | 0 | 20 |
| dev_first_buy_sol | 3.083 | 7 | 2.471 | 20 |
| dev_first_buy_tokens | 9.99e+07 | 7 | 1.22e+08 | 20 |
| dev_supply_share | 0.1 | 7 | 0.122 | 20 |
| dev_same_slot_buyers | 0 | 7 | 2 | 20 |
| dev_fee_lamports_med | 356,222.5 | 7 | 502,500 | 20 |
| dev_first_sell_s | 23 | 5 | 25 | 14 |
| dev_sold_share_30m | 1 | 7 | 0.794 | 20 |
| member_first_buy_s | 276.5 | 4 | 16 | 3 |
| member_buyers_n | 1 | 7 | 0 | 20 |
| member_buy_sol_30m | 0.933 | 7 | 0 | 20 |
| member_first_sell_s | 1,030 | 1 | 105 | 1 |
| member_sell_sol_30m | 0 | 7 | 0 | 20 |
| outside_first_buy_s | 0 | 7 | 0 | 20 |
| outside_buy_sol_5m | 42.964 | 7 | 35.622 | 20 |
| outside_buy_sol_30m | 250.433 | 7 | 39.549 | 20 |
| sol_in_1m | 48.098 | 7 | 32.216 | 20 |
| sol_in_5m | 98.244 | 7 | 48.435 | 20 |
| sol_in_15m | 147.737 | 7 | 52.541 | 20 |
| sol_in_30m | 296.519 | 7 | 61.06 | 20 |
| peak_ts_s | 1,306 | 7 | 202 | 18 |
| peak_price_sol | 3.91e-07 | 7 | 9.13e-08 | 18 |
| peak_mult_vs_dev | 9.026 | 7 | 2.301 | 18 |
| top10_wallets_share_30m | 0.522 | 7 | 1 | 19 |
| n_wallets_net_long_30m | 59 | 7 | 7.5 | 20 |

## Member entry: five earliest

| symbol | hit | member_first_buy_s | member_first_buyer | member_buyers_n | member_buy_sol_30m | dev_first_buy_s | peak_ts_s | peak_mult_vs_dev |
|---|---|---|---|---|---|---|---|---|
| HITLERHAUS | False | 6 | hashbergers | 1 | 1.956 | 0 | 705 | 4.668 |
| KIKI | True | 13 | hashbergers | 1 | 0.933 | 0 | 1798 | 12.689 |
| PHOUSE | False | 16 | hashbergers | 1 | 3.447 | 0 | 643 | 5.292 |
| NOOB | False | 110 | hashbergers | 1 | 3.062 | 0 | 1482 | 8.794 |
| DIRECTOR | True | 206 | hashbergers | 1 | 1.467 | 0 | 1306 | 2.872 |

## Member entry: five latest

| symbol | hit | member_first_buy_s | member_first_buyer | member_buyers_n | member_buy_sol_30m | dev_first_buy_s | peak_ts_s | peak_mult_vs_dev |
|---|---|---|---|---|---|---|---|---|
| SNEAKERS | True | 949 | hashbergers | 1 | 1.027 | 0 | 1115 | 4.896 |
| CHICKY | True | 347 | hashbergers | 1 | 3.618 | 0 | 641 | 10.915 |
| DIRECTOR | True | 206 | hashbergers | 1 | 1.467 | 0 | 1306 | 2.872 |
| NOOB | False | 110 | hashbergers | 1 | 3.062 | 0 | 1482 | 8.794 |
| PHOUSE | False | 16 | hashbergers | 1 | 3.447 | 0 | 643 | 5.292 |

No member buy in the window: WATERFALL, ALBERT, COBSON, mouse, CREAMUS, SEKOLAH, JANICE, Jutsu, FLUFF, TYGR, LARD, BHOUSSSE, it, MOONCAT, all/in, TOLYBOT, ZEC, NUKE, WIF, ISRAELI

## The dev's own pattern

| group | first-buy share median | first-buy SOL median | first-sell s median (n sold) | sold share median | fee med (lamports − 5000) |
|---|---|---|---|---|---|
| hits | 0.1 | 3.083 | 23 (5/7) | 1 | 356,222.5 |
| non-hits | 0.122 | 2.471 | 25 (14/20) | 0.794 | 502,500 |

| symbol | hit | dev_first_buy_s | dev_supply_share | dev_first_buy_sol | dev_same_slot_buyers | dev_fee_lamports_med | dev_first_sell_s | dev_sold_share_30m | x_dev_sell_sol_30m |
|---|---|---|---|---|---|---|---|---|---|
| DIRECTOR | True | 0 | 0.034 | 0.99 | 3 | 762,780 | 16 | 1 | 1.033 |
| CHICKY | True | 0 | 0.066 | 1.977 | 0 | 323,939.5 | 15 | 1 | 2.915 |
| KIKI | True | 0 | 0.1 | 3.083 | 3 | 356,222.5 | 63 | 1 | 10.762 |
| SNEAKERS | True | 0 | 0.086 | 2.602 | 0 | 572 | 58 | 1 | 4.269 |
| WATERFALL | True | 0 | 0.303 | 11.794 | 3 | 4,250 | NULL | 0 | 0 |
| ALBERT | True | 0 | 0.107 | 6.468 | 0 | 505,000 | 23 | 0.767 | 11.96 |
| COBSON | True | 0 | 0.766 | 149.968 | 0 | 505,000 | NULL | 0 | 0 |
| mouse | False | 0 | 0.184 | 6.202 | 2 | 355,000 | 17 | 1 | 8.249 |
| CREAMUS | False | 0 | 0.703 | 57.002 | 2 | 355,000 | NULL | 0 | 0 |
| SEKOLAH | False | 0 | 0.028 | 1.496 | 0 | 5,000 | NULL | 0 | 0 |
| JANICE | False | 0 | 0.000353 | 0.012 | 4 | 702,645 | 44 | 1 | 0.011 |
| Jutsu | False | 0 | 0.000353 | 0.012 | 2 | 646,752 | NULL | 0 | 0 |
| FLUFF | False | 0 | 0.1 | 3.102 | 2 | 5e+06 | 33 | 1 | 3.368 |
| TYGR | False | 0 | 0.096 | 2.965 | 2 | 4e+06 | 18 | 1 | 7.351 |
| HITLERHAUS | False | 0 | 0.066 | 1.977 | 1 | 1e+07 | 36 | 1 | 5.685 |
| LARD | False | 0 | 0.000353 | 0.012 | 2 | 502,500 | 32 | 1 | 0.014 |
| PHOUSE | False | 0 | 0.066 | 1.977 | 5 | 1e+06 | 9 | 0.6 | 2.605 |
| BHOUSSSE | False | 0 | 0.034 | 0.989 | 6 | 502,500 | 11 | 1 | 1.652 |
| it | False | 0 | 0.152 | 4.939 | 9 | 5e+06 | 8 | 0.795 | 8.822 |
| NOOB | False | 0 | 0.152 | 4.94 | 2 | 1e+06 | 15 | 0.792 | 7.081 |
| MOONCAT | False | 436 | 0.034 | 1.481 | 8 | 1e+06 | 512 | 0.2 | 0.332 |
| all/in | False | 0 | 0.791 | 83.952 | 0 | 25,890 | NULL | 0 | 0 |
| TOLYBOT | False | 0 | 0.143 | 0.000507 | 1 | 417,066 | NULL | 0 | 0 |
| ZEC | False | 0 | 0.2 | 6.874 | 0 | 5,000 | 17 | 0.75 | 7.055 |
| NUKE | False | 0 | 0.2 | 6.874 | 0 | 193,322 | 51 | 0.952 | 8.741 |
| WIF | False | 0 | 0.251 | 0.000893 | 1 | 115,027 | NULL | 0 | 0 |
| ISRAELI | False | 0 | 0.339 | 19.342 | 0 | 485,873.5 | 219 | 1 | 19.661 |

## Data problems (auto-detected)

- CHICKY: 52 trades where the trader is not the fee payer (compact rows label these 'other')
- KIKI: 12 trades where the trader is not the fee payer (compact rows label these 'other')
- SNEAKERS: 4 trades where the trader is not the fee payer (compact rows label these 'other')
- WATERFALL: 299 trades where the trader is not the fee payer (compact rows label these 'other')
- ALBERT: quoted in EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v (not SOL); SOL columns converted at ~73.824 quote/SOL
- ALBERT: 22 trades where the trader is not the fee payer (compact rows label these 'other')
- COBSON: no create transaction found in the window (create_ts later than the mint?)
- COBSON: quoted in EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v (not SOL); SOL columns converted at ~71.372 quote/SOL
- COBSON: 8 trades where the trader is not the fee payer (compact rows label these 'other')
- mouse: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- CREAMUS: 3 trades where the trader is not the fee payer (compact rows label these 'other')
- SEKOLAH: quoted in EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v (not SOL); SOL columns converted at ~77.677 quote/SOL
- SEKOLAH: 5 trades where the trader is not the fee payer (compact rows label these 'other')
- TYGR: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- HITLERHAUS: 24 trades where the trader is not the fee payer (compact rows label these 'other')
- LARD: 111 of 361 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- LARD: 7 trades where the trader is not the fee payer (compact rows label these 'other')
- PHOUSE: 33 trades where the trader is not the fee payer (compact rows label these 'other')
- BHOUSSSE: 103 of 291 transactions move no tokens (fee-only bot spam); n_tx_30m is inflated, n_wallets_30m counts traders only
- it: 310 trades where the trader is not the fee payer (compact rows label these 'other')
- NOOB: 61 trades where the trader is not the fee payer (compact rows label these 'other')
- MOONCAT: creator's first buy is 436 s after create_ts, not in the create tx
- MOONCAT: 28 trades where the trader is not the fee payer (compact rows label these 'other')
- all/in: 37 trades where the trader is not the fee payer (compact rows label these 'other')
- TOLYBOT: no create transaction found in the window (create_ts later than the mint?)
- TOLYBOT: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- ZEC: 7 trades where the trader is not the fee payer (compact rows label these 'other')
- NUKE: 35 trades where the trader is not the fee payer (compact rows label these 'other')
- WIF: no create transaction found in the window (create_ts later than the mint?)
- WIF: 1 trades where the trader is not the fee payer (compact rows label these 'other')
- ISRAELI: quoted in XsoCS1TfEyfFhfvj8EtZ528L3CaKBDBRqRapnBbDF2W (not SOL); SOL columns converted at ~0.133 quote/SOL
- ISRAELI: 1 trades where the trader is not the fee payer (compact rows label these 'other')
