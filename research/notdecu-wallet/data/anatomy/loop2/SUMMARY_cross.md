# SUMMARY_cross — cross-launch tables, loop 1 (Phase C, offline)



Built by `scripts/anatomy_cross.py` from the Phase A transaction files and the Phase B tables (see the script docstring). Trades are re-derived from account-level token balance changes with an extended market-account set; multiples are in quote units; SOL figures for non-SOL-quoted launches use the window's own router rate. `kol_*` was never fetched, so 'outside' = everyone but the creator and the 31 other members.

## Coverage

- 0xkgc: 47 rows in the launch list, 47 with trades (hits 7, misses 40); coverage >= 60 s: 47, >= 300 s: 47, full 1800 s: 46; non-SOL quote: 11 (SOL rate observable on 11); dev never bought: 0
- gampsito: 16 rows in the launch list, 16 with trades (hits 6, misses 10); coverage >= 60 s: 16, >= 300 s: 16, full 1800 s: 15; non-SOL quote: 1 (SOL rate observable on 1); dev never bought: 0
- hashbergers: 12 rows in the launch list, 12 with trades (hits 2, misses 10); coverage >= 60 s: 12, >= 300 s: 12, full 1800 s: 12; non-SOL quote: 0 (SOL rate observable on 0); dev never bought: 0
- jester: 27 rows in the launch list, 27 with trades (hits 7, misses 20); coverage >= 60 s: 27, >= 300 s: 27, full 1800 s: 27; non-SOL quote: 6 (SOL rate observable on 6); dev never bought: 0
- mitch: 11 rows in the launch list, 11 with trades (hits 2, misses 9); coverage >= 60 s: 11, >= 300 s: 11, full 1800 s: 11; non-SOL quote: 0 (SOL rate observable on 0); dev never bought: 6
- trades in the cache: 106108 across 113 launches; member-launch rows: 29 (26 with a buy)

## 1. Member graph (creator excluded on his own launches; entry = first buy, s after create)

Columns: launches bought per launcher, hits among them, median/min entry lag, median first-buy SOL and per-launch SOL, share of bought launches with any sell inside the observed window, median hold (first sell − first buy), realized net SOL (sells − buys, unrealized remainder counted at 0) and marked net SOL (remainder valued at the window's last 10-s buy VWAP), over launches where SOL is computable. `*` marks hits in the launch list; the 3 truncated slingoor hits and the LaunchLab launches shorten the observable window (n_trunc).

| username | n_launches_bought | n_0xkgc | n_gampsito | n_hashbergers | n_jester | n_mitch | n_hits | n_nonhits | med_entry_s | min_entry_s | med_entry_mult_vs_dev | med_first_buy_sol | med_buy_sol_per_launch | total_buy_sol | share_sold_in_window | med_hold_s | n_closed_in_window | net_sol_realized | net_sol_marked | n_sol_computable | n_truncated_after_buy | n_sell_only | tags |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| hashbergers | 7 | 0 | 0 | 0 | 7 | 0 | 4 | 3 | 110 | 6 | 2.447 | 1.858 | 1.956 | 15.508 | 0.286 | 386 | 1 | -9.562 | 10.211 | 7 | 0 | 0 | sandwich_bot,axiom,padre |
| 0xPromiser | 7 | 6 | 1 | 0 | 0 | 0 | 2 | 5 | 335 | 48 | 2.942 | 0.296 | 0.68 | 5.23 | 0.429 | 432 | 2 | 2.135 | 4.465 | 7 | 1 | 3 |  |
| trenchdigger | 4 | 2 | 1 | 1 | 0 | 0 | 3 | 1 | 627 | 38 | 5.848 | 1.439 | 1.933 | 7.822 | 1 | 17 | 3 | -1.681 | 1.6 | 4 | 1 | 0 | launchpad_smart |
| slingoor | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 2 | 242.5 | 169 | 2.147 | 12.337 | 17.275 | 34.55 | 1 | 13 | 2 | 28.8 | 28.8 | 2 | 0 | 0 | arbitrager,axiom,top_dev,top_renamed,top_followed |
| stellanyang | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 2 | 1,001 | 894 | 6.316 | 1.48 | 1.48 | 2.96 | 0 | NULL | 0 | -2.96 | -1.743 | 2 | 0 | 0 | bluechip_owner |
| SleepyyMike | 2 | 2 | 0 | 0 | 0 | 0 | 0 | 2 | 1,039 | 516 | 6.069 | 0.368 | 0.615 | 1.23 | 0.5 | 726 | 1 | -0.738 | -0.505 | 2 | 0 | 0 | gmgn_go,gmgn |
| retardmode | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 1 | 424 | 424 | 4.011 | 2.956 | 2.956 | 2.956 | 1 | 12 | 1 | 0.149 | 0.149 | 1 | 0 | 0 | top_dev |
| LowiqdegN | 1 | 0 | 0 | 1 | 0 | 0 | 1 | 0 | 1,557 | 1,557 | 44.628 | 0.991 | 0.991 | 0.991 | 0 | NULL | 0 | -0.991 | 0.218 | 1 | 0 | 0 |  |
| 0xkgc | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | arbitrager,padre |
| Fabricci | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 |  |
| MidCurveMortal | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | gmgn,gmgn_go |
| TMH | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | arbitrager,padre |
| agentpuffle | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | axiom |
| alpha_co | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | arbitrager |
| b69 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | trojan |
| badattrading | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | smart_degen,gmgn_go,top_followed,gmgn |
| baseddom | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | arbitrager |
| bsol_x | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 |  |
| gampsito | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | launchpad_smart,axiom,arbitrager |
| hoeleeshiet | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 |  |
| ibuycoin | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | gmgn,arbitrager,padre,gmgn_go |
| ibuyrunners | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | axiom |
| jester | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | axiom,kol,wash_trader,gmgn_go,gmgn,arbitrager,padre,top_followed |
| kanpai | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | arbitrager |
| lvvpumpy | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | padre |
| mitch | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | bluechip_owner |
| moonpie666 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 |  |
| pumpguy__ | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | arbitrager |
| rohwhale | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | trojan |
| trenchdiga | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 |  |
| usurp | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 |  |
| waynecapital | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | axiom,smart_degen,padre,arbitrager |

Launches bought per member (symbol, `*` = hit, @ first-buy second):

- hashbergers: HITLERHAUS@6.0s,KIKI*@13.0s,PHOUSE@16.0s,NOOB@110.0s,DIRECTOR*@206.0s,CHICKY*@347.0s,SNEAKERS*@949.0s
- 0xPromiser: ats@48.0s,SlowRogan@60.0s,Hunter*@79.0s,fries@335.0s,Biz*@552.0s,duve@769.0s,CRIME@1021.0s
- trenchdigger: PINU*@38.0s,Biz*@402.0s,1trump@852.0s,BIKESON*@972.0s
- slingoor: CRIME@169.0s,ats@316.0s
- stellanyang: CRIME@894.0s,ktw@1108.0s
- SleepyyMike: ktw@516.0s,RIPASS@1562.0s
- retardmode: fries@424.0s
- LowiqdegN: PINU*@1557.0s

Members never seen buying in any window: 0xkgc, Fabricci, MidCurveMortal, TMH, agentpuffle, alpha_co, b69, badattrading, baseddom, bsol_x, gampsito, hoeleeshiet, ibuycoin, ibuyrunners, jester, kanpai, lvvpumpy, mitch, moonpie666, pumpguy__, rohwhale, trenchdiga, usurp, waynecapital

### Member positions on hits (one row per member × hit)

| dev | symbol | username | first_buy_s | entry_mult_vs_dev | first_buy_sol | buy_sol | buy_supply_share | sold | first_sell_s | hold_s | sold_share | net_sol_realized | net_sol_marked | coverage_s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0xkgc | BIKESON | trenchdigger | 972 | 2.163 | 1.89 | 1.89 | 0.018 | True | 1,080 | 108 | 1 | -0.157 | -0.157 | 1800 |
| 0xkgc | Hunter | 0xPromiser | 79 | 2.942 | 0.01 | 0.01 | 0.000113 | False | NULL | NULL | 0 | -0.01 | 0.028 | 1800 |
| gampsito | Biz | trenchdigger | 402 | 7.19 | 1.975 | 1.975 | 0.009 | True | 409 | 7 | 1 | 0.027 | 0.027 | 1070 |
| gampsito | Biz | 0xPromiser | 552 | 7.504 | 0.296 | 1.385 | 0.003 | True | 819 | 267 | 0.481 | -0.483 | 1.006 | 1070 |
| hashbergers | PINU | trenchdigger | 38 | 7.964 | 0.988 | 2.969 | 0.004 | True | 65 | 27 | 0.673 | -1.612 | 1.668 | 1800 |
| hashbergers | PINU | LowiqdegN | 1,557 | 44.628 | 0.991 | 0.991 | 0.000424 | False | NULL | NULL | 0 | -0.991 | 0.218 | 1800 |
| jester | CHICKY | hashbergers | 347 | 5.244 | 1.858 | 3.618 | 0.021 | True | 1,030 | 683 | 1 | 0.127 | 0.127 | 1800 |
| jester | DIRECTOR | hashbergers | 206 | 1.432 | 0.978 | 1.467 | 0.036 | False | NULL | NULL | 0 | -1.467 | 0.155 | 1800 |
| jester | KIKI | hashbergers | 13 | 2.447 | 0.933 | 0.933 | 0.012 | False | NULL | NULL | 0 | -0.933 | 3.824 | 1800 |
| jester | SNEAKERS | hashbergers | 949 | 3.318 | 0.978 | 1.027 | 0.01 | False | NULL | NULL | 0 | -1.027 | 0.2 | 1800 |

### Member positions on misses

| dev | symbol | username | first_buy_s | entry_mult_vs_dev | first_buy_sol | buy_sol | sold | first_sell_s | hold_s | sold_share | net_sol_realized | net_sol_marked | coverage_s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0xkgc | 1trump | trenchdigger | 852 | 4.506 | 0.988 | 0.988 | True | 857 | 5 | 1 | 0.062 | 0.062 | 1800 |
| 0xkgc | CRIME | slingoor | 169 | 1.901 | 14.797 | 14.797 | True | 189 | 20 | 1 | 20.547 | 20.547 | 1800 |
| 0xkgc | CRIME | stellanyang | 894 | 10.247 | 1.972 | 1.972 | False | NULL | NULL | 0 | -1.972 | -1.466 | 1800 |
| 0xkgc | CRIME | 0xPromiser | 1,021 | 9.241 | 0.984 | 1.97 | True | 1,453 | 432 | 1 | 0.341 | 0.341 | 1800 |
| 0xkgc | RIPASS | SleepyyMike | 1,562 | 8.127 | 0.242 | 0.242 | False | NULL | NULL | 0 | -0.242 | -0.009 | 1800 |
| 0xkgc | SlowRogan | 0xPromiser | 60 | 2.021 | 0.099 | 0.099 | False | NULL | NULL | 0 | -0.099 | -0.011 | 1800 |
| 0xkgc | ats | 0xPromiser | 48 | 2.101 | 0.198 | 0.198 | False | NULL | NULL | 0 | -0.198 | -0.008 | 1800 |
| 0xkgc | ats | slingoor | 316 | 2.393 | 9.877 | 19.753 | True | 322 | 6 | 1 | 8.253 | 8.253 | 1800 |
| 0xkgc | duve | 0xPromiser | 769 | 3.748 | 0.889 | 0.889 | False | NULL | NULL | 0 | -0.889 | -0.362 | 1800 |
| 0xkgc | fries | 0xPromiser | 335 | 1.769 | 0.68 | 0.68 | True | 1,203 | 868 | 1 | 3.472 | 3.472 | 1800 |
| 0xkgc | fries | retardmode | 424 | 4.011 | 2.956 | 2.956 | True | 436 | 12 | 1 | 0.149 | 0.149 | 1800 |
| 0xkgc | ktw | SleepyyMike | 516 | 4.011 | 0.494 | 0.988 | True | 1,242 | 726 | 1 | -0.496 | -0.496 | 1800 |
| 0xkgc | ktw | stellanyang | 1,108 | 2.385 | 0.988 | 0.988 | False | NULL | NULL | 0 | -0.988 | -0.277 | 1800 |
| jester | HITLERHAUS | hashbergers | 6 | 1.925 | 1.956 | 1.956 | False | NULL | NULL | 0 | -1.956 | 1.374 | 1800 |
| jester | NOOB | hashbergers | 110 | 3.055 | 2.963 | 3.062 | False | NULL | NULL | 0 | -3.062 | 3.631 | 1800 |
| jester | PHOUSE | hashbergers | 16 | 1.997 | 1.975 | 3.447 | True | 105 | 89 | 0.514 | -1.246 | 0.899 | 1800 |

## 2. Launcher fingerprints

### 0xkgc

| metric | all n | all med [p25, p75] | hits n | hits med [p25, p75] | misses n | misses med [p25, p75] |
|---|---|---|---|---|---|---|
| dev_supply_share | 47 | 0.034 [0.034, 0.066] | 7 | 0.066 [0.05, 0.081] | 40 | 0.034 [0.034, 0.057] |
| dev_first_buy_sol | 47 | 0.992 [0.992, 1.981] | 7 | 1.981 [1.486, 2.886] | 40 | 0.992 [0.992, 1.823] |
| dev_same_slot_buyers | 47 | 2 [1, 3.5] | 7 | 2 [0.5, 2] | 40 | 2 [1, 4] |
| dev_fee_lamports_med | 47 | 452,500 [398,353.25, 505,000] | 7 | 400,000 [27,714.5, 452,500] | 40 | 452,500 [400,000, 505,000] |
| dev_fee_first_tx | 47 | 505,000 [35,000, 505,000] | 7 | 505,000 [35,000, 505,000] | 40 | 505,000 [180,479, 505,000] |
| dev_first_sell_s | 25 | 738 [387, 818] | 4 | 673 [503, 900] | 21 | 738 [343, 802] |
| dev_sold_share_30m | 46 | 0.15 [0, 1] | 6 | 0.072 [0, 0.153] | 40 | 0.23 [0, 1] |
| dev_sell_sol_30m | 46 | 0.897 [0, 1.312] | 6 | 1.731 [0, 3.723] | 40 | 0.897 [0, 1.242] |
| dev_sold_share_60s | 47 | 0 [0, 0] | 7 | 0 [0, 0] | 40 | 0 [0, 0] |
| dev_sold_share_300s | 47 | 0 [0, 0] | 7 | 0 [0, 0] | 40 | 0 [0, 0] |
| grad_s | 47 | 1,765 [1,536, 1,794] | 7 | 1,798 [1,430, 1,799] | 40 | 1,762 [1,541, 1,792.25] |
| peak10_mult | 47 | 3.289 [2.437, 7.066] | 7 | 9.94 [5.871, 13.467] | 40 | 3.16 [2.283, 6.387] |
| peak10_ts_s | 47 | 620 [435, 955] | 7 | 950 [780, 1,205] | 40 | 550 [397.5, 907.5] |
| sol_in_1m | 47 | 17.171 [10.148, 24.553] | 7 | 22.097 [19.648, 24.553] | 40 | 15.471 [9.561, 25.466] |
| sol_in_5m | 47 | 27.213 [15.796, 63.745] | 7 | 58.961 [35.926, 86.779] | 40 | 24.472 [14.117, 57.465] |
| n_wallets_1m | 47 | 40 [25.5, 58.5] | 7 | 38 [35.5, 51.5] | 40 | 40 [23, 60] |
| n_wallets_5m | 47 | 57 [48, 149] | 7 | 101 [67.5, 173.5] | 40 | 56 [44.75, 146.5] |

| count | all | hits | misses |
|---|---|---|---|
| n_launches | 47 | 7 | 40 |
| n_dev_sold_in_window | 25 | 4 | 21 |
| n_dev_sold_by_60s | 1 | 0 | 1 |
| n_dev_sold_by_300s | 4 | 0 | 4 |
| n_non_sol_quote | 11 | 3 | 8 |
| n_graduated_in_window | 47 | 7 | 40 |
| n_graduated_by_60s | 0 | 0 | 0 |
| n_dev_buy_in_create_slot | 47 | 7 | 40 |
| launchpad:Pump.fun | 40 | 5 | 35 |
| launchpad:stonkfun | 7 | 2 | 5 |

Launch hour (UTC), all launches in the list (hits in brackets): 00h: 1 (0), 01h: 1 (1), 02h: 2 (1), 03h: 2 (0), 04h: 2 (0), 05h: 3 (1), 06h: 3 (0), 07h: 1 (0), 08h: 1 (0), 10h: 1 (0), 11h: 2 (1), 12h: 1 (0), 13h: 1 (0), 14h: 4 (0), 15h: 2 (0), 16h: 3 (0), 17h: 4 (1), 18h: 1 (0), 19h: 4 (2), 20h: 4 (0), 21h: 4 (0)

Weekday (UTC): Fri 2, Mon 4, Sat 6, Sun 2, Thu 15, Tue 1, Wed 17
- hour_utc: n=47 median=14 p25=6 p75=18.5 min=0 max=21 (distribution of the UTC hour of creation)
- gap_between_launches_h: n=46 median=2.647 p25=1.134 p75=7.195 min=0.395 max=48.583 (hours between consecutive launches)
- book_bundler_rate: n=47 median=0 p25=0 p75=0 min=0 max=0.203 (dev_tokens.bundler_rate)
- span: 47 launches over 12.477 days (first to last in the list)
- gaps < 1 h: 10; gaps < 24 h: 44

### gampsito

| metric | all n | all med [p25, p75] | hits n | hits med [p25, p75] | misses n | misses med [p25, p75] |
|---|---|---|---|---|---|---|
| dev_supply_share | 16 | 0.164 [0.152, 0.177] | 6 | 0.152 [0.152, 0.171] | 10 | 0.177 [0.152, 0.177] |
| dev_first_buy_sol | 16 | 5.434 [4.94, 5.928] | 6 | 4.94 [4.94, 5.681] | 10 | 5.928 [4.94, 5.928] |
| dev_same_slot_buyers | 16 | 6.5 [4.75, 8.25] | 6 | 7 [6.25, 7.75] | 10 | 5.5 [3.25, 11] |
| dev_fee_lamports_med | 16 | 63,718.25 [50,663, 95,968.75] | 6 | 90,480.5 [59,671.5, 774,775] | 10 | 55,087.25 [47,147.75, 69,049.75] |
| dev_fee_first_tx | 16 | 5,000 [5,000, 5,000] | 6 | 5,000 [5,000, 5,000] | 10 | 5,000 [5,000, 5,000] |
| dev_first_sell_s | 16 | 2 [1, 4] | 6 | 3 [1.25, 4] | 10 | 2 [1, 3.75] |
| dev_sold_share_30m | 15 | 1 [1, 1] | 5 | 1 [0.989, 1] | 10 | 1 [1, 1] |
| dev_sell_sol_30m | 15 | 9.203 [7.358, 13.873] | 5 | 10.836 [9.203, 14.582] | 10 | 8.178 [7.348, 13.082] |
| dev_sold_share_60s | 16 | 1 [1, 1] | 6 | 1 [1, 1] | 10 | 1 [1, 1] |
| dev_sold_share_300s | 16 | 1 [1, 1] | 6 | 1 [1, 1] | 10 | 1 [1, 1] |
| grad_s | 16 | 790 [545.25, 1,655.5] | 6 | 711.5 [604.25, 1,550.75] | 10 | 900 [451.5, 1,498.75] |
| peak10_mult | 16 | 1.949 [1.38, 6.37] | 6 | 5.495 [2.017, 16.118] | 10 | 1.687 [1.4, 2.374] |
| peak10_ts_s | 16 | 10 [0, 512.5] | 6 | 415 [97.5, 912.5] | 10 | 5 [0, 130] |
| sol_in_1m | 16 | 100.999 [36.511, 120.01] | 6 | 109.51 [49.635, 122.487] | 10 | 70.448 [37.931, 114.898] |
| sol_in_5m | 16 | 113.838 [36.511, 197.271] | 6 | 181.607 [68.79, 224.235] | 10 | 75.73 [37.958, 124.86] |
| n_wallets_1m | 16 | 142.5 [51, 177] | 6 | 154 [57, 170.75] | 10 | 109.5 [58.25, 172.5] |
| n_wallets_5m | 16 | 173.5 [51, 272.5] | 6 | 240 [75.75, 313.5] | 10 | 121.5 [58.75, 209] |

| count | all | hits | misses |
|---|---|---|---|
| n_launches | 16 | 6 | 10 |
| n_dev_sold_in_window | 16 | 6 | 10 |
| n_dev_sold_by_60s | 16 | 6 | 10 |
| n_dev_sold_by_300s | 16 | 6 | 10 |
| n_non_sol_quote | 1 | 0 | 1 |
| n_graduated_in_window | 16 | 6 | 10 |
| n_graduated_by_60s | 0 | 0 | 0 |
| n_dev_buy_in_create_slot | 16 | 6 | 10 |
| launchpad:Pump.fun | 16 | 6 | 10 |

Launch hour (UTC), all launches in the list (hits in brackets): 08h: 3 (1), 10h: 2 (1), 11h: 2 (1), 13h: 1 (0), 15h: 2 (0), 19h: 2 (2), 20h: 3 (1), 23h: 1 (0)

Weekday (UTC): Sat 1, Sun 1, Thu 9, Tue 2, Wed 3
- hour_utc: n=16 median=14 p25=10 p75=19.25 min=8 max=23 (distribution of the UTC hour of creation)
- gap_between_launches_h: n=15 median=11.781 p25=3.081 p75=105.613 min=0.04 max=609.915 (hours between consecutive launches)
- book_bundler_rate: n=16 median=0 p25=0 p75=0.00025 min=0 max=0.018 (dev_tokens.bundler_rate)
- span: 16 launches over 49.355 days (first to last in the list)
- gaps < 1 h: 3; gaps < 24 h: 9

### hashbergers

| metric | all n | all med [p25, p75] | hits n | hits med [p25, p75] | misses n | misses med [p25, p75] |
|---|---|---|---|---|---|---|
| dev_supply_share | 12 | 0.034 [0.034, 0.041] | 2 | 0.251 [0.126, 0.375] | 10 | 0.034 [0.034, 0.034] |
| dev_first_buy_sol | 12 | 0.989 [0.989, 1.187] | 2 | 13.121 [6.571, 19.67] | 10 | 0.989 [0.989, 0.989] |
| dev_same_slot_buyers | 12 | 1 [0, 3] | 2 | 5.5 [2.75, 8.25] | 10 | 1 [0, 2.5] |
| dev_fee_lamports_med | 12 | 193,981.25 [71,887.75, 209,324.25] | 2 | 313,194 [252,559, 373,829] | 10 | 146,860 [65,663.25, 205,256.75] |
| dev_fee_first_tx | 12 | 200,596 [110,025.5, 388,804.75] | 2 | 98,462 [51,731, 145,193] | 10 | 293,953 [141,917.25, 396,912.25] |
| dev_first_sell_s | 10 | 10 [9, 12.75] | 0 | NULL [NULL, NULL] | 10 | 10 [9, 12.75] |
| dev_sold_share_30m | 12 | 1 [1, 1] | 2 | 0 [0, 0] | 10 | 1 [1, 1] |
| dev_sell_sol_30m | 12 | 1.097 [0.78, 1.453] | 2 | 0 [0, 0] | 10 | 1.177 [1.016, 1.953] |
| dev_sold_share_60s | 12 | 1 [0.888, 1] | 2 | 0 [0, 0] | 10 | 1 [1, 1] |
| dev_sold_share_300s | 12 | 1 [0.888, 1] | 2 | 0 [0, 0] | 10 | 1 [1, 1] |
| grad_s | 12 | 712.5 [528, 826] | 2 | 655 [594.5, 715.5] | 10 | 712.5 [525.25, 920] |
| peak10_mult | 12 | 1.282 [1.031, 2.821] | 2 | 38.399 [30.237, 46.561] | 10 | 1.139 [1.024, 1.738] |
| peak10_ts_s | 12 | 40 [0, 305] | 2 | 1,335 [1,117.5, 1,552.5] | 10 | 0 [0, 87.5] |
| sol_in_1m | 12 | 6.477 [3.678, 13.931] | 2 | 120.496 [70.344, 170.649] | 10 | 6.053 [2.741, 7.031] |
| sol_in_5m | 12 | 11.251 [5.231, 25.046] | 2 | 310.806 [169.334, 452.278] | 10 | 10.199 [3.258, 15.923] |
| n_wallets_1m | 12 | 10 [4.75, 31.75] | 2 | 94 [74.5, 113.5] | 10 | 7.5 [4.25, 13.75] |
| n_wallets_5m | 12 | 26.5 [4.75, 58] | 2 | 288 [180.5, 395.5] | 10 | 14.5 [4.25, 35.5] |

| count | all | hits | misses |
|---|---|---|---|
| n_launches | 12 | 2 | 10 |
| n_dev_sold_in_window | 10 | 0 | 10 |
| n_dev_sold_by_60s | 10 | 0 | 10 |
| n_dev_sold_by_300s | 10 | 0 | 10 |
| n_non_sol_quote | 0 | 0 | 0 |
| n_graduated_in_window | 12 | 2 | 10 |
| n_graduated_by_60s | 0 | 0 | 0 |
| n_dev_buy_in_create_slot | 12 | 2 | 10 |
| launchpad:Pump.fun | 12 | 2 | 10 |

Launch hour (UTC), all launches in the list (hits in brackets): 00h: 1 (0), 01h: 1 (0), 02h: 1 (0), 03h: 1 (0), 06h: 1 (0), 09h: 1 (0), 20h: 4 (1), 22h: 1 (1), 23h: 1 (0)

Weekday (UTC): Fri 3, Mon 1, Sat 1, Sun 3, Thu 2, Tue 1, Wed 1
- hour_utc: n=12 median=14.5 p25=2.75 p75=20 min=0 max=23 (distribution of the UTC hour of creation)
- gap_between_launches_h: n=11 median=46.347 p25=20.913 p75=428.051 min=0.151 max=3,251.401 (hours between consecutive launches)
- book_bundler_rate: n=12 median=0 p25=0 p75=0.016 min=0 max=0.517 (dev_tokens.bundler_rate)
- span: 12 launches over 214.92 days (first to last in the list)
- gaps < 1 h: 1; gaps < 24 h: 4

### jester

| metric | all n | all med [p25, p75] | hits n | hits med [p25, p75] | misses n | misses med [p25, p75] |
|---|---|---|---|---|---|---|
| dev_supply_share | 27 | 0.1 [0.05, 0.2] | 7 | 0.1 [0.076, 0.205] | 20 | 0.122 [0.034, 0.2] |
| dev_first_buy_sol | 27 | 3.102 [1.736, 6.874] | 7 | 3.083 [2.289, 9.131] | 20 | 3.941 [1.493, 6.874] |
| dev_same_slot_buyers | 27 | 2 [0, 3] | 7 | 0 [0, 3] | 20 | 2 [0, 2.5] |
| dev_fee_lamports_med | 27 | 502,500 [258,630.75, 881,390] | 7 | 356,222.5 [164,094.75, 505,000] | 20 | 502,500 [314,580.5, 1e+06] |
| dev_fee_first_tx | 27 | 35,000 [6,877.5, 430,000] | 7 | 8,500 [8,500, 505,000] | 20 | 35,000 [5,000, 355,000] |
| dev_first_sell_s | 21 | 26 [16, 44] | 5 | 23 [16, 58] | 16 | 27 [16.5, 38] |
| dev_sold_share_30m | 27 | 1 [0.4, 1] | 7 | 1 [0.384, 1] | 20 | 0.976 [0.5, 1] |
| dev_sell_sol_30m | 27 | 3.368 [0.013, 8.495] | 7 | 2.915 [0.517, 7.515] | 20 | 4.526 [0.013, 8.372] |
| dev_sold_share_60s | 26 | 0.777 [0, 1] | 7 | 0.292 [0, 0.884] | 19 | 0.793 [0.25, 1] |
| dev_sold_share_300s | 26 | 0.925 [0.457, 1] | 7 | 0.767 [0.204, 1] | 19 | 1 [0.675, 1] |
| grad_s | 27 | 1,561 [962, 1,781.5] | 7 | 1,752 [1,382, 1,789.5] | 20 | 1,443 [836.5, 1,781.25] |
| peak10_mult | 27 | 3.312 [1.923, 5.689] | 7 | 8.902 [4.732, 11.669] | 20 | 2.146 [1.668, 4.064] |
| peak10_ts_s | 27 | 430 [80, 1,025] | 7 | 1,300 [840, 1,670] | 20 | 225 [20, 610] |
| sol_in_1m | 27 | 36.223 [28.079, 68.343] | 7 | 48.098 [33.446, 91.296] | 20 | 34.744 [28.088, 60.896] |
| sol_in_5m | 27 | 54.757 [39.379, 106.122] | 7 | 98.244 [47.37, 172.237] | 20 | 52.414 [37.609, 95.681] |
| n_wallets_1m | 27 | 46 [27, 80.5] | 7 | 50 [25.5, 83] | 20 | 44 [28.5, 80.25] |
| n_wallets_5m | 27 | 69 [38.5, 134.5] | 7 | 69 [42, 157.5] | 20 | 70.5 [38.75, 113.25] |

| count | all | hits | misses |
|---|---|---|---|
| n_launches | 27 | 7 | 20 |
| n_dev_sold_in_window | 21 | 5 | 16 |
| n_dev_sold_by_60s | 18 | 4 | 14 |
| n_dev_sold_by_300s | 20 | 5 | 15 |
| n_non_sol_quote | 6 | 2 | 4 |
| n_graduated_in_window | 27 | 7 | 20 |
| n_graduated_by_60s | 1 | 0 | 1 |
| n_dev_buy_in_create_slot | 26 | 7 | 19 |
| launchpad:Pump.fun | 25 | 7 | 18 |
| launchpad: | 1 | 0 | 1 |
| launchpad:stonkfun | 1 | 0 | 1 |

Launch hour (UTC), all launches in the list (hits in brackets): 00h: 2 (0), 01h: 2 (1), 02h: 2 (0), 03h: 1 (0), 04h: 3 (1), 14h: 1 (0), 16h: 4 (1), 17h: 2 (0), 18h: 1 (0), 19h: 2 (0), 20h: 1 (0), 21h: 2 (1), 22h: 2 (2), 23h: 2 (1)

Weekday (UTC): Fri 3, Mon 3, Sun 5, Thu 4, Tue 9, Wed 3
- hour_utc: n=27 median=16 p25=3.5 p75=19.5 min=0 max=23 (distribution of the UTC hour of creation)
- gap_between_launches_h: n=26 median=70.48 p25=23.163 p75=192.331 min=0.36 max=3,176.935 (hours between consecutive launches)
- book_bundler_rate: n=27 median=0 p25=0 p75=0 min=0 max=0.023 (dev_tokens.bundler_rate)
- span: 27 launches over 295.149 days (first to last in the list)
- gaps < 1 h: 1; gaps < 24 h: 8

### mitch

| metric | all n | all med [p25, p75] | hits n | hits med [p25, p75] | misses n | misses med [p25, p75] |
|---|---|---|---|---|---|---|
| dev_supply_share | 5 | 0.554 [0.442, 0.731] | 1 | 0.792 [0.792, 0.792] | 4 | 0.498 [0.356, 0.598] |
| dev_first_buy_sol | 5 | 32.001 [21.001, 64.001] | 1 | 84.682 [84.682, 84.682] | 4 | 26.501 [16.501, 40.001] |
| dev_same_slot_buyers | 5 | 0 [0, 0] | 1 | 1 [1, 1] | 4 | 0 [0, 0] |
| dev_fee_lamports_med | 8 | 114,471 [52,500, 500,000] | 2 | 45,000 [37,500, 52,500] | 6 | 321,971 [99,735.5, 500,000] |
| dev_fee_first_tx | 5 | 85,000 [30,000, 143,942] | 1 | 30,000 [30,000, 30,000] | 4 | 114,471 [71,250, 317,540] |
| dev_first_sell_s | 1 | 39 [39, 39] | 1 | 39 [39, 39] | 0 | NULL [NULL, NULL] |
| dev_sold_share_30m | 5 | 0 [0, 0] | 1 | 0 [0, 0] | 4 | 0 [0, 0] |
| dev_sell_sol_30m | 11 | 0 [0, 0] | 2 | 29.638 [14.819, 44.457] | 9 | 0 [0, 0] |
| dev_sold_share_60s | 5 | 0 [0, 0] | 1 | 0 [0, 0] | 4 | 0 [0, 0] |
| dev_sold_share_300s | 5 | 0 [0, 0] | 1 | 0 [0, 0] | 4 | 0 [0, 0] |
| grad_s | 11 | 219 [65.5, 498] | 2 | 546.5 [273.75, 819.25] | 9 | 219 [78, 418] |
| peak10_mult | 5 | 4.69 [2.455, 7.11] | 1 | 1.591 [1.591, 1.591] | 4 | 5.9 [4.131, 7.493] |
| peak10_ts_s | 5 | 410 [150, 410] | 1 | 0 [0, 0] | 4 | 410 [345, 450] |
| sol_in_1m | 11 | 77.409 [63.763, 124.112] | 2 | 112.614 [83.914, 141.313] | 9 | 77.409 [72.311, 92.697] |
| sol_in_5m | 11 | 155.529 [91.118, 164.312] | 2 | 116.285 [89.421, 143.149] | 9 | 155.529 [92.697, 158.612] |
| n_wallets_1m | 11 | 29 [15, 41.5] | 2 | 22 [13, 31] | 9 | 29 [20, 43] |
| n_wallets_5m | 11 | 33 [23, 50] | 2 | 26 [15, 37] | 9 | 33 [24, 52] |

| count | all | hits | misses |
|---|---|---|---|
| n_launches | 11 | 2 | 9 |
| n_dev_sold_in_window | 1 | 1 | 0 |
| n_dev_sold_by_60s | 0 | 0 | 0 |
| n_dev_sold_by_300s | 0 | 0 | 0 |
| n_non_sol_quote | 0 | 0 | 0 |
| n_graduated_in_window | 11 | 2 | 9 |
| n_graduated_by_60s | 3 | 1 | 2 |
| n_dev_buy_in_create_slot | 5 | 1 | 4 |
| launchpad:Pump.fun | 11 | 2 | 9 |

Launch hour (UTC), all launches in the list (hits in brackets): 02h: 3 (0), 11h: 1 (0), 16h: 1 (0), 18h: 2 (0), 19h: 2 (0), 20h: 1 (1), 21h: 1 (1)

Weekday (UTC): Fri 1, Mon 2, Sat 3, Thu 2, Tue 3
- hour_utc: n=11 median=18 p25=6.5 p75=19 min=2 max=21 (distribution of the UTC hour of creation)
- gap_between_launches_h: n=10 median=103.711 p25=27.677 p75=264.525 min=0.943 max=10,555.287 (hours between consecutive launches)
- book_bundler_rate: n=11 median=0 p25=0 p75=0 min=0 max=0.813 (dev_tokens.bundler_rate)
- span: 11 launches over 484.813 days (first to last in the list)
- gaps < 1 h: 1; gaps < 24 h: 3

### Per-launch dev fingerprint (both launchers)

| dev | symbol | hit | launchpad_platform | coverage_s | dev_supply_share | dev_first_buy_sol | dev_same_slot_buyers | dev_fee_first_tx | dev_fee_lamports_med | dev_first_sell_s | dev_sold_share_60s | dev_sold_share_300s | dev_sold_share_30m | grad_s | peak10_mult | peak10_ts_s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0xkgc | OG | False | Pump.fun | 1800 | 0.034 | 0.992 | 0 | 505,000 | 452,500 | 211 | 0 | 1 | 1 | 516 | 1.436 | 10 |
| 0xkgc | tradoor | False | Pump.fun | 1800 | 0.034 | 0.992 | 0 | 505,000 | 452,500 | 224 | 0 | 1 | 1 | 997 | 1.204 | 0 |
| 0xkgc | 1LEFT | False | Pump.fun | 1800 | 0.038 | 1.09 | 3 | 505,000 | 452,500 | 753 | 0 | 0 | 0.223 | 1,672 | 3.677 | 770 |
| 0xkgc | missooor | False | Pump.fun | 1800 | 0.034 | 0.992 | 3 | 505,000 | 452,500 | 1,611 | 0 | 0 | 1 | 1,640 | 1.787 | 500 |
| 0xkgc | madeitup | False | Pump.fun | 1800 | 0.034 | 0.992 | 0 | 505,000 | 505,000 | NULL | 0 | 0 | 0 | 1,799 | 2.393 | 620 |
| 0xkgc | topbuyer | False | Pump.fun | 1800 | 0.034 | 0.992 | 1 | 505,000 | 505,000 | NULL | 0 | 0 | 0 | 1,526 | 2.481 | 530 |
| 0xkgc | 1minute | False | Pump.fun | 1800 | 0.034 | 0.989 | 2 | 28,240 | 514,120 | 802 | 0 | 0 | 1 | 1,673 | 2.193 | 490 |
| 0xkgc | 1trump | False | Pump.fun | 1800 | 0.034 | 0.989 | 1 | 26,664 | 400,000 | 738 | 0 | 0 | 1 | 1,797 | 8 | 930 |
| 0xkgc | few | False | Pump.fun | 1800 | 0.034 | 0.989 | 1 | 27,753 | 400,000 | 763 | 0 | 0 | 1 | 1,775 | 7.163 | 760 |
| 0xkgc | SOLMOG | False | Pump.fun | 1800 | 0.034 | 0.992 | 2 | 505,000 | 505,000 | NULL | 0 | 0 | 0 | 1,792 | 4.184 | 570 |
| 0xkgc | ducknana | False | Pump.fun | 1800 | 0.034 | 0.992 | 1 | 505,000 | 400,000 | 777 | 0 | 0 | 0.437 | 1,227 | 15.103 | 1,430 |
| 0xkgc | SOLONLY | False | Pump.fun | 1800 | 0.034 | 0.992 | 1 | 505,000 | 505,000 | NULL | 0 | 0 | 0 | 1,546 | 1.763 | 470 |
| 0xkgc | happyegg | False | Pump.fun | 1800 | 0.034 | 0.992 | 5 | 505,000 | 452,500 | 873 | 0 | 0 | 1 | 1,462 | 3.289 | 500 |
| 0xkgc | ETH | False | Pump.fun | 1800 | 0.034 | 0.992 | 1 | 505,000 | 452,500 | 685 | 0 | 0 | 1 | 1,672 | 2.976 | 480 |
| 0xkgc | swingdog | False | Pump.fun | 1800 | 0.034 | 0.992 | 2 | 505,000 | 452,500 | 703 | 0 | 0 | 1 | 1,750 | 3.053 | 400 |
| 0xkgc | biip | False | Pump.fun | 1800 | 0.034 | 0.992 | 2 | 505,000 | 505,000 | NULL | 0 | 0 | 0 | 1,578 | 2.314 | 680 |
| 0xkgc | BOT | False | Pump.fun | 1800 | 0.034 | 0.989 | 3 | 5,000 | 502,500 | 36 | 1 | 1 | 1 | 1,279 | 1.545 | 20 |
| 0xkgc | initials | False | Pump.fun | 1800 | 0.034 | 0.989 | 3 | 228,972 | 1e+06 | NULL | 0 | 0 | 0 | 1,777 | 3.256 | 1,250 |
| 0xkgc | GOAT | False | Pump.fun | 1800 | 0.034 | 0.992 | 1 | 505,000 | 452,500 | 1,298 | 0 | 0 | 1 | 1,332 | 1.664 | 70 |
| 0xkgc | biketyson | True | Pump.fun | 1800 | 0.034 | 0.992 | 2 | 505,000 | 400,000 | 428 | 0 | 0 | 0.719 | 1,799 | 9.94 | 720 |
| 0xkgc | GAPE | False | Pump.fun | 1800 | 0.034 | 0.992 | 4 | 505,000 | 752,500 | 343 | 0 | 0 | 1 | 352 | 1.673 | 140 |
| 0xkgc | oversold | False | Pump.fun | 1800 | 0.034 | 0.992 | 3 | 505,000 | 452,500 | 784 | 0 | 0 | 1 | 1,765 | 3.029 | 500 |
| 0xkgc | IBRN | False | Pump.fun | 1800 | 0.034 | 0.992 | 4 | 505,000 | 505,000 | NULL | 0 | 0 | 0 | 1,776 | 2.927 | 510 |
| 0xkgc | Catiban | False | Pump.fun | 1800 | 0.034 | 0.992 | 3 | 505,000 | 752,500 | 915 | 0 | 0 | 1 | 1,224 | 1.86 | 290 |
| 0xkgc | MAC | False | stonkfun | 1800 | 0.047 | 1.429 | 1 | 35,000 | 35,000 | NULL | 0 | 0 | 0 | 125 | 1.145 | 40 |
| 0xkgc | ZUPERCYCLE | False | stonkfun | 1800 | 0.058 | 1.776 | 2 | 35,000 | 20,086 | NULL | 0 | 0 | 0 | 1,759 | 6.477 | 500 |
| 0xkgc | MelonMusk | True | Pump.fun | 1800 | 0.066 | 1.981 | 1 | 505,000 | 452,500 | 528 | 0 | 0 | 0.156 | 1,800 | 13.573 | 1,780 |
| 0xkgc | thewok | True | Pump.fun | 1800 | 0.034 | 0.991 | 2 | 505,000 | 505,000 | NULL | 0 | 0 | 0 | 1,735 | 3.031 | 1,170 |
| 0xkgc | BABYLMAO | False | stonkfun | 1800 | 0.09 | 5.595 | 0 | 35,000 | 17,852.5 | NULL | 0 | 0 | 0 | 1,754 | 2.494 | 1,710 |
| 0xkgc | Hunter | True | Pump.fun | 1800 | 0.066 | 1.981 | 0 | 505,000 | 452,500 | 1,146 | 0 | 0 | 0.145 | 1,125 | 16.956 | 1,240 |
| 0xkgc | duve | False | Pump.fun | 1800 | 0.034 | 0.991 | 6 | 505,000 | 452,500 | 387 | 0 | 0 | 0.25 | 1,793 | 6.97 | 900 |
| 0xkgc | AAPLTOP | False | stonkfun | 1800 | 0.091 | 2.897 | 3 | 35,000 | 3,370 | NULL | 0 | 0 | 0 | 1,798 | 6.357 | 1,280 |
| 0xkgc | Keanu | False | Pump.fun | 1800 | 0.06 | 1.778 | 6 | 5,000 | 42,173.5 | NULL | 0 | 0 | 0 | 1,800 | 6.641 | 1,340 |
| 0xkgc | fries | False | Pump.fun | 1800 | 0.048 | 1.96 | 0 | 605,000 | 306,781 | NULL | 0 | 0 | 0 | 1,795 | 8.066 | 1,340 |
| 0xkgc | CRIME | False | Pump.fun | 1800 | 0.049 | 2.039 | 0 | 605,000 | 605,000 | 555 | 0 | 0 | 0.461 | 1,792 | 12.531 | 710 |
| 0xkgc | fleaman | False | Pump.fun | 1800 | 0.051 | 1.486 | 0 | 505,000 | 505,000 | NULL | 0 | 0 | 0 | 1,799 | 4.085 | 960 |
| 0xkgc | dump | False | Pump.fun | 1800 | 0.036 | 1.455 | 0 | 605,000 | 605,000 | NULL | 0 | 0 | 0 | 1,788 | 2.811 | 390 |
| 0xkgc | CUM | False | Pump.fun | 1800 | 0.066 | 1.981 | 11 | 505,000 | 400,000 | 278 | 0 | 0.274 | 0.237 | 1,777 | 4.995 | 270 |
| 0xkgc | ats | False | Pump.fun | 1800 | 0.066 | 1.981 | 13 | 505,000 | 252,500 | NULL | 0 | 0 | 0 | 1,793 | 4.276 | 840 |
| 0xkgc | UNC | True | stonkfun | 845 | 0.091 | 2.894 | 5 | 35,000 | 20,429 | 818 | 0 | 0 | NULL | 845 | 13.36 | 840 |
| 0xkgc | ktw | False | Pump.fun | 1800 | 0.097 | 2.969 | 6 | 505,000 | 400,000 | 320 | 0 | 0 | 0.375 | 1,749 | 6.264 | 600 |
| 0xkgc | BIKESON | True | stonkfun | 1800 | 0.114 | 4.369 | 0 | 35,000 | 35,000 | NULL | 0 | 0 | 0 | 1,798 | 3.528 | 390 |
| 0xkgc | SlowRogan | False | Pump.fun | 1800 | 0.082 | 2.475 | 6 | 505,000 | 505,000 | NULL | 0 | 0 | 0 | 1,771 | 3.203 | 1,340 |
| 0xkgc | K-Train | False | Pump.fun | 1800 | 0.057 | 1.684 | 12 | 505,000 | 505,000 | NULL | 0 | 0 | 0 | 1,796 | 3.116 | 110 |
| 0xkgc | COMMUNISM | False | Pump.fun | 1800 | 0.066 | 1.956 | 1 | 393,413 | 396,706.5 | 1,169 | 0 | 0 | 0.5 | 1,790 | 7.961 | 640 |
| 0xkgc | ZEC | True | Pump.fun | 1800 | 0.071 | 2.878 | 2 | 11,000 | 11,000 | NULL | 0 | 0 | 0 | 1,799 | 8.215 | 950 |
| 0xkgc | RIPASS | False | stonkfun | 1800 | 0.088 | 2.754 | 6 | 35,000 | 35,000 | NULL | 0 | 0 | 0 | 1,800 | 8.936 | 1,590 |
| gampsito | PP | True | Pump.fun | 1800 | 0.152 | 4.94 | 8 | 5,000 | 1e+06 | 1 | 1 | 1 | 0.972 | 1,798 | 6.888 | 440 |
| gampsito | petcat | True | Pump.fun | 1800 | 0.177 | 5.928 | 6 | 5,000 | 1e+06 | 1 | 1 | 1 | 1 | 1,798 | 4.101 | 390 |
| gampsito | Polycat | True | Pump.fun | 1800 | 0.152 | 4.94 | 6 | 5,000 | 81,861 | 4 | 1 | 1 | 0.989 | 809 | 19.195 | 1,710 |
| gampsito | Biz | True | Pump.fun | 1070 | 0.125 | 3.953 | 7 | 5,000 | 52,275 | 2 | 1 | 1 | NULL | 614 | 27.53 | 1,070 |
| gampsito | Dancedoge | True | Pump.fun | 1800 | 0.201 | 6.916 | 7 | 5,000 | 51,429 | 5 | 1 | 1 | 1 | 225 | 1.322 | 0 |
| gampsito | ok | True | Pump.fun | 1800 | 0.152 | 4.94 | 9 | 5,000 | 99,100 | 4 | 1 | 1 | 1 | 601 | 1.192 | 0 |
| gampsito | mlem | False | Pump.fun | 1800 | 0.152 | 4.94 | 6 | 5,000 | 35,251 | 3 | 1 | 1 | 1 | 1,171 | 1.504 | 0 |
| gampsito | looong | False | Pump.fun | 1800 | 0.177 | 5.928 | 8 | 5,000 | 46,050 | 2 | 1 | 1 | 1 | 1,799 | 6.198 | 850 |
| gampsito | Shrekt | False | Pump.fun | 1800 | 0.201 | 6.916 | 18 | 5,000 | 67,999 | 1 | 1 | 1 | 1 | 1,029 | 1.871 | 0 |
| gampsito | HeHa | False | Pump.fun | 1800 | 0.152 | 4.94 | 2 | 5,000 | 50,441 | 1 | 1 | 1 | 1 | 221 | 1.434 | 0 |
| gampsito | OrgyInu | False | Pump.fun | 1800 | 0.177 | 5.928 | 2 | 5,000 | 69,400 | 1 | 1 | 0.999 | 1 | 1,608 | 2.027 | 170 |
| gampsito | hats | False | Pump.fun | 1800 | 0.152 | 4.94 | 4 | 5,000 | 94,925 | 1 | 1 | 1 | 1 | 378 | 1.355 | 10 |
| gampsito | Chimpi | False | Pump.fun | 1800 | 0.177 | 5.928 | 12 | 5,000 | 59,437.5 | 2 | 1 | 1 | 1 | 148 | 1.389 | 0 |
| gampsito | blep | False | Pump.fun | 1800 | 0.177 | 5.928 | 5 | 5,000 | 115,630 | 4 | 1 | 1 | 1 | 771 | 2.49 | 10 |
| gampsito | yap | False | Pump.fun | 1800 | 0.177 | 5.928 | 12 | 5,000 | 50,737 | 5 | 1 | 1 | 1 | 672 | 1.302 | 0 |
| gampsito | BTD | False | Pump.fun | 1800 | 0.086 | 3.744 | 3 | 5,000 | 14,925 | 4 | 1 | 1 | 1 | 1,800 | 7.7 | 730 |
| hashbergers | SCRAP | True | Pump.fun | 1800 | 0.000706 | 0.022 | 0 | 191,924 | 191,924 | NULL | 0 | 0 | 0 | 776 | 22.076 | 900 |
| hashbergers | RAPEHIM | False | Pump.fun | 1800 | 0.003 | 0.08 | 0 | 423,506 | 216,753 | 13 | 1 | 1 | 1 | 246 | 1.034 | 0 |
| hashbergers | PVE | False | Pump.fun | 1800 | 0.034 | 0.989 | 0 | 382,077 | 196,038.5 | 9 | 1 | 1 | 1 | 967 | 1.114 | 0 |
| hashbergers | PENGU | False | Pump.fun | 1800 | 0.034 | 0.989 | 0 | 205,829 | 206,848 | 8 | 1 | 1 | 1 | 650 | 1.163 | 0 |
| hashbergers | OBESE | False | Pump.fun | 1800 | 0.06 | 1.779 | 3 | 744,577 | 372,788.5 | 17 | 1 | 1 | 1 | 1,744 | 5.682 | 650 |
| hashbergers | AMIGA | False | Pump.fun | 1800 | 0.285 | 10.866 | 0 | 67,796 | 34,398 | 9 | 1 | 1 | 1 | 234 | 1 | 0 |
| hashbergers | OARFISH | False | Pump.fun | 1800 | 0.034 | 0.989 | 1 | 124,102 | 62,551 | 12 | 1 | 1 | 1 | 775 | 1.868 | 80 |
| hashbergers | KINDA | False | Pump.fun | 1800 | 0.034 | 0.989 | 3 | 384,751 | 75,000 | 10 | 1 | 1 | 1 | 571 | 1.85 | 190 |
| hashbergers | FLOAT | False | Pump.fun | 1800 | 0.034 | 0.989 | 1 | 195,363 | 97,681.5 | 10 | 1 | 1 | 1 | 779 | 1.021 | 0 |
| hashbergers | COMPUTA | False | Pump.fun | 1800 | 0.034 | 0.989 | 1 | 400,966 | 200,483 | 9 | 1 | 1 | 1 | 510 | 1.021 | 0 |
| hashbergers | piss | False | Pump.fun | 1800 | 0.034 | 0.989 | 3 | 57,840 | 50,000 | 24 | 0.551 | 0.551 | 1 | 1,757 | 1.401 | 90 |
| hashbergers | PINU | True | Pump.fun | 1800 | 0.5 | 26.22 | 11 | 5,000 | 434,464 | NULL | 0 | 0 | 0 | 534 | 54.723 | 1,770 |
| jester | DIRECTOR | True | Pump.fun | 1800 | 0.034 | 0.99 | 3 | 941,775 | 762,780 | 16 | 1 | 1 | 1 | 1,781 | 2.872 | 1,300 |
| jester | CHICKY | True | Pump.fun | 1800 | 0.066 | 1.977 | 0 | 8,500 | 323,939.5 | 15 | 1 | 1 | 1 | 1,800 | 10.857 | 650 |
| jester | KIKI | True | Pump.fun | 1800 | 0.1 | 3.083 | 3 | 8,500 | 356,222.5 | 63 | 0 | 1 | 1 | 1,798 | 12.481 | 1,790 |
| jester | SNEAKERS | True | Pump.fun | 1800 | 0.086 | 2.602 | 0 | 8,500 | 572 | 58 | 0.292 | 0.409 | 1 | 1,707 | 4.795 | 1,030 |
| jester | WATERFALL | True | Pump.fun | 1800 | 0.303 | 11.794 | 3 | 8,500 | 4,250 | NULL | 0 | 0 | 0 | 1,057 | 54.85 | 1,630 |
| jester | ALBERT | True | Pump.fun | 1800 | 0.107 | 6.468 | 0 | 505,000 | 505,000 | 23 | 0.767 | 0.767 | 0.767 | 1,752 | 4.67 | 300 |
| jester | COBSON | True | Pump.fun | 1800 | 0.766 | 149.968 | 0 | 505,000 | 505,000 | NULL | 0 | 0 | 0 | 354 | 8.902 | 1,710 |
| jester | mouse | False | Pump.fun | 1800 | 0.184 | 6.202 | 2 | 355,000 | 355,000 | 17 | 1 | 1 | 1 | 1,590 | 1.508 | 20 |
| jester | CREAMUS | False | Pump.fun | 1800 | 0.703 | 57.002 | 2 | 355,000 | 355,000 | NULL | 0 | 0 | 0 | 1,720 | 3.491 | 1,670 |
| jester | SEKOLAH | False | Pump.fun | 1800 | 0.028 | 1.496 | 0 | 10,000 | 5,000 | NULL | 0 | 0 | 0 | 1,785 | 2.222 | 280 |
| jester | JANICE | False | Pump.fun | 1800 | 0.000353 | 0.012 | 4 | 645,290 | 702,645 | 44 | 1 | 1 | 1 | 515 | 1.157 | 140 |
| jester | Jutsu | False | Pump.fun | 1800 | 0.000353 | 0.012 | 2 | 646,752 | 646,752 | NULL | 0 | 0 | 0 | 311 | 0.98 | 0 |
| jester | FLUFF | False | Pump.fun | 1800 | 0.1 | 3.102 | 2 | 5,255 | 5e+06 | 33 | 1 | 1 | 1 | 610 | 1.434 | 20 |
| jester | TYGR | False | Pump.fun | 1800 | 0.096 | 2.965 | 2 | 664,310 | 4e+06 | 18 | 1 | 1 | 1 | 1,012 | 1.913 | 240 |
| jester | HITLERHAUS | False | Pump.fun | 1800 | 0.066 | 1.977 | 1 | 148,523 | 1e+07 | 36 | 1 | 1 | 1 | 1,790 | 4.382 | 700 |
| jester | LARD | False | Pump.fun | 1800 | 0.000353 | 0.012 | 2 | 5,000 | 502,500 | 32 | 1 | 1 | 1 | 1,561 | 1.721 | 120 |
| jester | PHOUSE | False | Pump.fun | 1800 | 0.066 | 1.977 | 5 | 5,000 | 1e+06 | 9 | 0.6 | 0.6 | 0.6 | 1,782 | 5.175 | 640 |
| jester | BHOUSSSE | False | Pump.fun | 1800 | 0.034 | 0.989 | 6 | 5,000 | 502,500 | 11 | 1 | 1 | 1 | 1,176 | 2.152 | 40 |
| jester | it | False | Pump.fun | 1800 | 0.152 | 4.939 | 9 | 5,000 | 5e+06 | 8 | 1 | 0.837 | 0.795 | 422 | 13.262 | 430 |
| jester | NOOB | False | Pump.fun | 1800 | 0.152 | 4.94 | 2 | 47,393 | 1e+06 | 15 | 0.793 | 0.793 | 0.792 | 1,795 | 8.78 | 1,480 |
| jester | MOONCAT | False | Pump.fun | 1800 | 0.034 | 1.481 | 8 | 5e+06 | 1e+06 | 512 | NULL | NULL | 0.2 | 1,526 | 1.932 | 10 |
| jester | all/in | False | Pump.fun | 1800 | 0.791 | 83.952 | 0 | 25,890 | 25,890 | NULL | 0 | 0 | 0 | 13 | 6.203 | 470 |
| jester | TOLYBOT | False |  | 1800 | 0.143 | 4.781 | 0 | 35,000 | 417,066 | 28 | 0.787 | 1 | 1 | 1,789 | 3.312 | 10 |
| jester | ZEC | False | Pump.fun | 1800 | 0.2 | 6.874 | 0 | 5,000 | 5,000 | 17 | 0.75 | 0.75 | 0.75 | 1,360 | 2.014 | 1,020 |
| jester | NUKE | False | Pump.fun | 1800 | 0.2 | 6.874 | 0 | 5,000 | 193,322 | 51 | 0.5 | 0.85 | 0.952 | 1,781 | 3.957 | 600 |
| jester | WIF | False | stonkfun | 1800 | 0.251 | 9.541 | 0 | 35,000 | 115,027 | 26 | 0.85 | 1 | 1 | 912 | 2.139 | 10 |
| jester | ISRAELI | False | Pump.fun | 1800 | 0.339 | 19.342 | 0 | 53,000 | 485,873.5 | 219 | 0 | 1 | 1 | 1,283 | 1.481 | 210 |
| mitch | kai | False | Pump.fun | 1800 | 0.098 | 3.001 | 0 | 85,000 | 85,000 | NULL | 0 | 0 | 0 | 1,533 | 2.455 | 150 |
| mitch | glown | False | Pump.fun | 1800 | 0.442 | 21.001 | 0 | 30,000 | 30,000 | NULL | 0 | 0 | 0 | 578 | 8.644 | 570 |
| mitch | SOSA | False | Pump.fun | 1800 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 78 | NULL | NULL |
| mitch | BCC | False | Pump.fun | 1800 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 36 | NULL | NULL |
| mitch | mitch | True | Pump.fun | 1800 | NULL | NULL | NULL | NULL | 60,000 | 39 | NULL | NULL | NULL | 1,092 | NULL | NULL |
| mitch | XXX | False | Pump.fun | 1800 | NULL | NULL | NULL | NULL | 500,000 | NULL | NULL | NULL | NULL | 101 | NULL | NULL |
| mitch | HARD | False | Pump.fun | 1800 | 0.731 | 64.001 | 0 | 838,334 | 838,334 | NULL | 0 | 0 | 0 | 415 | 4.69 | 410 |
| mitch | fagua | False | Pump.fun | 1800 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 53 | NULL | NULL |
| mitch | RNT | False | Pump.fun | 1800 | 0.554 | 32.001 | 0 | 143,942 | 143,942 | NULL | 0 | 0 | 0 | 418 | 7.11 | 410 |
| mitch | JDS | False | Pump.fun | 1800 | NULL | NULL | NULL | NULL | 500,000 | NULL | NULL | NULL | NULL | 219 | NULL | NULL |
| mitch | MITCH | True | Pump.fun | 1800 | 0.792 | 84.682 | 1 | 30,000 | 30,000 | NULL | 0 | 0 | 0 | 1 | 1.591 | 0 |

## 3. Hit vs miss at minute 1 and minute 5 (distributions; n = launches with a value; in-sample, no model)

### 0xkgc, minute 1

| column | hits n | hits med | hits p25 | hits p75 | misses n | misses med | misses p25 | misses p75 |
|---|---|---|---|---|---|---|---|---|
| dev_supply_share | 7 | 0.066 | 0.05 | 0.081 | 40 | 0.034 | 0.034 | 0.057 |
| dev_first_buy_sol | 7 | 1.981 | 1.486 | 2.886 | 40 | 0.992 | 0.992 | 1.823 |
| dev_same_slot_buyers | 7 | 2 | 0.5 | 2 | 40 | 2 | 1 | 4 |
| dev_fee_first_tx | 7 | 505,000 | 35,000 | 505,000 | 40 | 505,000 | 180,479 | 505,000 |
| dev_fee_med_60s | 7 | 505,000 | 35,000 | 505,000 | 40 | 505,000 | 352,302.75 | 505,000 |
| dev_fee_lamports_med | 7 | 400,000 | 27,714.5 | 452,500 | 40 | 452,500 | 400,000 | 505,000 |
| dev_sold_share_60s | 7 | 0 | 0 | 0 | 40 | 0 | 0 | 0 |
| sol_in_1m | 7 | 22.097 | 19.648 | 24.553 | 40 | 15.471 | 9.561 | 25.466 |
| sol_out_1m | 7 | 8.796 | 7.122 | 15.413 | 40 | 10.236 | 5.093 | 16.837 |
| net_sol_1m | 7 | 12.23 | 9.016 | 14.569 | 40 | 6.439 | 3.813 | 14.569 |
| n_buys_1m | 7 | 42 | 40 | 53.5 | 40 | 42.5 | 25.75 | 63.5 |
| n_wallets_1m | 7 | 38 | 35.5 | 51.5 | 40 | 40 | 23 | 60 |
| member_buy_sol_1m | 7 | 0 | 0 | 0 | 40 | 0 | 0 | 0 |
| outside_buy_sol_1m | 7 | 19.203 | 17.714 | 21.378 | 40 | 14.116 | 8.569 | 23.886 |
| top10_share_1m | 7 | 0.857 | 0.779 | 0.913 | 40 | 0.91 | 0.751 | 0.975 |
| n_net_long_1m | 7 | 26 | 22.5 | 30.5 | 40 | 22.5 | 15.75 | 40.5 |
| mult_30s | 7 | 1.655 | 1.461 | 1.924 | 40 | 1.314 | 1.188 | 1.799 |
| mult_60s | 7 | 1.74 | 1.551 | 1.966 | 40 | 1.318 | 1.201 | 1.902 |
| dev_sold_by_60s (share true) | 7 | 0 | NULL | NULL | 40 | 0.025 | NULL | NULL |
| member_buy_by_1m (share true) | 7 | 0 | NULL | NULL | 40 | 0.05 | NULL | NULL |

### 0xkgc, minute 5

| column | hits n | hits med | hits p25 | hits p75 | misses n | misses med | misses p25 | misses p75 |
|---|---|---|---|---|---|---|---|---|
| dev_sold_share_120s | 7 | 0 | 0 | 0 | 40 | 0 | 0 | 0 |
| dev_sold_share_300s | 7 | 0 | 0 | 0 | 40 | 0 | 0 | 0 |
| sol_in_5m | 7 | 58.961 | 35.926 | 86.779 | 40 | 24.472 | 14.117 | 57.465 |
| sol_out_5m | 7 | 26.092 | 19.235 | 58.029 | 40 | 15.953 | 9.884 | 37.971 |
| net_sol_5m | 7 | 27.443 | 12.252 | 35.901 | 40 | 6.687 | 4.187 | 19.261 |
| n_buys_5m | 7 | 117 | 77 | 293 | 40 | 58.5 | 50 | 174.5 |
| n_wallets_5m | 7 | 101 | 67.5 | 173.5 | 40 | 56 | 44.75 | 146.5 |
| member_buy_sol_5m | 7 | 0 | 0 | 0 | 40 | 0 | 0 | 0 |
| member_buyers_5m | 7 | 0 | 0 | 0 | 40 | 0 | 0 | 0 |
| outside_buy_sol_5m | 7 | 56.067 | 33.246 | 84.345 | 40 | 22.528 | 13.126 | 55.454 |
| top10_share_5m | 7 | 0.63 | 0.477 | 0.827 | 40 | 0.963 | 0.637 | 1 |
| n_net_long_5m | 7 | 60 | 29 | 116 | 40 | 16.5 | 8 | 64.75 |
| mult_120s | 7 | 1.942 | 1.707 | 2.326 | 40 | 1.408 | 1.227 | 1.866 |
| mult_300s | 7 | 2.662 | 1.949 | 4.16 | 40 | 1.467 | 1.271 | 2.23 |
| dev_sold_by_120s (share true) | 7 | 0 | NULL | NULL | 40 | 0.025 | NULL | NULL |
| dev_sold_by_300s (share true) | 7 | 0 | NULL | NULL | 40 | 0.1 | NULL | NULL |
| member_buy_by_5m (share true) | 7 | 0.143 | NULL | NULL | 40 | 0.075 | NULL | NULL |

### gampsito, minute 1

| column | hits n | hits med | hits p25 | hits p75 | misses n | misses med | misses p25 | misses p75 |
|---|---|---|---|---|---|---|---|---|
| dev_supply_share | 6 | 0.152 | 0.152 | 0.171 | 10 | 0.177 | 0.152 | 0.177 |
| dev_first_buy_sol | 6 | 4.94 | 4.94 | 5.681 | 10 | 5.928 | 4.94 | 5.928 |
| dev_same_slot_buyers | 6 | 7 | 6.25 | 7.75 | 10 | 5.5 | 3.25 | 11 |
| dev_fee_first_tx | 6 | 5,000 | 5,000 | 5,000 | 10 | 5,000 | 5,000 | 5,000 |
| dev_fee_med_60s | 6 | 75,687.5 | 51,640.5 | 774,775 | 10 | 55,087.25 | 47,147.75 | 72,690.25 |
| dev_fee_lamports_med | 6 | 90,480.5 | 59,671.5 | 774,775 | 10 | 55,087.25 | 47,147.75 | 69,049.75 |
| dev_sold_share_60s | 6 | 1 | 1 | 1 | 10 | 1 | 1 | 1 |
| sol_in_1m | 6 | 109.51 | 49.635 | 122.487 | 10 | 70.448 | 37.931 | 114.898 |
| sol_out_1m | 6 | 88.111 | 44.071 | 90.745 | 10 | 64.645 | 36.964 | 100.582 |
| net_sol_1m | 6 | 17.572 | 5.563 | 25.972 | 10 | 3.201 | 1.464 | 13.202 |
| n_buys_1m | 6 | 181.5 | 63.5 | 235 | 10 | 130.5 | 66 | 203.75 |
| n_wallets_1m | 6 | 154 | 57 | 170.75 | 10 | 109.5 | 58.25 | 172.5 |
| member_buy_sol_1m | 6 | 0 | 0 | 0 | 10 | 0 | 0 | 0 |
| outside_buy_sol_1m | 6 | 104.57 | 43.46 | 117.3 | 10 | 64.521 | 32.991 | 108.97 |
| top10_share_1m | 6 | 0.571 | 0.439 | 0.905 | 10 | 0.93 | 0.655 | 1 |
| n_net_long_1m | 6 | 58 | 20.5 | 68.5 | 10 | 21.5 | 6.25 | 40 |
| mult_30s | 6 | 2.812 | 1.301 | 3.594 | 10 | 1.3 | 1.032 | 1.937 |
| mult_60s | 6 | 2.224 | 1.234 | 2.868 | 10 | 1.033 | 0.949 | 1.719 |
| dev_sold_by_60s (share true) | 6 | 1 | NULL | NULL | 10 | 1 | NULL | NULL |
| member_buy_by_1m (share true) | 6 | 0 | NULL | NULL | 10 | 0 | NULL | NULL |

### gampsito, minute 5

| column | hits n | hits med | hits p25 | hits p75 | misses n | misses med | misses p25 | misses p75 |
|---|---|---|---|---|---|---|---|---|
| dev_sold_share_120s | 6 | 1 | 1 | 1 | 10 | 1 | 1 | 1 |
| dev_sold_share_300s | 6 | 1 | 1 | 1 | 10 | 1 | 1 | 1 |
| sol_in_5m | 6 | 181.607 | 68.79 | 224.235 | 10 | 75.73 | 37.958 | 124.86 |
| sol_out_5m | 6 | 153.788 | 61.505 | 189.462 | 10 | 73.807 | 37.812 | 117.216 |
| net_sol_5m | 6 | 27.82 | 6.695 | 35.431 | 10 | 0.634 | 0.187 | 9.849 |
| n_buys_5m | 6 | 367.5 | 104 | 528.25 | 10 | 160 | 66.5 | 273.25 |
| n_wallets_5m | 6 | 240 | 75.75 | 313.5 | 10 | 121.5 | 58.75 | 209 |
| member_buy_sol_5m | 6 | 0 | 0 | 0 | 10 | 0 | 0 | 0 |
| member_buyers_5m | 6 | 0 | 0 | 0 | 10 | 0 | 0 | 0 |
| outside_buy_sol_5m | 6 | 176.667 | 62.121 | 219.542 | 10 | 69.802 | 33.018 | 118.925 |
| top10_share_5m | 5 | 0.47 | 0.362 | 0.473 | 9 | 0.999 | 0.725 | 1 |
| n_net_long_5m | 6 | 73.5 | 20 | 116.5 | 10 | 7 | 1.25 | 30.25 |
| mult_120s | 6 | 3.043 | 1.371 | 4.324 | 10 | 0.958 | 0.904 | 1.784 |
| mult_300s | 6 | 2.878 | 1.398 | 3.935 | 10 | 0.958 | 0.902 | 1.405 |
| dev_sold_by_120s (share true) | 6 | 1 | NULL | NULL | 10 | 1 | NULL | NULL |
| dev_sold_by_300s (share true) | 6 | 1 | NULL | NULL | 10 | 1 | NULL | NULL |
| member_buy_by_5m (share true) | 6 | 0 | NULL | NULL | 10 | 0 | NULL | NULL |

### hashbergers, minute 1

| column | hits n | hits med | hits p25 | hits p75 | misses n | misses med | misses p25 | misses p75 |
|---|---|---|---|---|---|---|---|---|
| dev_supply_share | 2 | 0.251 | 0.126 | 0.375 | 10 | 0.034 | 0.034 | 0.034 |
| dev_first_buy_sol | 2 | 13.121 | 6.571 | 19.67 | 10 | 0.989 | 0.989 | 0.989 |
| dev_same_slot_buyers | 2 | 5.5 | 2.75 | 8.25 | 10 | 1 | 0 | 2.5 |
| dev_fee_first_tx | 2 | 98,462 | 51,731 | 145,193 | 10 | 293,953 | 141,917.25 | 396,912.25 |
| dev_fee_med_60s | 2 | 98,462 | 51,731 | 145,193 | 10 | 194,207 | 71,333.625 | 212,685.5 |
| dev_fee_lamports_med | 2 | 313,194 | 252,559 | 373,829 | 10 | 146,860 | 65,663.25 | 205,256.75 |
| dev_sold_share_60s | 2 | 0 | 0 | 0 | 10 | 1 | 1 | 1 |
| sol_in_1m | 2 | 120.496 | 70.344 | 170.649 | 10 | 6.053 | 2.741 | 7.031 |
| sol_out_1m | 2 | 70.984 | 42.544 | 99.424 | 10 | 3.164 | 1.92 | 6.239 |
| net_sol_1m | 2 | 49.512 | 27.8 | 71.225 | 10 | 0.72 | 0.374 | 2.222 |
| n_buys_1m | 2 | 120 | 90.5 | 149.5 | 10 | 7.5 | 4.25 | 14 |
| n_wallets_1m | 2 | 94 | 74.5 | 113.5 | 10 | 7.5 | 4.25 | 13.75 |
| member_buy_sol_1m | 2 | 0.494 | 0.247 | 0.741 | 10 | 0 | 0 | 0 |
| outside_buy_sol_1m | 2 | 106.882 | 63.526 | 150.238 | 10 | 4.028 | 1.282 | 5.212 |
| top10_share_1m | 2 | 0.873 | 0.831 | 0.915 | 10 | 1 | 1 | 1 |
| n_net_long_1m | 2 | 56 | 36.5 | 75.5 | 10 | 2 | 1.25 | 6.75 |
| mult_30s | 2 | 4.273 | 2.879 | 5.668 | 10 | 1.114 | 1.008 | 1.209 |
| mult_60s | 2 | 7.13 | 4.215 | 10.046 | 10 | 1.074 | 0.995 | 1.209 |
| dev_sold_by_60s (share true) | 2 | 0 | NULL | NULL | 10 | 1 | NULL | NULL |
| member_buy_by_1m (share true) | 2 | 0.5 | NULL | NULL | 10 | 0 | NULL | NULL |

### hashbergers, minute 5

| column | hits n | hits med | hits p25 | hits p75 | misses n | misses med | misses p25 | misses p75 |
|---|---|---|---|---|---|---|---|---|
| dev_sold_share_120s | 2 | 0 | 0 | 0 | 10 | 1 | 1 | 1 |
| dev_sold_share_300s | 2 | 0 | 0 | 0 | 10 | 1 | 1 | 1 |
| sol_in_5m | 2 | 310.806 | 169.334 | 452.278 | 10 | 10.199 | 3.258 | 15.923 |
| sol_out_5m | 2 | 226.532 | 126.008 | 327.055 | 10 | 8.263 | 2.955 | 15.498 |
| net_sol_5m | 2 | 84.275 | 43.326 | 125.223 | 10 | 0.403 | 0.002 | 1.797 |
| n_buys_5m | 2 | 438 | 260.5 | 615.5 | 10 | 14.5 | 4.25 | 37.75 |
| n_wallets_5m | 2 | 288 | 180.5 | 395.5 | 10 | 14.5 | 4.25 | 35.5 |
| member_buy_sol_5m | 2 | 0.989 | 0.495 | 1.484 | 10 | 0 | 0 | 0 |
| member_buyers_5m | 2 | 0.5 | 0.25 | 0.75 | 10 | 0 | 0 | 0 |
| outside_buy_sol_5m | 2 | 296.696 | 162.269 | 431.124 | 10 | 6.5 | 1.282 | 14.638 |
| top10_share_5m | 2 | 0.863 | 0.795 | 0.93 | 6 | 1 | 0.996 | 1 |
| n_net_long_5m | 2 | 174.5 | 93.25 | 255.75 | 10 | 1 | 0 | 7.5 |
| mult_120s | 2 | 8.035 | 4.77 | 11.3 | 10 | 1.076 | 0.995 | 1.332 |
| mult_300s | 2 | 19.325 | 10.415 | 28.235 | 10 | 1.076 | 0.995 | 1.348 |
| dev_sold_by_120s (share true) | 2 | 0 | NULL | NULL | 10 | 1 | NULL | NULL |
| dev_sold_by_300s (share true) | 2 | 0 | NULL | NULL | 10 | 1 | NULL | NULL |
| member_buy_by_5m (share true) | 2 | 0.5 | NULL | NULL | 10 | 0 | NULL | NULL |

### jester, minute 1

| column | hits n | hits med | hits p25 | hits p75 | misses n | misses med | misses p25 | misses p75 |
|---|---|---|---|---|---|---|---|---|
| dev_supply_share | 7 | 0.1 | 0.076 | 0.205 | 20 | 0.122 | 0.034 | 0.2 |
| dev_first_buy_sol | 7 | 3.083 | 2.289 | 9.131 | 20 | 3.941 | 1.493 | 6.874 |
| dev_same_slot_buyers | 7 | 0 | 0 | 3 | 20 | 2 | 0 | 2.5 |
| dev_fee_first_tx | 7 | 8,500 | 8,500 | 505,000 | 20 | 35,000 | 5,000 | 355,000 |
| dev_fee_med_60s | 7 | 323,939.5 | 8,500 | 633,890 | 19 | 502,500 | 141,843.5 | 916,077.5 |
| dev_fee_lamports_med | 7 | 356,222.5 | 164,094.75 | 505,000 | 20 | 502,500 | 314,580.5 | 1e+06 |
| dev_sold_share_60s | 7 | 0.292 | 0 | 0.884 | 19 | 0.793 | 0.25 | 1 |
| sol_in_1m | 7 | 48.098 | 33.446 | 91.296 | 20 | 34.744 | 28.088 | 60.896 |
| sol_out_1m | 7 | 18.616 | 9.413 | 30.45 | 20 | 23.555 | 15.055 | 30.502 |
| net_sol_1m | 7 | 29.473 | 12.662 | 49.717 | 20 | 10.945 | 4.959 | 19.629 |
| n_buys_1m | 7 | 51 | 33.5 | 99.5 | 20 | 56 | 35.25 | 88.25 |
| n_wallets_1m | 7 | 50 | 25.5 | 83 | 20 | 44 | 28.5 | 80.25 |
| member_buy_sol_1m | 7 | 0 | 0 | 0 | 20 | 0 | 0 | 0 |
| outside_buy_sol_1m | 7 | 28.282 | 17.425 | 57.054 | 20 | 26.604 | 17.402 | 43.583 |
| top10_share_1m | 7 | 0.811 | 0.633 | 0.916 | 20 | 0.949 | 0.724 | 1 |
| n_net_long_1m | 7 | 27 | 16.5 | 53 | 20 | 14.5 | 9 | 32.5 |
| mult_30s | 7 | 2.398 | 1.503 | 2.408 | 20 | 1.565 | 1.396 | 1.867 |
| mult_60s | 7 | 2.564 | 1.883 | 3.352 | 20 | 1.476 | 1.161 | 2.137 |
| dev_sold_by_60s (share true) | 7 | 0.571 | NULL | NULL | 20 | 0.7 | NULL | NULL |
| member_buy_by_1m (share true) | 7 | 0.143 | NULL | NULL | 20 | 0.1 | NULL | NULL |

### jester, minute 5

| column | hits n | hits med | hits p25 | hits p75 | misses n | misses med | misses p25 | misses p75 |
|---|---|---|---|---|---|---|---|---|
| dev_sold_share_120s | 7 | 0.767 | 0.204 | 1 | 19 | 0.85 | 0.3 | 1 |
| dev_sold_share_300s | 7 | 0.767 | 0.204 | 1 | 19 | 1 | 0.675 | 1 |
| sol_in_5m | 7 | 98.244 | 47.37 | 172.237 | 20 | 52.414 | 37.609 | 95.681 |
| sol_out_5m | 7 | 38.197 | 16.241 | 83.3 | 20 | 43.267 | 27.914 | 72.627 |
| net_sol_5m | 7 | 39.032 | 21.106 | 57.826 | 20 | 3.579 | 1.623 | 25.922 |
| n_buys_5m | 7 | 83 | 53.5 | 215.5 | 20 | 90.5 | 46.5 | 151.5 |
| n_wallets_5m | 7 | 69 | 42 | 157.5 | 20 | 70.5 | 38.75 | 113.25 |
| member_buy_sol_5m | 7 | 0 | 0 | 0.466 | 20 | 0 | 0 | 0 |
| member_buyers_5m | 7 | 0 | 0 | 0.5 | 20 | 0 | 0 | 0 |
| outside_buy_sol_5m | 7 | 42.964 | 27.43 | 135.884 | 20 | 41.008 | 25.236 | 77.847 |
| top10_share_5m | 7 | 0.776 | 0.414 | 1 | 20 | 1 | 0.914 | 1 |
| n_net_long_5m | 7 | 31 | 9 | 82 | 20 | 9 | 6.75 | 22.5 |
| mult_120s | 7 | 3.408 | 1.775 | 3.878 | 20 | 1.552 | 1.136 | 1.888 |
| mult_300s | 7 | 3.546 | 2.406 | 4.863 | 20 | 1.272 | 1.016 | 2.402 |
| dev_sold_by_120s (share true) | 7 | 0.714 | NULL | NULL | 20 | 0.7 | NULL | NULL |
| dev_sold_by_300s (share true) | 7 | 0.714 | NULL | NULL | 20 | 0.75 | NULL | NULL |
| member_buy_by_5m (share true) | 7 | 0.286 | NULL | NULL | 20 | 0.15 | NULL | NULL |

### mitch, minute 1

| column | hits n | hits med | hits p25 | hits p75 | misses n | misses med | misses p25 | misses p75 |
|---|---|---|---|---|---|---|---|---|
| dev_supply_share | 1 | 0.792 | 0.792 | 0.792 | 4 | 0.498 | 0.356 | 0.598 |
| dev_first_buy_sol | 1 | 84.682 | 84.682 | 84.682 | 4 | 26.501 | 16.501 | 40.001 |
| dev_same_slot_buyers | 1 | 1 | 1 | 1 | 4 | 0 | 0 | 0 |
| dev_fee_first_tx | 1 | 30,000 | 30,000 | 30,000 | 4 | 114,471 | 71,250 | 317,540 |
| dev_fee_med_60s | 1 | 30,000 | 30,000 | 30,000 | 4 | 114,471 | 71,250 | 317,540 |
| dev_fee_lamports_med | 1 | 30,000 | 30,000 | 30,000 | 4 | 114,471 | 71,250 | 317,540 |
| dev_sold_share_60s | 1 | 0 | 0 | 0 | 4 | 0 | 0 | 0 |
| sol_in_1m | 1 | 170.013 | 170.013 | 170.013 | 4 | 64.741 | 33.021 | 90.329 |
| sol_out_1m | 1 | 0 | 0 | 0 | 4 | 3.281 | 1.522 | 5.322 |
| net_sol_1m | 1 | 170.013 | 170.013 | 170.013 | 4 | 61.46 | 31.499 | 85.007 |
| n_buys_1m | 1 | 4 | 4 | 4 | 4 | 16 | 10.75 | 22.25 |
| n_wallets_1m | 1 | 4 | 4 | 4 | 4 | 15 | 9.25 | 22.25 |
| member_buy_sol_1m | 1 | 0 | 0 | 0 | 4 | 0 | 0 | 0 |
| outside_buy_sol_1m | 1 | 85.33 | 85.33 | 85.33 | 4 | 22.24 | 16.52 | 34.327 |
| top10_share_1m | 1 | 1 | 1 | 1 | 4 | 0.981 | 0.944 | 1 |
| n_net_long_1m | 1 | 4 | 4 | 4 | 4 | 13.5 | 7.75 | 21.25 |
| mult_30s | 1 | 1.591 | 1.591 | 1.591 | 4 | 3.245 | 1.74 | 4.931 |
| mult_60s | 1 | 1.591 | 1.591 | 1.591 | 4 | 3.784 | 2.703 | 4.931 |
| dev_sold_by_60s (share true) | 1 | 0 | NULL | NULL | 4 | 0 | NULL | NULL |
| member_buy_by_1m (share true) | 1 | 0 | NULL | NULL | 4 | 0 | NULL | NULL |

### mitch, minute 5

| column | hits n | hits med | hits p25 | hits p75 | misses n | misses med | misses p25 | misses p75 |
|---|---|---|---|---|---|---|---|---|
| dev_sold_share_120s | 1 | 0 | 0 | 0 | 4 | 0 | 0 | 0 |
| dev_sold_share_300s | 1 | 0 | 0 | 0 | 4 | 0 | 0 | 0 |
| sol_in_5m | 1 | 170.013 | 170.013 | 170.013 | 4 | 91.118 | 72.835 | 93.942 |
| sol_out_5m | 1 | 0 | 0 | 0 | 4 | 10.439 | 6.901 | 14.904 |
| net_sol_5m | 1 | 170.013 | 170.013 | 170.013 | 4 | 81.312 | 60.598 | 85.007 |
| n_buys_5m | 1 | 4 | 4 | 4 | 4 | 28 | 23.25 | 38.25 |
| n_wallets_5m | 1 | 4 | 4 | 4 | 4 | 26.5 | 20.5 | 34.75 |
| member_buy_sol_5m | 1 | 0 | 0 | 0 | 4 | 0 | 0 | 0 |
| member_buyers_5m | 1 | 0 | 0 | 0 | 4 | 0 | 0 | 0 |
| outside_buy_sol_5m | 1 | 85.33 | 85.33 | 85.33 | 4 | 43.117 | 24.084 | 64.69 |
| top10_share_5m | 1 | 1 | 1 | 1 | 4 | 0.945 | 0.88 | 0.998 |
| n_net_long_5m | 1 | 4 | 4 | 4 | 4 | 19.5 | 10.25 | 30.75 |
| mult_120s | 1 | 1.591 | 1.591 | 1.591 | 4 | 4.974 | 3.901 | 5.588 |
| mult_300s | 1 | 1.591 | 1.591 | 1.591 | 4 | 5.325 | 3.813 | 6.475 |
| dev_sold_by_120s (share true) | 1 | 0 | NULL | NULL | 4 | 0 | NULL | NULL |
| dev_sold_by_300s (share true) | 1 | 0 | NULL | NULL | 4 | 0 | NULL | NULL |
| member_buy_by_5m (share true) | 1 | 0 | NULL | NULL | 4 | 0 | NULL | NULL |

### Threshold rules (hits passing / hits, misses passing / misses; launches with a dev buy and coverage to the mark)

| dev | mark | rule | hits | misses | precision | recall |
|---|---|---|---|---|---|---|
| 0xkgc | 1m | dev share >= 0.35 | 0 of 7 | 0 of 40 | NULL | 0 |
| 0xkgc | 1m | dev share >= 0.50 | 0 of 7 | 0 of 40 | NULL | 0 |
| 0xkgc | 1m | no dev sell by 60 s | 7 of 7 | 39 of 40 | 0.152 | 1 |
| 0xkgc | 1m | dev share >= 0.35 and no dev sell by 60 s | 0 of 7 | 0 of 40 | NULL | 0 |
| 0xkgc | 1m | dev share >= 0.35 and no dev sell by 60 s and same-slot buyers >= 2 | 0 of 7 | 0 of 40 | NULL | 0 |
| 0xkgc | 1m | dev share >= 0.35 and no dev sell by 60 s and sol_in_1m >= 50 | 0 of 7 | 0 of 40 | NULL | 0 |
| 0xkgc | 1m | no dev sell by 60 s and sol_in_1m >= 100 | 0 of 7 | 0 of 40 | NULL | 0 |
| 0xkgc | 1m | no dev sell by 60 s and n_wallets_1m >= 100 | 0 of 7 | 7 of 40 | 0 | 0 |
| 0xkgc | 1m | dev share >= 0.35 and mult_60s >= 2 | 0 of 7 | 0 of 40 | NULL | 0 |
| 0xkgc | 5m | dev share >= 0.35 and no dev sell by 120 s | 0 of 7 | 0 of 40 | NULL | 0 |
| 0xkgc | 5m | dev share >= 0.35 and no dev sell by 300 s | 0 of 7 | 0 of 40 | NULL | 0 |
| 0xkgc | 5m | no dev sell by 300 s | 7 of 7 | 36 of 40 | 0.163 | 1 |
| 0xkgc | 5m | no dev sell by 300 s and sol_in_5m >= 100 | 2 of 7 | 5 of 40 | 0.286 | 0.286 |
| 0xkgc | 5m | no dev sell by 300 s and n_wallets_5m >= 200 | 2 of 7 | 5 of 40 | 0.286 | 0.286 |
| 0xkgc | 5m | dev share >= 0.35 and no dev sell by 300 s and member buy by 300 s | 0 of 7 | 0 of 40 | NULL | 0 |
| 0xkgc | 5m | member buy by 300 s | 1 of 7 | 3 of 40 | 0.25 | 0.143 |
| 0xkgc | 5m | dev share >= 0.35 and no dev sell by 300 s and mult_300s >= 3 | 0 of 7 | 0 of 40 | NULL | 0 |
| gampsito | 1m | dev share >= 0.35 | 0 of 6 | 0 of 10 | NULL | 0 |
| gampsito | 1m | dev share >= 0.50 | 0 of 6 | 0 of 10 | NULL | 0 |
| gampsito | 1m | no dev sell by 60 s | 0 of 6 | 0 of 10 | NULL | 0 |
| gampsito | 1m | dev share >= 0.35 and no dev sell by 60 s | 0 of 6 | 0 of 10 | NULL | 0 |
| gampsito | 1m | dev share >= 0.35 and no dev sell by 60 s and same-slot buyers >= 2 | 0 of 6 | 0 of 10 | NULL | 0 |
| gampsito | 1m | dev share >= 0.35 and no dev sell by 60 s and sol_in_1m >= 50 | 0 of 6 | 0 of 10 | NULL | 0 |
| gampsito | 1m | no dev sell by 60 s and sol_in_1m >= 100 | 0 of 6 | 0 of 10 | NULL | 0 |
| gampsito | 1m | no dev sell by 60 s and n_wallets_1m >= 100 | 0 of 6 | 0 of 10 | NULL | 0 |
| gampsito | 1m | dev share >= 0.35 and mult_60s >= 2 | 0 of 6 | 0 of 10 | NULL | 0 |
| gampsito | 5m | dev share >= 0.35 and no dev sell by 120 s | 0 of 6 | 0 of 10 | NULL | 0 |
| gampsito | 5m | dev share >= 0.35 and no dev sell by 300 s | 0 of 6 | 0 of 10 | NULL | 0 |
| gampsito | 5m | no dev sell by 300 s | 0 of 6 | 0 of 10 | NULL | 0 |
| gampsito | 5m | no dev sell by 300 s and sol_in_5m >= 100 | 0 of 6 | 0 of 10 | NULL | 0 |
| gampsito | 5m | no dev sell by 300 s and n_wallets_5m >= 200 | 0 of 6 | 0 of 10 | NULL | 0 |
| gampsito | 5m | dev share >= 0.35 and no dev sell by 300 s and member buy by 300 s | 0 of 6 | 0 of 10 | NULL | 0 |
| gampsito | 5m | member buy by 300 s | 0 of 6 | 0 of 10 | NULL | 0 |
| gampsito | 5m | dev share >= 0.35 and no dev sell by 300 s and mult_300s >= 3 | 0 of 6 | 0 of 10 | NULL | 0 |
| hashbergers | 1m | dev share >= 0.35 | 1 of 2 | 0 of 10 | 1 | 0.5 |
| hashbergers | 1m | dev share >= 0.50 | 1 of 2 | 0 of 10 | 1 | 0.5 |
| hashbergers | 1m | no dev sell by 60 s | 2 of 2 | 0 of 10 | 1 | 1 |
| hashbergers | 1m | dev share >= 0.35 and no dev sell by 60 s | 1 of 2 | 0 of 10 | 1 | 0.5 |
| hashbergers | 1m | dev share >= 0.35 and no dev sell by 60 s and same-slot buyers >= 2 | 1 of 2 | 0 of 10 | 1 | 0.5 |
| hashbergers | 1m | dev share >= 0.35 and no dev sell by 60 s and sol_in_1m >= 50 | 1 of 2 | 0 of 10 | 1 | 0.5 |
| hashbergers | 1m | no dev sell by 60 s and sol_in_1m >= 100 | 1 of 2 | 0 of 10 | 1 | 0.5 |
| hashbergers | 1m | no dev sell by 60 s and n_wallets_1m >= 100 | 1 of 2 | 0 of 10 | 1 | 0.5 |
| hashbergers | 1m | dev share >= 0.35 and mult_60s >= 2 | 1 of 2 | 0 of 10 | 1 | 0.5 |
| hashbergers | 5m | dev share >= 0.35 and no dev sell by 120 s | 1 of 2 | 0 of 10 | 1 | 0.5 |
| hashbergers | 5m | dev share >= 0.35 and no dev sell by 300 s | 1 of 2 | 0 of 10 | 1 | 0.5 |
| hashbergers | 5m | no dev sell by 300 s | 2 of 2 | 0 of 10 | 1 | 1 |
| hashbergers | 5m | no dev sell by 300 s and sol_in_5m >= 100 | 1 of 2 | 0 of 10 | 1 | 0.5 |
| hashbergers | 5m | no dev sell by 300 s and n_wallets_5m >= 200 | 1 of 2 | 0 of 10 | 1 | 0.5 |
| hashbergers | 5m | dev share >= 0.35 and no dev sell by 300 s and member buy by 300 s | 1 of 2 | 0 of 10 | 1 | 0.5 |
| hashbergers | 5m | member buy by 300 s | 1 of 2 | 0 of 10 | 1 | 0.5 |
| hashbergers | 5m | dev share >= 0.35 and no dev sell by 300 s and mult_300s >= 3 | 1 of 2 | 0 of 10 | 1 | 0.5 |
| jester | 1m | dev share >= 0.35 | 1 of 7 | 2 of 20 | 0.333 | 0.143 |
| jester | 1m | dev share >= 0.50 | 1 of 7 | 2 of 20 | 0.333 | 0.143 |
| jester | 1m | no dev sell by 60 s | 3 of 7 | 6 of 20 | 0.333 | 0.429 |
| jester | 1m | dev share >= 0.35 and no dev sell by 60 s | 1 of 7 | 2 of 20 | 0.333 | 0.143 |
| jester | 1m | dev share >= 0.35 and no dev sell by 60 s and same-slot buyers >= 2 | 0 of 7 | 1 of 20 | 0 | 0 |
| jester | 1m | dev share >= 0.35 and no dev sell by 60 s and sol_in_1m >= 50 | 1 of 7 | 2 of 20 | 0.333 | 0.143 |
| jester | 1m | no dev sell by 60 s and sol_in_1m >= 100 | 1 of 7 | 1 of 20 | 0.5 | 0.143 |
| jester | 1m | no dev sell by 60 s and n_wallets_1m >= 100 | 0 of 7 | 0 of 20 | NULL | 0 |
| jester | 1m | dev share >= 0.35 and mult_60s >= 2 | 1 of 7 | 2 of 20 | 0.333 | 0.143 |
| jester | 5m | dev share >= 0.35 and no dev sell by 120 s | 1 of 7 | 2 of 20 | 0.333 | 0.143 |
| jester | 5m | dev share >= 0.35 and no dev sell by 300 s | 1 of 7 | 2 of 20 | 0.333 | 0.143 |
| jester | 5m | no dev sell by 300 s | 2 of 7 | 5 of 20 | 0.286 | 0.286 |
| jester | 5m | no dev sell by 300 s and sol_in_5m >= 100 | 1 of 7 | 1 of 20 | 0.5 | 0.143 |
| jester | 5m | no dev sell by 300 s and n_wallets_5m >= 200 | 0 of 7 | 0 of 20 | NULL | 0 |
| jester | 5m | dev share >= 0.35 and no dev sell by 300 s and member buy by 300 s | 0 of 7 | 0 of 20 | NULL | 0 |
| jester | 5m | member buy by 300 s | 2 of 7 | 3 of 20 | 0.4 | 0.286 |
| jester | 5m | dev share >= 0.35 and no dev sell by 300 s and mult_300s >= 3 | 1 of 7 | 1 of 20 | 0.5 | 0.143 |
| mitch | 1m | dev share >= 0.35 | 1 of 1 | 3 of 4 | 0.25 | 1 |
| mitch | 1m | dev share >= 0.50 | 1 of 1 | 2 of 4 | 0.333 | 1 |
| mitch | 1m | no dev sell by 60 s | 1 of 1 | 4 of 4 | 0.2 | 1 |
| mitch | 1m | dev share >= 0.35 and no dev sell by 60 s | 1 of 1 | 3 of 4 | 0.25 | 1 |
| mitch | 1m | dev share >= 0.35 and no dev sell by 60 s and same-slot buyers >= 2 | 0 of 1 | 0 of 4 | NULL | 0 |
| mitch | 1m | dev share >= 0.35 and no dev sell by 60 s and sol_in_1m >= 50 | 1 of 1 | 2 of 4 | 0.333 | 1 |
| mitch | 1m | no dev sell by 60 s and sol_in_1m >= 100 | 1 of 1 | 0 of 4 | 1 | 1 |
| mitch | 1m | no dev sell by 60 s and n_wallets_1m >= 100 | 0 of 1 | 0 of 4 | NULL | 0 |
| mitch | 1m | dev share >= 0.35 and mult_60s >= 2 | 0 of 1 | 3 of 4 | 0 | 0 |
| mitch | 5m | dev share >= 0.35 and no dev sell by 120 s | 1 of 1 | 3 of 4 | 0.25 | 1 |
| mitch | 5m | dev share >= 0.35 and no dev sell by 300 s | 1 of 1 | 3 of 4 | 0.25 | 1 |
| mitch | 5m | no dev sell by 300 s | 1 of 1 | 4 of 4 | 0.2 | 1 |
| mitch | 5m | no dev sell by 300 s and sol_in_5m >= 100 | 1 of 1 | 0 of 4 | 1 | 1 |
| mitch | 5m | no dev sell by 300 s and n_wallets_5m >= 200 | 0 of 1 | 0 of 4 | NULL | 0 |
| mitch | 5m | dev share >= 0.35 and no dev sell by 300 s and member buy by 300 s | 0 of 1 | 0 of 4 | NULL | 0 |
| mitch | 5m | member buy by 300 s | 0 of 1 | 0 of 4 | NULL | 0 |
| mitch | 5m | dev share >= 0.35 and no dev sell by 300 s and mult_300s >= 3 | 0 of 1 | 3 of 4 | 0 | 0 |

## 4. The entry window on hits

Multiples are the 10-second buy VWAP over the dev's first-buy price (quote units). `mult_Ts` = last complete bucket before T; `max_after_Ts` = best bucket at or after T inside the observed window; `ahead_Ts` = max_after / mult (how much of the run was still ahead of a buyer at T). `peak1_*` is Phase B's 1-second peak. Retardmode hits and slingoor's PEACE-like cases ran after the window, so window peaks are lower bounds.

### 0xkgc hits (n=7)

| column | n | median | p25 | p75 | min | max |
|---|---|---|---|---|---|---|
| member_first_buy_s | 2 | 525.5 | 302.25 | 748.75 | 79 | 972 |
| outside_first_buy_s | 7 | 0 | 0 | 0 | 0 | 1 |
| peak1_ts_s | 5 | 1,008 | 724 | 1,249 | 455 | 1,782 |
| peak10_ts_s | 7 | 950 | 780 | 1,205 | 390 | 1,780 |
| peak10_mult | 7 | 9.94 | 5.871 | 13.467 | 3.031 | 16.956 |
| mult_30s | 7 | 1.655 | 1.461 | 1.924 | 1.24 | 2.297 |
| mult_60s | 7 | 1.74 | 1.551 | 1.966 | 1.239 | 2.173 |
| mult_120s | 7 | 1.942 | 1.707 | 2.326 | 1.13 | 2.809 |
| mult_300s | 7 | 2.662 | 1.949 | 4.16 | 1.262 | 6.341 |
| ahead_30s | 7 | 6.707 | 3.89 | 7.284 | 1.933 | 8.073 |
| ahead_60s | 7 | 6.149 | 3.764 | 7.247 | 1.976 | 7.9 |
| ahead_120s | 7 | 5.186 | 3.457 | 6.078 | 1.97 | 6.569 |
| ahead_300s | 7 | 2.184 | 2.056 | 4.985 | 1.325 | 7.877 |

| symbol | coverage_s | member_first_buy_s | outside_first_buy_s | peak10_ts_s | peak10_mult | peak1_mult | mult_30s | ahead_30s | mult_60s | ahead_60s | mult_120s | ahead_120s | mult_300s | ahead_300s | end_mult | kl_mult_5m | kl_mult_30m | kl_max_mult_100m | kl_min_to_max_100m |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| BIKESON | 1800 | 972 | 0 | 390 | 3.528 | NULL | 1.825 | 1.933 | 1.786 | 1.976 | 1.79 | 1.97 | 2.662 | 1.325 | 2.285 | 1.462 | 1.54 | 2.834 | 6.15 |
| biketyson | 1800 | NULL | 0 | 720 | 9.94 | 10.17 | 1.383 | 7.185 | 1.485 | 6.694 | 1.624 | 6.12 | 1.262 | 7.877 | 3.339 | 1.323 | 2.083 | 6.8 | 11.9 |
| UNC | 845 | NULL | 0 | 840 | 13.36 | NULL | 1.655 | 8.073 | 2.173 | 6.149 | 2.034 | 6.569 | 4.153 | 3.217 | 13.36 | 1.688 | 11.555 | 18.989 | 18.683 |
| ZEC | 1800 | NULL | 0 | 950 | 8.215 | 8.202 | 1.539 | 5.337 | 1.617 | 5.082 | 1.942 | 4.231 | 4.166 | 1.972 | 3.965 | 2.479 | 2.54 | 40.201 | 51.85 |
| thewok | 1800 | NULL | 0 | 1,170 | 3.031 | 3.658 | 1.24 | 2.444 | 1.239 | 2.446 | 1.13 | 2.683 | 1.388 | 2.184 | 2.042 | 1.286 | 1.588 | 4.075 | 57.783 |
| Hunter | 1800 | 79 | 1 | 1,240 | 16.956 | 17.734 | 2.297 | 7.383 | 2.146 | 7.9 | 2.809 | 6.036 | 2.511 | 6.754 | 11.409 | 1.023 | 4.076 | 7.169 | 18.633 |
| MelonMusk | 1800 | NULL | 0 | 1,780 | 13.573 | 13.714 | 2.024 | 6.707 | 1.74 | 7.8 | 2.617 | 5.186 | 6.341 | 2.14 | 13.163 | 4.227 | 6.647 | 11.743 | 37.5 |

### gampsito hits (n=6)

| column | n | median | p25 | p75 | min | max |
|---|---|---|---|---|---|---|
| member_first_buy_s | 1 | 402 | 402 | 402 | 402 | 402 |
| outside_first_buy_s | 6 | 0 | 0 | 0 | 0 | 0 |
| peak1_ts_s | 6 | 421 | 99.25 | 910 | 1 | 1,715 |
| peak10_ts_s | 6 | 415 | 97.5 | 912.5 | 0 | 1,710 |
| peak10_mult | 6 | 5.495 | 2.017 | 16.118 | 1.192 | 27.53 |
| mult_30s | 6 | 2.812 | 1.301 | 3.594 | 0.936 | 3.744 |
| mult_60s | 6 | 2.224 | 1.234 | 2.868 | 0.936 | 3.88 |
| mult_120s | 6 | 3.043 | 1.371 | 4.324 | 0.936 | 5.391 |
| mult_300s | 6 | 2.878 | 1.398 | 3.935 | 0.936 | 8.027 |
| ahead_30s | 4 | 3.649 | 1.87 | 6.76 | 1.095 | 11.532 |
| ahead_60s | 4 | 5.01 | 1.668 | 9.429 | 1.345 | 12.985 |
| ahead_120s | 4 | 2.713 | 1.258 | 5.69 | 1.2 | 10.314 |
| ahead_300s | 4 | 2.005 | 1.558 | 4.272 | 1.376 | 9.916 |

| symbol | coverage_s | member_first_buy_s | outside_first_buy_s | peak10_ts_s | peak10_mult | peak1_mult | mult_30s | ahead_30s | mult_60s | ahead_60s | mult_120s | ahead_120s | mult_300s | ahead_300s | end_mult | kl_mult_5m | kl_mult_30m | kl_max_mult_100m | kl_min_to_max_100m |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Dancedoge | 1800 | NULL | 0 | 0 | 1.322 | 1.914 | 0.936 | NULL | 0.936 | NULL | 0.936 | NULL | 0.936 | NULL | 0.936 | 0.832 | 0.832 | 1 | 0.75 |
| ok | 1800 | NULL | 0 | 0 | 1.192 | 1.466 | 0.939 | NULL | 0.939 | NULL | 0.939 | NULL | 0.939 | NULL | 0.939 | 0.906 | 0.905 | 1 | 0.333 |
| petcat | 1800 | NULL | 0 | 390 | 4.101 | 4.125 | 3.744 | 1.095 | 3.048 | 1.345 | 3.418 | 1.2 | 2.98 | 1.376 | 1.139 | 1.213 | 0.357 | 1.681 | 0.117 |
| PP | 1800 | NULL | 0 | 440 | 6.888 | 6.931 | 3.237 | 2.128 | 3.88 | 1.775 | 5.391 | 1.278 | 4.254 | 1.619 | 5.179 | 1.458 | 1.711 | 3.253 | 75.467 |
| Biz | 1070 | 402 | 0 | 1,070 | 27.53 | 28.62 | 2.387 | 11.532 | 2.12 | 12.985 | 2.669 | 10.314 | 2.776 | 9.916 | 27.53 | 2.08 | 15.193 | 38.2 | 51.767 |
| Polycat | 1800 | NULL | 0 | 1,710 | 19.195 | 19.584 | 3.713 | 5.169 | 2.328 | 8.244 | 4.626 | 4.149 | 8.027 | 2.391 | 16.03 | 3.127 | 5.48 | 8.128 | 69.2 |

### hashbergers hits (n=2)

| column | n | median | p25 | p75 | min | max |
|---|---|---|---|---|---|---|
| member_first_buy_s | 1 | 38 | 38 | 38 | 38 | 38 |
| outside_first_buy_s | 2 | 0 | 0 | 0 | 0 | 0 |
| peak1_ts_s | 2 | 1,342 | 1,122.5 | 1,561.5 | 903 | 1,781 |
| peak10_ts_s | 2 | 1,335 | 1,117.5 | 1,552.5 | 900 | 1,770 |
| peak10_mult | 2 | 38.399 | 30.237 | 46.561 | 22.076 | 54.723 |
| mult_30s | 2 | 4.273 | 2.879 | 5.668 | 1.485 | 7.062 |
| mult_60s | 2 | 7.13 | 4.215 | 10.046 | 1.299 | 12.962 |
| mult_120s | 2 | 8.035 | 4.77 | 11.3 | 1.505 | 14.564 |
| mult_300s | 2 | 19.325 | 10.415 | 28.235 | 1.505 | 37.145 |
| ahead_30s | 2 | 11.309 | 9.529 | 13.089 | 7.749 | 14.869 |
| ahead_60s | 2 | 10.608 | 7.415 | 13.8 | 4.222 | 16.993 |
| ahead_120s | 2 | 9.212 | 6.485 | 11.939 | 3.757 | 14.666 |
| ahead_300s | 2 | 8.07 | 4.771 | 11.368 | 1.473 | 14.666 |

| symbol | coverage_s | member_first_buy_s | outside_first_buy_s | peak10_ts_s | peak10_mult | peak1_mult | mult_30s | ahead_30s | mult_60s | ahead_60s | mult_120s | ahead_120s | mult_300s | ahead_300s | end_mult | kl_mult_5m | kl_mult_30m | kl_max_mult_100m | kl_min_to_max_100m |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SCRAP | 1800 | NULL | 0 | 900 | 22.076 | 25.012 | 1.485 | 14.869 | 1.299 | 16.993 | 1.505 | 14.666 | 1.505 | 14.666 | 6.26 | NULL | NULL | NULL | NULL |
| PINU | 1800 | 38 | 0 | 1,770 | 54.723 | 55.556 | 7.062 | 7.749 | 12.962 | 4.222 | 14.564 | 3.757 | 37.145 | 1.473 | 54.467 | NULL | NULL | NULL | NULL |

### jester hits (n=7)

| column | n | median | p25 | p75 | min | max |
|---|---|---|---|---|---|---|
| member_first_buy_s | 4 | 276.5 | 157.75 | 497.5 | 13 | 949 |
| outside_first_buy_s | 7 | 0 | 0 | 0.5 | 0 | 3 |
| peak1_ts_s | 7 | 1,306 | 928 | 1,674.5 | 641 | 1,798 |
| peak10_ts_s | 7 | 1,300 | 840 | 1,670 | 300 | 1,790 |
| peak10_mult | 7 | 8.902 | 4.732 | 11.669 | 2.872 | 54.85 |
| mult_30s | 7 | 2.398 | 1.503 | 2.408 | 1.039 | 3.658 |
| mult_60s | 7 | 2.564 | 1.883 | 3.352 | 1.051 | 3.828 |
| mult_120s | 7 | 3.408 | 1.775 | 3.878 | 1.051 | 6.204 |
| mult_300s | 7 | 3.546 | 2.406 | 4.863 | 1.069 | 6.458 |
| ahead_30s | 7 | 3.207 | 2.599 | 4.846 | 1.947 | 36.3 |
| ahead_60s | 7 | 3.218 | 2.578 | 4.175 | 1.22 | 24.105 |
| ahead_120s | 7 | 2.732 | 2.098 | 3.417 | 1.37 | 23.969 |
| ahead_300s | 7 | 2.42 | 1.897 | 3.499 | 1.022 | 15.89 |

| symbol | coverage_s | member_first_buy_s | outside_first_buy_s | peak10_ts_s | peak10_mult | peak1_mult | mult_30s | ahead_30s | mult_60s | ahead_60s | mult_120s | ahead_120s | mult_300s | ahead_300s | end_mult | kl_mult_5m | kl_mult_30m | kl_max_mult_100m | kl_min_to_max_100m |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| ALBERT | 1800 | NULL | 0 | 300 | 4.67 | 6.98 | 2.398 | 1.947 | 3.828 | 1.22 | 3.408 | 1.37 | 4.568 | 1.022 | 2.556 | NULL | NULL | NULL | NULL |
| CHICKY | 1800 | 347 | 0 | 650 | 10.857 | 10.915 | 2.418 | 4.49 | 2.564 | 4.235 | 6.204 | 1.75 | 6.458 | 1.681 | 6.499 | NULL | NULL | NULL | NULL |
| SNEAKERS | 1800 | 949 | 1 | 1,030 | 4.795 | 4.896 | 1.495 | 3.207 | 1.49 | 3.218 | 1.261 | 3.802 | 1.069 | 4.487 | 4.025 | NULL | NULL | NULL | NULL |
| DIRECTOR | 1800 | 206 | 0 | 1,300 | 2.872 | 2.872 | 1.039 | 2.765 | 1.051 | 2.732 | 1.051 | 2.732 | 1.359 | 2.113 | 1.556 | NULL | NULL | NULL | NULL |
| WATERFALL | 1800 | NULL | 0 | 1,630 | 54.85 | 60.177 | 1.511 | 36.3 | 2.275 | 24.105 | 2.288 | 23.969 | 3.452 | 15.89 | 43.578 | NULL | NULL | NULL | NULL |
| COBSON | 1800 | NULL | 3 | 1,710 | 8.902 | 9.026 | 3.658 | 2.434 | 3.671 | 2.425 | 3.64 | 2.445 | 3.546 | 2.511 | 8.223 | NULL | NULL | NULL | NULL |
| KIKI | 1800 | 13 | 0 | 1,790 | 12.481 | 12.689 | 2.399 | 5.202 | 3.033 | 4.115 | 4.116 | 3.032 | 5.158 | 2.42 | 12.481 | NULL | NULL | NULL | NULL |

### mitch hits (n=2)

| column | n | median | p25 | p75 | min | max |
|---|---|---|---|---|---|---|
| member_first_buy_s | 0 | NULL | NULL | NULL | NULL | NULL |
| outside_first_buy_s | 2 | 0 | 0 | 0 | 0 | 0 |
| peak1_ts_s | 2 | 19 | 9.5 | 28.5 | 0 | 38 |
| peak10_ts_s | 1 | 0 | 0 | 0 | 0 | 0 |
| peak10_mult | 1 | 1.591 | 1.591 | 1.591 | 1.591 | 1.591 |
| mult_30s | 1 | 1.591 | 1.591 | 1.591 | 1.591 | 1.591 |
| mult_60s | 1 | 1.591 | 1.591 | 1.591 | 1.591 | 1.591 |
| mult_120s | 1 | 1.591 | 1.591 | 1.591 | 1.591 | 1.591 |
| mult_300s | 1 | 1.591 | 1.591 | 1.591 | 1.591 | 1.591 |
| ahead_30s | 0 | NULL | NULL | NULL | NULL | NULL |
| ahead_60s | 0 | NULL | NULL | NULL | NULL | NULL |
| ahead_120s | 0 | NULL | NULL | NULL | NULL | NULL |
| ahead_300s | 0 | NULL | NULL | NULL | NULL | NULL |

| symbol | coverage_s | member_first_buy_s | outside_first_buy_s | peak10_ts_s | peak10_mult | peak1_mult | mult_30s | ahead_30s | mult_60s | ahead_60s | mult_120s | ahead_120s | mult_300s | ahead_300s | end_mult | kl_mult_5m | kl_mult_30m | kl_max_mult_100m | kl_min_to_max_100m |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| MITCH | 1800 | NULL | 0 | 0 | 1.591 | 1.591 | 1.591 | NULL | 1.591 | NULL | 1.591 | NULL | 1.591 | NULL | 1.591 | NULL | NULL | NULL | NULL |
| mitch | 1800 | NULL | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL |

### Both launchers pooled, hits

| column | n | median | p25 | p75 | min | max |
|---|---|---|---|---|---|---|
| member_first_buy_s | 8 | 276.5 | 68.75 | 538.75 | 13 | 972 |
| outside_first_buy_s | 24 | 0 | 0 | 0 | 0 | 3 |
| peak10_ts_s | 23 | 950 | 415 | 1,465 | 0 | 1,790 |
| peak10_mult | 23 | 8.902 | 3.815 | 15.264 | 1.192 | 54.85 |
| mult_30s | 23 | 1.825 | 1.49 | 2.408 | 0.936 | 7.062 |
| mult_60s | 23 | 2.12 | 1.487 | 2.798 | 0.936 | 12.962 |
| mult_120s | 23 | 2.288 | 1.548 | 3.529 | 0.936 | 14.564 |
| mult_300s | 23 | 2.98 | 1.447 | 4.411 | 0.936 | 37.145 |
| ahead_30s | 20 | 5.186 | 2.442 | 7.474 | 1.095 | 36.3 |
| ahead_60s | 20 | 4.228 | 2.441 | 7.825 | 1.22 | 24.105 |
| ahead_120s | 20 | 3.78 | 2.327 | 6.057 | 1.2 | 23.969 |
| ahead_300s | 20 | 2.288 | 1.666 | 5.053 | 1.022 | 15.89 |

`kl_*` columns are DuckDB dev_runs kline multiples relative to the first candle's open, not to the dev's average price, so they are not on the same scale as `mult_*`.

Misses, for contrast (same multiples):

| dev | symbol | coverage_s | peak10_ts_s | peak10_mult | mult_30s | mult_60s | mult_120s | mult_300s | end_mult | dev_first_sell_s |
|---|---|---|---|---|---|---|---|---|---|---|
| 0xkgc | OG | 1800 | 10 | 1.436 | 1.436 | 1.241 | 1.338 | 1.338 | 1.338 | 211 |
| 0xkgc | tradoor | 1800 | 0 | 1.204 | 1.19 | 1.145 | 1.156 | 1.129 | 1.129 | 224 |
| 0xkgc | 1LEFT | 1800 | 770 | 3.677 | 1.111 | 1.105 | 1.139 | 1.348 | 1.113 | 753 |
| 0xkgc | missooor | 1800 | 500 | 1.787 | 1.092 | 1.092 | 1.205 | 1.086 | 1.057 | 1,611 |
| 0xkgc | madeitup | 1800 | 620 | 2.393 | 1.248 | 1.101 | 1.15 | 1.16 | 1.393 | NULL |
| 0xkgc | topbuyer | 1800 | 530 | 2.481 | 1.369 | 1.173 | 1.173 | 1.259 | 1.235 | NULL |
| 0xkgc | 1minute | 1800 | 490 | 2.193 | 1.108 | 1.108 | 1.101 | 1.169 | 1.21 | 802 |
| 0xkgc | 1trump | 1800 | 930 | 8 | 1.18 | 1.18 | 1.235 | 1.179 | 1.838 | 738 |
| 0xkgc | few | 1800 | 760 | 7.163 | 1.16 | 1.16 | 1.16 | 1.272 | 1.216 | 763 |
| 0xkgc | SOLMOG | 1800 | 570 | 4.184 | 1.138 | 1.207 | 1.262 | 1.339 | 1.361 | NULL |
| 0xkgc | ducknana | 1800 | 1,430 | 15.103 | 1.281 | 1.308 | 1.297 | 1.211 | 2.245 | 777 |
| 0xkgc | SOLONLY | 1800 | 470 | 1.763 | 1.26 | 1.25 | 1.625 | 1.488 | 1.134 | NULL |
| 0xkgc | happyegg | 1800 | 500 | 3.289 | 1.238 | 1.224 | 1.284 | 1.358 | 1.232 | 873 |
| 0xkgc | ETH | 1800 | 480 | 2.976 | 1.414 | 1.349 | 1.373 | 1.281 | 1.136 | 685 |
| 0xkgc | swingdog | 1800 | 400 | 3.053 | 1.444 | 1.605 | 1.501 | 1.49 | 1.102 | 703 |
| 0xkgc | biip | 1800 | 680 | 2.314 | 1.154 | 1.409 | 1.409 | 1.447 | 1.168 | NULL |
| 0xkgc | BOT | 1800 | 20 | 1.545 | 1.545 | 1.494 | 1.317 | 1.195 | 0.992 | 36 |
| 0xkgc | initials | 1800 | 1,250 | 3.256 | 1.405 | 1.282 | 1.595 | 1.335 | 1.602 | NULL |
| 0xkgc | GOAT | 1800 | 70 | 1.664 | 1.283 | 1.488 | 1.664 | 1.429 | 1.025 | 1,298 |
| 0xkgc | GAPE | 1800 | 140 | 1.673 | 1.246 | 1.295 | 1.529 | 1.596 | 1.596 | 343 |
| 0xkgc | oversold | 1800 | 500 | 3.029 | 1.088 | 1.325 | 1.407 | 1.266 | 1.069 | 784 |
| 0xkgc | IBRN | 1800 | 510 | 2.927 | 1.359 | 1.31 | 1.35 | 1.558 | 1.078 | NULL |
| 0xkgc | Catiban | 1800 | 290 | 1.86 | 1.217 | 1.331 | 1.413 | 1.86 | 1.604 | 915 |
| 0xkgc | MAC | 1800 | 40 | 1.145 | 1.044 | 1.145 | 1.145 | 1.145 | 1.145 | NULL |
| 0xkgc | ZUPERCYCLE | 1800 | 500 | 6.477 | 1.345 | 1.345 | 1.162 | 2.208 | 2.713 | NULL |
| 0xkgc | BABYLMAO | 1800 | 1,710 | 2.494 | 1.014 | 1.014 | 1.158 | 1.397 | 2.494 | NULL |
| 0xkgc | duve | 1800 | 900 | 6.97 | 2.263 | 2.794 | 2.134 | 3.273 | 2.22 | 387 |
| 0xkgc | AAPLTOP | 1800 | 1,280 | 6.357 | 1.762 | 1.868 | 1.443 | 2.004 | 4.095 | NULL |
| 0xkgc | Keanu | 1800 | 1,340 | 6.641 | 2.26 | 2.059 | 1.825 | 3.882 | 3.881 | NULL |
| 0xkgc | fries | 1800 | 1,340 | 8.066 | 1.279 | 1.279 | 1.607 | 2.026 | 6.072 | NULL |
| 0xkgc | CRIME | 1800 | 710 | 12.531 | 1.197 | 1.259 | 1.31 | 4.035 | 2.625 | 555 |
| 0xkgc | fleaman | 1800 | 960 | 4.085 | 3.498 | 2.461 | 4.052 | 2.463 | 2.875 | NULL |
| 0xkgc | dump | 1800 | 390 | 2.811 | 1.647 | 1.788 | 1.988 | 2.572 | 1.613 | NULL |
| 0xkgc | CUM | 1800 | 270 | 4.995 | 2.2 | 2.932 | 3.312 | 4.62 | 2.038 | 278 |
| 0xkgc | ats | 1800 | 840 | 4.276 | 2.3 | 2.169 | 2.291 | 1.985 | 2.015 | NULL |
| 0xkgc | ktw | 1800 | 600 | 6.264 | 2.485 | 2.004 | 3.698 | 4.347 | 1.716 | 320 |
| 0xkgc | SlowRogan | 1800 | 1,340 | 3.203 | 2.135 | 2.083 | 2.344 | 3.18 | 1.797 | NULL |
| 0xkgc | K-Train | 1800 | 110 | 3.116 | 2.375 | 2.471 | 3.116 | 1.667 | 1.426 | NULL |
| 0xkgc | COMMUNISM | 1800 | 640 | 7.961 | 1.913 | 2.125 | 2.063 | 2.297 | 1.593 | 1,169 |
| 0xkgc | RIPASS | 1800 | 1,590 | 8.936 | 3.245 | 2.861 | 3.465 | 4.798 | 7.959 | NULL |
| gampsito | mlem | 1800 | 0 | 1.504 | 0.934 | 0.934 | 0.921 | 0.921 | 0.921 | 3 |
| gampsito | looong | 1800 | 850 | 6.198 | 3.101 | 2.14 | 2.946 | 2.307 | 1.344 | 2 |
| gampsito | Shrekt | 1800 | 0 | 1.871 | 1.542 | 1.45 | 1.327 | 1.001 | 1.119 | 1 |
| gampsito | HeHa | 1800 | 0 | 1.434 | 0.994 | 0.912 | 0.912 | 0.912 | 0.912 | 1 |
| gampsito | OrgyInu | 1800 | 170 | 2.027 | 1.436 | 1.809 | 1.936 | 1.54 | 1.31 | 1 |
| gampsito | hats | 1800 | 10 | 1.355 | 1.164 | 1.018 | 0.899 | 0.899 | 0.899 | 1 |
| gampsito | Chimpi | 1800 | 0 | 1.389 | 0.994 | 0.994 | 0.994 | 0.994 | 0.994 | 2 |
| gampsito | blep | 1800 | 10 | 2.49 | 2.068 | 1.048 | 0.902 | 0.875 | 0.875 | 4 |
| gampsito | yap | 1800 | 0 | 1.302 | 1.145 | 0.892 | 0.892 | 0.892 | 0.892 | 5 |
| gampsito | BTD | 1800 | 730 | 7.7 | 2.738 | 2.631 | 2.61 | 5.121 | 1.987 | 4 |
| hashbergers | RAPEHIM | 1800 | 0 | 1.034 | 1.034 | 1.034 | 1.034 | 1.034 | 1.034 | 13 |
| hashbergers | PVE | 1800 | 0 | 1.114 | 1.114 | 0.99 | 0.99 | 0.99 | 0.99 | 9 |
| hashbergers | PENGU | 1800 | 0 | 1.163 | 1.163 | 1.163 | 1.118 | 1.118 | 1.118 | 8 |
| hashbergers | OBESE | 1800 | 650 | 5.682 | 1.664 | 1.892 | 3.172 | 3.973 | 3.476 | 17 |
| hashbergers | AMIGA | 1800 | 0 | 1 | 0.758 | 0.758 | 0.758 | 0.758 | 0.758 | 9 |
| hashbergers | OARFISH | 1800 | 80 | 1.868 | 1.224 | 1.224 | 1.846 | 1.846 | 1.846 | 12 |
| hashbergers | KINDA | 1800 | 190 | 1.85 | 1.115 | 1.115 | 1.124 | 1.19 | 1.012 | 10 |
| hashbergers | FLOAT | 1800 | 0 | 1.021 | 1 | 1 | 1 | 1 | 1 | 10 |
| hashbergers | COMPUTA | 1800 | 0 | 1.021 | 0.994 | 0.994 | 0.994 | 0.994 | 0.968 | 9 |
| hashbergers | piss | 1800 | 90 | 1.401 | 1.355 | 1.262 | 1.401 | 1.401 | 1.237 | 24 |
| jester | mouse | 1800 | 20 | 1.508 | 1.508 | 1.486 | 1.037 | 1.042 | 1.042 | 17 |
| jester | CREAMUS | 1800 | 1,670 | 3.491 | 3.035 | 3.035 | 3.016 | 2.973 | 3.491 | NULL |
| jester | SEKOLAH | 1800 | 280 | 2.222 | 1.762 | 1.631 | 1.492 | 2.222 | 2.083 | NULL |
| jester | JANICE | 1800 | 140 | 1.157 | 1.003 | 1.03 | 1.03 | 1.157 | 1.157 | 44 |
| jester | Jutsu | 1800 | 0 | 0.98 | 0.937 | 0.937 | 0.937 | 0.937 | 0.937 | NULL |
| jester | FLUFF | 1800 | 20 | 1.434 | 1.434 | 1.18 | 1.169 | 1.169 | 1.169 | 33 |
| jester | TYGR | 1800 | 240 | 1.913 | 1.105 | 1.105 | 1.034 | 0.914 | 0.914 | 18 |
| jester | HITLERHAUS | 1800 | 700 | 4.382 | 3.53 | 3.095 | 4.124 | 4.229 | 3.277 | 36 |
| jester | LARD | 1800 | 120 | 1.721 | 1.428 | 1.291 | 1.693 | 1.115 | 1.009 | 32 |
| jester | PHOUSE | 1800 | 640 | 5.175 | 1.605 | 2.58 | 1.611 | 1.606 | 2.298 | 9 |
| jester | BHOUSSSE | 1800 | 40 | 2.152 | 1.81 | 2.003 | 1.748 | 1.748 | 1.078 | 11 |
| jester | it | 1800 | 430 | 13.262 | 1.361 | 1.331 | 1.825 | 2.94 | 7.14 | 8 |
| jester | NOOB | 1800 | 1,480 | 8.78 | 1.685 | 1.682 | 3.368 | 3.174 | 6.811 | 15 |
| jester | MOONCAT | 1800 | 10 | 1.932 | 1.837 | 1.467 | 1.173 | 0.898 | 0.999 | 512 |
| jester | all/in | 1800 | 470 | 6.203 | 4.811 | 4.706 | 4.859 | 5.183 | 5.948 | NULL |
| jester | TOLYBOT | 1800 | 10 | 3.312 | 3.175 | 2.539 | 2.077 | 1.375 | 1.788 | 28 |
| jester | ZEC | 1800 | 1,020 | 2.014 | 1.408 | 1.211 | 1.235 | 1.085 | 0.926 | 17 |
| jester | NUKE | 1800 | 600 | 3.957 | 1.954 | 1.706 | 1.648 | 0.925 | 1.282 | 51 |
| jester | WIF | 1800 | 10 | 2.139 | 1.525 | 1.051 | 1.037 | 1.433 | 0.936 | 26 |
| jester | ISRAELI | 1800 | 210 | 1.481 | 1 | 1 | 1.463 | 0.728 | 0.728 | 219 |
| mitch | kai | 1800 | 150 | 2.455 | 1.093 | 1.715 | 1.998 | 1.644 | 1.581 | NULL |
| mitch | glown | 1800 | 570 | 8.644 | 1.955 | 3.033 | 5.413 | 7.555 | 8.644 | NULL |
| mitch | HARD | 1800 | 410 | 4.69 | 4.536 | 4.536 | 4.536 | 4.536 | 4.69 | NULL |
| mitch | RNT | 1800 | 410 | 7.11 | 6.115 | 6.115 | 6.115 | 6.115 | 7.11 | NULL |

## Data problems

- hits whose in-window peak lies in the last 5 minutes (the run continued after the window; window multiples are lower bounds): 0xkgc/MelonMusk (peak at 1780 s, 13.573x), gampsito/Polycat (peak at 1710 s, 19.195x), hashbergers/PINU (peak at 1770 s, 54.723x), jester/KIKI (peak at 1790 s, 12.481x), jester/WATERFALL (peak at 1630 s, 54.85x), jester/COBSON (peak at 1710 s, 8.902x)
- hits with fewer than 50 trades in the window (nothing happened until after minute 30): mitch/MITCH (4 trades)
- 0xkgc/MAC: quoted in XsqE9cRRpzxcGKDXj1BJ7Xmg4GRhZoyY1KpmGSxAWT2 (launchpad stonkfun); SOL rate 0.388 quote/SOL from 2 minute(s) of router legs
- 0xkgc/MAC: LaunchLab launch; market accounts taken from the create tx (2, vault authority WLHv2UAZ… added); Phase B's dev_first_buy_sol/sol_in_* for this launch are rent only and were not used
- 0xkgc/ZUPERCYCLE: quoted in A7bdiYdS5GjqGFtxf17ppRHtDKPkkRqbKtR27dxvQXaS (launchpad stonkfun); SOL rate 0.089 quote/SOL from 29 minute(s) of router legs
- 0xkgc/ZUPERCYCLE: LaunchLab launch; market accounts taken from the create tx (2, vault authority WLHv2UAZ… added); Phase B's dev_first_buy_sol/sol_in_* for this launch are rent only and were not used
- 0xkgc/BABYLMAO: quoted in H74CYmXgMkYHYuSRsZt6RJb4NYp2u72Vw8BS5huApump (launchpad stonkfun); SOL rate 39,839.083 quote/SOL from 19 minute(s) of router legs
- 0xkgc/BABYLMAO: LaunchLab launch; market accounts taken from the create tx (2, vault authority WLHv2UAZ… added); Phase B's dev_first_buy_sol/sol_in_* for this launch are rent only and were not used
- 0xkgc/AAPLTOP: quoted in XsbEhLAtcf6HdfpFZ5xEMdqW8nfAvcsP5bdudRLJzJp (launchpad stonkfun); SOL rate 0.327 quote/SOL from 30 minute(s) of router legs
- 0xkgc/AAPLTOP: LaunchLab launch; market accounts taken from the create tx (2, vault authority WLHv2UAZ… added); Phase B's dev_first_buy_sol/sol_in_* for this launch are rent only and were not used
- 0xkgc/fries: quoted in XsqE9cRRpzxcGKDXj1BJ7Xmg4GRhZoyY1KpmGSxAWT2 (launchpad Pump.fun); SOL rate 0.394 quote/SOL from 30 minute(s) of router legs
- 0xkgc/CRIME: quoted in pumpCmXqMfrsAkQ5r49WcJnRayYRqmXz6ae8H7H9Dfn (launchpad Pump.fun); SOL rate 23,783.239 quote/SOL from 30 minute(s) of router legs
- 0xkgc/dump: quoted in 7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs (launchpad Pump.fun); SOL rate 0.041 quote/SOL from 29 minute(s) of router legs
- 0xkgc/UNC: observed window ends at 845 s (LaunchLab curve migrated at 845.0 s and the pool was never pulled); later marks NULL
- 0xkgc/UNC: quoted in 6UpQcMAb5xMzxc7ZfPaVMgx3KqsvKZdT5U718BzD5We2 (launchpad stonkfun); SOL rate 73.448 quote/SOL from 14 minute(s) of router legs
- 0xkgc/UNC: LaunchLab launch; market accounts taken from the create tx (2, vault authority WLHv2UAZ… added); Phase B's dev_first_buy_sol/sol_in_* for this launch are rent only and were not used
- 0xkgc/BIKESON: quoted in CbyTNf7UPzvewHh4Zp6umogM2RWahhmGRJWLJnPwpump (launchpad stonkfun); SOL rate 369,533.244 quote/SOL from 30 minute(s) of router legs
- 0xkgc/BIKESON: LaunchLab launch; market accounts taken from the create tx (2, vault authority WLHv2UAZ… added); Phase B's dev_first_buy_sol/sol_in_* for this launch are rent only and were not used
- 0xkgc/ZEC: quoted in A7bdiYdS5GjqGFtxf17ppRHtDKPkkRqbKtR27dxvQXaS (launchpad Pump.fun); SOL rate 0.09 quote/SOL from 29 minute(s) of router legs
- 0xkgc/RIPASS: quoted in H74CYmXgMkYHYuSRsZt6RJb4NYp2u72Vw8BS5huApump (launchpad stonkfun); SOL rate 28,845.216 quote/SOL from 30 minute(s) of router legs
- 0xkgc/RIPASS: LaunchLab launch; market accounts taken from the create tx (2, vault authority WLHv2UAZ… added); Phase B's dev_first_buy_sol/sol_in_* for this launch are rent only and were not used
- gampsito/Biz: observed window ends at 1070 s (pull truncated at 30,000 tx); later marks NULL
- gampsito/BTD: quoted in XsqE9cRRpzxcGKDXj1BJ7Xmg4GRhZoyY1KpmGSxAWT2 (launchpad Pump.fun); SOL rate 0.385 quote/SOL from 30 minute(s) of router legs
- jester/ALBERT: quoted in EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v (launchpad Pump.fun); SOL rate 73.824 quote/SOL from 27 minute(s) of router legs
- jester/COBSON: quoted in EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v (launchpad Pump.fun); SOL rate 71.372 quote/SOL from 29 minute(s) of router legs
- jester/SEKOLAH: quoted in EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v (launchpad Pump.fun); SOL rate 77.677 quote/SOL from 24 minute(s) of router legs
- jester/TOLYBOT: quoted in SKRbvo6Gf7GondiT3BbTfuRDPqLWei4j2Qy2NPGZhW3 (launchpad ); SOL rate 5,208.521 quote/SOL from 20 minute(s) of router legs
- jester/WIF: quoted in SPHRp8cZaSQBTp1KMNP4V1X821SXhXWt4Q2yLdyHzju (launchpad stonkfun); SOL rate 0.736 quote/SOL from 7 minute(s) of router legs
- jester/WIF: LaunchLab launch; market accounts taken from the create tx (2, vault authority WLHv2UAZ… added); Phase B's dev_first_buy_sol/sol_in_* for this launch are rent only and were not used
- jester/ISRAELI: quoted in XsoCS1TfEyfFhfvj8EtZ528L3CaKBDBRqRapnBbDF2W (launchpad Pump.fun); SOL rate 0.133 quote/SOL from 1 minute(s) of router legs
- mitch/SOSA: no create transaction found in the window
- mitch/BCC: no create transaction found in the window
- mitch/XXX: no create transaction found in the window
- mitch/fagua: no create transaction found in the window
- mitch/JDS: no create transaction found in the window
- Phase B `dev_fee_lamports_med` is a window median over every dev tx; `dev_fee_first_tx` here is the create-tx fee minus 5000 (measurable at second 0).
- `outside_*` includes KOL / smart-money wallets (kol_* never fetched). Members are the 32 wallets in member_wallets.json; slingoor counts as a member on retardmode's launches and vice versa.
- Sells after a truncated or migrated window are unobservable, so `share_sold_in_window` and `net_sol_*` understate exits on catcall, sling, LIZARD (slingoor hits) and on ETH/GRND/LMAO! (LaunchLab).
- `net_sol_marked` values the unsold remainder at the last 10-s buy VWAP of the observed window; for launches whose run came after minute 30 (PEACE, MRHATE, RETARDIO) this understates the eventual result.
- Multiples for non-SOL-quoted launches are in quote units and assume the quote/SOL rate is flat over the mark; `sol_*` for them carries the per-minute router rate.
- Threshold rules are evaluated in-sample on 14/4 hits; they describe the sample, they do not predict.
