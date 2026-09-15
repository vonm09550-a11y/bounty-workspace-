# SUMMARY_cross — cross-launch tables, loop 1 (Phase C, offline)

## Reading (10 lines)

1. Both launchers buy in the create transaction on every launch (28/28 slingoor, 19/19 retardmode), so the only thing visible before anyone else can act is the size of that buy and, seconds later, whether the dev sells into the first buyers.
2. On slingoor a create-slot buy of >= 35% of supply with no dev sell in the first 60 s picks 7 of 13 hits and 1 of 12 misses (SEXY); adding >= 2 same-slot bundled buyers gives 6 of 13 hits and 0 of 12 misses. "No dev sell by 300 s" alone keeps 11 of 13 hits and 2 of 12 misses. He dumped 11 of 14 misses within 5-217 s (median 17 s) and still sold 100% at 13-15 s on two launches that went on to be hits (WINNIE, HOODWARTS).
3. On retardmode the same rule (>= 35% and no sell by 60 s) picks 3 of 4 hits and 1 of 15 misses (WOJAK, dumped at 73 s); at 120 s it is 3 of 4 vs 0 of 15. He sold 12 of 15 misses within seconds (median 7.5 s) and none of the 4 hits. PEACE (12.5% buy) is the hit that no size rule catches.
4. Scale is launcher-specific: slingoor's misses draw more wallets in minute 1 (median 126) than retardmode's hits (18), because slingoor's curve is bundle-filled and graduates almost at once (18 of 28 within 60 s, median 4 s; hits 11/14, misses 7/14), so graduation speed is his habit, not a hit signal. Retardmode's hits graduate in 8-20 minutes and no miss but WOJAK graduates at all.
5. Members are never early. Outside wallets buy in the create slot on every launch (outside_first_buy_s = 0), while the first member buy on hits is at a median 184 s (min 38 s, pooled n=14); only 14 of the 32 member wallets ever bought a loop-1 launch and 18 never did.
6. Two members carry the group: ibuycoin (Owner) bought 11 launches, 10 of them hits, median entry 115 s; trenchdigger bought 12, 10 hits, median entry 235 s. Everyone else bought 1-3. Their median entry price is already 6x (ibuycoin) and 13x (trenchdigger) above the dev's average price, i.e. they enter after the first leg, and they exit only partially inside the window (realized -13 and -9 SOL, marked +24 and +18 SOL).
7. Being late still paid on hits: from the price at 60 s the best price still ahead inside the window was a median 3.6x (pooled n=16; slingoor 3.6x n=12, retardmode 5.1x n=4), from 120 s 2.6x, from 300 s 2.3x. Four hits (OFFICIAL, TOAD, PQ, PEACE) peaked in the last five minutes and Graped/ETH had essentially no window trading, so these are lower bounds.
8. Peaks come late: median in-window peak at 895 s on slingoor hits and 1465 s on retardmode hits; misses peak at 15 s and 50 s. A buyer at 30-60 s on a slingoor hit sat at 8-13x the dev's average price, which is the multiple of his 30-60 SOL bundle, not a gain available to anyone else.
9. Fingerprints: slingoor 32 launches in 75 days (median gap 14 h, a 6-launch LaunchLab/"stonkfun" burst quoted in other tokens at the end, 5 of 6 misses), priority fee on hits 2-3x that on misses (median 72k vs 35k lamports on the create tx); retardmode 19 launches in 314 days, 7 of 19 created in the 01h UTC hour, small fees (11-20k), bundle proxy uninformative (0-5 same-slot buyers either way).
10. Sample sizes are 14 and 4 hits; every rule above is in-sample. The 4 MPN rows are mint-only (no curve, no trades) and are excluded; three slingoor hits are truncated at 30,000 tx (427-881 s) and the LaunchLab ETH/GRND/LMAO! windows end at migration (3-7 s), so their later marks are NULL.

Built by `scripts/anatomy_cross.py` from the Phase A transaction files and the Phase B tables (see the script docstring). Trades are re-derived from account-level token balance changes with an extended market-account set; multiples are in quote units; SOL figures for non-SOL-quoted launches use the window's own router rate. `kol_*` was never fetched, so 'outside' = everyone but the creator and the 31 other members.

## Coverage

- slingoor: 32 rows in the launch list, 28 with trades (hits 14, misses 14); coverage >= 60 s: 25, >= 300 s: 25, full 1800 s: 22; non-SOL quote: 8 (SOL rate observable on 8); dev never bought: 0
- retardmode: 19 rows in the launch list, 19 with trades (hits 4, misses 15); coverage >= 60 s: 19, >= 300 s: 19, full 1800 s: 19; non-SOL quote: 4 (SOL rate observable on 4); dev never bought: 0
- trades in the cache: 106493 across 47 launches; member-launch rows: 40 (40 with a buy)

## 1. Member graph (creator excluded on his own launches; entry = first buy, s after create)

Columns: launches bought per launcher, hits among them, median/min entry lag, median first-buy SOL and per-launch SOL, share of bought launches with any sell inside the observed window, median hold (first sell − first buy), realized net SOL (sells − buys, unrealized remainder counted at 0) and marked net SOL (remainder valued at the window's last 10-s buy VWAP), over launches where SOL is computable. `*` marks hits in the launch list; the 3 truncated slingoor hits and the LaunchLab launches shorten the observable window (n_trunc).

| username | n_launches_bought | n_slingoor | n_retardmode | n_hits | n_nonhits | med_entry_s | min_entry_s | med_entry_mult_vs_dev | med_first_buy_sol | med_buy_sol_per_launch | total_buy_sol | share_sold_in_window | med_hold_s | n_closed_in_window | net_sol_realized | net_sol_marked | n_sol_computable | n_truncated_after_buy | n_sell_only | tags |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| trenchdigger | 12 | 10 | 2 | 10 | 2 | 235 | 24 | 12.71 | 1.487 | 2.918 | 42.418 | 0.75 | 65 | 4 | -9.427 | 17.599 | 12 | 3 | 0 | launchpad_smart |
| ibuycoin | 11 | 8 | 3 | 10 | 1 | 115 | 38 | 6.328 | 0.988 | 2.876 | 29.477 | 0.636 | 121 | 3 | -13.129 | 23.804 | 11 | 2 | 0 | gmgn,arbitrager,padre,gmgn_go |
| stellanyang | 3 | 0 | 3 | 3 | 0 | 1,095 | 724 | 14.859 | 2.881 | 2.897 | 24.59 | 0 | NULL | 0 | -24.59 | 4.819 | 3 | 0 | 0 | bluechip_owner |
| hashbergers | 2 | 2 | 0 | 2 | 0 | 768 | 70 | 39.956 | 2.458 | 11.765 | 23.53 | 1 | 175 | 2 | 6.103 | 6.103 | 2 | 0 | 0 | sandwich_bot,axiom,padre |
| ibuyrunners | 2 | 0 | 2 | 1 | 1 | 953 | 799 | 14.364 | 0.455 | 1.559 | 3.117 | 0 | NULL | 0 | -3.117 | -0.585 | 2 | 0 | 0 | axiom |
| TMH | 2 | 0 | 2 | 0 | 2 | 983.5 | 269 | 4.07 | 1.702 | 1.702 | 3.404 | 0.5 | 37 | 1 | -2.346 | 0.04 | 2 | 0 | 0 | arbitrager,padre |
| bsol_x | 1 | 1 | 0 | 1 | 0 | 60 | 60 | 43.537 | 2.628 | 2.628 | 2.628 | 0 | NULL | 0 | -2.628 | 2.603 | 1 | 1 | 0 |  |
| waynecapital | 1 | 1 | 0 | 1 | 0 | 100 | 100 | 2.97 | 0.988 | 0.988 | 0.988 | 1 | 22 | 1 | 0.724 | 0.724 | 1 | 0 | 0 | axiom,smart_degen,padre,arbitrager |
| LowiqdegN | 1 | 1 | 0 | 1 | 0 | 131 | 131 | 31.752 | 0.495 | 0.495 | 0.495 | 0 | NULL | 0 | -0.495 | 0.149 | 1 | 1 | 0 |  |
| baseddom | 1 | 0 | 1 | 0 | 1 | 417 | 417 | 2.671 | 0.049 | 0.049 | 0.049 | 0 | NULL | 0 | -0.049 | -0.019 | 1 | 0 | 0 | arbitrager |
| mitch | 1 | 0 | 1 | 1 | 0 | 602 | 602 | 7.209 | 9.769 | 9.769 | 9.769 | 0 | NULL | 0 | -9.769 | 58.925 | 1 | 0 | 0 | bluechip_owner |
| badattrading | 1 | 1 | 0 | 1 | 0 | 1,207 | 1,207 | 24.058 | 1.98 | 1.98 | 1.98 | 0 | NULL | 0 | -1.98 | 2.949 | 1 | 0 | 0 | smart_degen,gmgn_go,top_followed,gmgn |
| hoeleeshiet | 1 | 1 | 0 | 1 | 0 | 1,461 | 1,461 | 66.078 | 0.013 | 0.024 | 0.024 | 0 | NULL | 0 | -0.024 | -0.005 | 1 | 0 | 0 |  |
| slingoor | 1 | 0 | 1 | 0 | 1 | 1,461 | 1,461 | 4.538 | 6.306 | 6.306 | 6.306 | 0 | NULL | 0 | -6.306 | 2.255 | 1 | 0 | 0 | arbitrager,axiom,top_dev,top_renamed,top_followed |
| 0xPromiser | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 |  |
| 0xkgc | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | arbitrager,padre |
| Fabricci | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 |  |
| MidCurveMortal | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | gmgn,gmgn_go |
| SleepyyMike | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | gmgn_go,gmgn |
| agentpuffle | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | axiom |
| alpha_co | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | arbitrager |
| b69 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | trojan |
| gampsito | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | launchpad_smart,axiom,arbitrager |
| jester | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | axiom,kol,wash_trader,gmgn_go,gmgn,arbitrager,padre,top_followed |
| kanpai | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | arbitrager |
| lvvpumpy | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | padre |
| moonpie666 | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 |  |
| pumpguy__ | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | arbitrager |
| retardmode | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | top_dev |
| rohwhale | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 | trojan |
| trenchdiga | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 |  |
| usurp | 0 | 0 | 0 | 0 | 0 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 0 | NULL | NULL | 0 | 0 | 0 |  |

Launches bought per member (symbol, `*` = hit, @ first-buy second):

- trenchdigger: INSANE@24s,catcall*@105s,OFFICIAL*@138s,WOJAK@139s,WINNIE*@141s,sling*@229s,LIZARD*@241s,PQ*@265s,Chairman*@307s,HOODWARTS*@612s,DIDDY*@626s,nothing*@1431s
- ibuycoin: HOODWARTS*@38s,RETARDIO*@38s,WINNIE*@62s,LIZARD*@70s,DIDDY*@90s,catcall*@115s,OFFICIAL*@185s,MARVIN*@406s,PQ*@577s,Chairman*@1380s,WOJAK@1689s
- stellanyang: RETARDIO*@724s,MRHATE*@1095s,PQ*@1206s
- hashbergers: DIDDY*@70s,Chairman*@1466s
- ibuyrunners: WOJAK@799s,RETARDIO*@1107s
- TMH: yoohoo@269s,WOJAK@1698s
- bsol_x: LIZARD*@60s
- waynecapital: WINNIE*@100s
- LowiqdegN: catcall*@131s
- baseddom: GIGAY@417s
- mitch: PQ*@602s
- badattrading: TOAD*@1207s
- hoeleeshiet: Chairman*@1461s
- slingoor: WOJAK@1461s

Members never seen buying in any window: 0xPromiser, 0xkgc, Fabricci, MidCurveMortal, SleepyyMike, agentpuffle, alpha_co, b69, gampsito, jester, kanpai, lvvpumpy, moonpie666, pumpguy__, retardmode, rohwhale, trenchdiga, usurp

### Member positions on hits (one row per member × hit)

| dev | symbol | username | first_buy_s | entry_mult_vs_dev | first_buy_sol | buy_sol | buy_supply_share | sold | first_sell_s | hold_s | sold_share | net_sol_realized | net_sol_marked | coverage_s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| retardmode | MRHATE | stellanyang | 1095 | 3.223 | 0.967 | 2.897 | 0.02 | False | NULL | NULL | 0 | -2.897 | 0.091 | 1800 |
| retardmode | PQ | trenchdigger | 265 | 4.965 | 0.956 | 0.956 | 0.002 | False | NULL | NULL | 0 | -0.956 | 9.004 | 1800 |
| retardmode | PQ | ibuycoin | 577 | 6.328 | 1.389 | 2.122 | 0.003 | True | 1,266 | 689 | 0.503 | 2.631 | 9.907 | 1800 |
| retardmode | PQ | mitch | 602 | 7.209 | 9.769 | 9.769 | 0.016 | False | NULL | NULL | 0 | -9.769 | 58.925 | 1800 |
| retardmode | PQ | stellanyang | 1206 | 14.859 | 2.881 | 2.881 | 0.002 | False | NULL | NULL | 0 | -2.881 | 6.787 | 1800 |
| retardmode | RETARDIO | ibuycoin | 38 | 3.209 | 0.988 | 0.988 | 0.006 | False | NULL | NULL | 0 | -0.988 | 4.566 | 1800 |
| retardmode | RETARDIO | stellanyang | 724 | 23.575 | 3.862 | 18.812 | 0.018 | False | NULL | NULL | 0 | -18.812 | -2.059 | 1800 |
| retardmode | RETARDIO | ibuyrunners | 1107 | 19.059 | 0.232 | 0.435 | 0.000475 | False | NULL | NULL | 0 | -0.435 | 0.000421 | 1800 |
| slingoor | Chairman | trenchdigger | 307 | 34.738 | 1.981 | 5.942 | 0.004 | True | 1,363 | 1,056 | 0.5 | 1.785 | 7.263 | 1800 |
| slingoor | Chairman | ibuycoin | 1380 | 69.285 | 0.992 | 4.065 | 0.001 | False | NULL | NULL | 0 | -4.065 | -0.647 | 1800 |
| slingoor | Chairman | hoeleeshiet | 1461 | 66.078 | 0.013 | 0.024 | 6.34e-06 | False | NULL | NULL | 0 | -0.024 | -0.005 | 1800 |
| slingoor | Chairman | hashbergers | 1466 | 65.978 | 0.015 | 0.015 | 3.48e-06 | True | 1,651 | 185 | 1 | -0.004 | -0.004 | 1800 |
| slingoor | DIDDY | hashbergers | 70 | 13.933 | 4.901 | 23.515 | 0.022 | True | 235 | 165 | 1 | 6.107 | 6.107 | 1800 |
| slingoor | DIDDY | ibuycoin | 90 | 13.884 | 0.495 | 3.467 | 0.002 | True | 601 | 511 | 0.475 | -1.165 | 1.21 | 1800 |
| slingoor | DIDDY | trenchdigger | 626 | 34.993 | 1.981 | 7.928 | 0.003 | True | 709 | 83 | 1 | -0.033 | -0.033 | 1800 |
| slingoor | HOODWARTS | ibuycoin | 38 | 1.864 | 0.099 | 1.087 | 0.006 | True | 134 | 96 | 1 | 0.388 | 0.388 | 1800 |
| slingoor | HOODWARTS | trenchdigger | 612 | 1.994 | 2.964 | 5.927 | 0.049 | True | 677 | 65 | 0.411 | -3.248 | -1.055 | 1800 |
| slingoor | LIZARD | bsol_x | 60 | 43.537 | 2.628 | 2.628 | 0.000725 | False | NULL | NULL | 0 | -2.628 | 2.603 | 881 |
| slingoor | LIZARD | ibuycoin | 70 | 51.989 | 0.992 | 6.448 | 0.001 | True | 129 | 59 | 0.259 | -4.475 | 2.411 | 881 |
| slingoor | LIZARD | trenchdigger | 241 | 90.344 | 1.984 | 2.976 | 0.000434 | False | NULL | NULL | 0 | -2.976 | 0.152 | 881 |
| slingoor | MARVIN | ibuycoin | 406 | 5.418 | 0.012 | 2.876 | 0.009 | False | NULL | NULL | 0 | -2.876 | 1.824 | 1800 |
| slingoor | OFFICIAL | trenchdigger | 138 | 10.773 | 0.495 | 1.485 | 0.003 | True | 967 | 829 | 0.712 | 1.117 | 2.478 | 1800 |
| slingoor | OFFICIAL | ibuycoin | 185 | 21.526 | 0.099 | 0.099 | 0.000112 | True | 200 | 15 | 1 | 0.004 | 0.004 | 1800 |
| slingoor | TOAD | badattrading | 1207 | 24.058 | 1.98 | 1.98 | 0.002 | False | NULL | NULL | 0 | -1.98 | 2.949 | 1800 |
| slingoor | WINNIE | ibuycoin | 62 | 4.562 | 0.988 | 1.482 | 0.006 | True | 355 | 293 | 1 | 2.883 | 2.883 | 1800 |
| slingoor | WINNIE | waynecapital | 100 | 2.97 | 0.988 | 0.988 | 0.006 | True | 122 | 22 | 1 | 0.724 | 0.724 | 1800 |
| slingoor | WINNIE | trenchdigger | 141 | 8.441 | 0.99 | 2.968 | 0.007 | True | 1,551 | 1,410 | 0.602 | -1.307 | -0.594 | 1800 |
| slingoor | catcall | trenchdigger | 105 | 14.647 | 0.495 | 0.495 | 0.001 | True | 152 | 47 | 0.744 | 0.5 | 0.857 | 427 |
| slingoor | catcall | ibuycoin | 115 | 20.343 | 0.495 | 2.97 | 0.003 | True | 236 | 121 | 0.322 | -1.592 | 0.916 | 427 |
| slingoor | catcall | LowiqdegN | 131 | 31.752 | 0.495 | 0.495 | 0.000523 | False | NULL | NULL | 0 | -0.495 | 0.149 | 427 |
| slingoor | nothing | trenchdigger | 1431 | 21.978 | 0.99 | 0.99 | 0.000797 | True | 1,437 | 6 | 1 | -0.033 | -0.033 | 1800 |
| slingoor | sling | trenchdigger | 229 | 140.546 | 0.993 | 0.993 | 8.4e-05 | True | 270 | 41 | 1 | -0.145 | -0.145 | 872 |

### Member positions on misses

| dev | symbol | username | first_buy_s | entry_mult_vs_dev | first_buy_sol | buy_sol | sold | first_sell_s | hold_s | sold_share | net_sol_realized | net_sol_marked | coverage_s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| retardmode | GIGAY | baseddom | 417 | 2.671 | 0.049 | 0.049 | False | NULL | NULL | 0 | -0.049 | -0.019 | 1800 |
| retardmode | WOJAK | trenchdigger | 139 | 4.606 | 2.867 | 2.867 | False | NULL | NULL | 0 | -2.867 | 0.967 | 1800 |
| retardmode | WOJAK | ibuyrunners | 799 | 9.67 | 0.679 | 2.682 | False | NULL | NULL | 0 | -2.682 | -0.586 | 1800 |
| retardmode | WOJAK | slingoor | 1461 | 4.538 | 6.306 | 6.306 | False | NULL | NULL | 0 | -6.306 | 2.255 | 1800 |
| retardmode | WOJAK | ibuycoin | 1689 | 5.427 | 2.424 | 3.874 | False | NULL | NULL | 0 | -3.874 | 0.343 | 1800 |
| retardmode | WOJAK | TMH | 1698 | 6.245 | 2.416 | 2.416 | False | NULL | NULL | 0 | -2.416 | -0.03 | 1800 |
| retardmode | yoohoo | TMH | 269 | 1.895 | 0.988 | 0.988 | True | 306 | 37 | 1 | 0.07 | 0.07 | 1800 |
| slingoor | INSANE | trenchdigger | 24 | 7.121 | 2.964 | 8.891 | True | 26 | 2 | 1 | -1.264 | -1.264 | 1800 |

## 2. Launcher fingerprints

### slingoor

| metric | all n | all med [p25, p75] | hits n | hits med [p25, p75] | misses n | misses med [p25, p75] |
|---|---|---|---|---|---|---|
| dev_supply_share | 28 | 0.443 [0.248, 0.61] | 14 | 0.576 [0.375, 0.66] | 14 | 0.381 [0.229, 0.465] |
| dev_first_buy_sol | 28 | 22.368 [15.742, 40.444] | 14 | 35.063 [18.664, 49.058] | 14 | 17.977 [11.495, 23.703] |
| dev_same_slot_buyers | 28 | 3.5 [0, 7] | 14 | 5 [2, 7.75] | 14 | 1 [0, 4] |
| dev_fee_lamports_med | 28 | 35,000 [10,797.5, 150,551.375] | 14 | 76,434.5 [22,200.5, 154,888.125] | 14 | 27,908.75 [8,000, 75,582.75] |
| dev_fee_first_tx | 28 | 35,000 [27,161, 92,290.5] | 14 | 72,120 [27,185, 110,090.25] | 14 | 35,000 [27,218.25, 42,551] |
| dev_first_sell_s | 13 | 15 [12, 155] | 2 | 14 [13.5, 14.5] | 11 | 17 [11.5, 167] |
| dev_sold_share_30m | 22 | 1 [0, 1] | 10 | 0 [0, 0] | 12 | 1 [1, 1] |
| dev_sell_sol_30m | 22 | 11.28 [0, 36.381] | 10 | 0 [0, 0] | 12 | 25.911 [11.459, 38.531] |
| dev_sold_share_60s | 25 | 0 [0, 1] | 13 | 0 [0, 0] | 12 | 1 [0, 1] |
| dev_sold_share_300s | 25 | 0 [0, 1] | 13 | 0 [0, 0] | 12 | 1 [0.987, 1] |
| grad_s | 20 | 4 [2, 22.75] | 12 | 4 [2, 22.75] | 8 | 4.5 [2.25, 12.5] |
| peak10_mult | 28 | 6.841 [2.753, 50.399] | 14 | 50.482 [14.92, 64.781] | 14 | 3.017 [2.544, 6.306] |
| peak10_ts_s | 28 | 125 [0, 867.5] | 14 | 895 [237.5, 1,295] | 14 | 15 [0, 80] |
| sol_in_1m | 25 | 274.913 [175.351, 394.916] | 13 | 385.135 [279.3, 680.086] | 12 | 179.93 [116.353, 242.219] |
| sol_in_5m | 25 | 512.206 [212.433, 659.468] | 13 | 659.468 [591.017, 1,593.634] | 12 | 216.059 [123.442, 324.054] |
| n_wallets_1m | 25 | 242 [123, 401] | 13 | 374 [242, 460] | 12 | 125.5 [105.5, 235] |
| n_wallets_5m | 25 | 499 [151, 691] | 13 | 659 [569, 1,074] | 12 | 165 [123, 341.75] |

| count | all | hits | misses |
|---|---|---|---|
| n_launches | 28 | 14 | 14 |
| n_dev_sold_in_window | 13 | 2 | 11 |
| n_dev_sold_by_60s | 9 | 2 | 7 |
| n_dev_sold_by_300s | 12 | 2 | 10 |
| n_non_sol_quote | 8 | 2 | 6 |
| n_graduated_in_window | 20 | 12 | 8 |
| n_graduated_by_60s | 18 | 11 | 7 |
| n_dev_buy_in_create_slot | 28 | 14 | 14 |
| launchpad:pump_agent | 1 | 1 | 0 |
| launchpad:Pump.fun | 21 | 12 | 9 |
| launchpad:stonkfun | 6 | 1 | 5 |

Launch hour (UTC), all launches in the list (hits in brackets): 00h: 1 (0), 01h: 1 (0), 02h: 3 (2), 03h: 3 (0), 05h: 3 (3), 06h: 1 (0), 08h: 1 (0), 13h: 2 (1), 15h: 3 (0), 16h: 2 (0), 17h: 1 (1), 19h: 2 (2), 20h: 3 (1), 21h: 2 (1), 22h: 3 (2), 23h: 1 (1)

Weekday (UTC): Fri 4, Mon 4, Sat 7, Sun 3, Thu 9, Tue 2, Wed 3
- hour_utc: n=32 median=15 p25=4.5 p75=20 min=0 max=23 (distribution of the UTC hour of creation)
- gap_between_launches_h: n=31 median=13.812 p25=3.366 p75=45.068 min=0.068 max=727.743 (hours between consecutive launches)
- book_bundler_rate: n=32 median=0 p25=0 p75=0.011 min=0 max=0.067 (dev_tokens.bundler_rate)
- span: 32 launches over 74.793 days (first to last in the list)
- gaps < 1 h: 6; gaps < 24 h: 18

### retardmode

| metric | all n | all med [p25, p75] | hits n | hits med [p25, p75] | misses n | misses med [p25, p75] |
|---|---|---|---|---|---|---|
| dev_supply_share | 19 | 0.152 [0.05, 0.353] | 4 | 0.418 [0.296, 0.505] | 15 | 0.097 [0.034, 0.199] |
| dev_first_buy_sol | 19 | 4.944 [1.488, 14.735] | 4 | 19.621 [12.005, 30.236] | 15 | 2.969 [0.995, 9.717] |
| dev_same_slot_buyers | 19 | 1 [0, 2.5] | 4 | 0.5 [0, 1.25] | 15 | 2 [0.5, 3] |
| dev_fee_lamports_med | 19 | 11,000 [7,000, 104,092.5] | 4 | 20,500 [10,750, 32,500] | 15 | 9,079 [7,000, 125,000] |
| dev_fee_first_tx | 19 | 11,000 [10,000, 30,000] | 4 | 20,500 [10,750, 32,500] | 15 | 11,000 [10,000, 30,000] |
| dev_first_sell_s | 12 | 7.5 [6, 78.75] | 0 | NULL [NULL, NULL] | 12 | 7.5 [6, 78.75] |
| dev_sold_share_30m | 19 | 0.761 [0, 1] | 4 | 0 [0, 0] | 15 | 0.895 [0.5, 1] |
| dev_sell_sol_30m | 19 | 1.744 [0, 11.989] | 4 | 0 [0, 0] | 15 | 4.531 [1.2, 16.575] |
| dev_sold_share_60s | 19 | 0 [0, 0.609] | 4 | 0 [0, 0] | 15 | 0.5 [0, 0.829] |
| dev_sold_share_300s | 19 | 0.719 [0, 1] | 4 | 0 [0, 0] | 15 | 0.895 [0.5, 1] |
| grad_s | 4 | 717 [649.5, 980.25] | 3 | 728 [604, 1,232.5] | 1 | 706 [706, 706] |
| peak10_mult | 19 | 2.654 [1.665, 4.053] | 4 | 16.556 [3.843, 39.658] | 15 | 2.029 [1.328, 3.245] |
| peak10_ts_s | 19 | 120 [0, 800] | 4 | 1,465 [1,160, 1,692.5] | 15 | 50 [0, 195] |
| sol_in_1m | 19 | 46.352 [13.245, 65.278] | 4 | 36.057 [15.823, 57.633] | 15 | 46.352 [13.245, 65.572] |
| sol_in_5m | 19 | 49.126 [24.32, 104.45] | 4 | 68.505 [31.856, 108.985] | 15 | 49.126 [24.32, 100.246] |
| n_wallets_1m | 19 | 37 [9, 64.5] | 4 | 17.5 [5.5, 38.25] | 15 | 41 [19.5, 74] |
| n_wallets_5m | 19 | 59 [35.5, 122.5] | 4 | 82.5 [61.75, 96.25] | 15 | 58 [33, 134.5] |

| count | all | hits | misses |
|---|---|---|---|
| n_launches | 19 | 4 | 15 |
| n_dev_sold_in_window | 12 | 0 | 12 |
| n_dev_sold_by_60s | 8 | 0 | 8 |
| n_dev_sold_by_300s | 12 | 0 | 12 |
| n_non_sol_quote | 4 | 1 | 3 |
| n_graduated_in_window | 4 | 3 | 1 |
| n_graduated_by_60s | 0 | 0 | 0 |
| n_dev_buy_in_create_slot | 19 | 4 | 15 |
| launchpad:Pump.fun | 19 | 4 | 15 |

Launch hour (UTC), all launches in the list (hits in brackets): 01h: 7 (1), 02h: 1 (1), 07h: 1 (0), 08h: 2 (0), 10h: 1 (0), 13h: 1 (1), 17h: 1 (0), 18h: 3 (0), 20h: 1 (1), 21h: 1 (0)

Weekday (UTC): Mon 2, Sat 2, Sun 3, Thu 3, Tue 4, Wed 5
- hour_utc: n=19 median=8 p25=1 p75=17.5 min=1 max=21 (distribution of the UTC hour of creation)
- gap_between_launches_h: n=18 median=19.583 p25=1.915 p75=91.055 min=0.034 max=3,273.33 (hours between consecutive launches)
- book_bundler_rate: n=19 median=0 p25=0 p75=0.019 min=0 max=0.275 (dev_tokens.bundler_rate)
- span: 19 launches over 313.764 days (first to last in the list)
- gaps < 1 h: 4; gaps < 24 h: 9

### Per-launch dev fingerprint (both launchers)

| dev | symbol | hit | launchpad_platform | coverage_s | dev_supply_share | dev_first_buy_sol | dev_same_slot_buyers | dev_fee_first_tx | dev_fee_lamports_med | dev_first_sell_s | dev_sold_share_60s | dev_sold_share_300s | dev_sold_share_30m | grad_s | peak10_mult | peak10_ts_s |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| retardmode | CARDAMOM | False | Pump.fun | 1800 | 0.034 | 0.989 | 0 | 30,000 | 125,000 | 97 | 0 | 1 | 1 | NULL | 2.654 | 770 |
| retardmode | NIGGERMAS | False | Pump.fun | 1800 | 0.034 | 0.989 | 2 | 30,000 | 125,000 | 48 | 1 | 1 | 1 | NULL | 1.803 | 170 |
| retardmode | HANUKKAH | False | Pump.fun | 1800 | 0.034 | 0.989 | 4 | 30,000 | 125,000 | 7 | 1 | 1 | 1 | NULL | 1.129 | 0 |
| retardmode | clappy | False | Pump.fun | 1800 | 0.034 | 0.989 | 1 | 645,000 | 645,000 | NULL | 0 | 0 | 0 | NULL | 1.061 | 0 |
| retardmode | Chazerei | False | Pump.fun | 1800 | 0.066 | 1.975 | 3 | 40,000 | 40,000 | NULL | 0 | 0 | 0 | NULL | 1.061 | 0 |
| retardmode | PEACE | True | Pump.fun | 1800 | 0.125 | 3.948 | 0 | 40,000 | 40,000 | NULL | 0 | 0 | 0 | NULL | 3.909 | 1,790 |
| retardmode | YGIG | False | Pump.fun | 1800 | 0.035 | 1.002 | 0 | 8,500 | 8,500 | NULL | 0 | 0 | 0 | NULL | 5.022 | 220 |
| retardmode | yoohoo | False | Pump.fun | 1800 | 0.152 | 4.944 | 0 | 10,000 | 7,000 | 8 | 0.5 | 0.5 | 0.5 | NULL | 2.1 | 0 |
| retardmode | GOOSE | False | Pump.fun | 1800 | 0.097 | 2.969 | 2 | 10,000 | 4,000 | 7 | 0.5 | 1 | 1 | NULL | 1.892 | 0 |
| retardmode | BIRD | False | Pump.fun | 1800 | 0.097 | 2.969 | 3 | 10,000 | 7,000 | 6 | 0.5 | 0.5 | 0.5 | NULL | 1.528 | 300 |
| retardmode | MRHATE | True | Pump.fun | 1800 | 0.353 | 14.691 | 1 | 10,000 | 10,000 | NULL | 0 | 0 | 0 | 1,737 | 3.642 | 1,270 |
| retardmode | RETARDIO | True | Pump.fun | 1800 | 0.483 | 24.551 | 2 | 30,000 | 30,000 | NULL | 0 | 0 | 0 | 728 | 29.202 | 830 |
| retardmode | GIGAY | False | Pump.fun | 1800 | 0.197 | 9.653 | 1 | 11,000 | 9,079 | 96 | 0 | 0.761 | 0.761 | NULL | 3.831 | 90 |
| retardmode | GMONAD | False | Pump.fun | 1800 | 0.2 | 9.781 | 1 | 11,000 | 377,391.5 | 124 | 0 | 1 | 1 | NULL | 2.659 | 50 |
| retardmode | PQ | True | Pump.fun | 1800 | 0.573 | 47.291 | 0 | 11,000 | 11,000 | NULL | 0 | 0 | 0 | 480 | 71.026 | 1,660 |
| retardmode | WOJAK | False | Pump.fun | 1800 | 0.385 | 23.65 | 2 | 11,000 | 83,185 | 73 | 0 | 0.895 | 0.895 | 706 | 11.565 | 1,040 |
| retardmode | MERCURY | False | Pump.fun | 1800 | 0.152 | 4.944 | 0 | 10,000 | 4,000 | 6 | 0.719 | 0.719 | 0.823 | NULL | 4.197 | 30 |
| retardmode | LEMON | False | Pump.fun | 1800 | 0.354 | 14.78 | 5 | 10,000 | 4,000 | 5 | 0.94 | 0.94 | 0.94 | NULL | 2.029 | 120 |
| retardmode | SPOON | False | Pump.fun | 1800 | 0.425 | 19.673 | 3 | 10,000 | 7,000 | 5 | 1 | 1 | 1 | NULL | 1.046 | 0 |
| slingoor | MARVIN | True | pump_agent | 1800 | 0.247 | 17.026 | 5 | 87,149 | 87,149 | NULL | 0 | 0 | 0 | NULL | 10.886 | 1,280 |
| slingoor | FibFrog | False | Pump.fun | 1800 | 0.391 | 17.187 | 7 | 52,463 | 80,049 | 14 | 1 | 1 | 1 | 0 | 3.168 | 0 |
| slingoor | 78 | False | Pump.fun | 1800 | 0.582 | 35.557 | 2 | 165,242 | 165,242 | 38 | 1 | 1 | 1 | 3 | 2.866 | 20 |
| slingoor | 💀 | False | Pump.fun | 1800 | 0.385 | 16.792 | 0 | 27,201 | 62,184 | 11 | 1 | 1 | 1 | 961 | 1.82 | 0 |
| slingoor | BEGFI | False | Pump.fun | 1800 | 0.413 | 18.767 | 4 | 45,068 | 804,637 | 10 | 1 | 1 | 1 | NULL | 1.601 | 40 |
| slingoor | catcall | True | Pump.fun | 427 | 0.065 | 1.932 | 3 | 5,255 | 5,255 | NULL | 0 | 0 | NULL | 31 | 55.794 | 260 |
| slingoor | dontbuy | False | Pump.fun | 1800 | 0.026 | 0.742 | 4 | 610,885 | 805,442.5 | 217 | 0 | 1 | 1 | NULL | 2.188 | 0 |
| slingoor | OFFICIAL | True | Pump.fun | 1800 | 0.343 | 14.076 | 0 | 305,445 | 157,056.5 | NULL | 0 | 0 | 0 | 4 | 52.34 | 1,600 |
| slingoor | Chairman | True | Pump.fun | 1800 | 0.61 | 39.508 | 6 | 27,041 | 513,520.5 | NULL | 0 | 0 | 0 | 0 | 71.558 | 1,360 |
| slingoor | TOAD | True | Pump.fun | 1800 | 0.201 | 6.915 | 21 | 112,553 | 112,553 | NULL | 0 | 0 | 0 | 25 | 67.777 | 1,740 |
| slingoor | sling | True | Pump.fun | 872 | 0.716 | 60.249 | 2 | 110,882 | 555,441 | NULL | 0 | 0 | NULL | 2 | 146.057 | 160 |
| slingoor | WINNIE | True | Pump.fun | 1800 | 0.533 | 29.631 | 7 | 121,132 | 148,383 | 13 | 1 | 1 | 1 | 22 | 27.023 | 950 |
| slingoor | HOODWARTS | True | Pump.fun | 1800 | 0.667 | 49.384 | 2 | 78,520 | 20,395 | 15 | 1 | 1 | 1 | 2 | 4.101 | 230 |
| slingoor | LIZARD | True | Pump.fun | 881 | 0.712 | 59.261 | 10 | 65,720 | 65,720 | NULL | 0 | 0 | NULL | 19 | 97.554 | 820 |
| slingoor | DIDDY | True | Pump.fun | 1800 | 0.61 | 39.508 | 0 | 107,715 | 918,459 | NULL | 0 | 0 | 0 | 996 | 50.317 | 840 |
| slingoor | 🐺 | True | Pump.fun | 1800 | 0.727 | 62.997 | 5 | 10,000 | 10,190 | NULL | 0 | 0 | 0 | 4 | 50.646 | 1,300 |
| slingoor | INSANE | False | Pump.fun | 1800 | 0.199 | 6.818 | 22 | 10,000 | 4,000 | 17 | 1 | 0.946 | 0.887 | 6 | 10.412 | 650 |
| slingoor | nothing | True | Pump.fun | 1800 | 0.542 | 30.619 | 10 | 27,617 | 27,617 | NULL | 0 | 0 | 0 | 1 | 44.632 | 1,040 |
| slingoor | Graped | True | Pump.fun | 1800 | 0.472 | 23.577 | 8 | 10,000 | 10,000 | NULL | 0 | 0 | 0 | NULL | 2.217 | 0 |
| slingoor | donotbuy | False | Pump.fun | 1800 | 0.378 | 16.298 | 0 | 27,270 | 14,752 | 12 | 1 | 1 | 1 | NULL | 2.627 | 0 |
| slingoor | link | False | Pump.fun | 1800 | 0.483 | 24.551 | 13 | 10,000 | 7,000 | 5 | 1 | 1 | 1 | 0 | 5.593 | 480 |
| slingoor | SEXY | False | Pump.fun | 1800 | 0.571 | 48.183 | 0 | 11,000 | 11,000 | NULL | 0 | 0 | 0 | 29 | 9.498 | 50 |
| slingoor | ETH | True | stonkfun | 3 | 0.639 | 48.08 | 1 | 35,000 | 35,000 | NULL | NULL | NULL | NULL | 3 | 2.342 | 0 |
| slingoor | GRND | False | stonkfun | 3 | 0.613 | 43.251 | 0 | 35,000 | 35,000 | NULL | NULL | NULL | NULL | 3 | 2.516 | 0 |
| slingoor | LMAO! | False | stonkfun | 7 | 0.032 | 1.055 | 0 | 35,000 | 35,000 | NULL | NULL | NULL | NULL | 7 | 6.543 | 0 |
| slingoor | USDC | False | stonkfun | 1800 | 0.251 | 9.894 | 4 | 35,000 | 20,817.5 | 155 | 0 | 1 | 1 | NULL | 7.139 | 10 |
| slingoor | GREEN | False | stonkfun | 1800 | 0.223 | 18.933 | 0 | 35,000 | 4,483 | 179 | 0 | 1 | 1 | NULL | 3.673 | 90 |
| slingoor | DAMN | False | stonkfun | 1800 | 0.249 | 21.16 | 0 | 35,000 | 3,010 | 658 | 0 | 0 | 1 | NULL | 2.796 | 90 |

## 3. Hit vs miss at minute 1 and minute 5 (distributions; n = launches with a value; in-sample, no model)

### slingoor, minute 1

| column | hits n | hits med | hits p25 | hits p75 | misses n | misses med | misses p25 | misses p75 |
|---|---|---|---|---|---|---|---|---|
| dev_supply_share | 13 | 0.542 | 0.343 | 0.667 | 12 | 0.381 | 0.242 | 0.43 |
| dev_first_buy_sol | 13 | 30.619 | 17.026 | 49.384 | 12 | 17.977 | 14.697 | 22.008 |
| dev_same_slot_buyers | 13 | 5 | 2 | 8 | 12 | 3 | 0 | 4.75 |
| dev_fee_first_tx | 13 | 78,520 | 27,041 | 110,882 | 12 | 35,000 | 23,150.75 | 46,916.75 |
| dev_fee_med_60s | 13 | 65,720 | 20,395 | 112,553 | 12 | 35,000 | 13,814 | 130,571.75 |
| dev_fee_lamports_med | 13 | 87,149 | 20,395 | 157,056.5 | 12 | 17,784.75 | 6,370.75 | 101,347.25 |
| dev_sold_share_60s | 13 | 0 | 0 | 0 | 12 | 1 | 0 | 1 |
| sol_in_1m | 13 | 385.135 | 279.3 | 680.086 | 12 | 179.93 | 116.353 | 242.219 |
| sol_out_1m | 13 | 269.524 | 177.722 | 462.31 | 12 | 134.542 | 107.863 | 184.157 |
| net_sol_1m | 13 | 94.972 | 65.868 | 115.611 | 12 | 28.016 | 11.337 | 48.982 |
| n_buys_1m | 13 | 514 | 300 | 663 | 12 | 157 | 131.5 | 292.5 |
| n_wallets_1m | 13 | 374 | 242 | 460 | 12 | 125.5 | 105.5 | 235 |
| member_buy_sol_1m | 13 | 0 | 0 | 0 | 12 | 0 | 0 | 0 |
| outside_buy_sol_1m | 13 | 354.516 | 249.726 | 617.09 | 12 | 160.757 | 99.525 | 228.661 |
| top10_share_1m | 13 | 0.779 | 0.538 | 0.833 | 12 | 0.703 | 0.648 | 0.828 |
| n_net_long_1m | 13 | 257 | 147 | 298 | 12 | 55.5 | 28.75 | 113.25 |
| mult_30s | 13 | 8.437 | 4.816 | 13.913 | 12 | 2.1 | 1.11 | 3.384 |
| mult_60s | 13 | 12.858 | 3.696 | 15.574 | 12 | 1.649 | 1.077 | 3.491 |
| dev_sold_by_60s (share true) | 13 | 0.154 | NULL | NULL | 12 | 0.583 | NULL | NULL |
| member_buy_by_1m (share true) | 13 | 0.154 | NULL | NULL | 12 | 0.083 | NULL | NULL |

### slingoor, minute 5

| column | hits n | hits med | hits p25 | hits p75 | misses n | misses med | misses p25 | misses p75 |
|---|---|---|---|---|---|---|---|---|
| dev_sold_share_120s | 13 | 0 | 0 | 0 | 12 | 1 | 0 | 1 |
| dev_sold_share_300s | 13 | 0 | 0 | 0 | 12 | 1 | 0.987 | 1 |
| sol_in_5m | 13 | 659.468 | 591.017 | 1,593.634 | 12 | 216.059 | 123.442 | 324.054 |
| sol_out_5m | 13 | 571.827 | 498.864 | 1,517.602 | 12 | 181.312 | 120.259 | 292.218 |
| net_sol_5m | 13 | 119.29 | 87.641 | 151.788 | 12 | 20.75 | 5.02 | 50.11 |
| n_buys_5m | 13 | 1,083 | 1,006 | 1,790 | 12 | 245.5 | 167 | 457 |
| n_wallets_5m | 13 | 659 | 569 | 1,074 | 12 | 165 | 123 | 341.75 |
| member_buy_sol_5m | 13 | 0.993 | 0 | 2.97 | 12 | 0 | 0 | 0 |
| member_buyers_5m | 13 | 1 | 0 | 2 | 12 | 0 | 0 | 0 |
| outside_buy_sol_5m | 13 | 652.553 | 560.398 | 1,559.552 | 12 | 196.394 | 110.749 | 303.091 |
| top10_share_5m | 13 | 0.774 | 0.43 | 0.798 | 12 | 0.856 | 0.679 | 1 |
| n_net_long_5m | 13 | 356 | 246 | 439 | 12 | 40.5 | 12.75 | 85.5 |
| mult_120s | 13 | 17.671 | 5.043 | 20.63 | 12 | 1.639 | 0.88 | 3.627 |
| mult_300s | 13 | 20.074 | 11.618 | 31.071 | 12 | 1.466 | 0.777 | 2.458 |
| dev_sold_by_120s (share true) | 13 | 0.154 | NULL | NULL | 12 | 0.583 | NULL | NULL |
| dev_sold_by_300s (share true) | 13 | 0.154 | NULL | NULL | 12 | 0.833 | NULL | NULL |
| member_buy_by_5m (share true) | 13 | 0.538 | NULL | NULL | 12 | 0.083 | NULL | NULL |

### retardmode, minute 1

| column | hits n | hits med | hits p25 | hits p75 | misses n | misses med | misses p25 | misses p75 |
|---|---|---|---|---|---|---|---|---|
| dev_supply_share | 4 | 0.418 | 0.296 | 0.505 | 15 | 0.097 | 0.034 | 0.199 |
| dev_first_buy_sol | 4 | 19.621 | 12.005 | 30.236 | 15 | 2.969 | 0.995 | 9.717 |
| dev_same_slot_buyers | 4 | 0.5 | 0 | 1.25 | 15 | 2 | 0.5 | 3 |
| dev_fee_first_tx | 4 | 20,500 | 10,750 | 32,500 | 15 | 11,000 | 10,000 | 30,000 |
| dev_fee_med_60s | 4 | 20,500 | 10,750 | 32,500 | 15 | 11,000 | 7,000 | 35,000 |
| dev_fee_lamports_med | 4 | 20,500 | 10,750 | 32,500 | 15 | 9,079 | 7,000 | 125,000 |
| dev_sold_share_60s | 4 | 0 | 0 | 0 | 15 | 0.5 | 0 | 0.829 |
| sol_in_1m | 4 | 36.057 | 15.823 | 57.633 | 15 | 46.352 | 13.245 | 65.572 |
| sol_out_1m | 4 | 1.661 | 1.147 | 6.848 | 15 | 11.349 | 8.64 | 50.674 |
| net_sol_1m | 4 | 30.726 | 14.228 | 47.564 | 15 | 8.626 | 2.956 | 24.067 |
| n_buys_1m | 4 | 19 | 7.75 | 39.25 | 15 | 61 | 20 | 94.5 |
| n_wallets_1m | 4 | 17.5 | 5.5 | 38.25 | 15 | 41 | 19.5 | 74 |
| member_buy_sol_1m | 4 | 0 | 0 | 0.247 | 15 | 0 | 0 | 0 |
| outside_buy_sol_1m | 4 | 6.682 | 5.434 | 15.78 | 15 | 30.576 | 11.266 | 59 |
| top10_share_1m | 4 | 0.961 | 0.917 | 1 | 14 | 0.851 | 0.743 | 0.985 |
| n_net_long_1m | 4 | 15 | 5.5 | 28.75 | 15 | 18 | 9 | 31.5 |
| mult_30s | 4 | 1.102 | 1.05 | 1.449 | 15 | 1.407 | 1.115 | 1.698 |
| mult_60s | 4 | 1.96 | 1.516 | 2.758 | 15 | 1.291 | 1.115 | 2.463 |
| dev_sold_by_60s (share true) | 4 | 0 | NULL | NULL | 15 | 0.533 | NULL | NULL |
| member_buy_by_1m (share true) | 4 | 0.25 | NULL | NULL | 15 | 0 | NULL | NULL |

### retardmode, minute 5

| column | hits n | hits med | hits p25 | hits p75 | misses n | misses med | misses p25 | misses p75 |
|---|---|---|---|---|---|---|---|---|
| dev_sold_share_120s | 4 | 0 | 0 | 0 | 15 | 0.761 | 0.25 | 1 |
| dev_sold_share_300s | 4 | 0 | 0 | 0 | 15 | 0.895 | 0.5 | 1 |
| sol_in_5m | 4 | 68.505 | 31.856 | 108.985 | 15 | 49.126 | 24.32 | 100.246 |
| sol_out_5m | 4 | 18.365 | 9.455 | 30.906 | 15 | 48.71 | 16.962 | 83.368 |
| net_sol_5m | 4 | 42.763 | 22.401 | 70.702 | 15 | 6.496 | 1.296 | 18.032 |
| n_buys_5m | 4 | 99.5 | 63.75 | 127.5 | 15 | 65 | 42.5 | 195 |
| n_wallets_5m | 4 | 82.5 | 61.75 | 96.25 | 15 | 58 | 33 | 134.5 |
| member_buy_sol_5m | 4 | 0.478 | 0 | 0.964 | 15 | 0 | 0 | 0 |
| member_buyers_5m | 4 | 0.5 | 0 | 1 | 15 | 0 | 0 | 0 |
| outside_buy_sol_5m | 4 | 48.39 | 19.851 | 77.769 | 15 | 39.345 | 22.341 | 89.827 |
| top10_share_5m | 4 | 0.889 | 0.863 | 0.912 | 14 | 0.975 | 0.686 | 1 |
| n_net_long_5m | 4 | 44.5 | 32 | 56.75 | 15 | 9 | 2 | 30.5 |
| mult_120s | 4 | 2.555 | 2.11 | 3.124 | 15 | 1.283 | 1.115 | 2.085 |
| mult_300s | 4 | 3.554 | 2.24 | 4.952 | 15 | 1.576 | 1.095 | 1.904 |
| dev_sold_by_120s (share true) | 4 | 0 | NULL | NULL | 15 | 0.733 | NULL | NULL |
| dev_sold_by_300s (share true) | 4 | 0 | NULL | NULL | 15 | 0.8 | NULL | NULL |
| member_buy_by_5m (share true) | 4 | 0.5 | NULL | NULL | 15 | 0.133 | NULL | NULL |

### Threshold rules (hits passing / hits, misses passing / misses; launches with a dev buy and coverage to the mark)

| dev | mark | rule | hits | misses | precision | recall |
|---|---|---|---|---|---|---|
| slingoor | 1m | dev share >= 0.35 | 9 of 13 | 7 of 12 | 0.562 | 0.692 |
| slingoor | 1m | dev share >= 0.50 | 8 of 13 | 2 of 12 | 0.8 | 0.615 |
| slingoor | 1m | no dev sell by 60 s | 11 of 13 | 5 of 12 | 0.688 | 0.846 |
| slingoor | 1m | dev share >= 0.35 and no dev sell by 60 s | 7 of 13 | 1 of 12 | 0.875 | 0.538 |
| slingoor | 1m | dev share >= 0.35 and no dev sell by 60 s and same-slot buyers >= 2 | 6 of 13 | 0 of 12 | 1 | 0.462 |
| slingoor | 1m | dev share >= 0.35 and no dev sell by 60 s and sol_in_1m >= 50 | 7 of 13 | 1 of 12 | 0.875 | 0.538 |
| slingoor | 1m | no dev sell by 60 s and sol_in_1m >= 100 | 10 of 13 | 4 of 12 | 0.714 | 0.769 |
| slingoor | 1m | no dev sell by 60 s and n_wallets_1m >= 100 | 10 of 13 | 5 of 12 | 0.667 | 0.769 |
| slingoor | 1m | dev share >= 0.35 and mult_60s >= 2 | 8 of 13 | 1 of 12 | 0.889 | 0.615 |
| slingoor | 5m | dev share >= 0.35 and no dev sell by 120 s | 7 of 13 | 1 of 12 | 0.875 | 0.538 |
| slingoor | 5m | dev share >= 0.35 and no dev sell by 300 s | 7 of 13 | 1 of 12 | 0.875 | 0.538 |
| slingoor | 5m | no dev sell by 300 s | 11 of 13 | 2 of 12 | 0.846 | 0.846 |
| slingoor | 5m | no dev sell by 300 s and sol_in_5m >= 100 | 10 of 13 | 2 of 12 | 0.833 | 0.769 |
| slingoor | 5m | no dev sell by 300 s and n_wallets_5m >= 200 | 9 of 13 | 1 of 12 | 0.9 | 0.692 |
| slingoor | 5m | dev share >= 0.35 and no dev sell by 300 s and member buy by 300 s | 3 of 13 | 0 of 12 | 1 | 0.231 |
| slingoor | 5m | member buy by 300 s | 7 of 13 | 1 of 12 | 0.875 | 0.538 |
| slingoor | 5m | dev share >= 0.35 and no dev sell by 300 s and mult_300s >= 3 | 6 of 13 | 1 of 12 | 0.857 | 0.462 |
| retardmode | 1m | dev share >= 0.35 | 3 of 4 | 3 of 15 | 0.5 | 0.75 |
| retardmode | 1m | dev share >= 0.50 | 1 of 4 | 0 of 15 | 1 | 0.25 |
| retardmode | 1m | no dev sell by 60 s | 4 of 4 | 7 of 15 | 0.364 | 1 |
| retardmode | 1m | dev share >= 0.35 and no dev sell by 60 s | 3 of 4 | 1 of 15 | 0.75 | 0.75 |
| retardmode | 1m | dev share >= 0.35 and no dev sell by 60 s and same-slot buyers >= 2 | 1 of 4 | 1 of 15 | 0.5 | 0.25 |
| retardmode | 1m | dev share >= 0.35 and no dev sell by 60 s and sol_in_1m >= 50 | 2 of 4 | 1 of 15 | 0.667 | 0.5 |
| retardmode | 1m | no dev sell by 60 s and sol_in_1m >= 100 | 0 of 4 | 1 of 15 | 0 | 0 |
| retardmode | 1m | no dev sell by 60 s and n_wallets_1m >= 100 | 0 of 4 | 1 of 15 | 0 | 0 |
| retardmode | 1m | dev share >= 0.35 and mult_60s >= 2 | 2 of 4 | 1 of 15 | 0.667 | 0.5 |
| retardmode | 5m | dev share >= 0.35 and no dev sell by 120 s | 3 of 4 | 0 of 15 | 1 | 0.75 |
| retardmode | 5m | dev share >= 0.35 and no dev sell by 300 s | 3 of 4 | 0 of 15 | 1 | 0.75 |
| retardmode | 5m | no dev sell by 300 s | 4 of 4 | 3 of 15 | 0.571 | 1 |
| retardmode | 5m | no dev sell by 300 s and sol_in_5m >= 100 | 2 of 4 | 1 of 15 | 0.667 | 0.5 |
| retardmode | 5m | no dev sell by 300 s and n_wallets_5m >= 200 | 0 of 4 | 0 of 15 | NULL | 0 |
| retardmode | 5m | dev share >= 0.35 and no dev sell by 300 s and member buy by 300 s | 2 of 4 | 0 of 15 | 1 | 0.5 |
| retardmode | 5m | member buy by 300 s | 2 of 4 | 2 of 15 | 0.5 | 0.5 |
| retardmode | 5m | dev share >= 0.35 and no dev sell by 300 s and mult_300s >= 3 | 2 of 4 | 0 of 15 | 1 | 0.5 |

## 4. The entry window on hits

Multiples are the 10-second buy VWAP over the dev's first-buy price (quote units). `mult_Ts` = last complete bucket before T; `max_after_Ts` = best bucket at or after T inside the observed window; `ahead_Ts` = max_after / mult (how much of the run was still ahead of a buyer at T). `peak1_*` is Phase B's 1-second peak. Retardmode hits and slingoor's PEACE-like cases ran after the window, so window peaks are lower bounds.

### slingoor hits (n=14)

| column | n | median | p25 | p75 | min | max |
|---|---|---|---|---|---|---|
| member_first_buy_s | 11 | 138 | 66 | 356.5 | 38 | 1,431 |
| outside_first_buy_s | 14 | 0 | 0 | 0 | 0 | 0 |
| peak1_ts_s | 13 | 849 | 118 | 1,299 | 0 | 1,743 |
| peak10_ts_s | 14 | 895 | 237.5 | 1,295 | 0 | 1,740 |
| peak10_mult | 14 | 50.482 | 14.92 | 64.781 | 2.217 | 146.057 |
| mult_30s | 13 | 8.437 | 4.816 | 13.913 | 1.514 | 88.728 |
| mult_60s | 13 | 12.858 | 3.696 | 15.574 | 1.74 | 122.07 |
| mult_120s | 13 | 17.671 | 5.043 | 20.63 | 2.217 | 145.94 |
| mult_300s | 13 | 20.074 | 11.618 | 31.071 | 2.217 | 127.755 |
| ahead_30s | 12 | 4.377 | 3.457 | 6.203 | 1.646 | 10.867 |
| ahead_60s | 12 | 3.566 | 2.361 | 5.322 | 1.196 | 10.449 |
| ahead_120s | 12 | 2.616 | 1.776 | 4.377 | 1.001 | 7.215 |
| ahead_300s | 12 | 2.314 | 1.329 | 2.544 | 0.864 | 3.96 |

| symbol | coverage_s | member_first_buy_s | outside_first_buy_s | peak10_ts_s | peak10_mult | peak1_mult | mult_30s | ahead_30s | mult_60s | ahead_60s | mult_120s | ahead_120s | mult_300s | ahead_300s | end_mult | kl_mult_5m | kl_mult_30m | kl_max_mult_100m | kl_min_to_max_100m |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Graped | 1800 | NULL | 0 | 0 | 2.217 | 2.217 | 2.217 | NULL | 2.217 | NULL | 2.217 | NULL | 2.217 | NULL | 2.217 | 0.929 | 3.2 | 4.222 | 70.867 |
| ETH | 3 | NULL | 0 | 0 | 2.342 | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | NULL | 2.342 | 0.559 | 0.024 | 1.002 | 0.667 |
| sling | 872 | 229 | 0 | 160 | 146.057 | 167.998 | 88.728 | 1.646 | 122.07 | 1.196 | 145.94 | 1.001 | 127.755 | 1.133 | 98.964 | 1.024 | 1.234 | 1.954 | 0.467 |
| HOODWARTS | 1800 | 38 | 0 | 230 | 4.101 | 13.806 | 1.514 | 2.709 | 1.74 | 2.357 | 2.246 | 1.826 | 2.798 | 0.864 | 1.029 | 1.059 | 0.55 | 2.35 | 3.3 |
| catcall | 427 | 105 | 0 | 260 | 55.794 | 60.364 | 7.626 | 7.316 | 15.574 | 3.583 | 19.981 | 2.792 | 51.296 | 0.934 | 41.312 | 2.68 | 3.39 | 5.62 | 42.917 |
| LIZARD | 881 | 60 | 0 | 820 | 97.554 | 106.313 | 23.865 | 4.088 | 41.292 | 2.363 | 63.009 | 1.548 | 69.973 | 1.394 | 86.675 | 6.626 | 8.225 | 11.658 | 51.2 |
| DIDDY | 1800 | 70 | 0 | 840 | 50.317 | 52.308 | 8.437 | 5.964 | 11.354 | 4.432 | 20.63 | 2.439 | 20.57 | 2.446 | 33.459 | 1.824 | 2.902 | 5.254 | 75.9 |
| WINNIE | 1800 | 62 | 0 | 950 | 27.023 | 58.692 | 6.441 | 4.196 | 3.696 | 7.311 | 5.043 | 5.359 | 11.618 | 2.326 | 4.505 | 1.632 | 0.605 | 4.243 | 13.783 |
| nothing | 1800 | 1,431 | 0 | 1,040 | 44.632 | 46.065 | 9.791 | 4.558 | 13.682 | 3.262 | 18.798 | 2.374 | 17.116 | 2.608 | 15.031 | 2.087 | 1.867 | 5.794 | 17.183 |
| MARVIN | 1800 | 406 | 0 | 1,280 | 10.886 | 10.93 | 2.937 | 3.706 | 3.067 | 3.549 | 3.611 | 3.015 | 4.022 | 2.706 | 7.874 | 1.423 | 2.467 | 4.713 | 80 |
| 🐺 | 1800 | NULL | 0 | 1,300 | 50.646 | 51.354 | 25.337 | 1.999 | 31.205 | 1.623 | 31.122 | 1.627 | 20.074 | 2.523 | 26.623 | 3.469 | 4.863 | 9.52 | 21.017 |
| Chairman | 1800 | 307 | 0 | 1,360 | 71.558 | 78.272 | 10.339 | 6.921 | 13.075 | 5.473 | 17.671 | 4.049 | 31.071 | 2.303 | 46.514 | 3.856 | 5.388 | 9.657 | 22.083 |
| OFFICIAL | 1800 | 138 | 0 | 1,600 | 52.34 | 55.038 | 4.816 | 10.867 | 5.009 | 10.449 | 7.255 | 7.215 | 26.275 | 1.992 | 45.604 | 6.283 | 8.698 | 28.401 | 67.917 |
| TOAD | 1800 | 1,207 | 0 | 1,740 | 67.777 | 71.64 | 13.913 | 4.872 | 12.858 | 5.271 | 10.356 | 6.545 | 17.116 | 3.96 | 59.885 | 1.86 | 8.11 | 299.633 | 98.783 |

### retardmode hits (n=4)

| column | n | median | p25 | p75 | min | max |
|---|---|---|---|---|---|---|
| member_first_buy_s | 3 | 265 | 151.5 | 680 | 38 | 1,095 |
| outside_first_buy_s | 4 | 0.5 | 0 | 10 | 0 | 37 |
| peak1_ts_s | 4 | 1,466.5 | 1,160.75 | 1,696.5 | 833 | 1,797 |
| peak10_ts_s | 4 | 1,465 | 1,160 | 1,692.5 | 830 | 1,790 |
| peak10_mult | 4 | 16.556 | 3.843 | 39.658 | 3.642 | 71.026 |
| mult_30s | 4 | 1.102 | 1.05 | 1.449 | 1 | 2.383 |
| mult_60s | 4 | 1.96 | 1.516 | 2.758 | 1.301 | 4.037 |
| mult_120s | 4 | 2.555 | 2.11 | 3.124 | 1.633 | 3.977 |
| mult_300s | 4 | 3.554 | 2.24 | 4.952 | 1.659 | 5.786 |
| ahead_30s | 4 | 7.845 | 3.43 | 26.947 | 3.416 | 71.026 |
| ahead_60s | 4 | 5.119 | 2.827 | 13.04 | 2.294 | 30.46 |
| ahead_120s | 4 | 4.868 | 2.196 | 11.759 | 1.605 | 25.01 |
| ahead_300s | 4 | 4.302 | 2.141 | 7.755 | 1.497 | 12.275 |

| symbol | coverage_s | member_first_buy_s | outside_first_buy_s | peak10_ts_s | peak10_mult | peak1_mult | mult_30s | ahead_30s | mult_60s | ahead_60s | mult_120s | ahead_120s | mult_300s | ahead_300s | end_mult | kl_mult_5m | kl_mult_30m | kl_max_mult_100m | kl_min_to_max_100m |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| RETARDIO | 1800 | 38 | 0 | 830 | 29.202 | 29.642 | 2.383 | 12.255 | 4.037 | 7.234 | 3.977 | 7.342 | 4.674 | 6.248 | 18.041 | NULL | NULL | NULL | NULL |
| MRHATE | 1800 | 1,095 | 0 | 1,270 | 3.642 | 3.642 | 1.066 | 3.416 | 1.588 | 2.294 | 2.269 | 1.605 | 2.433 | 1.497 | 3.527 | NULL | NULL | NULL | NULL |
| PQ | 1800 | 265 | 37 | 1,660 | 71.026 | 86.554 | 1 | 71.026 | 2.332 | 30.46 | 2.84 | 25.01 | 5.786 | 12.275 | 46.861 | NULL | NULL | NULL | NULL |
| PEACE | 1800 | NULL | 1 | 1,790 | 3.909 | 3.909 | 1.138 | 3.435 | 1.301 | 3.005 | 1.633 | 2.393 | 1.659 | 2.356 | 3.909 | NULL | NULL | NULL | NULL |

### Both launchers pooled, hits

| column | n | median | p25 | p75 | min | max |
|---|---|---|---|---|---|---|
| member_first_buy_s | 14 | 183.5 | 64 | 381.25 | 38 | 1,431 |
| outside_first_buy_s | 18 | 0 | 0 | 0 | 0 | 37 |
| peak10_ts_s | 18 | 995 | 400 | 1,345 | 0 | 1,790 |
| peak10_mult | 18 | 47.474 | 5.797 | 64.781 | 2.217 | 146.057 |
| mult_30s | 17 | 6.441 | 2.217 | 10.339 | 1 | 88.728 |
| mult_60s | 17 | 5.009 | 2.332 | 13.682 | 1.301 | 122.07 |
| mult_120s | 17 | 7.255 | 2.84 | 19.981 | 1.633 | 145.94 |
| mult_300s | 17 | 17.116 | 4.022 | 26.275 | 1.659 | 127.755 |
| ahead_30s | 16 | 4.377 | 3.43 | 7.02 | 1.646 | 71.026 |
| ahead_60s | 16 | 3.566 | 2.361 | 5.913 | 1.196 | 30.46 |
| ahead_120s | 16 | 2.616 | 1.776 | 5.655 | 1.001 | 25.01 |
| ahead_300s | 16 | 2.341 | 1.471 | 2.632 | 0.864 | 12.275 |

`kl_*` columns are DuckDB dev_runs kline multiples relative to the first candle's open, not to the dev's average price, so they are not on the same scale as `mult_*`.

Misses, for contrast (same multiples):

| dev | symbol | coverage_s | peak10_ts_s | peak10_mult | mult_30s | mult_60s | mult_120s | mult_300s | end_mult | dev_first_sell_s |
|---|---|---|---|---|---|---|---|---|---|---|
| retardmode | CARDAMOM | 1800 | 770 | 2.654 | 1.415 | 1.612 | 1.803 | 1.576 | 1.604 | 97 |
| retardmode | NIGGERMAS | 1800 | 170 | 1.803 | 1.407 | 1.384 | 1.253 | 1.76 | 1.202 | 48 |
| retardmode | HANUKKAH | 1800 | 0 | 1.129 | 1.129 | 1.129 | 1.129 | 1.129 | 0.998 | 7 |
| retardmode | clappy | 1800 | 0 | 1.061 | 1.061 | 1.061 | 1.061 | 1.061 | 1.061 | NULL |
| retardmode | Chazerei | 1800 | 0 | 1.061 | 1.061 | 1.061 | 1.061 | 1.061 | 1.061 | NULL |
| retardmode | YGIG | 1800 | 220 | 5.022 | 2.246 | 2.614 | 3.314 | 3.964 | 2.895 | NULL |
| retardmode | yoohoo | 1800 | 0 | 2.1 | 1.327 | 1.291 | 1.283 | 2.049 | 1.126 | 8 |
| retardmode | GOOSE | 1800 | 0 | 1.892 | 1.518 | 1.232 | 1.232 | 1.232 | 1.232 | 7 |
| retardmode | BIRD | 1800 | 300 | 1.528 | 1.1 | 1.1 | 1.1 | 1.463 | 1.419 | 6 |
| retardmode | GIGAY | 1800 | 90 | 3.831 | 1.682 | 2.312 | 2.931 | 2.462 | 1.635 | 96 |
| retardmode | GMONAD | 1800 | 50 | 2.659 | 1.714 | 2.659 | 1.468 | 1.003 | 0.842 | 124 |
| retardmode | WOJAK | 1800 | 1,040 | 11.565 | 5.645 | 6.732 | 2.397 | 5.291 | 6.159 | 73 |
| retardmode | MERCURY | 1800 | 30 | 4.197 | 3.328 | 3.317 | 2.176 | 1.622 | 1.134 | 6 |
| retardmode | LEMON | 1800 | 120 | 2.029 | 1.221 | 1.255 | 1.994 | 1.675 | 0.74 | 5 |
| retardmode | SPOON | 1800 | 0 | 1.046 | 1.034 | 0.855 | 0.752 | 0.752 | 0.619 | 5 |
| slingoor | FibFrog | 1800 | 0 | 3.168 | 1.113 | 0.67 | 0.729 | 0.634 | 0.434 | 14 |
| slingoor | 78 | 1800 | 20 | 2.866 | 2.866 | 0.536 | 0.468 | 0.341 | 0.334 | 38 |
| slingoor | 💀 | 1800 | 0 | 1.82 | 0.938 | 0.88 | 0.651 | 0.651 | 0.651 | 11 |
| slingoor | BEGFI | 1800 | 40 | 1.601 | 0.964 | 1.147 | 0.93 | 0.894 | 0.894 | 10 |
| slingoor | dontbuy | 1800 | 0 | 2.188 | 1.77 | 2.051 | 1.461 | 1.374 | 1.223 | 217 |
| slingoor | INSANE | 1800 | 650 | 10.412 | 7.151 | 5.95 | 3.62 | 8.395 | 5.074 | 17 |
| slingoor | donotbuy | 1800 | 0 | 2.627 | 1.098 | 1.143 | 1.159 | 0.819 | 0.704 | 12 |
| slingoor | link | 1800 | 480 | 5.593 | 1.837 | 1.358 | 1.817 | 3.066 | 1.396 | 5 |
| slingoor | SEXY | 1800 | 50 | 9.498 | 5.943 | 9.498 | 6.573 | 5.386 | 3.956 | NULL |
| slingoor | GRND | 3 | 0 | 2.516 | NULL | NULL | NULL | NULL | 2.516 | NULL |
| slingoor | LMAO! | 7 | 0 | 6.543 | NULL | NULL | NULL | NULL | 6.543 | NULL |
| slingoor | USDC | 1800 | 10 | 7.139 | 4.938 | 4.546 | 5.063 | 1.557 | 1.252 | 155 |
| slingoor | GREEN | 1800 | 90 | 3.673 | 2.362 | 3.139 | 3.649 | 2.255 | 1.001 | 179 |
| slingoor | DAMN | 1800 | 90 | 2.796 | 2.482 | 1.941 | 2.763 | 2.108 | 0.914 | 658 |

## Data problems

- hits whose in-window peak lies in the last 5 minutes (the run continued after the window; window multiples are lower bounds): retardmode/PEACE (peak at 1790 s, 3.909x), retardmode/PQ (peak at 1660 s, 71.026x), slingoor/OFFICIAL (peak at 1600 s, 52.34x), slingoor/TOAD (peak at 1740 s, 67.777x)
- hits with fewer than 50 trades in the window (nothing happened until after minute 30): slingoor/Graped (10 trades), slingoor/ETH (32 trades)
- retardmode/GIGAY: quoted in 63LfDmNb3MQ8mw9MtZ2To9bEA2M71kZUUGq5tiJxcqj9 (launchpad Pump.fun); SOL rate 46,388.606 quote/SOL from 27 minute(s) of router legs
- retardmode/GMONAD: quoted in CrAr4RRJMBVwRsZtT62pEhfA9H5utymC2mVx8e7FreP2 (launchpad Pump.fun); SOL rate 4,283.118 quote/SOL from 5 minute(s) of router legs
- retardmode/PQ: quoted in GkyPYa7NnCFbduLknCfBfP7p8564X1VZhwZYJ6CZpump (launchpad Pump.fun); SOL rate 35,720.51 quote/SOL from 30 minute(s) of router legs
- retardmode/WOJAK: quoted in 5UUH9RTDiSpq6HKS6bp4NdU9PNJpXRXuiw6ShBTBhgH2 (launchpad Pump.fun); SOL rate 2,157.469 quote/SOL from 30 minute(s) of router legs
- slingoor/MARVIN: quoted in EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v (launchpad pump_agent); SOL rate 75.471 quote/SOL from 30 minute(s) of router legs
- slingoor/catcall: observed window ends at 427 s (pull truncated at 30,000 tx); later marks NULL
- slingoor/sling: observed window ends at 872 s (pull truncated at 30,000 tx); later marks NULL
- slingoor/LIZARD: observed window ends at 881 s (pull truncated at 30,000 tx); later marks NULL
- slingoor/MPN: no trades in the window (sig_source=mint, 1 tx); excluded from every denominator
- slingoor/SEXY: quoted in XsDoVfqeBukxuZHWhdvWHBhgEHjGNst4MLodqsJHzoB (launchpad Pump.fun); SOL rate 0.276 quote/SOL from 20 minute(s) of router legs
- slingoor/MPN: no trades in the window (sig_source=mint, 1 tx); excluded from every denominator
- slingoor/MPN: no trades in the window (sig_source=mint, 1 tx); excluded from every denominator
- slingoor/ETH: observed window ends at 3 s (LaunchLab curve migrated at 3.0 s and the pool was never pulled); later marks NULL
- slingoor/ETH: quoted in GRNDYDpqwpCm6jVxpbh4xT5AM4r3p391qYsKTHqgaET2 (launchpad stonkfun); SOL rate 6.486 quote/SOL from 1 minute(s) of router legs
- slingoor/ETH: LaunchLab launch; market accounts taken from the create tx (2, vault authority WLHv2UAZ… added); Phase B's dev_first_buy_sol/sol_in_* for this launch are rent only and were not used
- slingoor/GRND: observed window ends at 3 s (LaunchLab curve migrated at 3.0 s and the pool was never pulled); later marks NULL
- slingoor/GRND: quoted in 7vfCXTUXx5WJV5JADk17DUJ4ksgau7utNKj4b963voxs (launchpad stonkfun); SOL rate 0.04 quote/SOL from 1 minute(s) of router legs
- slingoor/GRND: LaunchLab launch; market accounts taken from the create tx (2, vault authority WLHv2UAZ… added); Phase B's dev_first_buy_sol/sol_in_* for this launch are rent only and were not used
- slingoor/MPN: no trades in the window (sig_source=mint, 1 tx); excluded from every denominator
- slingoor/LMAO!: observed window ends at 7 s (LaunchLab curve migrated at 7.0 s and the pool was never pulled); later marks NULL
- slingoor/LMAO!: quoted in H74CYmXgMkYHYuSRsZt6RJb4NYp2u72Vw8BS5huApump (launchpad stonkfun); SOL rate 50,501.372 quote/SOL from 1 minute(s) of router legs
- slingoor/LMAO!: LaunchLab launch; market accounts taken from the create tx (2, vault authority WLHv2UAZ… added); Phase B's dev_first_buy_sol/sol_in_* for this launch are rent only and were not used
- slingoor/USDC: quoted in CB9dDufT3ZuQXqqSfa1c5kY935TEreyBw9XJXxHKpump (launchpad stonkfun); SOL rate 22,499.725 quote/SOL from 20 minute(s) of router legs
- slingoor/USDC: LaunchLab launch; market accounts taken from the create tx (2, vault authority WLHv2UAZ… added); Phase B's dev_first_buy_sol/sol_in_* for this launch are rent only and were not used
- slingoor/GREEN: quoted in 4vqind26DsicHecdGyrjYc4yhQN9HtyfzJ3d1ouppump (launchpad stonkfun); SOL rate 2.95e+06 quote/SOL from 16 minute(s) of router legs
- slingoor/GREEN: LaunchLab launch; market accounts taken from the create tx (2, vault authority WLHv2UAZ… added); Phase B's dev_first_buy_sol/sol_in_* for this launch are rent only and were not used
- slingoor/DAMN: quoted in 6zjLjqd483pWwrowtKdyhie8tqEvkWwRcrR4btkVpump (launchpad stonkfun); SOL rate 2.11e+06 quote/SOL from 19 minute(s) of router legs
- slingoor/DAMN: LaunchLab launch; market accounts taken from the create tx (1, vault authority WLHv2UAZ… added); Phase B's dev_first_buy_sol/sol_in_* for this launch are rent only and were not used
- Phase B `dev_fee_lamports_med` is a window median over every dev tx; `dev_fee_first_tx` here is the create-tx fee minus 5000 (measurable at second 0).
- `outside_*` includes KOL / smart-money wallets (kol_* never fetched). Members are the 32 wallets in member_wallets.json; slingoor counts as a member on retardmode's launches and vice versa.
- Sells after a truncated or migrated window are unobservable, so `share_sold_in_window` and `net_sol_*` understate exits on catcall, sling, LIZARD (slingoor hits) and on ETH/GRND/LMAO! (LaunchLab).
- `net_sol_marked` values the unsold remainder at the last 10-s buy VWAP of the observed window; for launches whose run came after minute 30 (PEACE, MRHATE, RETARDIO) this understates the eventual result.
- Multiples for non-SOL-quoted launches are in quote units and assume the quote/SOL rate is flat over the mark; `sol_*` for them carries the per-minute router rate.
- Threshold rules are evaluated in-sample on 14/4 hits; they describe the sample, they do not predict.
