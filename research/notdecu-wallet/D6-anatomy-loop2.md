# D6 — Loop 2: five more launchers, out-of-sample test of the loop-1 rule (2026-09-15 17:45 UTC)

113 launches (0xkgc 47, jester 27, gampsito 16, hashbergers 12, mitch 11; 24 hits) pulled the same way as
loop 1 (curve + pool accounts, no block scans needed), built with the same scripts. Tables in
`data/anatomy/loop2/` (`anatomy_<dev>`, `cross_*`, `SUMMARY_cross.md`, `backtest_v2_*`). Read-only.

## 1. The loop-1 rule does not generalise

Base rule from loop 1 (self-buy ≥ 35%, no dev sell by the mark, trail 40%, hard stop 50%), full cost
model, $50 per trigger:

| Set | Triggers | Wins | P&L | Hits caught | Misses entered |
|---|---|---|---|---|---|
| Loop 1 (in-sample, slingoor + retardmode) | 10 | 7 | +$1,120 | 9 of 18 | 1 of 33 |
| **Loop 2 (out of sample, five launchers)** | 7 | 4 | **−$49** | 2 of 24 | 5 of 89 |

The dev-hold tell is a habit of slingoor, retardmode and hashbergers, not a property of the group.

## 2. Why: each launcher has a different tell

Medians per launcher, hits vs misses (from `cross_launches`):

| Launcher | Self-buy share, hits / misses | Dev sold by 60 s, hits / misses | Wallets in minute 1 | SOL in by 5 min | Read |
|---|---|---|---|---|---|
| 0xkgc | 7% / 3% | 0% / 3% | 38 / 40 | 59 / 24 | never sells early on either; the only separator is inflow by minute 5 |
| gampsito | 15% / 18% | **100% / 100%** | 154 / 110 | 182 / 76 | dumps every launch within a minute; the run, when it comes, forms after his exit |
| hashbergers | 25% / 3% | 0% / 100% | 94 / 8 | 311 / 10 | the loop-1 pattern exactly (2 hits only) |
| jester | 10% / 12% | 57% / 70% | 50 / 44 | 98 / 52 | sells early on most hits too; flow separates, weakly |
| mitch | 79% / 50% | 0% / 0% | 22 / 29 | 116 / 156 | huge self-buy, never sells in-window, and his misses still pop 5.9×; 2 hits |

Two families: **holders** (slingoor, retardmode, mitch, hashbergers, 0xkgc), where the tell is the size of
the self-buy and whether it is still held; **dumpers** (gampsito, jester, and slingoor on his misses),
where the dev's exit is the start of the trade, not the end, and the tell is what the crowd does after.

## 3. A rule that does generalise, weakly: flow relative to the dev's own baseline

Walk-forward rule, no look-ahead: for each launch, baseline = median SOL inflow by 5 min over that dev's
earlier launches (≥ 3); trigger at 300 s if this launch's inflow ≥ k × baseline; exit trail 50% / TP 5× /
30 min. Same costs.

| k | Loop 1: triggers / wins / P&L / ex-best | Loop 2: triggers / wins / P&L / ex-best |
|---|---|---|
| 1.5× | 18 / 9 / +$513 / +$315 | 39 / 16 / +$239 / +$45 |
| 2.0× | 16 / 8 / +$496 / +$298 | 29 / 12 / +$267 / +$73 |
| 3.0× | 14 / 7 / +$519 / +$321 | 17 / 7 / +$143 / −$51 |

Positive on both sets, but with a 41% win rate and a negative median trade on loop 2: the P&L is a few
big winners. That is a real but thin edge on its own, and it is the one that survives out of sample.

## 4. What this means for the strategy

1. **Per-launcher rules, not one rule.** The hold tell is worth keeping for the holders; the dumpers need
   a post-exit flow rule. Selecting the rule per launcher from his own history is the walk-forward
   version of what the user described (each loss a filter, each win a refinement), and it needs more
   launches per launcher than we have (2–7 hits each in loop 2).
2. **Flow-by-5-minutes relative to the dev's own baseline is the common denominator**; combining it
   with the hold tell where the launcher is a holder is the next configuration to test, walk-forward.
3. **Exits matter as much as entries**: the loop-2 losses are mostly hard stops on launches that had
   already popped by 300 s (mitch's misses at 5.9×); an entry that late on a spike needs a tighter stop
   or no entry when the price at the mark is already > 3× the dev's price.
4. **Scale**: the Bitquery collector now adds every tracked launcher's new launch twice a day at no
   Helius cost. Two weeks of that roughly doubles the sample for the active launchers (slingoor, 0xkgc,
   jester, trenchdigger, badattrading, 1B) and gives the per-launcher rules something to be fitted and
   tested on in sequence.

## 5. Caveats

- 24 hits across five launchers, 2 each for mitch and hashbergers; every per-launcher number above is
  a handful of launches.
- Flow baselines use the same loop's earlier launches, so the first three launches of each dev never
  trigger; with the collector this becomes a rolling baseline.
- KOL wallets still untagged; "flow" is everyone who is not the dev or a member.

---

## 6. Joint grid, no look-ahead (2026-09-15 18:20 UTC): the first configuration that survives both loops

576 configurations run on loop 1 and loop 2 separately (`data/anatomy/backtest_v2_joint.csv`); kept
those with ≥ 6 triggers on both. Flow baselines use only the dev's *earlier* launches and, for marks
before 300 s, only the minute-1 inflow, so nothing in the trigger is known after the entry.

**Surviving rule**: tracked launcher; at 60 s, SOL inflow so far ≥ 1.5× the median minute-1 inflow of
that dev's earlier launches (≥ 3 prior); no self-buy or hold condition; exit on +5× take-profit, or a
40% trailing stop from the running high, or −50%, or 30 minutes. Full cost model, $50 per trigger.

| Set | Triggers | Wins | Win rate | P&L | P&L without best trade | Median trade | Worst | Hits caught | Misses entered |
|---|---|---|---|---|---|---|---|---|---|
| Loop 1 | 20 | 11 | 55% | +$960 | +$758 | +$4 | −$35 | 12 of 18 | 8 |
| Loop 2 | 35 | 21 | 60% | +$1,054 | +$841 | +$5 | −$29 | 8 of 24 | 27 |

What it does on the misses it enters: most exit on the trailing stop between 0.8× and 1.2×, i.e. small
losses after fees; the hard stops are the fast dumps (WOJAK, MERCURY, PHOUSE, TOLYBOT). What it does on
hits: five take-profits at 5× (OFFICIAL, WINNIE, RETARDIO, PQ, it, ducknana, MelonMusk, Hunter) carry
the result, the rest exit on the trail at 1.2–2.4×.

Why it works where the hold rule did not: it does not ask what the dev is doing, it asks whether this
launch is drawing more money in its first minute than the dev's launches usually do, which is the
same measurement for holders and dumpers. Its cost is that most of its entries are misses by the $100K definition (27 of 35 on loop 2): it is a first-minute momentum scalp on tracked launchers, not a hit finder, and its wins on misses are launches that popped and were sold on the trail at 1.1–1.7×.

Still in-sample in one sense: the exit parameters were chosen on these two loops. The collector's new
launches are the next out-of-sample set for this exact configuration.

## 7. First live paper loss and the dev-sell veto (2026-09-16)

**The trade.** DUDAS by slingoor, created 01:59:37 UTC. Minute-1 inflow 1,307 SOL = 4.75× his baseline
(274.9) → paper buy at 60 s at 4.44e-7 SOL/token ($50, pool fee 1.20%). Hard stop at 162 s at 0.477×,
net −$27.20. Capital $50 → $22.80.

**Postmortem tape (Bitquery realtime, first 10 min, 3,991 trades).** The dev bought 353.6M tokens for
14.75 SOL in the create transaction and sold all of it in three Jupiter-routed sells at 37 s, 43 s and
47 s for ≈142 SOL, i.e. he was fully out 13 seconds before our entry. No Synagogue member traded the
token in the window. The 10-s buy VWAP (×1e7 SOL/token) went 3.4 → 9.7 (10 s) → 5.5 (40 s, the dev's
dump) → 8.6 (60 s, our entry) → 17.5 (70 s) → spikes → collapse; the sellers from 60 s to 180 s were
unknown wallets, not members. The flow rule saw a token drawing 4.75× the dev's usual money and did not
look at what the dev had already done with his own bag.

**New filter, tested walk-forward on both loops.** `veto_dev_sell=F`: skip the entry when the creator has
sold ≥ F of the tokens he bought by the mark. Everything else unchanged (flow ≥ 1.5×, mark 60 s, TP 5×,
trail 40%, hard −50%, 30 min, full cost model, $50 per trigger).

| Set | Veto | Triggers | Wins | Win rate | P&L | P&L ex-best | Median | Worst | Hits caught |
|---|---|---|---|---|---|---|---|---|---|
| Loop 1 | off | 20 | 11 | 55% | +$960 | +$758 | +$4 | −$35 | 12 of 18 |
| Loop 1 | ≥50% sold | 15 | 9 | 60% | +$804 | +$602 | +$6 | −$34 | 10 of 18 |
| Loop 1 | any sell | 14 | 9 | 64% | +$807 | +$605 | +$14 | −$34 | 10 of 18 |
| Loop 2 | off | 35 | 21 | 60% | +$1,054 | +$841 | +$5 | −$29 | 8 of 24 |
| Loop 2 | ≥50% sold | 28 | 18 | 64% | +$929 | +$717 | +$6 | −$19 | 7 of 24 |
| Loop 2 | any sell | 28 | 18 | 64% | +$929 | +$717 | +$6 | −$19 | 7 of 24 |

The 13 trades the veto removes (6 on loop 1, 7 on loop 2): 5 wins, 8 losses, median −$9. Two of the
five wins are 5× take-profits (WINNIE +$200, "it" +$209) where the dev sold 100% and the token ran
anyway, which is why total P&L drops; without those two outliers the removed set is −$131. The losses
it removes are the fast dumps: MERCURY −$35, PHOUSE −$29, TOLYBOT −$28, HITLERHAUS −$23, ALBERT −$21.
DUDAS has the same profile as the removed set (dev out at 37–47 s, unknown wallets holding the bag).

**Decision.** Veto on at 50%: it raises the win rate on both loops (55→60%, 60→64%), lifts the median,
cuts the worst loop-2 loss from −$29 to −$19, and costs the occasional dev-dumped 5× outlier. With $50
of capital the drawdown matters more than the outlier. Adopted in `scripts/live_paper.py` (measured from
the same 60-s Bitquery window used for the inflow) and available in `scripts/backtest_v2.py` as
`--config veto_dev_sell=0.5`.

**Data fix found during the postmortem.** Bitquery returns aggregator-routed swaps (Jupiter, DFlow) as
two rows: the aggregator leg and the underlying pump_amm leg. On DUDAS this doubled the dev's sold
amount (200% of his bag) and added 0.2% to the inflow. Both the paper trader and the forward collector
now keep only the pump / pump_amm / raydium_launchpad rows, one per swap.
