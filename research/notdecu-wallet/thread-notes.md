# Source thread — @notdecu (decu), 30 Apr 2026

Wallet (Solana): `4vw54BmAogeRV3vPKWyFet5yf8DTLcREzdSzx4rw9Ud9`

Claim: "I publicly took my wallet from $250,000 PNL to $1,000,000 in 6 months."
Screenshots in `refs/` show a GMGN profile card: Realized PnL +19.39% (+$1M), win rate 61.2%,
earlier card (228d) +35.72% (+$243.6K), win rate 50.25%. "I have made 7 figs on pumpfun, but my
doxxed wallet is only at $250k."

## Self-described strategy (verbatim points, in thread order)

1. **Niche: new pairs.** "Whether it's high-caps, mid-caps, or even deving, everyone has a niche.
   In my case, I have seen success in new pairs and unfortunately, I am not the best at the rest."
2. **Filter bad coins from good ones by tracking dev wallets.** "To find the good ones: analyze
   previous performances through their wallet. Stay chronically online to spot recurring names."
   (Screenshot of a GMGN "Add Wallet" dialog: dev wallet address + name + group.)
3. **Know the meta.** "It is hard to trench new pairs only being online 2-3 hours a day. You have
   to know what's already ran, understand the current meta, and recognize exactly how coins are
   moving. Even if you aren't trading, just staring at the scope/charts is the best way to build
   your edge."
4. **Inspect every detail before buying:** name, ticker, dev wallet, holders. "With vamps
   everywhere, even a tiny misspelling or a bearish image is a red flag."
5. **Global-fees rug filter.** "If a coin is getting volume and global fees look like this
   [Global Fees Paid ≈ 0.0₂1 SOL] it is most likely a rug." I.e. real volume with near-zero
   fees paid = wash / bundled volume.
6. **Mental game.** "You usually think you are pvping others when most of the time you are pvping
   yourself. One small hesitation could be the reason you miss out on that one cook."

## What this gives phase 2 (hypotheses to test against on-chain data)

- H1: entries concentrate on very new pump.fun pairs (age at first buy in minutes, pre- or
  just-post-migration).
- H2: token selection correlates with dev wallets that have a prior graduated / high-ATH launch
  (`token info` → `dev.creator_address` → `portfolio created-tokens`).
- H3: he avoids tokens with wash-trade / bundler signatures (`is_wash_trading`,
  `bundler_trader_amount_rate`, `rat_trader_amount_rate`, low `total_fee` vs volume).
- H4: exits are fast, scaled (multiple sells per token), and losses are cut (bucket data already
  shows only 12 of 2,276 tokens down >50% in 7d).
- H5: the 7d cadence (~1,000 trades/day, 2,276 tokens/week) is not manual — look for bot /
  copy-trade / sniper signatures in timing (sub-second gaps, same-block buys, fixed clip sizes).
