# notdecu wallet research — Phase 1 checkpoint

Target: Solana wallet `4vw54BmAogeRV3vPKWyFet5yf8DTLcREzdSzx4rw9Ud9` (X: @notdecu, "decu").
Goal: reverse-engineer the trading system and strategy behind the wallet using the GMGN OpenAPI
(`gmgn-cli`) and the GMGN skills knowledge base.

Phase 1 = knowledge ingestion + environment set-up. **Phase 2 (the actual analysis) has not
started; it waits on approval.**

## 1. What was installed

| Item | State |
|------|-------|
| `gmgn-cli` 1.6.2 | installed globally (`npm install -g gmgn-cli`), `gmgn-cli config --check` exits 0 |
| GMGN API key | written to `~/.config/gmgn/.env` (chmod 600). Not committed. `.env` added to `.gitignore` |
| GMGN skills | 15 skills copied into `.claude/skills/` and `.agents/skills/` (`skills-lock.json` tracks source hashes) |
| Source clone | `GMGNAI/gmgn-skills` cloned to scratchpad for the CLI source and docs |

Live verification: `market trending --chain sol` and `portfolio stats` on the target wallet both
return data with the supplied key.

## 2. What was read (the "26")

The GMGN repo ships **15 skills**, not 26. The full reading set was 15 `SKILL.md` files + the two
analysis scripts + 4 reference docs + 10 `docs/` files + `CLAUDE.md` + `Readme.md`.

| Skill | One-line purpose | Relevance to this wallet |
|-------|------------------|--------------------------|
| gmgn-wallet-analysis | four pass/fail gates (authentic, current, reachable, survivable) + live book + copy window + entry mcap band | **core** — its `analyze.py` is the reference implementation for wallet dissection |
| gmgn-wallet-score | 0–100 track-record + copy-tradeability + dev-reputation scores, latency/slippage/gas backtest | core — exact formulas captured in `knowledge/` |
| gmgn-portfolio | raw `stats` / `profits` / `activity` / `holdings` / `created-tokens` commands and field reference | core — the data source for everything |
| gmgn-dev-score | CONDUCT/POWER score of a token creator from launch history + own trades | core — tests the "track dev wallets" hypothesis |
| gmgn-token | `token info/security/pool/holders/traders`, launchpad + creator + wash/bundler/rat fields | core — per-token enrichment of every entry |
| gmgn-holder-analysis | chip structure of a token's top-100 holders (float-based) | secondary — spot-check his best entries |
| gmgn-track | KOL / smart-money / followed-wallet trade feeds | secondary — is he a signal source others copy? |
| gmgn-market | kline (30s…1d), trending, trenches (new pump.fun pairs), signals, hot-searches, search | core — kline around each entry, trenches for the universe he picks from |
| gmgn-kline-pattern | names a chart pattern and scores it 0–100 from six measurements | secondary — classify what charts he enters on |
| gmgn-contract-dd | 0–100 contract due-diligence composite | secondary — replicate his safety filter |
| gmgn-heat-rank | cross-chain screened hot list | low |
| gmgn-narrative | X/social narrative card | low |
| gmgn-token-buy | name→contract resolution + order sizing | low (execution side) |
| gmgn-swap | buy/sell/limit/TP/SL execution, needs private key | not used (read-only research) |
| gmgn-cooking | launch tokens on launchpads | not used |

Workflow docs read: wallet-analysis, smart-money-profile, token-research, token-due-diligence,
project-deep-report, risk-warning, early-project-screening, daily-brief, market-opportunities,
cli-usage. Digest with exact commands, fields, thresholds and formulas: `knowledge/`.

## 3. API surface confirmed live against the target wallet

| Call | Auth | Weight | Result |
|------|------|--------|--------|
| `portfolio stats --period 7d/30d` | key only | 3 | OK — buckets, win rate, hold time, identity, tags |
| `portfolio profits --period 1d/7d/30d/all` | key only | 3 | OK — all-time realized P&L and cost |
| `portfolio activity` | key only | 3 | OK, **server caps a page at 20 rows** regardless of `--limit`; `next` cursor works; rows carry `price_usd`, `token.total_supply`, `gas_usd`, `priority_fee`, `tip_fee`, `launchpad_platform`, `quote_token`, `buy_cost_usd` |
| `portfolio created-tokens` | key only | 2 | OK — wallet has launched 0 tokens (not a dev) |
| `portfolio holdings` | **key + private key** | 5 | **BLOCKED** — needs `GMGN_PRIVATE_KEY` (the Ed25519 PEM whose public key was registered when this API key was created at gmgn.ai/ai). Without it: no live book, no per-position profit concentration, no honeypot check |
| `track follow-wallet` | key + private key | 3 | blocked for the same reason (not needed) |
| everything under `token *`, `market *`, `track kol/smartmoney` | key only | 1–5 | available |

Where the per-token quality signals actually live (verified live on a pump.fun token, sol):

| Signal | Source |
|--------|--------|
| creator address, `creator_token_status`, `creator_open_count`, `cto_flag`, launchpad + status, `open_timestamp`, `migration_market_cap`, `total_fee` (= the "Global Fees Paid" number from the thread), `stat.top_bundler_trader_percentage`, `stat.top_rat_trader_percentage`, `stat.bot_degen_rate`, `stat.fresh_wallet_rate`, `stat.top70_sniper_hold_rate`, `stat.creator_created_count` | `token info` (weight 1) |
| `renounced_mint`, `renounced_freeze_account`, `top_10_holder_rate`, `burn_status` | `token security` (weight 1). **`rug_ratio`, `is_wash_trading`, `sniper_count` are null here on sol** despite the skill docs |
| `rug_ratio`, `is_wash_trading`, `sniper_count`, `smart_degen_count`, `renowned_count`, `bundler_rate` | only on `market trending` / `trenches` / `hot-searches` rank rows (listed tokens only) |
| `total_fee`, `progress`, `launchpad_status`, `creator`, `is_honeypot`, `kol_count`, `hot_level` | `market search -q <CA>` (weight 1, no chain needed) |

Rate limit: leaky bucket `rate=20 / capacity=20` weight units. A full activity history for this
wallet is large (see below), so phase 2 must pace calls (~0.35 s gap, sequential, never parallel)
and persist every page to disk so nothing is re-fetched.

## 4. Baseline snapshot (taken 2026-09-14, files in `data/baseline/`)

| Window | Buys | Sells | Realized P&L | Cost | ROI | Tokens | Win rate |
|--------|------|-------|--------------|------|-----|--------|----------|
| 1d | 616 | 287 | $17.4K | $76.0K | 22.9% | — | — |
| 7d | 5,175 | 1,809 | $94.2K | $381.3K | 18.8% | 2,276 | 62.3% |
| 30d | 18,210 | 6,927 | $350.1K | $1.42M | 19.9% | 2,441 | 59.2% |
| all | 111,693 | 52,606 | $1.91M | $9.89M | 19.4% | — | — |

7d outcome buckets (count tokens): >5x 2 · 2–5x 13 · 0–2x 1,976 · −50–0% 273 · <−50% 12.
Average holding period ≈ 60 h. Unrealized P&L ≈ $0 (holds nothing of value → flat book).

Identity from `common`: X @notdecu, blue-verified, 85,280 followers, 56,845 GMGN followers.
GMGN tags: `kol`, `top_followed`, `top_renamed`, `photon`, `axiom`, `padre`, `arbitrager`,
`wash_trader`. Wallet created 2024-10-26; last funded 1.0 SOL from an Axiom address.
Native balance ≈ 933 SOL.

First observations (not conclusions):

- ~1,000 trades/day and ~2,300 distinct tokens/week is machine cadence. Every skill in the set
  would tag this "bot-tier". The most recent row is a USDC-quoted sell of a non-meme token
  (`ARB`, supply 1.2M), which together with the `arbitrager` tag suggests more than one strategy
  runs from this address.
- The `wash_trader` tag needs the conviction-share test from `gmgn-wallet-analysis` before it
  means anything; that test needs `holdings`, which is blocked (see §3). A substitute using
  activity-derived per-token P&L is planned.
- Realized ROI is stable at 19–23% across every window: no decay, no one-coin dependence
  visible in the buckets.

## 5. Constraints and open items for approval

1. **Private key.** If you have the PEM generated when the API key was created, adding it as
   `GMGN_PRIVATE_KEY` unlocks `portfolio holdings`. If not, phase 2 reconstructs positions from
   `activity` instead (slower, but complete for closed trades).
2. **History depth.** ~164K lifetime trades ÷ 20 rows/page ≈ 8,200 pages at weight 3. Full
   history is not feasible in one session. Proposed scope: the last 30 days (≈25K trades →
   ~1,260 pages ≈ 1.5–2 h of paced pulls), plus targeted `--token` walks for the biggest winners
   and losers of all time.
3. **Read-only.** No swap, order, or cooking command will be run.

## 6. Proposed Phase 2 plan (waiting on approval)

1. **Pull** 30 days of `activity` (buy/sell, then transferIn/transferOut) into
   `data/activity/*.jsonl`, resumable by cursor.
2. **Reconstruct positions** per token: first buy time, entry market cap (`price_usd ×
   total_supply`), clip size, buys/sells per position, hold time, realized P&L, fees.
3. **Enrich** each token (rate-paced): `token info` (launchpad, creator, open_timestamp,
   migration mcap), `token security` (rug ratio, wash flag, bundler/rat rates, sniper count),
   and for the top-N tokens `market kline --resolution 1m` around his entry and exit.
4. **Dev-wallet hypothesis:** for every creator address seen, `created-tokens` → does he prefer
   devs with a prior graduated / high-ATH launch? Run `dev_score.py` on the recurring devs.
5. **Cadence / automation analysis:** inter-trade gaps, buys per block, clip-size histogram,
   hour-of-day profile, quote-token mix (SOL vs USDC), priority/tip fee behaviour, DEX routing
   tags (`photon`/`axiom`/`padre`).
6. **Exit model:** sells per position, fraction sold at first exit, time from first buy to first
   sell, stop-loss behaviour (where do the 273 small losers get cut).
7. **Copyability check:** run the shipped `gmgn-wallet-analysis` and `gmgn-wallet-score` scripts
   for the official verdicts and backtest, then compare against our reconstruction.
8. **Deliverable:** `research/notdecu-wallet/REPORT.md` — strategy description, rules inferred
   with evidence tables, what is and is not replicable, and a rule-set draft for a screener.
