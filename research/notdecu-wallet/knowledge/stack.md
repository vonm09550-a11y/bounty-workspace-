# Minimum stack beyond GMGN (read-only research, free plans)

Decided 2026-09-14. Rule: one paid-capable provider (on its free plan), everything else keyless
or local. No trading APIs, no SDK that signs.

## Why GMGN alone is not enough

| Gap in GMGN | Consequence for phase 2 | Filled by |
|-------------|-------------------------|-----------|
| `portfolio activity` returns 20 rows/page (≈8,200 pages for this wallet's 164K trades) | full history infeasible, 30d costs ~1,260 paced calls | Helius transaction history (100/page, unlimited mainnet retention) |
| no slot / block position, no program IDs, no router identity per trade | cannot tell pump.fun curve vs PumpSwap vs Jupiter route, cannot see same-slot buys, Jito tips, or which bot (Axiom/Photon/Padre) sent the tx | Helius parsed tx (`source`, `type=SWAP`, instructions, fee payer, inner transfers) |
| `holdings` needs the API key's private key | no live book | Helius `getTokenAccountsByOwner` (RPC, keyless alternative) |
| kline exists only for tokens GMGN indexed a pool for | no candles for many never-graduated pump tokens | reconstruct price from the wallet's own fills + pump.fun `TradeEvent` logs; Birdeye only if still needed |
| GMGN tags are opaque (`wash_trader`, `arbitrager`) | cannot verify | raw tx data |

## Tier A — required: Helius (Free plan)

- Sign up: https://dashboard.helius.dev (free, one API key). Plans: https://www.helius.dev/docs/billing/plans
- Free plan: 1M credits/month, RPC 10 req/s, Enhanced APIs 2 req/s, DAS 2 req/s, Wallet API included.
- Enhanced transaction history: `GET https://api.helius.xyz/v0/addresses/{wallet}/transactions?api-key=…&limit=100&type=SWAP&before-signature=…` with `gt-time/lt-time` filters; unlimited retention on mainnet. Docs: https://www.helius.dev/docs/enhanced-transactions/transaction-history , overview https://www.helius.dev/docs/enhanced-transactions/overview
- RPC: `getSignaturesForAddress` (1,000/page → ~165 calls for the whole wallet), `getTransaction`, `getBlock`, `getTokenAccountsByOwner`.
- Budget estimate for our scope: 30 days ≈ 25K trades ≈ 250 history calls; whole life ≈ 1,650 calls. Even at 100 credits per enhanced call that is ≤165K credits, inside the 1M/month. At 2 req/s the whole-life pull is ~15 min of wall time.
- Env var: `HELIUS_API_KEY` in `~/.config/gmgn/.env` alongside the GMGN key (never committed).

## Tier B — free, keyless, used opportunistically

| Tool | Use | Limits | Link |
|------|-----|--------|------|
| DexScreener API | current pair snapshot (price, liquidity, FDV, pair created time) for any token GMGN cannot resolve | 300 req/min, no key, no rate-limit headers → self-pace | https://docs.dexscreener.com/api/reference |
| Jupiter Lite Price API | SOL/USD at analysis time for USD conversions | free Lite tier, shared default bucket | https://developers.jup.ag/docs/api-reference/price |
| PumpPortal data websocket | live `subscribeNewToken` + `subscribeMigration` stream if we replay "what was launching when he bought" | those two streams free; per-token/account trade streams cost 0.01 SOL / 10K msgs → not used | https://pumpportal.fun/data-api/real-time/ |
| pump.fun public docs + IDLs | program IDs, `TradeEvent`/`CreateEvent` layouts for local log decoding | none (git repo) | https://github.com/pump-fun/pump-public-docs |

Program IDs (verify against the IDL folder before decoding): pump bonding curve
`6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P`, global account
`4wTV1YmiEkRvAtNtsSGPtUrqRYQMe5SKy2uB4Jjaxnjf`, fee recipient
`62qc2CNXwrYqQScmEdiZFFAnJR262PxWEuNQtxfafNgV`. PumpSwap AMM program ID is not in the README;
take it from `idl/pump_amm.json` in that repo.

## Tier C — optional, only if a specific question needs it

| Tool | When | Free limits | Link |
|------|------|-------------|------|
| Birdeye Data API | 1s/15s/30s candles for a handful of his best trades where GMGN kline is empty | 30K CU/month, 1 req/s; OHLCV = 40 CU/call, ≤1,000 candles | https://docs.birdeye.so/reference/get-defi-v3-ohlcv , https://bds.birdeye.so/pricing |
| Dune | cohort questions across many wallets (e.g. "who else buys the same devs") | free tier went view-only for legacy accounts on 2026-09-10; new accounts get 2,500 credits | https://docs.dune.com/learning/how-tos/credit-system |

## Explicitly not in the stack

- PumpPortal Trading API (0.5% fee), pump.fun trading SDKs, Jito, GMGN `swap`/`order`/`cooking`: research is read-only.
- Bitquery, Moralis, Solscan Pro, QuickNode/Alchemy: duplicate Helius, paid for the parts we need.
- Public `api.mainnet-beta.solana.com`: 100 req/10 s per IP, no archival guarantee; Helius replaces it.

## Local tooling (already available in this environment or pip-installable)

- Python 3 + `requests`, `duckdb`, `pandas` for the parquet/duckdb dataset under `research/notdecu-wallet/data/`.
- `solders` + `solana-py` only if we drop to raw RPC; Helius parsed output should cover most of it.
- Node 22 + `gmgn-cli` (installed).
