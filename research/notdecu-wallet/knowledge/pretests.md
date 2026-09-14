# Pre-test results (2026-09-14) — what the tools actually return for this wallet

Raw outputs (keys stripped) are in `data/pretests/`.

## 1. Helius works, but the address history is buried in spam

`getSignaturesForAddress` for the wallet returned its newest 1,000 signatures spanning **13
seconds**. 983 of them (98.3%) are failed transactions, signed by other wallets, that merely
reference this address. They run through two unknown programs
(`BMofZXeaBSzWWdSnMbnRQNFCabDfziwxMMeS32jKUoyf`, `DhpyNWkdxFh3DRPsBrwRwrK3TYC5t7Q4arnSvf3t84HY`,
error `Custom: 7`), up to 51 in a single slot. Helius labels the second one `PUMP_FUN`. The
likely reading: copy-trade bots of his 56K GMGN followers hammering his address as a reference
account. Whatever it is, it means:

- Helius **enhanced history** (`/v0/addresses/{wallet}/transactions`) is unusable as the index:
  with `type=SWAP` it scans, finds nothing within its window and returns 404 with a
  continuation signature, ~10–12 s per call. Time filters (`lt-time`) do not help.
- Raw signature paging would need millions of rows to reach his real trades.
- The Helius Wallet API is paid-plan only and has no fee-payer filter.

## 2. The design that works: GMGN as the index, Helius as the enricher

`gmgn-cli portfolio activity` returns only his own trades (20 rows/page, `tx_hash` on every
row). The 20 rows of page 1 mapped to **15 unique signatures** (multi-leg swaps produce several
rows per tx). `POST /v0/transactions` parsed all 15 in **1.3 s** in one call, every one with
`feePayer == wallet`. So phase 2 pulls the index from GMGN and enriches in batches of 100.

Cost for 30 days (≈25K trade rows ≈ 19K unique tx): ~1,260 GMGN pages (weight 3, paced 0.4 s →
~10 min) + ~190 Helius parse calls. Whole life (~164K rows) is ~8,200 GMGN pages ≈ 1 h of
paced pulls if ever wanted.

## 3. What the parsed trades already reveal (15 tx sample, not a conclusion)

| Observation | Value |
|-------------|-------|
| Top-level program on every trade | `FLASHX8DrLbgeR8FcfNV1F5krxYcYMUdBkrP1EPBtxB9` (upgradeable BPF program, unlabeled in public maps) — a single router/bot for 15/15 trades |
| Inner venues | pump.fun bonding curve (8), PumpSwap AMM (7), Meteora DLMM (3), Raydium AMM v4 (3), Jupiter (2), Raydium CLMM (2); pump fee program `pfeeUxB6…` on 15/15 |
| Native SOL transfers out of the wallet per trade | to `6E2GiNVz…` (10/15), `ECDrSz47…` (5), `EqGzowSp…` (4), `2ApLdwLr…` (4): bot fee / tip accounts to be labelled in phase 2 |
| Priority fees | 27K–114K lamports per tx |
| Quote assets | not only SOL: pump.fun tokens launched with **ARB** and **UNI** as the bonding-curve quote mint (`Hhj4846211…pump` "Alon" is quoted in `ARBzQTYD…`), routed token → ARB → USDC → SOL through Jupiter in one tx. GMGN records these as separate `ARB`/`UNI` buy and sell rows, which is probably why it tags the wallet `arbitrager` |
| Helius `type` labels | SWAP/PUMP_AMM 7, SWAP/PUMP_FUN 3, SWAP/JUPITER 2, TRANSFER/SYSTEM_PROGRAM 3 (the USDC→UNI legs are parsed as transfers, so never filter on `type=SWAP` alone) |

## 4. Other endpoints

| Tool | Result |
|------|--------|
| Helius RPC `getBalance` | 933.13 SOL (matches GMGN `native_balance`) |
| Helius RPC `getTokenAccountsByOwner` | 903 token accounts, 902 non-zero; GMGN says unrealized P&L ≈ $0, so these are dust bags. Usable holdings substitute while the GMGN PEM is unavailable |
| DexScreener `/latest/dex/tokens/{mint}` | 200, pair on `pumpswap` with `pairCreatedAt`, liquidity, FDV |
| Jupiter `lite-api.jup.ag/price/v3` | 200, SOL $101.82 |
| PumpPortal `wss://pumpportal.fun/api/data` `subscribeNewToken` | connects, messages carry `mint, name, symbol, traderPublicKey, initialBuy, marketCapSol, vSolInBondingCurve, bondingCurveKey, pool, is_mayhem_mode` |
| pump.fun IDLs | fetched to `refs/idl/`: pump `6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P`, pump_amm `pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA` (32 instructions), events incl. `TradeEvent`, `BuyEvent`, `SellEvent`, `AddQuoteControlMintEvent` (explains the ARB/UNI-quoted curves) |
| GMGN `token info` on the ARB-quoted pump token | `launchpad pump`, `launchpad_status 0`, `pool.quote_symbol ARB`, creator `Biuetdz3…`, 5 holders |

## 5. Scripts added

- `scripts/env_check.py` — re-runs every check above (no data pull). Exit 0 = ready.
- `scripts/clients.py` — paced, resumable `GmgnActivity` walker and `Helius.parse()` batch
  enricher with JSONL caches under `data/`. Not executed yet.
