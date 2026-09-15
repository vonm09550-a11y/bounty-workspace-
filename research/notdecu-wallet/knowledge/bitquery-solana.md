# Bitquery Solana / pump.fun trade-history API — knowledge file

Researched 2026-09-15 from docs.bitquery.io, bitquery.io/pricing and the public docs source repo
(`github.com/bitquery/streaming-data-platform-docs`, raw `.md/.mdx` files). Nothing here was tested against the
API (no signup, no calls). Every claim carries the page it came from; "UNKNOWN" marks what the docs do not say.

Our target: for one mint, every trade on pump.fun bonding curve (`6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P`,
ProtocolName `pump`), PumpSwap AMM (`pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA`, ProtocolName `pump_amm`) and
Raydium LaunchLab (`LanMV9sAd7wArD4vJFi2qDdfnVhFxYSUg6eADduJ3uj`, ProtocolName `raydium_launchpad`) in a time
window, with owner wallet, side, amounts, price, slot, signature, fee — for 2025–2026 history.

## TL;DR — what is and is not possible (read this first)

| Need | Feasible in Bitquery v2 GraphQL? | Where / how | Source |
|---|---|---|---|
| Per-trade rows for a mint, 2025–2026 | **Yes, only via `Solana(dataset: archive) { DEXTradeByTokens }`** — archive starts "mid-2024" / "1 June 2024" | §3, §5 | coverage matrix, historical page |
| Same via `DEXTrades` (Buy/Sell cube) | **No** — Solana `DEXTrades` realtime only, ~12 h, no archive | §3 | coverage matrix |
| `dataset: combined` on Solana | **Broken** — "every `Solana(dataset: combined)` cube tested returns a ClickHouse 500"; use `archive` | §1 | coverage matrix, DEX trades page |
| Trades in last ~30 days with USD, fee, trader | `Trading { Trades }` cube (realtime only, ~30 days, archive/combined rejected) | §3 | trades-api page |
| Token creation event (2025 token) via `Instructions` / `TokenSupplyUpdates` | **No** — those cubes keep ~12 h, no archive. Docs point to the **v1** transfers API (`transferType: mint`) or use first-trade time on archive `DEXTradeByTokens` as a proxy | §4 | coverage matrix, Pump-Fun-API page |
| Tokens created by creator X, historically | **v1 API only** (`solana.transfers`, `signer`, `externalProgramId`, `transferType: mint`) | §4 | Pump-Fun-API page |
| Archive access on self-serve plan | Requires the paid **Solana "Historical OHLCV & Token Price" add-on** ($210/mo per docs; pricing page also showed $150/mo annual). Trial (7 days, 1,000 points) "includes complete history" | §6 | archive page, paid page, billing page |
| Priority fee / compute units | **UNKNOWN / not found** — only `Transaction.Fee`, `FeeInUSD`, `FeePayer` are documented | §3 | fees page |

---

## 1. Endpoints and datasets

**v2 GraphQL endpoint (HTTP):** `https://streaming.bitquery.io/graphql`
- "If IDE points to the default endpoint https://graphql.bitquery.io, use the dropdown to change it to the new endpoint https://streaming.bitquery.io/graphql which is labelled as 'V2'." — https://docs.bitquery.io/docs/start/first-query/
- Python example posts to `url_graphql = "https://streaming.bitquery.io/graphql"` — https://docs.bitquery.io/docs/authorisation/how-to-use/
- Errors page: "Send `Authorization: Bearer <token>` to `https://streaming.bitquery.io/graphql` (v2)" — https://docs.bitquery.io/docs/start/errors/

**WebSocket:** `wss://streaming.bitquery.io/graphql` (token must go in the URL: `?token=ory_at_...`; "For the `wss` endpoint, the 2nd method is the only way") — https://docs.bitquery.io/docs/authorisation/how-to-use/

**EAP endpoint `https://streaming.bitquery.io/eap`:** deprecated. "Chains from the Early Access Program (EAP) have moved to v2." Existing customers can continue using it; new users use v2 — https://docs.bitquery.io/docs/graphql/dataset/EAP/. Some older use-case code still posts to `https://streaming.bitquery.io/eap` (e.g. https://docs.bitquery.io/docs/usecases/wash-trading-detector/prepare-data/getTrades/). **Use `/graphql`.** The coverage matrix and the DEX-trades page state their measurements were made "on the `/graphql` endpoint" — https://docs.bitquery.io/docs/graphql/data-coverage-retention/

**v1 endpoint (for the genesis-deep transfers fallback):** `https://graphql.bitquery.io` (from the first-query page quote above). v1 auth header: UNKNOWN from pages read (v1 docs auth page returned 404; search snippets mention both `X-API-KEY` and Bearer — unverified).

**Datasets are an argument on the chain root, same endpoint:** `Solana(dataset: realtime | archive | combined)`. Default is `realtime` ("Realtime is the default database (if you omit the attribute, then it is used)") — https://docs.bitquery.io/docs/graphql/dataset/realtime/

| dataset | What it is | Solana specifics |
|---|---|---|
| `realtime` | "contains the latest data available (up to the last second)"; "includes all blocks, including trunk, branches" | "roughly 12 hours on Solana `DEXTrades`, about 7 days on Solana `DEXTradeByTokens` … about 30 days on the `Trading` cubes". "Querying a date range wider than the retention window returns **fewer rows, not an error**" — https://docs.bitquery.io/docs/graphql/dataset/realtime/ |
| `archive` | "delay from tens of minutes to several hours"; "includes all blocks from the genesis" for most chains; "only trunk blocks included" | "**With the exception of Solana**, Bitquery provides complete historical data (from genesis onward)… For Solana, full historical token transfers are available via the V1 API, while in V2, Bitquery offers price aggregates starting from 2024." Requires historical add-on on self-serve plans — https://docs.bitquery.io/docs/graphql/dataset/archive/ |
| `combined` | "the query goes to the archive and real time databases separately and then the results are joined"; "you should avoid using this type of query, as it is slower… and does not give full consistency" — https://docs.bitquery.io/docs/graphql/dataset/combined/ | "every `Solana(dataset: combined)` cube tested returns a ClickHouse **500** on the `/graphql` endpoint. Use `realtime` for recent data and `archive` for history until this is resolved." — https://docs.bitquery.io/docs/graphql/data-coverage-retention/ (many doc examples still say `combined`; the DEX-trades page says "swap `combined` for `archive` to run them" — https://docs.bitquery.io/docs/blockchain/Solana/solana-dextrades/) |

**Solana coverage matrix (verbatim rows)** — https://docs.bitquery.io/docs/graphql/data-coverage-retention/

| Cube | realtime | archive / combined | Notes |
|---|---|---|---|
| `DEXTradeByTokens` | ✅ ~7 days | Since mid-2024 (`archive`) | "The longer-retention chain-level trade cube (vs ~12 h on `DEXTrades`)… use this for older history" |
| `DEXTrades` | ✅ ~12 hours | — | "Same trades as above, far shorter window." |
| OHLC / price aggregates | ✅ | Minute-level since October 2024 | |
| `Transfers` | ✅ ~12 hours | via S3 | "Deep history via S3 export." |
| `Instructions` | ✅ ~12 hours | — | "Deep historical instruction lookup by signature is not available via API." |
| `InstructionBalanceUpdates`, `BalanceUpdates` | ✅ ~12 hours | — | |
| `DEXPools` | ✅ ~12 hours | — | "`no API tables for cube DEXPool`" on archive/combined |
| `Transactions` / `Blocks` / `Rewards` / `DEXOrders` / `TokenSupplyUpdates` | ✅ ~12 hours | — | |
| `Trading.Trades` (cross-chain) | ~30 days | rejected | "`Trading.Trades` is **realtime only** — `dataset: archive` and `combined` are rejected — and holds roughly the last 30 days." — https://docs.bitquery.io/docs/trading/crypto-trades-api/trades-api/ |

Historical page summary: "Aggregate trade history (OHLCV, volume, ATH, first buyers, PnL) runs on the `DEXTradeByTokens` cube with `dataset: archive` or `combined` and starts on 1 June 2024." — https://docs.bitquery.io/docs/blockchain/Solana/historical-aggregate-data/

Measure your own retention floor (docs' query):
```graphql
query RetentionFloor {
  Solana(dataset: realtime) {
    Transfers(limit: { count: 1 }) {
      Block {
        oldest: Time(minimum: Block_Time)
        newest: Time(maximum: Block_Time)
      }
    }
  }
}
```
"Swap the cube, the `dataset:` and the chain root to fill in the matrix for your own account." — https://docs.bitquery.io/docs/graphql/data-coverage-retention/

## 2. Auth

Source: https://docs.bitquery.io/docs/authorisation/how-to-generate/ and https://docs.bitquery.io/docs/authorisation/how-to-use/

- Create an application at account.bitquery.io → Authorization → Applications ("+ New Application", "select an expiration time for the access tokens"), then Tokens → "Generate New Token" → Copy. Token lifetime is the per-application expiration you chose (UNKNOWN default; the page does not state a number for manual tokens).
- Programmatic (OAuth2 client-credentials, `scope=api` required):
```bash
curl -X POST "https://oauth2.bitquery.io/oauth2/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=client_credentials" \
  --data-urlencode "client_id=YOUR_CLIENT_ID" \
  --data-urlencode "client_secret=YOUR_CLIENT_SECRET" \
  --data-urlencode "scope=api"
```
  Sample responses in the docs: `{"access_token":"<your_access_token>","expires_in":17999,"scope":"api","token_type":"bearer"}` and `{'access_token': 'ory_at_sKK8sSq8', 'expires_in': 2627999, 'scope': 'api', 'token_type': 'bearer'}` (i.e. ~5 h and ~30 days; lifetime follows the application setting).
- "If you have no applications created, the `Bearer` token changes every 12 hours. If the token is invalid, you get 'Unauthorized' message."
- **Header:** `Authorization: Bearer <access_token>` with `Content-Type: application/json`. Alternative: `https://streaming.bitquery.io/graphql?token=ory_at_...` (mandatory for wss).
- After a plan upgrade "generate a new access token" or you keep the old `points limit exceeded` cap — https://docs.bitquery.io/docs/plans/how-billing-works/
- Tokens look like `ory_at_...`.

## 3. Schema: which cube, which fields

### 3.1 Cube choice (Solana)
- `Solana.DEXTrades` — "Complete trade data bifurcated by buy/sell sides": `Trade.Buy{Amount, Account{Address, Owner / Token{Owner}}, Currency{MintAddress…}, Price, PriceInUSD}` and `Trade.Sell{…}`. On Solana it is "Trader-focused—natural fit for signer, buyer/seller, and account-style filters" — https://docs.bitquery.io/docs/cubes/dextrades-dextradebytokens-trading-trades. **Realtime only, ~12 h → useless for 2025 history.**
- `Solana.DEXTradeByTokens` — token-centric: "`Trade{Currency}` is first currency and details just before side are for this first currency. Whereas details such as Account, Amount, Price, PriceInUSD, etc inside side are for side currency. Side also has `type` field which tells us if its a `buy` trade or a `sell` trade. The `type` is wrt the pool and side currency." — https://docs.bitquery.io/docs/cubes/solana/. **Only cube with Solana archive (mid-2024→).** Archive indexes: `Trade_Currency_MintAddress`, `Trade_Account_Owner` (realtime index: `Trade_Currency_MintAddress` only) — https://docs.bitquery.io/docs/graphql/indexed-fields-reference/
- Each swap appears twice in DEXTradeByTokens (once per token): "If a trade occurs between User A and User B, the DexTradeByTokens API shows User A as both buyer and a seller" — https://docs.bitquery.io/docs/cubes/dextradesbyTokens/. Filtering `Trade.Currency.MintAddress = <mint>` yields one row per fill for that mint.
- `Trading.Trades` — cross-chain, "clean, MEV-filtered swaps with USD price, market cap, and supply on every row", `Trader.Address`, `Side` ("Buy"/"Sell"), `TransactionHeader{Fee FeePayer Sender To Hash Index}`, `Amounts{Base Quote}`, `AmountsInUsd{Base Quote}`, `Price`, `PriceInUsd`, `Block{Date Time Timestamp}`; ~30 days only; `Block.Slot` not documented. Warns about duplicate rows: "Deduplicate on `(TransactionHeader.Hash, Trader.Address, Side, Amounts.Base)`" — https://docs.bitquery.io/docs/trading/crypto-trades-api/trades-api/
- `Solana.Instructions` / `TokenSupplyUpdates` — creation events (`Program.Method in ["create","create_v2"]`), realtime ~12 h only.

### 3.2 Filters (field names)
- Mint: `Trade: { Currency: { MintAddress: { is: "<mint>" } } }` (DEXTradeByTokens); `Trade: { Buy: { Currency: { MintAddress: { is } } } }` (DEXTrades) — https://docs.bitquery.io/docs/blockchain/Solana/Pumpfun/Pump-Fun-API/
- Quote/side currency: `Trade: { Side: { Currency: { MintAddress: { in: ["11111111111111111111111111111111", "So11111111111111111111111111111111111111112"] } } } }` — the docs' ATH example lists **both** the native-SOL sentinel `1111…` and WSOL — https://docs.bitquery.io/docs/blockchain/Solana/Pumpfun/Pump-Fun-API/
- Protocol: `Trade: { Dex: { ProtocolName: { is: "pump" } } }` (bonding curve), `"pump_amm"` (PumpSwap, "family `Pumpswap`"), `"raydium_launchpad"` (LaunchLab); or `Dex: { ProgramAddress: { is: "<program>" } }`. "In the trade cubes the two venues appear as `Dex.ProtocolName` `pump` for the bonding curve and `pump_amm` for PumpSwap" — https://docs.bitquery.io/docs/blockchain/Solana/Pumpfun/Pump-Fun-API/ ; `raydium_launchpad` — https://docs.bitquery.io/docs/blockchain/Solana/launchpad-raydium/
- Time: `Block: { Time: { since: "2024-06-01T00:00:00Z", till: "2024-06-02T00:00:00Z" } }` (operators `is, not, after, since, till, before`) — https://docs.bitquery.io/docs/graphql/filters/. `till` is inclusive; "`since` + `before` gives the half-open interval `[since, end)`" — https://docs.bitquery.io/docs/blockchain/Solana/solana-dextrades/. Relative: `since_relative/after_relative/till_relative/before_relative: { minutes_ago | hours_ago | days_ago … }` — https://docs.bitquery.io/docs/graphql/capabilities/relative-time/. `Block.Date` also works (`{ since: "2026-01-01", till: "2026-01-02" }`).
- Success only: `Transaction: { Result: { Success: true } }`.
- Trader: `Trade: { Account: { Owner: { is } } }` (archive-indexed) or `Transaction: { Signer: { is } }`.
- **Archive/combined `where:` restrictions (DEXTradeByTokens):** `Trade.Amount`, `Trade.Side.Amount`, `Trade.Price`, `Trade.Currency`, `Trade.Side.Currency`, `Trade.Account.Address`, `Trade.Side.Type`, `Trade.Dex`, `Block.Time` **work**; `Trade.PriceAsymmetry`, `Trade.Side.AmountInUSD`, `Trade.AmountInUSD`, `Trade.PriceInUSD` **error** as filters (still fine as outputs/measures); `Trade.Side.Account` **errors as filter and as projection** — https://docs.bitquery.io/docs/blockchain/Solana/historical-aggregate-data/#filter-limitations-on-aggregate-datasets

### 3.3 Output fields
- Time/slot: `Block { Time Slot Height }` (PumpSwap example) — https://docs.bitquery.io/docs/blockchain/Solana/Pumpfun/pump-swap-api/
- Signature / payer / fee: `Transaction { Signature Signer FeePayer Fee FeeInUSD Index Result { Success } }` — fees example on DEXTradeByTokens — https://docs.bitquery.io/docs/blockchain/Solana/solana_fees_api/. `FeePayer`: "The account responsible for paying the transaction fee"; `Fee`: "The fee paid for executing the transaction" — https://docs.bitquery.io/docs/cubes/solana/. Docs alias `sum(of: Transaction_Fee)` as `Total_fees_paid_in_SOL` (so SOL units, decimal; unit not explicitly stated). **Priority fee / compute-unit price: not found in any doc page.**
- Trader: `Trade { Account { Address Owner Token { Owner } } }` — `Address` = token account, `Owner` / `Token.Owner` = wallet owner (used as "trader address (Owner)" in the top-traders example) — https://docs.bitquery.io/docs/blockchain/Solana/historical-aggregate-data/. `Trade.Side.Account` is not available on archive.
- Amounts/price: `Trade { Amount AmountInUSD Price PriceInUSD Side { Type Amount AmountInUSD Currency { MintAddress Symbol Decimals } } Currency { MintAddress Symbol Name Decimals } Dex { ProtocolName ProtocolFamily ProgramAddress } Market { MarketAddress } }`. `Price` = "The rate at which this currency is exchanged for the side currency" — https://docs.bitquery.io/docs/cubes/solana/
- Instruction context: `Instruction { Program { Method } }` (e.g. `buy`/`sell`) shown in the PumpSwap latest-trades example.

### 3.4 Buy/sell semantics
- DEXTradeByTokens: "If `Side.Type` is `"buy"`, the pool is the buyer of the side currency (pool = `Side.Buyer`). If `Side.Type` is `"sell"`, the pool is the seller of the side currency" — https://docs.bitquery.io/docs/cubes/dextradesbyTokens/. With `Trade.Currency = token` and `Side.Currency = SOL`: **`Side.Type: buy` ⇒ pool takes SOL ⇒ trader bought the token**. Docs consistently use it that way: top-traders `bought: sum(of: Trade_Amount, if: {Trade: {Side: {Type: {is: buy}}}})`, `buyers: count(distinct: Transaction_Signer, if: {Trade: {Side: {Type: {is: buy}}}})`, LaunchLab "Top Buyers" `Side: { Type: { is: buy } }` — https://docs.bitquery.io/docs/blockchain/Solana/Pumpfun/Pump-Fun-API/, https://docs.bitquery.io/docs/blockchain/Solana/launchpad-raydium/. **Inconsistency to verify:** the historical page's "Get First 100 buyers of a Token" filters `Side: { Type: { is: sell } }` — https://docs.bitquery.io/docs/blockchain/Solana/historical-aggregate-data/. Cross-check on one known tx before trusting the sign.
- DEXTrades (Solana): buyer wallet of the token = `Trade.Buy.Account.Token.Owner` when `Trade.Buy.Currency.MintAddress = token` (first-100-buyers example) — https://docs.bitquery.io/docs/blockchain/Solana/Pumpfun/Pump-Fun-API/
- Trading.Trades: `Side` is `"Buy"`/`"Sell"` from the trader's view (`Amount_Bought: sum(of: AmountsInUsd_Base, if: { Side: { is: "Buy" } })`) — same page.

### 3.5 The one query for our need (per-trade rows, archive, one mint, time window)
Assembled from documented fields (PumpSwap latest-trades + fees example + archive filter table); **not run**. `Block.Slot`, `Transaction.Fee/FeePayer` are documented on the realtime path — their presence on `dataset: archive` is UNKNOWN (the archive filter table only lists trade fields). Test on the trial.
```graphql
query TokenTradesWindow($mint: String!, $since: DateTime!, $before: DateTime!, $limit: Int!, $offset: Int!) {
  Solana(dataset: archive) {
    DEXTradeByTokens(
      where: {
        Trade: {
          Currency: { MintAddress: { is: $mint } }
          Dex: { ProtocolName: { in: ["pump", "pump_amm", "raydium_launchpad"] } }
        }
        Block: { Time: { since: $since, before: $before } }
        Transaction: { Result: { Success: true } }
      }
      orderBy: [{ ascending: Block_Time }, { ascending: Transaction_Index }, { ascending: Trade_Index }]
      limit: { count: $limit, offset: $offset }
    ) {
      Block { Time Slot }
      Transaction { Signature Signer FeePayer Fee }
      Instruction { Program { Method } }
      Trade {
        Account { Address Owner }
        Amount
        Price
        PriceInUSD
        Side { Type Amount AmountInUSD Currency { MintAddress Symbol } }
        Dex { ProtocolName ProgramAddress }
        Market { MarketAddress }
      }
    }
  }
}
```
Variables: `{"mint":"<mint>","since":"2025-03-01T12:00:00Z","before":"2025-03-01T12:30:00Z","limit":10000,"offset":0}`.
Ordering keys are from the docs: "sort by `Block.Slot`, `Transaction.Index`, `Trade.Index` (add `Instruction.Index` and `Instruction.InternalSeqNumber` as further tie-breakers)" — https://docs.bitquery.io/docs/blockchain/Solana/solana-dextrades/ and the PumpSwap example's `orderBy: [{descending: Block_Time}, {descending: Transaction_Index}, {descending: Trade_Index}]`.

Docs' own per-token latest-trades query (PumpSwap, verbatim, default realtime) — https://docs.bitquery.io/docs/blockchain/Solana/Pumpfun/pump-swap-api/#latest-trades-for-a-token-on-pumpswap
```graphql
{
  Solana {
    DEXTradeByTokens(
      where: {
        Trade: {
          Dex:{ ProgramAddress:{ is:"pAMMBay6oceH9fJKBRHGP5D4bD4sWpmSwMn52FMfXEA" } }
          Currency: {MintAddress: {is: "token mint address"}}}}
      limit: {count: 20}
      orderBy: [{descending: Block_Time}, {descending: Transaction_Index}, {descending: Trade_Index}]
    ) {
      Instruction { Program { Method } }
      Trade {
        Currency { Name Symbol MintAddress }
        Price PriceInUSD Amount AmountInUSD
        Side { Type Amount AmountInUSD Currency { Symbol Name MintAddress } }
        Dex { ProtocolName ProtocolFamily ProgramAddress }
      }
      Block { Time Height Slot }
      Transaction { Signature FeePayer Signer }
    }
  }
}
```

Docs' fees query (verbatim) — https://docs.bitquery.io/docs/blockchain/Solana/solana_fees_api/
```graphql
query MyQuery {
  Solana {
    DEXTradeByTokens(
      where: {Transaction: {Result: {Success: true}}}
      limit: {count: 10}
      orderBy: {descending: Block_Time}
    ) {
      Block { Time Slot }
      Trade {
        Account { Address Token { Owner } }
        AmountInUSD Amount PriceInUSD Price
        Dex { ProtocolName }
        Currency { MintAddress Name }
        Side { Account { Address Token { Owner } } Type AmountInUSD Amount Currency { Name MintAddress } }
      }
      Transaction { Signer Signature FeeInUSD Fee FeePayer }
    }
  }
}
```

## 4. Pump.fun / PumpSwap / LaunchLab doc pages

| URL | What it gives |
|---|---|
| https://docs.bitquery.io/docs/blockchain/Solana/Pumpfun/ | Index of the four pump.fun pages |
| https://docs.bitquery.io/docs/blockchain/Solana/Pumpfun/Pump-Fun-API/ (also mirrored at /docs/examples/Solana/Pump-Fun-API/) | 57 sections: new-token streams (`TokenSupplyUpdates` / `Instructions` with `Method in ["create","create_v2"]`), creation time & dev for a mint (`Instructions` with `Accounts includes mint`, `Program.Name "pump"`), tokens created by address (`TokenSupplyUpdates` filtered `Transaction.Signer` — realtime only), **historical tokens-by-wallet via v1**, Mayhem mode, prices (`Trading.Pairs`), OHLCV (`DEXTradeByTokens`, `dataset: combined`, `ProgramAddress` 6EF8…), ATH, live trades (`DEXTrades` subscription, `ProtocolName "pump"`), latest trades of token (`DEXTradeByTokens`, `pump_amm`), 7-day volume, PairStats (buys/sells/makers), first 100 buyers (`DEXTrades`, `Trade.Buy.Account.Token.Owner`), bonding-curve progress (`DEXPools`, formula `100 - (((base_balance - 206900000) * 100) / 793100000)`), last trade before graduation (`DEXPools`, `Base.PostAmount eq "206900000"`), dev holdings / top holders (`BalanceUpdates`), top traders (`Trade.Account.Owner`, `sum(of: Trade_Side_AmountInUSD)`), top creators, phishing check, `Trading.Trades` PumpFun stream with `TransactionHeader.Fee`, creator-fee transfers (`InstructionBalanceUpdates`, method `collect_creator_fee`), pricing/trial FAQ |
| https://docs.bitquery.io/docs/blockchain/Solana/Pumpfun/pump-swap-api/ | PumpSwap: new pools (`create_pool`), migrations, latest trades (`DEXTrades`, `dataset: realtime`), trades of a token (`DEXTradeByTokens` with `Block.Slot`, `Signature`, `FeePayer`), trades by trader (`Transaction.Signer`), OHLC, top traders, volume in a time range, creator fees. Notes: "`dataset: realtime` on Solana only covers a rolling recent window (on the order of hours)"; "For older PumpSwap history, switch to `dataset: combined` or `dataset: archive`" |
| https://docs.bitquery.io/docs/blockchain/Solana/Pumpfun/Pump-Fun-Marketcap-Bonding-Curve-API/ | Market cap via `Trading.Pairs`, bonding-curve progress via `DEXPools`, near-graduation streams (`Base.PostAmount gt "206900000", lt "246555000"`), migration `create_pool` instructions |
| https://docs.bitquery.io/docs/blockchain/Solana/Pumpfun/pump-fun-to-pump-swap/ | Narrative on graduation ("~800 million tradable tokens fully sold", "$30K–$35K"); links out, no inline queries |
| https://docs.bitquery.io/docs/blockchain/Solana/launchpad-raydium/ | LaunchLab: pool creation (`Instructions`, `Method "initialize_v2"`, "Token address appears at index 7 in the Accounts array"; args `base_mint_param`, `curve_param`, `vesting_param`), migrations (`migrate_to_amm`, `migrate_to_cpswap`), latest trades / price / user trades / top buyers & sellers / OHLCV / pool address via `DEXTradeByTokens` with `ProtocolName "raydium_launchpad"`, liquidity via `DEXPools` |
| https://docs.bitquery.io/docs/blockchain/Solana/letsbonk-api/ | Same LaunchLab program (`LanMV9…`), LetsBonk flavour |
| https://docs.bitquery.io/docs/blockchain/Solana/historical-aggregate-data/ | Archive OHLCV, first-24h volume, top traders (combined), first 100 buyers (combined, `limitBy Trade_Account_Owner`), ATH, realised PnL — plus the archive filter-limitation table |
| https://docs.bitquery.io/docs/blockchain/Solana/solana-dextrades/ | General Solana DEX trade cookbook; "Get Token creation date" = `Time(minimum: Block_Time)` on `DEXTradeByTokens`; raw-path (`aggregates: no`) notes |
| https://github.com/bitquery/Pump-Fun-API | Same query set as the Pump-Fun-API page; "contains no explicit Python or JavaScript code" |

### 4.1 Creation events
Realtime only (`Instructions` ~12 h) — https://docs.bitquery.io/docs/blockchain/Solana/Pumpfun/Pump-Fun-API/
```graphql
query MyQuery {
  Solana(network: solana) {
    Instructions(
      where: {
        Instruction: {
          Accounts: { includes: { Address: { is: "token mint address" } } }
          Program: { Name: { is: "pump" } Method: { in: ["create", "create_v2"] } }
        }
      }
    ) {
      Block { Time }
      Transaction { Signer Signature }
      Instruction { Accounts { Address } }
    }
  }
}
```
Tokens created by a creator (realtime only, `TokenSupplyUpdates` ~12 h): filter `Transaction: { Result: { Success: true } Signer: { is: "ADD CREATOR ADDRESS HERE" } }`, `Instruction: { Program: { Address: { is: "6EF8…" } Method: { in: ["create","create_v2"] } } }`, output `Block.Time`, `TokenSupplyUpdate.Currency{MintAddress Symbol Name Uri Decimals}`, `PostBalance`, `Transaction{Signature Signer}` — same page.

**Historical (2025) creation / creator token list — docs say use v1** ("Use the **v1 Solana transfers API** to list Pump.fun tokens created by a specific wallet over a date range"):
```graphql
{
  solana {
    transfers(
      options: { limit: 100, desc: "block.height" }
      date: { since: "2025-02-08", till: "2025-06-08" }
      externalProgramId: { is: "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P" }
      transferType: { is: mint }
      signer: { is: "Ddu1xqgNHBRBiJrissrpLtevq2A7KAHjgiDzECoNL8HG" }
    ) {
      block { height timestamp { iso8601 } }
      instruction { action { name } callPath external externalAction { name type } program { name id } externalProgram { id name } }
      currency { name symbol address }
      date { date }
      amount
      receiver { address mintAccount type }
      transaction { signature signer }
      transferType
    }
  }
}
```
(v1 `amount` is raw units: the Mayhem check uses `amount: { is: 1000000000000000 }` = "1 billion tokens when adjusted for 6 decimal places".) Per-mint variant on the v1 page uses `currency: { is: "<mint>" }` + `transferType: { is: mint }` — https://docs.bitquery.io/v1/docs/Examples/Solana/transfers. v2 proxy for creation time: "we are providing first trade time which in most of the cases is around creation time only":
```graphql
{
 Solana(dataset: combined) {
  DEXTradeByTokens(where: {Trade: {Currency: {MintAddress: {is: "94vNH3HhLv42gfkF93n9EQq9vyHPKRZ5XG6U3HmDpump"}}}}) {
   Block { Time(minimum: Block_Time) }
  }
 }
}
```
(run with `archive` per §1) — https://docs.bitquery.io/docs/blockchain/Solana/solana-dextrades/#get-token-creation-date
LaunchLab historical creations: UNKNOWN — only the realtime `initialize_v2` subscription is documented.

## 5. Pagination

- Default/max rows: "GraphQL v2 uses a default of 25,000 rows per query result. You can override this by setting `limit` explicitly" — https://docs.bitquery.io/docs/graphql/limits/. Billing page: "There's a per-request record cap (around 25,000 records). For larger result sets, paginate or use a stream/export." — https://docs.bitquery.io/docs/plans/how-billing-works/. (Errors page inconsistently says "Default Limit: 10,000 records if unspecified" and shows `limit: { count: 30000 }` as a custom-limit example — https://docs.bitquery.io/docs/start/errors/.) Treat **25,000 rows per request** as the working cap; whether `count > 25000` is honoured is UNKNOWN.
- `limit: { count, offset }`; "do not use `offset` for pagination of the result, unless you sure that the results are not modified or added between the queries and also have strong ordering" — https://docs.bitquery.io/docs/graphql/limits/ (archive data is immutable and the multi-key order above is strong, so offset is acceptable there; errors page also lists "Use pagination with `offset` for large datasets").
- No cursor API exists in the docs. **Pattern for 30,000 trades of one token:** slice the time range with half-open windows `since`/`before` (e.g. 1–5-minute slices for launch minutes), each under 25,000 rows, ordered `Block_Time, Transaction_Index, Trade_Index` ascending; when a slice returns 25,000 rows, halve it (or offset within it). Docs warn scans must be bounded: "Scanning from an arbitrary earlier date makes the request time out, so find the first trade date first (`Block { Time(minimum: Block_Time) }` on the same cube) and bound the window to it." — https://docs.bitquery.io/docs/blockchain/Solana/historical-aggregate-data/
- `orderBy` forms: `ascending`/`descending` (indexed fields) and `ascendingByField`/`descendingByField` (aliases/metrics); multiple keys apply in order — https://docs.bitquery.io/docs/graphql/sorting/. Sort on indexed fields; filter on at least one indexed field (`Trade_Currency_MintAddress`) — https://docs.bitquery.io/docs/graphql/indexed-fields-reference/
- `limitBy: { by: Trade_Account_Owner, count: 1 }` gives one row per wallet (first-buyers example).
- Trading.Trades: "Both `since` and `till` bounds are inclusive"; "An unbounded request over the whole month can time out."

## 6. Rate limits, points, pricing

Sources: https://bitquery.io/pricing (fetched 2026-09-15), https://docs.bitquery.io/docs/plans/how-billing-works/, https://docs.bitquery.io/docs/plans/rate-limits/, https://docs.bitquery.io/docs/ide/paid/, https://docs.bitquery.io/docs/ide/points/

| Plan | Monthly / annual-per-mo | Points/mo | Rate limit | Simultaneous requests | Concurrent WS streams |
|---|---|---|---|---|---|
| Free trial | $0, 7 days, no card | 1,000 points (+100 MCP credits, 2 streams, 17 stream-min, 0.2 GB) "across all chains with complete history" | UNKNOWN | UNKNOWN | 2 |
| "Developer plan" (points page only) | — | "10K free points for the first month" | UNKNOWN | UNKNOWN | — |
| Personal | $49 / $39 | 100K (~20k calls) | 30/min | 3 | none |
| Pro | $99 / $79 | 1M (~200k calls) | 90/min | 6 | 100 |
| Scale | $299 / $239 | 5M (~1M calls) | 240/min | 12 | 1,000 |
| Enterprise | custom | custom | custom | custom | unlimited |

- Conflict: points page says Developer plan 10K points/first month; pricing + billing pages say 7-day trial with 1,000 points and "No free or Developer plan exists" in the plan table. Assume **1,000 trial points** is current.
- **Archive on self-serve:** "Self-service plans are real-time only — no plan includes archive history. Archive access is bought per chain as an add-on." Solana add-ons (paid page): "Historical OHLCV & Token Price" (covers `DEXTradeByTokens`) **$210/mo**; "Historical Token Transfers & Balances" **$400/mo**. Pricing page fetch showed OHLCV pack "$210/mo (monthly); $150/mo when billed yearly" and Transfers "$400/mo; $320/mo yearly". Without it: `access restricted: your plan only allows "realtime", but the request uses "archive:…"` — https://docs.bitquery.io/docs/graphql/dataset/archive/#access. "The trial includes complete history" — https://docs.bitquery.io/docs/blockchain/Solana/historical-aggregate-data/
- **Points per query:** "Points = Resources consumed × Price per unit"; "A call costs about 5 points, adjusted by how much data it scans"; "`dataset:realtime` … charged at 5 points per cube irrespective of the number of records". Archive per-row/per-query pricing: **UNKNOWN / not published** (only "rows scanned × complexity"; "Run representative queries on a trial key and read the per-query point cost shown in the IDE"). Points don't roll over. Overage $50/1M (monthly) or $40/1M (annual); one-time 1M top-up $100.
- **~15,000 trades cost:** one archive `DEXTradeByTokens` request with `limit.count: 15000` (under the 25k cap) ≈ one call ≈ "about 5 points, adjusted by how much data it scans" — realistic order of magnitude is single- to low-double-digit points per request, but the docs give no archive multiplier, so **unknown exactly**; a trial's 1,000 points would cover on the order of tens–hundreds of such calls. Verify in the IDE point counter.
- Concurrency/backoff: 429 on rate limit; "temporarily blocked due to a high number of long-running queries" = shared compute; "Run heavy queries sequentially"; "exponential backoff (start around 5s, double, cap at ~1 min)"; "one batched query (many addresses/tokens in a single `where`) over many small ones" — https://docs.bitquery.io/docs/plans/rate-limits/
- Timeouts still bill: "If the server executes your GraphQL operation before the client hits Net::ReadTimeout, that run can still deduct points." — https://docs.bitquery.io/docs/ide/points/

## 7. Gotchas (from the docs)

1. **Solana history exists only in `DEXTradeByTokens` archive (from ~June 2024)**; `DEXTrades`, `Instructions`, `TokenSupplyUpdates`, `Transfers`, `BalanceUpdates`, `DEXPools` are ~12 h realtime only — https://docs.bitquery.io/docs/graphql/data-coverage-retention/. "Pick a token launched within the recent window, since the Transfers and DEXTrades cubes on Solana keep no archive." — Pump-Fun-API page.
2. **`combined` 500s on Solana** — always use `archive` for history even where docs examples say `combined` — coverage matrix; DEX-trades page.
3. **Realtime silently truncates**: "returns fewer rows, not an error" beyond retention — realtime page.
4. **Archive filter restrictions**: no USD fields / `PriceAsymmetry` in `where`; `Trade.Side.Account` unavailable; "Fields like `Trade.Side` are only available with `dataset: realtime`… avoid `Trade_Side`, `Trade_Side_Type`" (Pump-Fun-API FAQ) **vs** the historical page table saying `Trade.Side.Type` works on archive and examples using it on `combined` — contradictory; test `Side.Type` on archive first.
5. **Raw vs pre-aggregated path** (`aggregates: no`): `Block.Slot(minimum/maximum)`, `uniq(...)`, second-resolution `Block.Time` are raw-path only; "The raw path is not available on `dataset: combined`, and it keeps a much shorter window… (hours to about a day)" — https://docs.bitquery.io/docs/blockchain/Solana/solana-dextrades/. Whether per-row (non-aggregated) archive queries expose `Block.Slot`/`Transaction.Fee` is not stated.
6. **Doubled rows**: DEXTradeByTokens holds each swap twice (per token); always filter `Trade.Currency.MintAddress`; when also selecting `Side { Currency }` you get one row per quote currency — cube page + DEX-trades page.
7. **Quote mint**: bonding-curve trades may carry native SOL as `11111111111111111111111111111111` rather than WSOL `So111…`; docs' `in:` filters include both — Pump-Fun-API ATH example.
8. **Units**: v2 `Amount`/`Price` appear decimal-adjusted (bonding-curve `Base.PostAmount eq "206900000"` = 206.9 M tokens; ATH market cap = `PriceInUSD * 1000000000` for the 1 B supply); v1 `amount` is raw (1e15 = 1 B tokens @ 6 decimals). Not stated explicitly — infer and verify. `AmountInUSD` "If it is 0, it means we don't have a USD value… you can use the AmountInUSD of WSOL" — https://docs.bitquery.io/docs/cubes/solana/
9. **`till` inclusive / `before` exclusive**; use `since`+`before` for non-overlapping slices — DEX-trades page.
10. **Trading.Trades**: ~30 days only, duplicates ("Deduplicate on `(TransactionHeader.Hash, Trader.Address, Side, Amounts.Base)`"), not DEX-only (Seaport/Polymarket rows) — trades-api page.
11. **Creator token list & creation events for 2025 tokens require v1** (`graphql.bitquery.io`) — Pump-Fun-API page; v1 auth header not confirmed.
12. **Token from an upgraded plan keeps old limits** until regenerated — billing page. **WS concurrency cap fails silently** — rate-limits page.
13. Errors to expect: `no table can query <Cube> ... consider use realtime dataset` (cube not on that dataset), `Memory limit (for query) exceeded` (add `limit`/narrow `since`/`till`), `402 points limit exceeded`, `ISO8601DateTime vs ISO8601Date` variable type mismatch (`Block.Time` wants `2024-01-15T12:00:00Z`, `Block.Date` wants `2024-01-15`) — https://docs.bitquery.io/docs/start/errors/
14. "Every query on this page runs as written in the Bitquery IDE on a free account" (historical page) — the IDE (ide.bitquery.io) is the cheapest way to sanity-check field availability and point cost before coding.

## 8. Minimal Python

Docs' example, verbatim (note the docs' own `//` comment line is not valid Python — remove it) — https://docs.bitquery.io/docs/authorisation/how-to-use/
```python
import requests
import json

def oAuth_example():
  //access_token generated using either of the two approaches
  # Step 2: Make Streaming API query
  url_graphql = "https://streaming.bitquery.io/graphql"
  headers_graphql = {
      'Content-Type': 'application/json',
      'Authorization': f'Bearer {access_token}'
  }
  graphql_query = '''
  {
    EVM(mempool: true, network: eth) {
      DEXTrades(limit: {count: 10}) {
        Transaction {
          Hash
        }
        Trade {
          Buy {
            Amount
            Currency {
              Name
            }
            Buyer
          }
          Sell {
            Amount
            Currency {
              Name
            }
            Buyer
          }
        }
      }
    }
  }
  '''
  payload_graphql = json.dumps({'query': graphql_query})
  # Step 3: Make request to Streaming API
  response_graphql = requests.post(url_graphql, headers=headers_graphql, data=payload_graphql)
  # Print the response
  print(response_graphql.text)

oAuth_example()
```

Adapted (stdlib only, with variables, the §3.5 query; untested):
```python
import json, os, urllib.request

URL = "https://streaming.bitquery.io/graphql"
TOKEN = os.environ["BITQUERY_TOKEN"]  # ory_at_... from account.bitquery.io

QUERY = """
query TokenTradesWindow($mint: String!, $since: DateTime!, $before: DateTime!, $limit: Int!, $offset: Int!) {
  Solana(dataset: archive) {
    DEXTradeByTokens(
      where: {
        Trade: { Currency: { MintAddress: { is: $mint } }
                 Dex: { ProtocolName: { in: ["pump", "pump_amm", "raydium_launchpad"] } } }
        Block: { Time: { since: $since, before: $before } }
        Transaction: { Result: { Success: true } }
      }
      orderBy: [{ ascending: Block_Time }, { ascending: Transaction_Index }, { ascending: Trade_Index }]
      limit: { count: $limit, offset: $offset }
    ) {
      Block { Time Slot }
      Transaction { Signature Signer FeePayer Fee }
      Trade { Account { Address Owner } Amount Price PriceInUSD
              Side { Type Amount AmountInUSD Currency { MintAddress Symbol } }
              Dex { ProtocolName ProgramAddress } Market { MarketAddress } }
    }
  }
}
"""

def run(variables):
    body = json.dumps({"query": QUERY, "variables": variables}).encode()
    req = urllib.request.Request(URL, data=body, method="POST", headers={
        "Content-Type": "application/json",
        "Authorization": f"Bearer {TOKEN}",
    })
    with urllib.request.urlopen(req, timeout=120) as r:
        out = json.load(r)
    if out.get("errors"):
        raise RuntimeError(out["errors"])
    return out["data"]["Solana"]["DEXTradeByTokens"]

rows = run({"mint": "<mint>", "since": "2025-03-01T12:00:00Z", "before": "2025-03-01T12:30:00Z",
            "limit": 10000, "offset": 0})
print(len(rows), rows[:1])
```
Pagination loop: keep `since`/`before` slices small (minutes) and, if a slice returns exactly `limit` rows, either raise `offset` (archive is immutable, ordering is strong) or split the slice. Respect plan rate limits (Personal 30/min) and back off on 429.

## Source list
- https://docs.bitquery.io/docs/graphql/data-coverage-retention/
- https://docs.bitquery.io/docs/graphql/dataset/archive/ · /realtime/ · /combined/ · /EAP/
- https://docs.bitquery.io/docs/blockchain/Solana/historical-aggregate-data/
- https://docs.bitquery.io/docs/blockchain/Solana/solana-dextrades/
- https://docs.bitquery.io/docs/blockchain/Solana/solana_fees_api/
- https://docs.bitquery.io/docs/blockchain/Solana/solana-trader-API/
- https://docs.bitquery.io/docs/blockchain/Solana/Pumpfun/ (+ Pump-Fun-API, pump-swap-api, Pump-Fun-Marketcap-Bonding-Curve-API, pump-fun-to-pump-swap)
- https://docs.bitquery.io/docs/blockchain/Solana/launchpad-raydium/ · /letsbonk-api/
- https://docs.bitquery.io/docs/cubes/solana/ · /cubes/dextradesbyTokens/ · /cubes/dextrades-dextradebytokens-trading-trades
- https://docs.bitquery.io/docs/trading/crypto-trades-api/trades-api/
- https://docs.bitquery.io/docs/graphql/limits/ · /sorting/ · /filters/ · /capabilities/relative-time/ · /indexed-fields-reference/ · /optimizing-graphql-queries/
- https://docs.bitquery.io/docs/authorisation/how-to-generate/ · /how-to-use/ · https://docs.bitquery.io/docs/start/first-query/ · /start/errors/
- https://docs.bitquery.io/docs/ide/points/ · /ide/paid/ · https://docs.bitquery.io/docs/plans/how-billing-works/ · /plans/rate-limits/
- https://bitquery.io/pricing
- https://docs.bitquery.io/v1/docs/Examples/Solana/transfers
- https://github.com/bitquery/Pump-Fun-API
- https://docs.bitquery.io/docs/migration/from-helius/
