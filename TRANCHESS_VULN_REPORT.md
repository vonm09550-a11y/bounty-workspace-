# Tranchess Security Assessment - Vulnerability Report

**Target:** https://tranchess.com/
**Source Code:** https://github.com/tranchess/contract-core
**Bounty Program:** https://immunefi.com/bounty/tranchess/
**Date:** 2026-02-06
**Solidity Version:** `>=0.6.10 <0.8.0` (pre-overflow-protection)

---

## Executive Summary

Analysis of 141 Solidity files in the Tranchess contract-core monorepo. Key risk areas:
smart contract fund management, oracle price feeds, flash swap mechanics, cross-chain bridges,
and governance. Below are findings ranked by exploitability and impact.

---

## FINDING 1: FlashSwapRouter Zero Slippage on External DEX Swap

**Severity:** High
**File:** `contracts/swap/FlashSwapRouter.sol:288-295`
**Impact:** Direct theft of user funds via sandwich attack / MEV extraction

### Description

The internal `_externalSwap()` function performs a token swap on an external Uniswap-style
router with `minAmountOut = 0`:

```solidity
amountOut = IUniswapV2Router01(externalRouter).swapExactTokensForTokens(
    amountIn,
    0,              // <-- NO SLIPPAGE PROTECTION
    externalPath,
    address(this),
    block.timestamp // <-- deadline = current block (useless)
)[externalPath.length - 1];
```

While `buyR()` has a `maxQuote` check and `sellR()` has a `minQuote` check at the user-facing
level, the zero-slippage internal swap creates an MEV extraction window. An attacker can:

1. Observe a pending `buyR`/`sellR` transaction in the mempool
2. Front-run to manipulate the external DEX pool price
3. The FlashSwapRouter executes the external swap at manipulated price
4. The invariant check on the overall trade may still pass if the manipulation
   is calibrated within the user's slippage tolerance
5. The attacker back-runs to extract profit

The `block.timestamp` deadline provides no protection since miners/validators set the timestamp.

### Recommendation

Pass a calculated `minAmountOut` to `swapExactTokensForTokens()` based on oracle price,
or propagate the user's slippage tolerance to the internal swap.

---

## FINDING 2: Oracle Owner Can Set Arbitrary TWAP Prices

**Severity:** High
**File:** `contracts/oracle/ChainlinkTwapOracleV2.sol:198-208`
**Impact:** Fund NAV manipulation, unfair rebalancing, potential theft

### Description

The `updateTwapFromOwner()` function allows the contract owner to set any price for
epochs where Chainlink data is unavailable:

```solidity
function updateTwapFromOwner(uint256 timestamp, uint256 price) external onlyOwner {
    require(timestamp % EPOCH == 0, "Unaligned timestamp");
    require(timestamp <= block.timestamp - EPOCH * 2, "Not ready for owner");
    require(_ownerUpdatedPrices[timestamp] == 0, "Owner cannot update an existing epoch");
    uint256 chainlinkTwap = _getTwapFromChainlink(timestamp);
    require(chainlinkTwap == 0, "Owner cannot overwrite Chainlink result");
    _ownerUpdatedPrices[timestamp] = price;  // <-- Arbitrary price, no bounds check
}
```

**Safeguards present:**
- Can only set when Chainlink TWAP returns 0 (data gap)
- Must be at least 2 epochs (60 min) old
- Cannot overwrite existing owner-set price

**Remaining risk:**
- No upper/lower bound validation on `price`
- No timelock or multi-sig requirement
- During Chainlink outages (which do occur), owner has unconstrained power
- Incorrect price directly affects fund settlement NAV calculations in `FundV5.settle()`

### Attack Scenario

If Chainlink has a brief data gap (e.g., round count drops below `chainlinkMinMessageCount`),
the owner can set an artificially low/high price. This flows into `FundV5.settle()` via
`twapOracle.getTwap(day)` and directly affects:
- BISHOP/ROOK NAV split calculations
- Rebalance trigger conditions
- New splitRatio computation

---

## FINDING 3: Unrestricted Fund Freeze - Public DoS Vector

**Severity:** Medium-High
**File:** `contracts/fund/FundV5.sol:708-725`
**Impact:** Taking down the application / Denial of Service

### Description

The `freeze()` function can be called by **anyone** and permanently freezes the fund:

```solidity
function freeze() external {
    require(!frozen, "Already frozen");
    uint256 day = currentDay;
    require(day != 0, "Not initialized");
    uint256 price = twapOracle.getLatest();
    (, , uint256 navR) = _extrapolateNav(
        block.timestamp, day - settlementPeriod, price,
        getEquivalentTotalR(), getTotalUnderlying()
    );
    require(navR == 0, "Not to be frozen");
    frozen = true;
    emit Frozen();
}
```

While the function requires `navR == 0`, this can be triggered through:

1. **Oracle price manipulation** - If the oracle returns an extreme price, NAV calculations
   can push ROOK NAV to zero
2. **During natural market crashes** - ROOK (leveraged token) NAV can approach zero during
   significant underlying price drops
3. **Flash loan + oracle manipulation** - Attacker manipulates spot price that feeds into
   `getLatest()`, temporarily making navR = 0

Once frozen, there is **no unfreeze function** in FundV5. The fund is permanently locked.

---

## FINDING 4: StableSwap Optimistic Transfer Callback Pattern

**Severity:** Medium
**File:** `contracts/swap/StableSwap.sol:254-293` (buy) and `295-338` (sell)
**Impact:** Potential reentrancy / flash loan attack vector

### Description

Both `buy()` and `sell()` follow an optimistic transfer pattern:

```solidity
// buy() - transfers BEFORE callback
fund.trancheTransfer(baseTranche, recipient, baseOut, version);  // Transfer first
if (data.length > 0) {
    ITranchessSwapCallee(msg.sender).tranchessSwapCallback(baseOut, 0, data);  // Then callback
}
uint256 newQuote = _getNewQuoteBalance();  // Then check payment
```

While `nonReentrant` protects against direct reentrancy to the same StableSwap instance,
the callback to `msg.sender` happens with tokens already transferred. The invariant check
`newD >= oldD` after the callback is the primary safety mechanism.

**Risk vectors:**
- Cross-contract reentrancy (callback can interact with OTHER Tranchess contracts)
- If the invariant check has edge cases with extreme amplification parameters
- Interaction with PrimaryMarket during callback (different contract, different lock)

---

## FINDING 5: ProxyOFT Cross-Chain Balance Accounting

**Severity:** Medium
**File:** `contracts/layerzero/ProxyOFT.sol:26-46`
**Impact:** Potential cross-chain fund theft with fee-on-transfer tokens

### Description

The `_debitFrom()` and `_creditTo()` functions use balance-difference accounting:

```solidity
function _debitFrom(address _from, ..., uint256 _amount) internal virtual override returns (uint256) {
    uint256 before = innerToken.balanceOf(address(this));
    innerToken.safeTransferFrom(_from, address(this), _amount);
    return innerToken.balanceOf(address(this)) - before;  // Actual received
}

function _creditTo(..., address _toAddress, uint256 _amount) internal virtual override returns (uint256) {
    uint256 before = innerToken.balanceOf(_toAddress);
    innerToken.safeTransfer(_toAddress, _amount);
    return innerToken.balanceOf(_toAddress) - before;  // Actual sent
}
```

If the underlying CHESS token (or any bridged token) implements fee-on-transfer or
rebasing mechanics, the amount received differs from `_amount`. The LayerZero message
contains the original `_amount`, but the actual bridge credit may be less. This creates
an imbalance between chains.

Currently, the CHESS token does not have fee-on-transfer. However, if `AnyswapChess`
or future token upgrades introduce fees, this becomes exploitable.

---

## FINDING 6: PrimaryMarket Redemption Queue DoS

**Severity:** Medium
**File:** `contracts/fund/PrimaryMarketV5.sol:37-41, 62-75`
**Impact:** Denial of Service for legitimate users

### Description

The redemption queue uses sequential indexing with no rate limiting:

```solidity
mapping(uint256 => QueuedRedemption) public queuedRedemptions;
uint256 public redemptionQueueHead;
uint256 public redemptionQueueTail;
```

An attacker can queue many tiny redemptions to:
1. Increase gas costs for `popRedemptionQueue()` processing
2. Create backlog that delays legitimate users
3. Exhaust available underlying liquidity in small portions

No minimum redemption size is enforced at the queue level.

---

## FINDING 7: Owner Can Replace Critical Infrastructure Without Timelock

**Severity:** Medium
**File:** `contracts/fund/FundV5.sol:844-860`
**Impact:** Owner privilege escalation / trust assumption

### Description

The owner can instantly replace critical oracles:

```solidity
function updateTwapOracle(address newTwapOracle) external onlyOwner {
    _updateTwapOracle(newTwapOracle);  // Instant, no timelock
}

function updateAprOracle(address newAprOracle) external onlyOwner {
    _updateAprOracle(newAprOracle);  // Instant, no timelock
}
```

A compromised owner key can:
1. Deploy a malicious oracle contract returning any price
2. Call `updateTwapOracle()` to point the fund at the malicious oracle
3. Next settlement uses the malicious price
4. Rebalance distributes value unfairly between BISHOP/ROOK holders

Note: PrimaryMarket and Strategy updates DO have a proposal/apply pattern with
time delay, but oracle updates are instant.

---

## Web Application Observations

**Reconnaissance limitations:** DNS does not resolve from this sandbox environment.
WebFetch only retrieved static HTML (SPA requires JavaScript execution).

**Observed:**
- React-based SPA (requires JS to render)
- Google Analytics: G-JPP12JVCHH
- PWA manifest with standalone display mode
- No `api.tranchess.com` found (404)
- No robots.txt restrictions (fully open)

**For full web testing, Shannon should be run from an environment with:**
1. Direct network access to tranchess.com
2. Playwright/Chromium for SPA interaction
3. ANTHROPIC_API_KEY for Shannon's AI agents

---

## Shannon Configuration

Shannon is installed, compiled, and ready in this workspace. To run the full autonomous
pipeline against tranchess.com, you need to:

1. Set `ANTHROPIC_API_KEY` in `shannon/.env`
2. Run from an environment with DNS resolution to tranchess.com

```bash
cd shannon
TEMPORAL_ADDRESS=localhost:7233 node dist/temporal/client.js \
  https://tranchess.com \
  /home/user/bounty-workspace-/tranchess-contract-core
```

Shannon will use the contract source code for white-box analysis combined with live
browser-based exploitation of the web application.

---

## Prioritized Next Steps

1. **FINDING 1** (FlashSwapRouter zero slippage) - Most likely to yield a bounty payout.
   Needs on-chain PoC demonstrating sandwich profit extraction via mempool monitoring.

2. **FINDING 3** (Fund freeze DoS) - If flash loan oracle manipulation can trigger
   freeze, this is Critical severity. Needs PoC with Foundry/Hardhat fork test.

3. **FINDING 2** (Oracle owner override) - Strong finding but may be classified as
   "admin privilege" by the program. Worth submitting with clear impact analysis.

4. **Web application testing** - Run Shannon from a network-capable environment to test
   for XSS, auth bypass, cookie theft, and other web-specific impacts listed in scope.
