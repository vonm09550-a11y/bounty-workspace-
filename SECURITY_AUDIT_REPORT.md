# IPOR Protocol Security Audit Report

**Date:** 2026-02-17
**Auditor:** Automated Security Analysis
**Target:** IPOR Protocol Smart Contracts (Solidity 0.8.26)
**Repository:** https://github.com/IPOR-Labs/ipor-protocol
**Scope:** All in-scope smart contracts per bug bounty program rules

---

## Executive Summary

This report presents findings from a comprehensive security audit of the IPOR Protocol smart contracts. The analysis covers the core AMM infrastructure including swap open/close services, liquidity pool management, spread calculations, oracle integration, router/access control patterns, token contracts, and multi-chain deployments (Ethereum, Arbitrum, Base).

The protocol uses a delegatecall-based router pattern, ECDSA-signed risk indicators for offchain parameter injection, continuous compounding interest calculations, and a SOAP-based accounting system for tracking aggregate swap positions.

---

## Finding #1: Batch Liquidation Can Fail Due to Insufficient Treasury Balance for Accumulated Liquidation Deposits

**Severity:** Medium
**Impact Classification:** Smart contract unable to operate due to lack of token funds for 24 hours
**Location:**
- `contracts/base/amm/services/AmmCloseSwapServiceBaseV1.sol:131-166` (`_closeSwaps`)
- `contracts/base/amm/services/AmmCloseSwapServiceBaseV2.sol:58-110` (`_transferDerivativeAmount`)

### Description

When a third-party liquidator closes multiple swaps in a single batch transaction, the liquidation deposits from each individual swap closure are **accumulated** and transferred as a lump sum at the end (line 165 in `AmmCloseSwapServiceBaseV1._closeSwaps`). However, each individual swap closure's rebalance logic in `AmmCloseSwapServiceBaseV2._transferDerivativeAmount` only ensures the AmmTreasury has sufficient tokens for **that specific swap's** buyer payout plus **that specific swap's** liquidation deposit.

After each buyer transfer, only that individual swap's liquidation deposit amount remains in the treasury. When the next swap is processed, a new rebalance targets only that next swap's total requirement. The critical issue: after processing N swaps, the treasury retains approximately the **last** swap's liquidation deposit amount, but needs to pay out **all N** accumulated liquidation deposits.

### Proof of Concept

Consider a liquidator closing 10 swaps, each with a 25 USDC liquidation deposit:

1. **Swap 1:** Rebalance ensures treasury has >= (buyerPayout_1 + 25). Transfer buyerPayout_1. Treasury retains ~25.
2. **Swap 2:** Treasury has ~25. Rebalance targets (buyerPayout_2 + 25). After buyer transfer, treasury retains ~25.
3. **...repeat for swaps 3-10...**
4. **Post-loop:** Accumulated `payoutForLiquidator = 250 USDC`. Treasury has ~25 USDC.
5. **`_transferLiquidationDepositAmount(liquidator, 250)`** attempts `safeTransferFrom(ammTreasury, liquidator, 250)` -- **REVERTS**.

```solidity
// AmmCloseSwapServiceBaseV1.sol:131-166
function _closeSwaps(...) internal returns (...) {
    // ...
    (payoutForLiquidatorPayFixed, closedPayFixedSwaps) = _closeSwapsPerLeg(...);
    (payoutForLiquidatorReceiveFixed, closedReceiveFixedSwaps) = _closeSwapsPerLeg(...);

    // THIS FINAL TRANSFER CAN FAIL - no rebalance check here
    _transferLiquidationDepositAmount(
        beneficiary,
        payoutForLiquidatorPayFixed + payoutForLiquidatorReceiveFixed  // accumulated total
    );
}
```

The `_transferLiquidationDepositAmount` function performs a simple `safeTransferFrom` without any rebalance:

```solidity
// AmmCloseSwapServiceBaseV1.sol:351-359
function _transferLiquidationDepositAmount(address liquidator, uint256 liquidationDepositAmount) internal {
    if (liquidationDepositAmount > 0) {
        IERC20Upgradeable(asset).safeTransferFrom(
            ammTreasury,
            liquidator,
            IporMath.convertWadToAssetDecimals(liquidationDepositAmount, decimals)
        );
        // No rebalance check! No asset management withdrawal!
    }
}
```

### Impact

- Batch liquidation of multiple underwater swaps by third-party liquidators can revert, preventing timely liquidation.
- If swaps cannot be liquidated, the protocol's LP balance accounting becomes stale, affecting exchange rate calculations and SOAP values.
- This could delay liquidation during volatile market conditions when timely liquidation is most critical.
- The `liquidationLegLimit` parameter bounds the maximum swaps per leg, but even modest limits (e.g., 10 per leg, 20 total) with small treasury balances relative to asset management can trigger this issue.

### Recommendation

Add a rebalance check in `_transferLiquidationDepositAmount` or modify `_transferDerivativeAmount` to account for the total accumulated liquidation deposits from prior swaps in the same batch. Alternatively, transfer each swap's liquidation deposit immediately within the per-swap processing loop rather than accumulating them.

---

## Finding #2: Max-Loss Swaps Cannot Be Closed by Community After Maturity

**Severity:** Low
**Impact Classification:** Contract fails to deliver promised returns, but doesn't lose value

**Location:** `contracts/base/amm/libraries/SwapCloseLogicLibBaseV1.sol:130-217` (`getClosableStatusForSwap`)

### Description

The `getClosableStatusForSwap` function contains a condition at lines 151-153 that restricts swap closure when `absPnlValue == closableSwapInput.swapCollateral` (i.e., the swap is at maximum loss). This restriction applies even **after maturity**, requiring only the buyer or a designated liquidator to close such swaps.

```solidity
// SwapCloseLogicLibBaseV1.sol:150-161
if (closableSwapInput.closeTimestamp >= swapEndTimestamp) {
    if (
        absPnlValue < minPnlValueToCloseBeforeMaturityByCommunity ||
        absPnlValue == closableSwapInput.swapCollateral  // <-- max loss case
    ) {
        if (
            AmmConfigurationManager.isSwapLiquidator(...) != true &&
            closableSwapInput.account != closableSwapInput.swapBuyer
        ) {
            return (AmmTypes.SwapClosableStatus.SWAP_REQUIRED_BUYER_OR_LIQUIDATOR_TO_CLOSE, false);
        }
    }
}
```

Since `normalizePnlValue` caps the absolute PnL at the collateral value, `absPnlValue == swapCollateral` represents the maximum possible loss. At this point, the buyer has no economic incentive to close the swap (payout = 0 besides liquidation deposit). If no liquidator acts, the swap remains open indefinitely after maturity.

### Impact

- The swap's collateral continues to be counted in `totalCollateralPayFixed` or `totalCollateralReceiveFixed`, affecting new swap collateral ratio checks.
- The SOAP indicators continue to accrue based on the open swap's parameters, distorting the LP exchange rate calculation.
- The liquidity pool balance appears lower than it should be since the collateral from max-loss swaps hasn't been returned to the pool.
- This doesn't result in permanent fund loss, but the LP exchange rate is temporarily inaccurate, and new swaps may be rejected due to inflated collateral ratios.

### Recommendation

Remove the `absPnlValue == closableSwapInput.swapCollateral` condition from the post-maturity check (line 153). After maturity, max-loss swaps should be closable by anyone since the buyer has no incentive to close, and the protocol benefits from prompt closure.

---

## Finding #3: Risk Indicator Signatures Use `abi.encodePacked` Without Domain Separator or Chain ID

**Severity:** Medium
**Impact Classification:** Smart contract unable to operate due to lack of token funds for 24 hours

**Location:** `contracts/libraries/RiskIndicatorsValidatorLib.sol:31-52` (`hashRiskIndicatorsInputs`)

### Description

The `RiskIndicatorsValidatorLib.hashRiskIndicatorsInputs` function uses `abi.encodePacked` to hash risk indicator inputs for signature verification. The hash does not include a domain separator (EIP-712), chain ID, or the verifying contract's address.

```solidity
// RiskIndicatorsValidatorLib.sol:37-52
function hashRiskIndicatorsInputs(
    AmmTypes.RiskIndicatorsInputs memory inputs,
    address asset,
    uint256 tenor,
    uint256 direction
) private pure returns (bytes32) {
    return
        keccak256(
            abi.encodePacked(
                inputs.maxCollateralRatio,
                inputs.maxCollateralRatioPerLeg,
                inputs.maxLeveragePerLeg,
                inputs.baseSpreadPerLeg,
                inputs.fixedRateCapPerLeg,
                inputs.demandSpreadFactor,
                inputs.expiration,
                asset,       // address = 20 bytes
                tenor,       // uint256 = 32 bytes
                direction    // uint256 = 32 bytes
            )
        );
}
```

While all parameters here are fixed-size types (uint256 and address), preventing `abi.encodePacked` hash collision issues, the lack of chain ID or domain separator means:

1. **Cross-chain replay:** A valid risk indicator signature on Ethereum can be replayed on Arbitrum or Base if the same asset address exists on multiple chains (which it typically doesn't due to different bridge addresses, mitigating this in practice).

2. **Cross-deployment replay:** If IPOR is deployed to a new chain or a new router contract is deployed, old signatures remain valid as long as the same signer key is used and the asset address matches.

3. **No nonce mechanism:** The only time-bounding is the `expiration` timestamp. Within the expiration window, the same signature can be reused for multiple transactions by different users.

### Impact

This primarily enables a scenario where a user front-runs favorable risk parameters. When the off-chain signer publishes a signature with favorable parameters (low spread, high leverage cap), any user can extract that signature and use it before the intended recipient. This is partially by design (the parameters are meant to be publicly available), but the lack of per-user binding means all users operate under the same risk parameters simultaneously.

The cross-chain replay risk is largely mitigated by different asset addresses on different chains. However, the lack of EIP-712 compliance is a deviation from security best practices.

### Recommendation

Implement EIP-712 structured signing with a domain separator that includes the chain ID and contract address. This prevents cross-chain replay and aligns with industry best practices for off-chain signature validation.

---

## Finding #4: Rounding Direction in `_toQuadruplePrecisionInt` Creates Asymmetric Bias for Negative Values

**Severity:** Low
**Impact Classification:** Contract fails to deliver promised returns, but doesn't lose value

**Location:** `contracts/libraries/math/InterestRates.sol:86-95` (`_toQuadruplePrecisionInt`)

### Description

The `_toQuadruplePrecisionInt` function applies a rounding adjustment (`number += 1`) when `number % decimals > 0`. In Solidity 0.8.x, the modulo operator for negative numbers returns a value with the sign of the dividend. This means for negative `number`, `number % decimals` will be negative or zero, and the condition `> 0` will never be true.

```solidity
// InterestRates.sol:86-95
function _toQuadruplePrecisionInt(int256 number, int256 decimals) private pure returns (bytes16) {
    if (number % decimals > 0) {  // Only true for positive numbers
        number += 1;              // Rounds UP positive numbers
    }
    bytes16 nominator = ABDKMathQuad.fromInt(number);
    bytes16 denominator = ABDKMathQuad.fromInt(decimals);
    bytes16 fraction = ABDKMathQuad.div(nominator, denominator);
    return fraction;
}
```

Consequence: Positive values are rounded up by 1 unit (before division by 1e18), while negative values are not adjusted. This creates a systematic bias in interest calculations that use the `Int` variant of the continuous compounding function.

### Impact

In practice, this function is called from `addContinuousCompoundInterestUsingRatePeriodMultiplicationInt` where the `value` parameter (notional) is typically positive. The bias is extremely small (1 wei in 18 decimal representation, equivalent to ~1e-18), making exploitation impractical for meaningful profit extraction. The cumulative effect across many calculations could theoretically create a tiny imbalance between pay-fixed and receive-fixed swap PnL calculations.

### Recommendation

Apply consistent rounding for both positive and negative numbers, or document the intended behavior. Consider whether the rounding should always favor the protocol (round down user gains, round up user losses).

---

## Finding #5: ETH Sent to Router via `receive()` Can Be Captured by Next `batchExecutor` Caller

**Severity:** Low
**Impact Classification:** Contract fails to deliver promised returns, but doesn't lose value

**Location:** `contracts/router/IporProtocolRouterAbstract.sol` (`receive()` and `_returnBackRemainingEth`)

### Description

The router contract has a `receive()` function that accepts ETH. The `_returnBackRemainingEth` function (called at the end of `_delegate`) sends the **entire** router ETH balance back to `msg.sender`, but only when the reentrancy status is `_ENTERED` (set by `batchExecutor`).

```solidity
function _returnBackRemainingEth() private {
    uint256 routerEthBalance = address(this).balance;
    if (routerEthBalance > 0) {
        if (StorageLibBaseV1.getReentrancyStatus().value == _ENTERED) {
            (bool success, ) = msg.sender.call{value: routerEthBalance}("");
            if (!success) {
                revert(IporErrors.ROUTER_RETURN_BACK_ETH_FAILED);
            }
        }
    }
}
```

If ETH is accidentally sent to the router (via `receive()`), it will be accumulated until a user calls `batchExecutor`, at which point the `batchExecutor` caller will receive all accumulated ETH, including ETH they didn't send.

### Impact

This is a low-severity issue since:
- Users should not be sending ETH directly to the router
- The ETH-specific pool interactions (stETH) are handled through dedicated service contracts
- The amount at risk is limited to accidentally sent ETH

However, it creates a minor griefing vector where ETH can be permanently captured by an opportunistic `batchExecutor` caller.

### Recommendation

Consider removing the `receive()` function or adding a mechanism for the owner to recover accidentally sent ETH rather than distributing it to the next `batchExecutor` caller.

---

## Finding #6: `AmmStorageBaseV1._updateBalancesWhenCloseSwap` Does Not Account for PnL in Balance Updates

**Severity:** Low
**Impact Classification:** Contract fails to deliver promised returns, but doesn't lose value

**Location:** `contracts/base/amm/AmmStorageBaseV1.sol:390-410`

### Description

When closing a swap, the `_updateBalancesWhenCloseSwapPayFixed` and `_updateBalancesWhenCloseSwapReceiveFixed` functions update the `totalCollateralPayFixed/ReceiveFixed` and `treasury` balances, but the `pnlValue` parameter is received but **not used** to update any liquidity pool balance field in the Base V1 storage implementation.

```solidity
// AmmStorageBaseV1.sol:390-399
function _updateBalancesWhenCloseSwapPayFixed(
    AmmTypesBaseV1.Swap memory swap,
    int256 pnlValue,           // <-- received but NOT USED
    uint256 swapUnwindFeeLPAmount,  // <-- NOT USED
    uint256 swapUnwindFeeTreasuryAmount
) internal {
    _balance.totalCollateralPayFixed = _balance.totalCollateralPayFixed - swap.collateral.toUint128();
    _balance.treasury = _balance.treasury + swapUnwindFeeTreasuryAmount.toUint128();
    totalLiquidationDepositBalance = totalLiquidationDepositBalance - swap.wadLiquidationDepositAmount.toUint128();
    // Note: pnlValue and swapUnwindFeeLPAmount are not applied to any balance
}
```

Compare with the Ethereum mainnet `AmmStorage.sol` which explicitly updates the liquidity pool balance based on PnL. The Base V1 implementation stores the balance differently (using `StorageTypesBaseV1.Balance` which does not contain a `liquidityPool` field), so LP balance is derived at query time rather than stored. This means the LP balance for Base/Arbitrum chains is computed dynamically from the treasury's actual ERC20 balance plus vault balance.

### Impact

This is by design for the Base V1 architecture where liquidity pool balance is computed dynamically. However, it means that any accounting discrepancy between the stored collateral totals and the actual token balances would not be caught by an internal balance consistency check. The `swapUnwindFeeLPAmount` parameter is also unused, meaning LP fee portions from unwind operations are implicitly absorbed into the treasury's token balance rather than tracked separately.

This is informational -- the architecture intentionally relies on dynamic balance computation rather than stored LP balances.

### Recommendation

No action required if the dynamic balance computation is intended. Consider adding documentation to clarify that this is a deliberate architectural decision for the Base V1 storage implementation.

---

## Informational Observations

### I-1: Governance Functions Lack Timelock

The `_getRouterImplementation` function in `IporProtocolRouterEthereum.sol` routes governance calls (e.g., `setAmmPoolsParams`, `setMessageSigner`, `setAssetServices`) directly to the governance service with only an `_onlyOwner()` check. There is no timelock mechanism for sensitive parameter changes. This is noted as informational since centralization risks are out of scope per program rules.

### I-2: Swap ID Uses `uint32` Limiting Total Swaps to ~4.29 Billion

The `_lastSwapId` in `AmmStorageBaseV1.sol` is `uint32`, limiting total swap count to 4,294,967,295. While practically sufficient, this is a hard limit that cannot be upgraded without a storage migration.

### I-3: Risk Indicator Expiration Has No Minimum Window

The `verify` function in `RiskIndicatorsValidatorLib.sol` only checks `inputs.expiration > block.timestamp`. The signer could theoretically set very long expiration windows, allowing stale risk parameters to be used. This is mitigated by the trusted signer model where the off-chain signer is expected to set reasonable expirations.

### I-4: `SoapIndicatorLogic.calculateHyphoteticalInterestTotal` Compounds Interest on Cumulative

At `SoapIndicatorLogic.sol:57`, the hypothetical interest delta is calculated using `si.totalNotional + si.hypotheticalInterestCumulative` as the base for the continuous compounding. This means interest compounds on previously accumulated interest (compound-on-compound), which is mathematically correct for continuous compounding but could amplify any errors in the `averageInterestRate` or `rebalanceTimestamp` tracking.

---

## Out of Scope Findings (Not Reported)

The following were identified but are explicitly out of scope per program rules:

- **Centralization risks:** Owner can change implementation addresses, message signers, pool parameters without timelock
- **Third-party oracle dependence:** IPOR index values depend on the trusted updater role
- **Known issues:** Asset management relies on published token exchange rate (gas optimization), liquidity pool amount equals zero edge cases
- **Best practice recommendations:** Various code style and documentation improvements

---

## Methodology

The audit was conducted through manual static analysis of the smart contract source code, focusing on:

1. **Data flow analysis** of funds through swap open/close lifecycle
2. **Access control review** of router delegatecall pattern and role-based permissions
3. **Mathematical verification** of interest rate, PnL, SOAP, and exchange rate calculations
4. **Cross-chain consistency analysis** between Ethereum, Arbitrum, and Base implementations
5. **Reentrancy and state manipulation** analysis through the delegatecall router pattern
6. **Edge case analysis** for swap lifecycle states (open, close, unwind, liquidation)

### Contracts Reviewed

| Contract | Lines | Notes |
|----------|-------|-------|
| AmmOpenSwapService.sol | ~500 | Swap opening logic for Ethereum stablecoins |
| AmmCloseSwapServiceStable.sol | ~600 | Swap closing for stablecoins |
| AmmCloseSwapServiceBaseV1.sol | ~545 | Base close swap logic |
| AmmCloseSwapServiceBaseV2.sol | ~112 | V2 with asset management rebalance |
| AmmStorage.sol | ~700 | Ethereum storage implementation |
| AmmStorageBaseV1.sol | ~686 | Base/Arbitrum storage implementation |
| AmmTreasury.sol | ~189 | Treasury management |
| AmmPoolsService.sol | ~300 | Liquidity provision/redemption |
| IporProtocolRouterAbstract.sol | ~200 | Router pattern |
| IporProtocolRouterEthereum.sol | ~402 | Ethereum router implementation |
| AccessControl.sol | ~100 | Access control |
| IporOracle.sol | ~319 | Oracle contract |
| RiskIndicatorsValidatorLib.sol | ~53 | Signature validation |
| RiskManagementLogic.sol | ~95 | Risk calculation |
| SwapCloseLogicLibBaseV1.sol | ~341 | Close/unwind logic |
| SwapLogicBaseV1.sol | ~260 | PnL calculations |
| InterestRates.sol | ~108 | Interest rate math |
| IporMath.sol | ~149 | Math utilities |
| SoapIndicatorLogic.sol | ~83 | SOAP calculations |
| AssetManagementLogic.sol | ~58 | Rebalance calculations |
| AmmLib.sol | ~99 | AMM core library |
| IpToken.sol | ~59 | LP token |
| SpreadBaseV1.sol | ~varied | Spread calculation |
| AmmConfigurationManager.sol | ~varied | Governance config |

---

## Disclaimer

This audit report is provided for informational purposes only and does not constitute financial advice. The findings represent the auditor's assessment at the time of review. Smart contract security is an ongoing process, and new vulnerabilities may be discovered after this report's publication. The severity classifications follow the program's defined impact categories.
