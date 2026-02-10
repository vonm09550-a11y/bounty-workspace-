# Research Report: _checkMinted Error Handling in MarketplaceV2

## Vulnerability Claim Under Analysis

**Claimed Severity:** Medium
**Claimed Impact:** Griefing — Incomplete error handling in `_checkMinted` permanently breaks lazy minting for modern ERC721 collections
**Target Contract:** MarketplaceV2 (0xFC1759E75180aeE982DC08D0d6D365ebFA0296a7)

---

## Executive Summary

**Finding: The vulnerability has ZERO demonstrated real-world impact on Xterio's ecosystem.**

The bug report claims that `_checkMinted` in `MarketplaceV2.sol` only catches `Error(string memory)` reverts, and therefore fails when `ownerOf` reverts with custom errors (as in OpenZeppelin v5.x, ERC721A, Solady). While the technical observation about the catch clause is accurate in isolation, **it is irrelevant to Xterio's actual deployment** because:

1. Lazy minting (`allowMint = true`) only works with NFTs registered in Xterio's Gateway.
2. All of Xterio's own ERC721 contracts use OpenZeppelin v4.9.3.
3. OpenZeppelin v4.9.3 `ownerOf` reverts with `require(owner != address(0), "ERC721: invalid token ID")` — a **string-based revert** that IS caught by `catch Error(string memory)`.

---

## Detailed Evidence Chain

### 1. MarketplaceV2 _checkMinted Function (Confirmed from Source)

```solidity
function _checkMinted(
    bytes32 transactionType,
    address tokenAddress,
    uint256 tokenId,
    address seller
) internal view returns (uint256 mintedAmount) {
    if (transactionType == TRANSACT_ERC721) {
        mintedAmount = 0;
        try IERC721(tokenAddress).ownerOf(tokenId) returns (address owner) {
            if (owner != address(0)) mintedAmount = 1;
        } catch Error(string memory) {
            // In most cases, querying the owner of an unminted NFT
            // will result in a revert.
        }
    }
    // ...
}
```

The catch clause handles `Error(string memory)` — which corresponds to `revert("reason")` and `require(condition, "reason")`.

### 2. Lazy Minting is Gateway-Restricted

The `_mintNFT` function enforces:

```solidity
require(
    IGateway(gateway).nftManager(order.targetTokenAddress) == from,
    "MarketplaceV2: only manager can mint at sale"
);
IGateway(gateway).ERC721_mint(order.targetTokenAddress, recipient, tokenId);
```

This means `allowMint = true` orders **ONLY** work for:
- NFT contracts registered in Xterio's `TokenGateway` (0x7127f0FEaEF8143241A5FaC62aC5b7be02Ef26A9)
- Where the seller is the registered `nftManager` for that NFT contract
- Where the NFT contract supports minting via the Gateway's `ERC721_mint` interface

The Gateway's `setManagerOf` function controls registration. This is an **admin-controlled** system — arbitrary external NFT contracts cannot self-register.

### 3. Xterio's NFT Contracts Use OpenZeppelin v4.x

**From `package.json` (xt-contracts repo):**
```json
"@openzeppelin/contracts": "^4.9.3",
"@limitbreak/creator-token-contracts": "^1.1.2"
```

**From `@limitbreak/creator-token-contracts` v1.1.2:**
```json
"@openzeppelin/contracts": "4.8.3"
```

**BasicERC721C.sol imports confirm OZ v4.x:**
- `@openzeppelin/contracts/utils/Counters.sol` — **removed in OZ v5.0**
- `@openzeppelin/contracts/security/Pausable.sol` — **moved to `utils/Pausable.sol` in OZ v5.0**

These imports are incompatible with OZ v5.x, conclusively proving OZ v4.x usage.

### 4. OpenZeppelin v4.9.3 ownerOf Uses String Reverts

**Direct from OZ v4.9.3 source (ERC721.sol):**

```solidity
function ownerOf(uint256 tokenId) public view virtual override returns (address) {
    address owner = _ownerOf(tokenId);
    require(owner != address(0), "ERC721: invalid token ID");
    return owner;
}
```

This is a `require` with a string reason → emits `Error(string)` on revert → **IS caught by `catch Error(string memory)`**.

### 5. ERC721C Does Not Override ownerOf

LimitBreak's ERC721C is a wrapper around OZ's ERC721 that adds transfer security policies (for enforceable royalties). It does **not** override `ownerOf`. The function behavior is inherited directly from OpenZeppelin v4.8.3's ERC721.

### 6. Inheritance Chain Summary

```
BasicERC721C
  └── ERC721C (LimitBreak, creator-token-contracts v1.1.2)
       └── ERC721 (OpenZeppelin v4.8.3)
            └── ownerOf → require(owner != address(0), "ERC721: invalid token ID")
                          ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                          String revert → Error(string) → CAUGHT by catch Error(string memory)
```

---

## Impact Assessment

### Current Real-World Impact: NONE

For the vulnerability to manifest, ALL of the following would need to be true simultaneously:

1. An ERC721 contract using custom errors in `ownerOf` (OZ v5.x, ERC721A, or Solady) ✗
2. That contract must be registered in Xterio's TokenGateway ✗
3. That contract must support the Gateway's `ERC721_mint` interface ✗
4. A seller must be registered as `nftManager` for that contract ✗
5. An order with `allowMint = true` must be created targeting that contract ✗

**None of these conditions are currently met.** Xterio's own NFT contracts (BasicERC721C, BasicERC721CWithBasicRoyalties, BasicERC721CWithImmutableMinterRoyalties) all use OZ v4.x with string-based reverts.

### Theoretical Future Impact

If Xterio were to deploy a new NFT contract using OpenZeppelin v5.x and register it in their Gateway, the vulnerability could manifest. However:

- This is speculative/hypothetical
- Xterio controls Gateway registration (admin function)
- Any migration to OZ v5.x would likely involve a comprehensive contract audit
- The MarketplaceV2 itself is an upgradeable proxy and could be updated alongside any such migration

---

## Classification Under Program Rules

### Applicable Severity: NOT SUBMITTABLE (Informational/Design Concern at best)

The claimed severity of **Medium → Griefing** requires:
> "no profit motive for an attacker, but damage to the users or the protocol"

**There is no demonstrated damage to users or the protocol** because:
- The catch clause works correctly for all NFTs currently in Xterio's ecosystem
- No Gateway-registered NFT uses custom errors in `ownerOf`
- The vulnerability requires admin-level configuration changes to manifest

### Out of Scope Factors

While not strictly matching the listed out-of-scope items, this report falls into the territory of:
- **Best practice recommendations** — suggesting `catch {}` instead of `catch Error(string memory)` is a defensive coding practice, not a vulnerability with demonstrated impact
- **Feature requests** — future-proofing for OZ v5.x compatibility

### Primacy of Impact Consideration

The program's Primacy of Impact policy applies to **Critical** and **High** severity smart contract impacts. Even under the most generous interpretation, this finding cannot reach High severity because:
- No funds are at risk
- No NFTs are at risk
- No unclaimed yield/royalties are affected
- The theoretical impact (order reversion) is neither theft nor permanent freezing

---

## Recommended Assessment

**Do NOT submit this as a Medium severity finding.** The program would likely reject it as:

1. **No demonstrated impact** — The vulnerability cannot be triggered against any currently deployed and Gateway-registered NFT contract
2. **Theoretical/informational only** — Relies on hypothetical future state changes controlled by the admin
3. **Best practice recommendation** — The suggested fix (`catch {}`) is sound defensive coding but addresses a non-existent current risk

If submitted, expect classification as **Informational** or outright rejection. The minimum reward tier (Medium flat $20,000) requires demonstrated protocol damage, which is absent here.

---

## Technical Recommendation (For Reference Only)

The suggested fix in the original report is technically correct as a defense-in-depth measure:

```solidity
try IERC721(tokenAddress).ownerOf(tokenId) returns (address owner) {
    if (owner != address(0)) mintedAmount = 1;
} catch {
    mintedAmount = 0;
}
```

This would future-proof the contract against OZ v5.x custom errors. However, since MarketplaceV2 is an upgradeable proxy, Xterio can deploy this fix alongside any future OZ migration without urgency.

---

## Sources

- [XterioTech/xt-contracts GitHub Repository](https://github.com/XterioTech/xt-contracts)
- [BasicERC721C.sol Source](https://github.com/XterioTech/xt-contracts/blob/main/contracts/basic-tokens/BasicERC721C.sol)
- [MarketplaceV2.sol Source](https://github.com/XterioTech/xt-contracts/blob/main/contracts/nft-marketplace/MarketplaceV2.sol)
- [OpenZeppelin v4.9.3 ERC721.sol](https://raw.githubusercontent.com/OpenZeppelin/openzeppelin-contracts/v4.9.3/contracts/token/ERC721/ERC721.sol)
- [LimitBreak creator-token-contracts](https://github.com/limitbreakinc/creator-token-contracts)
- [Xterio Bug Bounty on Immunefi](https://immunefi.com/bug-bounty/xterio/scope/)
- [MarketplaceV2 on Etherscan (Proxy)](https://etherscan.io/address/0xFC1759E75180aeE982DC08D0d6D365ebFA0296a7)
- [TokenGateway on Etherscan](https://etherscan.io/address/0x7127f0FEaEF8143241A5FaC62aC5b7be02Ef26A9)
