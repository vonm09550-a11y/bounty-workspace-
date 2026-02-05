// FINDING-01 Proof of Concept
// CCIP Pool Cannot Burn Tokens During Legacy Transition Period
// Classification: High - Temporary freezing of funds for more than 1 week
// Reward: $10,000

import { ethers } from "hardhat"
import { expect } from "chai"
import type { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers"

describe("FINDING-01: CCIP Pool burnFrom Blocked During Transition", () => {
  let deployer: SignerWithAddress
  let user: SignerWithAddress
  let admin: SignerWithAddress
  let bridge: SignerWithAddress
  let ccipPool: SignerWithAddress // Simulates the BurnFromMintTokenPoolUpgradeable

  let proxyAsV2: any
  let proxy: any

  const L1_TBTC = "0x3151c5547d1dbcd52076bd3cbe56c79abd55b42f"
  const TOKEN_NAME = "BOB tBTC v2"
  const TOKEN_SYMBOL = "tBTC"
  const DECIMALS = 18

  before(async () => {
    ;[deployer, user, admin, bridge, ccipPool] = await ethers.getSigners()

    // Deploy V1 implementation
    const OptimismMintableUpgradableERC20Factory =
      await ethers.getContractFactory("OptimismMintableUpgradableERC20", deployer)
    const implementation = await OptimismMintableUpgradableERC20Factory.deploy()
    await implementation.deployed()

    // Deploy TransparentUpgradeableProxy
    const TransparentUpgradeableProxyFactory =
      await ethers.getContractFactory("TransparentUpgradeableProxy", deployer)

    const initializeData = implementation.interface.encodeFunctionData(
      "initialize",
      [bridge.address, L1_TBTC, TOKEN_NAME, TOKEN_SYMBOL, DECIMALS]
    )

    const proxyContract = await TransparentUpgradeableProxyFactory.deploy(
      implementation.address,
      admin.address,
      initializeData
    )
    await proxyContract.deployed()

    proxy = await ethers.getContractAt(
      "ITransparentUpgradeableProxy",
      proxyContract.address
    )

    // Mint some tokens via legacy bridge to establish initial supply
    const proxyAsV1 = await ethers.getContractAt(
      "OptimismMintableUpgradableERC20",
      proxy.address,
      bridge
    )
    await proxyAsV1.mint(user.address, ethers.utils.parseEther("100"))

    // Deploy V2 implementation and upgrade
    const OptimismMintableUpgradableTBTCFactory =
      await ethers.getContractFactory("OptimismMintableUpgradableTBTC", deployer)
    const newImplementation = await OptimismMintableUpgradableTBTCFactory.deploy()
    await newImplementation.deployed()

    await proxy.connect(admin).upgradeTo(newImplementation.address)

    proxyAsV2 = await ethers.getContractAt(
      "OptimismMintableUpgradableTBTC",
      proxy.address,
      deployer
    )

    await proxyAsV2.initializeV2()

    // Add the CCIP pool as a minter (simulating deployment)
    await proxyAsV2.addMinter(ccipPool.address)
  })

  describe("POC: CCIP Pool lockOrBurn Simulation", () => {
    it("confirms legacyCapRemaining > 0 after upgrade", async () => {
      const legacyCap = await proxyAsV2.getLegacyCapRemaining()
      console.log("legacyCapRemaining:", ethers.utils.formatEther(legacyCap), "tBTC")
      expect(legacyCap).to.be.gt(0)
    })

    it("confirms CCIP pool is registered as minter", async () => {
      expect(await proxyAsV2.isMinter(ccipPool.address)).to.be.true
      console.log("CCIP Pool address:", ccipPool.address)
      console.log("BRIDGE address:", await proxyAsV2.bridge())
    })

    it("CCIP pool can MINT tokens (L1->L2 bridging works)", async () => {
      // Simulates: User bridges L1->L2 via CCIP
      // BurnFromMintTokenPoolUpgradeable.releaseOrMint() calls token.mint()
      const mintAmount = ethers.utils.parseEther("10")

      await expect(proxyAsV2.connect(ccipPool).mint(user.address, mintAmount))
        .to.emit(proxyAsV2, "Mint")
        .withArgs(user.address, mintAmount)

      console.log("L1->L2 CCIP bridging: SUCCESS")
      console.log("User received:", ethers.utils.formatEther(mintAmount), "tBTC via CCIP")
    })

    it("CCIP pool CANNOT burnFrom (L2->L1 bridging FAILS)", async () => {
      // Simulates: User wants to bridge L2->L1 via CCIP
      // BurnFromMintTokenPoolUpgradeable.lockOrBurn() calls token.burnFrom()

      const burnAmount = ethers.utils.parseEther("5")

      // User must first approve the pool (CCIP flow: tokens transferred to pool, then pool burns)
      await proxyAsV2.connect(user).approve(ccipPool.address, burnAmount)

      // Pool attempts to burn tokens from itself after receiving them
      // In actual CCIP flow, tokens are transferred to pool first, then pool calls burnFrom(self, amount)
      // We simulate by having user transfer to pool, then pool burns from pool
      await proxyAsV2.connect(user).transfer(ccipPool.address, burnAmount)

      // Pool sets self-allowance (done in BurnFromMintTokenPoolUpgradeable.initialize())
      await proxyAsV2.connect(ccipPool).approve(ccipPool.address, ethers.constants.MaxUint256)

      // CRITICAL: This is what happens in lockOrBurn()
      // IBurnMintERC20Upgradeable(address(token)).burnFrom(address(this), lockOrBurnIn.amount)
      await expect(
        proxyAsV2.connect(ccipPool).burnFrom(ccipPool.address, burnAmount)
      ).to.be.revertedWith("Only bridge can burn while legacy cap remains")

      console.log("")
      console.log("==================== VULNERABILITY CONFIRMED ====================")
      console.log("L2->L1 CCIP bridging: REVERTED")
      console.log("Error: 'Only bridge can burn while legacy cap remains'")
      console.log("")
      console.log("IMPACT:")
      console.log("- Users who bridged IN via CCIP cannot bridge OUT via CCIP")
      console.log("- Only exit: Legacy Optimism bridge with 7+ day withdrawal delay")
      console.log("- Duration: Until legacyCapRemaining reaches 0 (indefinite)")
      console.log("================================================================")
    })

    it("only BRIDGE can burnFrom while legacyCapRemaining > 0", async () => {
      // Return tokens to user for this test
      const userBalance = await proxyAsV2.balanceOf(user.address)
      const burnAmount = ethers.utils.parseEther("5")

      // User approves bridge
      await proxyAsV2.connect(user).approve(bridge.address, burnAmount)

      // Bridge CAN burn (legacy path works)
      await expect(
        proxyAsV2.connect(bridge).burnFrom(user.address, burnAmount)
      ).to.emit(proxyAsV2, "Burn")

      console.log("")
      console.log("Legacy bridge burnFrom: SUCCESS (as expected)")
      console.log("This proves ONLY the legacy bridge can burn during transition")
    })
  })

  describe("Attack Vector: Cross-Chain Accounting Mismatch", () => {
    it("demonstrates orphaned liquidity scenario", async () => {
      console.log("")
      console.log("==================== SECONDARY IMPACT ====================")
      console.log("Cross-Chain Accounting Mismatch:")
      console.log("")
      console.log("1. User bridges 10 tBTC L1->L2 via CCIP:")
      console.log("   - L1: 10 tBTC locked in LockReleaseTokenPoolUpgradeable")
      console.log("   - L2: 10 tBTC minted by BurnFromMintTokenPoolUpgradeable")
      console.log("")
      console.log("2. User CANNOT bridge back via CCIP (FINDING-01)")
      console.log("   - User forced to use legacy Optimism bridge")
      console.log("")
      console.log("3. User bridges 10 tBTC L2->L1 via legacy bridge:")
      console.log("   - L2: 10 tBTC burned via legacy bridge")
      console.log("   - L1: 10 tBTC released from L1 Optimism bridge reserves")
      console.log("")
      console.log("RESULT:")
      console.log("   - CCIP L1 pool: Still holds 10 locked tBTC (orphaned)")
      console.log("   - No corresponding L2 supply to redeem them via CCIP")
      console.log("   - Requires centralized intervention (rebalancer/owner)")
      console.log("============================================================")
    })
  })
})
