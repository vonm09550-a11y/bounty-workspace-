import { ethers } from "hardhat"
import "@nomiclabs/hardhat-waffle"
import { expect } from "chai"
import { toWei, createContract, toBytes32, toUnit } from "../scripts/deployUtils"
import { SignerWithAddress } from "@nomiclabs/hardhat-ethers/signers"
import {
  CollateralPool,
  OrderBook,
  TestMux3,
  MockERC20,
  WETH9,
  MockMux3FeeDistributor,
  CollateralPoolEventEmitter,
} from "../typechain"
import { time } from "@nomicfoundation/hardhat-network-helpers"

const a2b = (a: string) => {
  return a + "000000000000000000000000"
}
const u2b = (u: any) => {
  return ethers.utils.hexZeroPad(u.toTwos(256).toHexString(), 32)
}

/**
 * POC: Incorrect Token Decimal Handling in Remove Liquidity Minimum Order Validation
 *
 * VULNERABILITY SUMMARY:
 * In _fillRemoveLiquidityOrder (LibOrderBook2.sol), the min order value validation
 * incorrectly uses pool.collateralToken for decimal conversion and price lookup
 * instead of the actual withdrawal token (orderParams.token).
 *
 * BUG LOCATION:
 *   address collateralAddress = ICollateralPool(orderParams.poolAddress).collateralToken();
 *   uint256 price = LibOrderBook._priceOf(orderBook, collateralAddress);
 *   uint256 value = (LibOrderBook._collateralToWad(orderBook, collateralAddress, outAmount) * price) / 1e18;
 *
 * SHOULD BE:
 *   uint256 price = LibOrderBook._priceOf(orderBook, orderParams.token);
 *   uint256 value = (LibOrderBook._collateralToWad(orderBook, orderParams.token, outAmount) * price) / 1e18;
 */
describe("POC: RemoveLiquidity Decimal Mismatch Bug", () => {
  let usdc: MockERC20  // 6 decimals - token to withdraw
  let weth: WETH9      // 18 decimals - pool's native collateral

  let admin: SignerWithAddress
  let broker: SignerWithAddress
  let lp1: SignerWithAddress

  let core: TestMux3
  let imp: CollateralPool
  let pool1: CollateralPool
  let orderBook: OrderBook
  let feeDistributor: MockMux3FeeDistributor
  let emitter: CollateralPoolEventEmitter
  let callbackRegister: any

  let timestampOfTest: number

  before(async () => {
    const accounts = await ethers.getSigners()
    admin = accounts[0]
    broker = accounts[1]
    lp1 = accounts[2]
  })

  beforeEach(async () => {
    timestampOfTest = await time.latest()
    timestampOfTest = Math.ceil(timestampOfTest / 3600) * 3600

    // Deploy tokens
    // USDC: 6 decimals (token LP will withdraw)
    usdc = (await createContract("MockERC20", ["USDC", "USDC", 6])) as MockERC20
    // WETH: 18 decimals (pool's native collateral)
    weth = (await createContract("WETH9", [])) as WETH9

    // Deploy core
    core = (await createContract("TestMux3", [])) as TestMux3
    await core.initialize(weth.address)

    // Register both collateral tokens
    await core.addCollateralToken(weth.address, 18, false) // WETH: 18 decimals, non-stable
    await core.addCollateralToken(usdc.address, 6, true)   // USDC: 6 decimals, stable

    await core.setConfig(ethers.utils.id("MC_BORROWING_BASE_APY"), u2b(toWei("0.10")))
    await core.setConfig(ethers.utils.id("MC_BORROWING_INTERVAL"), u2b(ethers.BigNumber.from(3600)))

    // Deploy orderBook
    const libOrderBook = await createContract("LibOrderBook")
    const libOrderBook2 = await createContract("LibOrderBook2")
    orderBook = (await createContract("OrderBook", [], {
      "contracts/libraries/LibOrderBook.sol:LibOrderBook": libOrderBook,
      "contracts/libraries/LibOrderBook2.sol:LibOrderBook2": libOrderBook2,
    })) as OrderBook

    await orderBook.initialize(core.address, weth.address)
    await orderBook.setConfig(ethers.utils.id("MCO_LIQUIDITY_LOCK_PERIOD"), u2b(ethers.BigNumber.from(60 * 15)))
    await orderBook.setConfig(ethers.utils.id("MCO_MARKET_ORDER_TIMEOUT"), u2b(ethers.BigNumber.from(60 * 2)))
    await orderBook.setConfig(ethers.utils.id("MCO_LIMIT_ORDER_TIMEOUT"), u2b(ethers.BigNumber.from(86400 * 30)))
    await orderBook.setConfig(ethers.utils.id("MCO_CANCEL_COOL_DOWN"), u2b(ethers.BigNumber.from(5)))
    // Set min liquidity order to $1 USD
    await orderBook.setConfig(ethers.utils.id("MCO_MIN_LIQUIDITY_ORDER_USD"), u2b(toWei("1")))
    await orderBook.setConfig(ethers.utils.id("MCO_ORDER_GAS_FEE_GWEI"), u2b(ethers.BigNumber.from("0")))

    // Deploy callback register
    callbackRegister = await createContract("MockCallbackRegister")
    await orderBook.setConfig(ethers.utils.id("MCO_CALLBACK_REGISTER"), a2b(callbackRegister.address))

    // Deploy collateral pool
    emitter = (await createContract("CollateralPoolEventEmitter")) as CollateralPoolEventEmitter
    await emitter.initialize(core.address)
    imp = (await createContract("CollateralPool", [
      core.address,
      orderBook.address,
      weth.address,
      emitter.address,
    ])) as CollateralPool
    await core.setCollateralPoolImplementation(imp.address)

    // *** KEY: Create pool with WETH as native collateral (18 decimals) ***
    await core.createCollateralPool("WETH Pool", "mWETH", weth.address, 0)
    const pool1Addr = (await core.listCollateralPool())[0]
    pool1 = (await ethers.getContractAt("CollateralPool", pool1Addr)) as CollateralPool

    await core.setPoolConfig(pool1.address, ethers.utils.id("MCP_BORROWING_K"), u2b(toWei("6.36306")))
    await core.setPoolConfig(pool1.address, ethers.utils.id("MCP_BORROWING_B"), u2b(toWei("-6.58938")))
    await core.setPoolConfig(pool1.address, ethers.utils.id("MCP_LIQUIDITY_CAP_USD"), u2b(toWei("100000000")))
    await core.setPoolConfig(pool1.address, ethers.utils.id("MCP_LIQUIDITY_FEE_RATE"), u2b(toWei("0")))

    // Deploy fee distributor
    feeDistributor = (await createContract("MockMux3FeeDistributor", [core.address])) as MockMux3FeeDistributor
    await core.setConfig(ethers.utils.id("MC_FEE_DISTRIBUTOR"), a2b(feeDistributor.address))

    // Grant roles
    await orderBook.grantRole(ethers.utils.id("BROKER_ROLE"), broker.address)
    await core.grantRole(ethers.utils.id("ORDER_BOOK_ROLE"), orderBook.address)

    // Set prices (1e18 format)
    // WETH = $3000
    // USDC = $1
    await core.setMockPrice(a2b(weth.address), toWei("3000"))
    await core.setMockPrice(a2b(usdc.address), toWei("1"))
  })

  it("POC: Remove liquidity in USDC from WETH pool fails due to decimal mismatch", async () => {
    console.log("\n========== POC: Decimal Mismatch in Remove Liquidity ==========\n")

    // ============ STEP 1: LP adds liquidity with WETH ============
    console.log("STEP 1: LP deposits 10 WETH ($30,000) into pool")
    const depositAmount = toWei("10") // 10 WETH

    await weth.deposit({ value: depositAmount })
    await weth.transfer(orderBook.address, depositAmount)
    await orderBook.connect(lp1).placeLiquidityOrder({
      poolAddress: pool1.address,
      token: weth.address,
      rawAmount: depositAmount,
      isAdding: true,
      isUnwrapWeth: false,
    })

    await time.increaseTo(timestampOfTest + 86400)
    await orderBook.connect(broker).fillLiquidityOrder(0, [])

    const lpShares = await pool1.balanceOf(lp1.address)
    console.log(`   LP received ${ethers.utils.formatEther(lpShares)} shares`)

    // ============ STEP 2: Donate USDC to the pool ============
    console.log("\nSTEP 2: Donate 10,000 USDC ($10,000) to pool")
    const donateAmount = toUnit("10000", 6) // 10,000 USDC (6 decimals)

    await usdc.mint(orderBook.address, donateAmount)
    await orderBook.grantRole(ethers.utils.id("FEE_DONATOR_ROLE"), admin.address)
    await orderBook.donateLiquidity(pool1.address, usdc.address, donateAmount)
    await orderBook.revokeRole(ethers.utils.id("FEE_DONATOR_ROLE"), admin.address)

    const balances = await pool1.liquidityBalances()
    console.log("   Pool balances after donation:")
    for (let i = 0; i < balances.tokens.length; i++) {
      const symbol = balances.tokens[i] === weth.address ? "WETH" : "USDC"
      console.log(`     ${symbol}: ${ethers.utils.formatEther(balances.balances[i])} (wad)`)
    }

    // ============ STEP 3: LP removes liquidity requesting USDC ============
    console.log("\nSTEP 3: LP requests to withdraw $1000 worth in USDC (not WETH)")

    // Calculate shares for ~$1000 withdrawal
    // Pool AUM = $30,000 (WETH) + $10,000 (USDC) = $40,000
    // NAV = $40,000 / 30,000 shares = ~$1.33 per share
    // For $1000, we need ~750 shares
    const sharesToRemove = toWei("1000") // ~$1000 worth

    await pool1.connect(lp1).transfer(orderBook.address, sharesToRemove)
    await orderBook.connect(lp1).placeLiquidityOrder({
      poolAddress: pool1.address,
      token: usdc.address, // *** Requesting USDC, not native WETH ***
      rawAmount: sharesToRemove,
      isAdding: false,
      isUnwrapWeth: false,
    })
    console.log(`   Placed order to remove ${ethers.utils.formatEther(sharesToRemove)} shares for USDC`)

    // ============ STEP 4: Fill attempt - DEMONSTRATES THE BUG ============
    console.log("\nSTEP 4: Broker fills order - EXPECT FAILURE due to bug")
    await time.increaseTo(timestampOfTest + 86400 * 2)

    console.log("\n   BUG ANALYSIS:")
    console.log("   - Withdrawal amount: ~1000 USDC = 1,000,000,000 raw (1e9)")
    console.log("   - Bug: Code uses pool.collateralToken = WETH (18 decimals)")
    console.log("   - _collateralToWad(WETH, 1e9) = 1e9 * 1 = 1e9 (no scaling)")
    console.log("   - price = WETH price = $3000 = 3000e18")
    console.log("   - value = (1e9 * 3000e18) / 1e18 = 3e12")
    console.log("   - In USD terms: 3e12 / 1e18 = $0.000003")
    console.log("   - Min required: $1")
    console.log("   - Result: REVERT despite $1000+ actual value!")
    console.log("")
    console.log("   CORRECT CALCULATION (with fix):")
    console.log("   - _collateralToWad(USDC, 1e9) = 1e9 * 1e12 = 1e21")
    console.log("   - price = USDC price = $1 = 1e18")
    console.log("   - value = (1e21 * 1e18) / 1e18 = 1e21")
    console.log("   - In USD terms: 1e21 / 1e18 = $1000")
    console.log("   - Result: PASS")

    await expect(
      orderBook.connect(broker).fillLiquidityOrder(1, [])
    ).to.be.revertedWith("Min liquidity order value")

    console.log("\n========== BUG CONFIRMED ==========")
    console.log("Transaction reverted with 'Min liquidity order value'")
    console.log("despite withdrawing ~$1000 worth of USDC")
    console.log("\nIMPACT: Temporary freezing of funds - LP cannot withdraw")
    console.log("in non-native token until order is cancelled and resubmitted")
    console.log("using pool's native collateral token.")
  })
})
