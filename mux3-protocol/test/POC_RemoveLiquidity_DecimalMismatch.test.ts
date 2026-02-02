import { ethers } from "hardhat"
import "@nomiclabs/hardhat-waffle"
import { expect } from "chai"
import { toWei, createContract, toUnit } from "../scripts/deployUtils"
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

const a2b = (a: string) => a + "000000000000000000000000"
const u2b = (u: any) => ethers.utils.hexZeroPad(u.toTwos(256).toHexString(), 32)

describe("POC: RemoveLiquidity Decimal Mismatch", () => {
  let usdc: MockERC20
  let weth: WETH9
  let admin: SignerWithAddress
  let broker: SignerWithAddress
  let lp1: SignerWithAddress
  let core: TestMux3
  let pool1: CollateralPool
  let orderBook: OrderBook
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

    usdc = (await createContract("MockERC20", ["USDC", "USDC", 6])) as MockERC20
    weth = (await createContract("WETH9", [])) as WETH9

    core = (await createContract("TestMux3", [])) as TestMux3
    await core.initialize(weth.address)
    await core.addCollateralToken(weth.address, 18, false)
    await core.addCollateralToken(usdc.address, 6, true)
    await core.setConfig(ethers.utils.id("MC_BORROWING_BASE_APY"), u2b(toWei("0.10")))
    await core.setConfig(ethers.utils.id("MC_BORROWING_INTERVAL"), u2b(ethers.BigNumber.from(3600)))

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
    await orderBook.setConfig(ethers.utils.id("MCO_MIN_LIQUIDITY_ORDER_USD"), u2b(toWei("1")))
    await orderBook.setConfig(ethers.utils.id("MCO_ORDER_GAS_FEE_GWEI"), u2b(ethers.BigNumber.from("0")))

    const callbackRegister = await createContract("MockCallbackRegister")
    await orderBook.setConfig(ethers.utils.id("MCO_CALLBACK_REGISTER"), a2b(callbackRegister.address))

    const emitter = (await createContract("CollateralPoolEventEmitter")) as CollateralPoolEventEmitter
    await emitter.initialize(core.address)
    const imp = (await createContract("CollateralPool", [
      core.address,
      orderBook.address,
      weth.address,
      emitter.address,
    ])) as CollateralPool
    await core.setCollateralPoolImplementation(imp.address)

    // Pool with WETH (18 decimals) as native collateral
    await core.createCollateralPool("WETH Pool", "mWETH", weth.address, 0)
    const pool1Addr = (await core.listCollateralPool())[0]
    pool1 = (await ethers.getContractAt("CollateralPool", pool1Addr)) as CollateralPool

    await core.setPoolConfig(pool1.address, ethers.utils.id("MCP_BORROWING_K"), u2b(toWei("6.36306")))
    await core.setPoolConfig(pool1.address, ethers.utils.id("MCP_BORROWING_B"), u2b(toWei("-6.58938")))
    await core.setPoolConfig(pool1.address, ethers.utils.id("MCP_LIQUIDITY_CAP_USD"), u2b(toWei("100000000")))
    await core.setPoolConfig(pool1.address, ethers.utils.id("MCP_LIQUIDITY_FEE_RATE"), u2b(toWei("0")))

    const feeDistributor = (await createContract("MockMux3FeeDistributor", [core.address])) as MockMux3FeeDistributor
    await core.setConfig(ethers.utils.id("MC_FEE_DISTRIBUTOR"), a2b(feeDistributor.address))

    await orderBook.grantRole(ethers.utils.id("BROKER_ROLE"), broker.address)
    await core.grantRole(ethers.utils.id("ORDER_BOOK_ROLE"), orderBook.address)

    await core.setMockPrice(a2b(weth.address), toWei("3000"))
    await core.setMockPrice(a2b(usdc.address), toWei("1"))
  })

  it("remove liquidity in USDC from WETH pool reverts on min order check", async () => {
    // LP deposits 10 WETH
    await weth.deposit({ value: toWei("10") })
    await weth.transfer(orderBook.address, toWei("10"))
    await orderBook.connect(lp1).placeLiquidityOrder({
      poolAddress: pool1.address,
      token: weth.address,
      rawAmount: toWei("10"),
      isAdding: true,
      isUnwrapWeth: false,
    })
    await time.increaseTo(timestampOfTest + 86400)
    await orderBook.connect(broker).fillLiquidityOrder(0, [])

    // Donate USDC to pool
    await usdc.mint(orderBook.address, toUnit("10000", 6))
    await orderBook.grantRole(ethers.utils.id("FEE_DONATOR_ROLE"), admin.address)
    await orderBook.donateLiquidity(pool1.address, usdc.address, toUnit("10000", 6))

    // LP removes liquidity requesting USDC
    await pool1.connect(lp1).transfer(orderBook.address, toWei("1000"))
    await orderBook.connect(lp1).placeLiquidityOrder({
      poolAddress: pool1.address,
      token: usdc.address,
      rawAmount: toWei("1000"),
      isAdding: false,
      isUnwrapWeth: false,
    })

    await time.increaseTo(timestampOfTest + 86400 * 2)
    await expect(orderBook.connect(broker).fillLiquidityOrder(1, [])).to.be.revertedWith("Min liquidity order value")
  })
})
