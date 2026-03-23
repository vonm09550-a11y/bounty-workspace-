require('@openzeppelin/test-helpers/configure')({
	provider: 'http://localhost:7545',
});

const Governance = artifacts.require("Governance");
const ContractWallet = artifacts.require("ContractWallet");
const { BN, ether, constants, expectRevert } = require('@openzeppelin/test-helpers');
const { expect } = require('chai');

contract("PoC: .transfer() permanent fund freeze", accounts => {
	const funder = accounts[0];

	let governance, wallet;

	before(async () => {
		/// deploy governance in ETH mode (votingTokenAddress = address(0))
		governance = await Governance.new(funder, constants.ZERO_ADDRESS);

		/// deploy contract wallet mimicking Gnosis Safe's expensive receive()
		wallet = await ContractWallet.new();

		/// fund the wallet with ETH (full gas, receive() executes fine)
		await web3.eth.sendTransaction({ from: funder, to: wallet.address, value: ether('5') });
	});

	it("contract wallet ETH permanently frozen in Governance", async () => {
		/// deposit succeeds, balance recorded
		await wallet.doDeposit(governance.address, ether('5'));
		expect(await governance.balances(wallet.address)).to.be.bignumber.equal(ether('5'));
		expect(new BN(await web3.eth.getBalance(governance.address))).to.be.bignumber.equal(ether('5'));

		/// withdraw reverts, .transfer() can't deliver to contract wallet with > 2300 gas receive()
		await expectRevert.unspecified(wallet.doWithdraw(governance.address, ether('5')));

		/// funds still frozen, no state change, no recovery path
		expect(await governance.balances(wallet.address)).to.be.bignumber.equal(ether('5'));
		expect(new BN(await web3.eth.getBalance(governance.address))).to.be.bignumber.equal(ether('5'));
	});
});
