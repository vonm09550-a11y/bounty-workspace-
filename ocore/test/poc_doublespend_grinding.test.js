var objectHash = require("../object_hash.js");
var _ = require('lodash');
var test = require('ava');
var Database = require('better-sqlite3');

function makeUnit(tps_fee, timestamp, burn_fee) {
	var unit = {
		version: '4.0',
		alt: '3',
		timestamp: timestamp || 1700000000,
		authors: [{
			address: 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU',
			authentifiers: { r: 'sig_placeholder' }
		}],
		messages: [{
			app: 'payment',
			payload_location: 'inline',
			payload_hash: 'hash_placeholder_0000000000000000'
		}],
		witnesses: [
			'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU', 'O53X2I3IQHVMG2TQZS2EV2HFDMQKDY6R',
			'2PQWCEBJKB3NRQEMCTEH7KLYI7U6MOLD', '24FKNJRE2F43J7MSQSYEKF4DAV4VHPOI',
			'ILGXCHM5SAIJYAZXVJ2M47OKGK4JSUIY', '7WAF724NYVGIVTXNN3IYWU24EHX7AKFU',
			'O53X2I3IQHVMG2TQZS2EV2HFDMQKDY6R', '2PQWCEBJKB3NRQEMCTEH7KLYI7U6MOLD',
			'24FKNJRE2F43J7MSQSYEKF4DAV4VHPOI', 'ILGXCHM5SAIJYAZXVJ2M47OKGK4JSUIY',
			'7WAF724NYVGIVTXNN3IYWU24EHX7AKFU', 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU'
		],
		parent_units: ['oXGOcA9TQx8Tl5Syjp1d5+mB4xicsRk3kbcE82YQAS0='],
		last_ball: 'oXGOcA9TQx8Tl5Syjp1d5+mB4xicsRk3kbcE82YQAS0=',
		last_ball_unit: 'oXGOcA9TQx8Tl5Syjp1d5+mB4xicsRk3kbcE82YQAS0=',
		tps_fee: tps_fee
	};
	if (burn_fee) unit.burn_fee = burn_fee;
	return unit;
}

test('tps_fee produces distinct hashes via real getUnitHash', t => {
	var h1 = objectHash.getUnitHash(makeUnit(100));
	var h2 = objectHash.getUnitHash(makeUnit(101));
	var h3 = objectHash.getUnitHash(makeUnit(102));
	t.not(h1, h2);
	t.not(h2, h3);
	t.not(h1, h3);
});

test('attacker grinds smaller hash & wins double-spend resolution', t => {
	var victimHash = objectHash.getUnitHash(makeUnit(100));

	/// grind tps_fee to find a hash lexicographically smaller than victim's
	var attackerHash = null;
	for (var fee = 101; fee <= 200; fee++) {
		var h = objectHash.getUnitHash(makeUnit(fee));
		if (h < victimHash) {
			attackerHash = h;
			break;
		}
	}
	t.truthy(attackerHash);

	/// set up real SQLite with the same units table schema ocore uses
	var db = new Database(':memory:');
	db.exec('CREATE TABLE units (unit TEXT PRIMARY KEY, main_chain_index INT, sequence TEXT)');

	/// insert both units at the same MCI as temp-bad (pre-resolution state)
	var insert = db.prepare('INSERT INTO units VALUES (?, ?, ?)');
	insert.run(victimHash, 1000, 'temp-bad');
	insert.run(attackerHash, 1000, 'temp-bad');

	/// run the exact query from handleNonserialUnits in main_chain.js
	/// first row returned gets sequence='good', rest become 'final-bad'
	var rows = db.prepare("SELECT * FROM units WHERE main_chain_index=? AND sequence!='good' ORDER BY unit").all(1000);

	t.is(rows.length, 2);
	t.is(rows[0].unit, attackerHash);
	t.is(rows[1].unit, victimHash);

	db.close();
});

test('multi-axis grinding widens the advantage', t => {
	var victimHash = objectHash.getUnitHash(makeUnit(100));

	/// grind across tps_fee, timestamp & burn_fee
	var smallest = victimHash;
	for (var fee = 101; fee <= 110; fee++) {
		for (var ts = 1700000000; ts <= 1700000005; ts++) {
			for (var bf = 1; bf <= 3; bf++) {
				var h = objectHash.getUnitHash(makeUnit(fee, ts, bf));
				if (h < smallest) smallest = h;
			}
		}
	}

	/// even a small sample space (180 candidates) beats the victim
	var db = new Database(':memory:');
	db.exec('CREATE TABLE units (unit TEXT PRIMARY KEY, main_chain_index INT, sequence TEXT)');
	db.prepare('INSERT INTO units VALUES (?, ?, ?)').run(victimHash, 1000, 'temp-bad');
	db.prepare('INSERT INTO units VALUES (?, ?, ?)').run(smallest, 1000, 'temp-bad');

	var rows = db.prepare("SELECT * FROM units WHERE main_chain_index=? AND sequence!='good' ORDER BY unit").all(1000);
	t.is(rows[0].unit, smallest);
	t.not(rows[0].unit, victimHash);

	db.close();
});
