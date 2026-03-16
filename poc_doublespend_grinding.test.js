var objectHash = require("../object_hash.js");
var test = require('ava');
var Database = require('better-sqlite3');

var AUTHOR = 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU';
var MCI = 1000;
var LIMCI = 999;

function makeUnit(tps_fee, timestamp, burn_fee) {
	var unit = {
		version: '4.0', alt: '3',
		timestamp: timestamp || 1700000000,
		authors: [{ address: AUTHOR, authentifiers: { r: 'sig' } }],
		messages: [{ app: 'payment', payload_location: 'inline', payload_hash: 'hash_placeholder_0000000000000000' }],
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

// schema from initial-db/byteball-sqlite.sql (units + unit_authors)
function setupDb() {
	var db = new Database(':memory:');
	db.exec("\
		CREATE TABLE units (\
			unit CHAR(44) NOT NULL PRIMARY KEY,\
			main_chain_index INT NULL,\
			latest_included_mc_index INT NULL,\
			is_stable TINYINT NOT NULL DEFAULT 0,\
			sequence TEXT CHECK (sequence IN('good','temp-bad','final-bad')) NOT NULL DEFAULT 'good',\
			headers_commission INT NOT NULL DEFAULT 0,\
			payload_commission INT NOT NULL DEFAULT 0\
		);\
		CREATE TABLE unit_authors (\
			unit CHAR(44) NOT NULL,\
			address CHAR(32) NOT NULL,\
			PRIMARY KEY (unit, address)\
		);\
	");
	return db;
}

function insertUnit(db, unitHash, sequence) {
	db.prepare("INSERT INTO units (unit, main_chain_index, latest_included_mc_index, is_stable, sequence) VALUES (?,?,?,1,?)").run(unitHash, MCI, LIMCI, sequence);
	db.prepare("INSERT INTO unit_authors (unit, address) VALUES (?,?)").run(unitHash, AUTHOR);
}

test('full double-spend resolution: attacker grinds hash & wins via handleNonserialUnits path', t => {
	var victimHash = objectHash.getUnitHash(makeUnit(100));

	// grind tps_fee until we get a hash smaller than victim's
	var attackerHash = null;
	var attackerFee = null;
	for (var fee = 101; fee <= 200; fee++) {
		var h = objectHash.getUnitHash(makeUnit(fee));
		if (h < victimHash) { attackerHash = h; attackerFee = fee; break; }
	}
	t.truthy(attackerHash);
	t.true(attackerHash < victimHash);

	var db = setupDb();

	// two conflicting units from same author, both temp-bad before resolution
	insertUnit(db, victimHash, 'temp-bad');
	insertUnit(db, attackerHash, 'temp-bad');

	// query from handleNonserialUnits in main_chain.js -- ORDER BY unit is the key
	var rows = db.prepare(
		"SELECT * FROM units WHERE main_chain_index=? AND sequence!='good' ORDER BY unit"
	).all(MCI);

	t.is(rows.length, 2);
	t.is(rows[0].unit, attackerHash); // smallest hash comes first

	// walk rows in order (async.eachSeries in the real code)
	rows.forEach(function(row) {

		// findStableConflictingUnits query from main_chain.js
		var competitors = db.prepare("\
			SELECT competitor_units.* \
			FROM unit_authors AS this_unit_authors \
			JOIN unit_authors AS competitor_unit_authors USING(address) \
			JOIN units AS competitor_units ON competitor_unit_authors.unit=competitor_units.unit \
			JOIN units AS this_unit ON this_unit_authors.unit=this_unit.unit \
			WHERE this_unit_authors.unit=? AND competitor_units.is_stable=1 AND +competitor_units.sequence='good' \
				AND (competitor_units.main_chain_index > this_unit.latest_included_mc_index) \
				AND (competitor_units.main_chain_index <= this_unit.main_chain_index)\
		").all(row.unit);

		// no good competitor yet -> good, otherwise -> final-bad
		var sequence = (competitors.length > 0) ? 'final-bad' : 'good';
		db.prepare("UPDATE units SET sequence=? WHERE unit=?").run(sequence, row.unit);
	});

	// check: attacker got good, victim got reversed
	var attackerState = db.prepare("SELECT sequence FROM units WHERE unit=?").get(attackerHash);
	var victimState = db.prepare("SELECT sequence FROM units WHERE unit=?").get(victimHash);

	t.is(attackerState.sequence, 'good');
	t.is(victimState.sequence, 'final-bad');

	db.close();
});
