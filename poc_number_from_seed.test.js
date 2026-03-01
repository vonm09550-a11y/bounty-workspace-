var shell = require('child_process').execSync;
var path = require('path');
var crypto = require('crypto');
var constants = require("../constants.js");
constants.aa2UpgradeMci = 0;
constants.aa3UpgradeMci = 0;
constants.v4UpgradeMci = 0;

var desktop_app = require('../desktop_app.js');
desktop_app.getAppDataDir = function() { return __dirname + '/.testdata-' + path.basename(__filename); }

var dst_dir = __dirname + '/.testdata-' + path.basename(__filename);
shell('rm -rf ' + dst_dir);

var Decimal = require('decimal.js');
var formulaParser = require('../formula/index');
var test = require('ava');
require('./_init_datafeeds.js');
var db = require("../db");
var storage = require("../storage");

var readGetterProps = function (aa_address, func_name, cb) {
	storage.readAAGetterProps(db, aa_address, func_name, cb);
};

function evalFormulaWithVars(opts, callback) {
	var val_locals = {};
	for (var name in opts.locals)
		val_locals[name] = 'assigned';
	var val_opts = {
		formula: opts.formula,
		complexity: 1,
		count_ops: 0,
		bAA: true,
		bStateVarAssignmentAllowed: opts.bStateVarAssignmentAllowed,
		bStatementsOnly: opts.bStatementsOnly,
		mci: opts.objValidationState.last_ball_mci,
		readGetterProps: readGetterProps,
		locals: val_locals,
	};
	formulaParser.validate(val_opts, function(validation_res){
		if (validation_res.error)
			return callback(null);
		if (validation_res.complexity > 100)
			return callback(null, validation_res.complexity);
		formulaParser.evaluate(opts, [], '', function (err, eval_res) {
			callback(eval_res, validation_res.complexity, validation_res.count_ops, val_locals);
		});
	});
}

var objValidationState = {
	last_ball_mci: 1000,
	last_ball_timestamp: 1.5e9,
	mc_unit: "oXGOcA9TQx8Tl5Syjp1d5+mB4xicsRk3kbcE82YQAS0=",
	storage_size: 200,
	assocBalances: {},
	number_of_responses: 0,
	arrPreviousAAResponses: [],
	arrAugmentedMessages: [{
		"app": "payment",
		"payload_location": "inline",
		"payload_hash": "2p893QLyyaUi0Nw5IWGjRtocjAksxpiFvXYuBRwPTZI=",
		"payload": {
			"outputs": [
				{"address": "MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU", "amount": 19088}
			],
			"inputs": [{
				"unit": "p+U9OB+JOCW5/7hXiRpVw65HwzFprNfj68PCy/7BR6A=",
				"message_index": 0,
				"output_index": 1
			}]
		}
	}],
};

var AA = 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU';
var trigger = { address: "I2ADHGP4HL6J37NQAD73J7E5SKFIXJOT", data: {}, outputs: { base: 555 } };

// control: number_from_seed returns value within [0, 99] under normal conditions
test('number_from_seed returns within range for normal seed', t => {
	evalFormulaWithVars({
		conn: null,
		formula: 'number_from_seed("vvv", 0, 99)',
		trigger: trigger, locals: {}, stateVars: {},
		objValidationState: objValidationState, address: AA
	}, (res) => {
		t.deepEqual(res, 24);
		t.true(res >= 0 && res <= 99);
	});
});

// bug: Decimal precision 15 rounds nominator/denominator to exactly 1.0
// reproduces exact computation from formula/evaluation.js lines 1798-1802
test('precision 15 rounds near-max nominator to ratio 1.0', t => {
	var denominator = new Decimal("0x1" + "0".repeat(16));
	var boundary = new Decimal("0xFFFFFFFFFFFFDBF9");
	var belowBoundary = new Decimal("0xFFFFFFFFFFFFDBF8");
	t.true(boundary.div(denominator).eq(1));
	t.false(belowBoundary.div(denominator).eq(1));
});

// bug: ratio 1.0 through range mapping produces max+1
// reproduces exact computation from formula/evaluation.js lines 1819-1820
test('ratio 1.0 through range mapping returns max+1', t => {
	var num = new Decimal(1);
	var min = new Decimal(0);
	var max = new Decimal(99);
	var len = max.minus(min).plus(1);
	var result = num.times(len).floor().plus(min);
	t.deepEqual(result.toNumber(), 100);
	t.true(result.gt(max));
});

// full chain: hash prefix >= 0xFFFFFFFFFFFFDBF9 produces out-of-range return
// combines both stages matching formula/evaluation.js lines 1798-1820
test('full computation chain returns 100 for range [0, 99]', t => {
	var nominator = new Decimal("0xFFFFFFFFFFFFDBF9");
	var denominator = new Decimal("0x1" + "0".repeat(16));
	var num = nominator.div(denominator);
	var min = new Decimal(0);
	var max = new Decimal(99);
	var len = max.minus(min).plus(1);
	var result = num.times(len).floor().plus(min);
	t.deepEqual(result.toNumber(), 100);
	t.deepEqual(num.toNumber(), 1);
});
