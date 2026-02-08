"use strict";
// Run from ocore root: node poc.js

const crypto = require('crypto');
const objectHash = require('./object_hash.js');
const objectLength = require('./object_length.js');
const aa_validation = require('./aa_validation.js');

const definition = ["autonomous agent", {
    bounce_fees: { base: 10000 },
    messages: [{ app: "data", payload: { x: { "if": "{1}" } } }]
}];

const aaAddress = objectHash.getChash160(definition);
const payload = { address: aaAddress, definition: definition };
const payloadHash = objectHash.getBase64Hash(payload, true);

const unit = {
    version: '4.0t',
    alt: '2',
    timestamp: Math.floor(Date.now() / 1000),
    authors: [{ address: aaAddress }],
    messages: [{
        app: 'definition',
        payload_location: 'inline',
        payload_hash: payloadHash,
        payload: payload
    }],
    parent_units: ['oXGOcA9TQx8Tl5Syjp1d5+mB4xicsRk3kbcE82YDAR0='],
    last_ball: 'oXGOcA9TQx8Tl5Syjp1d5+mB4xicsRk3kbcE82YDAR0=',
    last_ball_unit: 'oXGOcA9TQx8Tl5Syjp1d5+mB4xicsRk3kbcE82YDAR0='
};

unit.headers_commission = objectLength.getHeadersSize(unit);
unit.payload_commission = objectLength.getTotalPayloadSize(unit);
unit.unit = objectHash.getUnitHash(unit);

console.log('Unit: ' + unit.unit);
console.log('AA: ' + aaAddress);
console.log('Payload: ' + payloadHash);

process.once('uncaughtException', (e) => {
    console.log('\n[CRASH] ' + e.message);
    console.log('[FILE] ' + e.stack.split('\n')[1].trim());
    process.exit(0);
});

aa_validation.validateAADefinition(definition, (err) => {
    console.log(err ? '[ERROR] ' + err : '[FAIL] No crash');
    process.exit(1);
});
