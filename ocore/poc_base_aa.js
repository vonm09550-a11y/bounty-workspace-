"use strict";
// Run from ocore root: node poc_base_aa.js

const objectHash = require('./object_hash.js');
const aa_validation = require('./aa_validation.js');
const storage = require('./storage.js');

const FAKE_BASE_AA = 'MXMEKGN37H5QO2AWHT7XRG6LHJVVTAWU';

const definition = ["autonomous agent", {
    base_aa: FAKE_BASE_AA,
    params: { key: "value" }
}];

const aaAddress = objectHash.getChash160(definition);

console.log('AA: ' + aaAddress);
console.log('base_aa: ' + FAKE_BASE_AA);

process.once('uncaughtException', (e) => {
    console.log('\n[CRASH] ' + e.message);
    console.log('[FILE] ' + e.stack.split('\n')[1].trim());
    process.exit(0);
});

aa_validation.validateAADefinition(definition, (err) => {
    if (err) {
        console.log('[ERROR] ' + err);
        process.exit(1);
    }

    const mockConn = {
        query: (sql, params, cb) => { cb([]); }
    };

    storage.readAADefinition(mockConn, FAKE_BASE_AA, (arrBaseDefinition) => {
        if (!arrBaseDefinition)
            throw Error("base AA not found: " + FAKE_BASE_AA);
    });
});
