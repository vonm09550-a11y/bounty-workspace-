"use strict";
// Run from ocore root: node poc.js

const aa_validation = require('./aa_validation.js');

const definition = ["autonomous agent", {
    bounce_fees: { base: 10000 },
    messages: [{ app: "data", payload: { x: { "if": "{1}" } } }]
}];

process.once('uncaughtException', (e) => {
    console.log('[CRASH] ' + e.message);
    console.log('[FILE] ' + e.stack.split('\n')[1].trim());
    process.exit(0);
});

aa_validation.validateAADefinition(definition, (err) => {
    console.log(err ? '[ERROR] ' + err : '[FAIL] No crash');
    process.exit(1);
});
