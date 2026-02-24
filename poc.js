const fs = require('fs');
const { spawn } = require('child_process');

const ocore = process.env.OCORE_PATH || './ocore';
const src = fs.readFileSync(`${ocore}/network.js`, 'utf8');
const fn = src.match(/function onWebsocketMessage\(message\) \{[\s\S]*?ws\.handlingMessage = false;\n\}/);
const eh = src.match(/process\.on\('uncaughtException'[\s\S]*?throw err;[\s\S]*?\}\);/);

if (!fn || !eh) { console.log('EXTRACT_FAILED'); process.exit(1); }

const srv = spawn('node', ['-e', `
const W = require('ws'), s = new W.Server({port:19740});
${fn[0]}
${eh[0]}
s.on('connection', w => {
    w.peer='x'; w.assocPendingRequests={}; w.assocCommandsInPreparingResponse={}; w.last_ts=Date.now();
    w.on('message', m => onWebsocketMessage.call(w, m));
});
process.stdout.write('1');
`]);

let x = 0;
srv.on('exit', () => x = 1);
srv.stdout.on('data', () => {
    const w = new (require('ws'))('ws://127.0.0.1:19740');
    w.on('open', () => w.send('null'));
    w.on('close', () => setTimeout(() => { console.log(x ? 'CRASH_CONFIRMED' : 'CRASH_FAILED'); process.exit(x ? 0 : 1); }, 100));
    w.on('error', () => {});
});
setTimeout(() => { srv.kill(); process.exit(1); }, 5000);
