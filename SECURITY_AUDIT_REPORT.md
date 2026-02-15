# Security Audit Report: Obyte Core (ocore)

**Repository:** https://github.com/byteball/ocore
**Audit Date:** 2026-02-15
**Scope:** Blockchain/DLT - Obyte Core Node
**Bounty Program:** Immunefi Classification

---

## Finding 1: Non-Deterministic Math.exp in Consensus-Critical Fee Calculations

**Severity:** Critical
**Impact:** Permanent chain split requiring hard fork to resolve
**Classification:** Blockchain/DLT - Direct theft of user funds / Network not following intended consensus rules

### Description

Four consensus-critical fee calculation functions in `storage.js` use JavaScript's `Math.exp()`, which the ECMAScript specification defines as returning an "implementation-approximated Number value" (Section 21.3.2.14). This means different JavaScript engines, different V8 versions, or different CPU architectures are permitted to return slightly different results for the same input. The fee values computed by these functions are either validated by exact match or stored in the database and used to determine `tps_fees_balance`, which directly affects validation of future units.

### Affected Code

**`storage.js:1129` - `getOversizeFee`:**
```javascript
return Math.ceil(size * (Math.exp(size / threshold_size - 1) - 1));
```

**`storage.js:1207` - `getFinalTpsFee`:**
```javascript
return Math.round(base_tps_fee * (Math.exp(tps / tps_interval) - 1));
```

**`storage.js:1309` - `getLocalTpsFee`:**
```javascript
const tps_fee_per_unit = Math.round(tps_fee_multiplier * base_tps_fee * (Math.exp(tps / tps_interval) - 1));
```

**`storage.js:1362` - `getCurrentTpsFee`:**
```javascript
return Math.round(base_tps_fee * (Math.exp(tps / tps_interval) - 1));
```

### Validation That Enforces Exact Match

**`validation.js:633-636` - Oversize fee validated by strict equality:**
```javascript
const oversize_fee = storage.getOversizeFee(objUnit, objValidationState.last_ball_mci);
if (oversize_fee) {
    if (objUnit.oversize_fee !== oversize_fee)
        return callback(createJointError(`oversize_fee mismatch: ...`));
}
```

### Attack Scenario

**Path A - Oversize Fee Exact Match Divergence:**
1. Node A (x86_64 Linux, V8 version X) computes `getOversizeFee` = 15000
2. Node B (ARM64 or different V8 version) computes `getOversizeFee` = 15001 for the same unit
3. The sending node includes `oversize_fee: 15000` in the unit
4. Node A validates successfully, Node B rejects the unit
5. Permanent chain split: the two groups of nodes disagree on whether the unit is valid

**Path B - TPS Fee Balance Accumulation Divergence:**
1. `getFinalTpsFee` (`storage.js:1218`) computes `actual_tps_fee` using `Math.exp`
2. `tps_fees_delta = paid_tps_fee - actual_tps_fee` is calculated (`storage.js:1220`)
3. This delta is stored in `tps_fees_balances` table (`storage.js:1232`)
4. Future unit validation reads `tps_fees_balance` to check if the unit's author has sufficient balance (`validation.js:930-932`)
5. Different Math.exp results cause different balance accumulation across nodes
6. Over time, accumulated differences cause nodes to disagree on whether a new unit has sufficient TPS fees

### Contrast with Oscript

The Oscript formula evaluation engine (`formula/evaluation.js`) correctly uses `Decimal.js` for all arithmetic operations, which is fully deterministic. The `Decimal.js` configuration in `formula/common.js:11-18` sets explicit precision (15 digits), rounding mode (ROUND_HALF_EVEN), and range limits. This demonstrates the codebase authors are aware of the need for deterministic arithmetic in consensus-critical paths, but this discipline was not applied to the fee calculation functions.

### Recommended Fix

Replace `Math.exp` with `Decimal.js` exponential calculation in all four functions, or implement a deterministic exponential approximation using only integer arithmetic. For example:

```javascript
const { Decimal } = require('./formula/common.js');
function getOversizeFee(objUnitOrSize, mci) {
    // ... size calculation ...
    const threshold_size = getSystemVar('threshold_size', mci);
    if (size <= threshold_size) return 0;
    const ratio = new Decimal(size).div(threshold_size).minus(1);
    return new Decimal(size).times(ratio.exp().minus(1)).ceil().toNumber();
}
```

---

## Finding 2: Hash Collision in getSourceString via NUL-Byte Separator Injection

**Severity:** Medium
**Impact:** Unintended smart contract behavior with no direct or foreseeable fund risk
**Classification:** Blockchain/DLT - Smart Contract vulnerability

### Description

The `getSourceString` function in `string_utils.js:11-56` serializes JavaScript objects into a string representation for hashing. It uses `\x00` (NUL byte) as the separator between all components (type prefixes, keys, values). However, NUL bytes are permitted within string values and object keys. This means the serialization is not injective -- structurally different objects can produce identical serialized strings and therefore identical hashes.

### Affected Code

**`string_utils.js:4` - Separator definition:**
```javascript
var STRING_JOIN_CHAR = "\x00";
```

**`string_utils.js:41-46` - Object key serialization (no escaping):**
```javascript
keys.forEach(function(key){
    if (typeof variable[key] === "undefined")
        throw Error("undefined at "+key+" of "+JSON.stringify(obj));
    arrComponents.push(key);        // key pushed without any escaping
    extractComponents(variable[key]);
});
```

### Confirmed Collision Classes

**Class A - Nested object flattening via NUL in keys:**
```javascript
obj1 = {a: {b: 'c'}}
// Serializes to: a \x00 b \x00 s \x00 c

obj2 = {}; obj2['a\x00b'] = 'c';
// Serializes to: a \x00 b \x00 s \x00 c  (IDENTICAL)
```

**Class B - Type confusion via NUL in strings:**
```javascript
obj1 = {a: "s\x00hello"}
// key 'a', value string "s\x00hello"
// Serializes to: a \x00 s \x00 s \x00 hello

obj2 = {a: {s: "hello"}}
// key 'a', nested object with key 's', value string "hello"
// Serializes to: a \x00 s \x00 s \x00 hello  (IDENTICAL)
```

### Functions Still Using getSourceString

| Function | File | Risk |
|---|---|---|
| `getDeviceMessageHashToSign` | `object_hash.js:149` | Medium - always uses getSourceString |
| `getChash160` (non-AA) | `object_hash.js:11` | Low - strict schema validation |
| `getChash288` | `object_hash.js:16` | Low - strict schema validation |
| `getHexHash` | `object_hash.js:20` | Low |

### Why Modern Units Are Not Affected

Modern units (version 2.0+, which includes all current protocol versions) use `getJsonSourceString` (`string_utils.js:190-227`), which properly JSON-quotes all keys and string values. NUL bytes become `\u0000` in the JSON representation, eliminating the collision. This is correctly selected at:
- `object_hash.js:11` - AA definitions use `getJsonSourceString`
- `object_hash.js:57-61` - Unit hashing uses `getJsonSourceString` for v2.0+
- `object_hash.js:89` - Unit hash-to-sign uses `getJsonSourceString` for v2.0+

### Practical Exploitability

**For `getDeviceMessageHashToSign`:** An attacker who observes a signed device message M1 could construct a different message M2 with the same hash-to-sign, enabling signature reuse. Device messages have "free format" (noted at `object_hash.js:148`), making NUL byte injection in keys feasible. However, constructing a M2 that is both structurally different from M1 AND semantically meaningful as a harmful command is highly constrained.

**For address derivation (`getChash160`):** Definition objects have strict schemas enforced by `definition.js` validation, which would likely reject objects with NUL bytes in unexpected positions. This limits practical exploitability for address collision attacks.

### Recommended Fix

Add NUL byte validation to `getSourceString`:
```javascript
function extractComponents(variable){
    // ... existing code ...
    case "string":
        if (variable.indexOf('\x00') >= 0)
            throw Error("NUL byte in string value");
        arrComponents.push("s", variable);
        break;
    // ... for object keys:
    keys.forEach(function(key){
        if (key.indexOf('\x00') >= 0)
            throw Error("NUL byte in object key");
        // ... rest ...
    });
}
```

Or migrate `getDeviceMessageHashToSign` to use `getJsonSourceString`.

---

## Areas Investigated and Confirmed Safe

The following areas were thoroughly analyzed and found to be secure:

### Oscript Formula Evaluation (`formula/evaluation.js`)
- All arithmetic uses Decimal.js (deterministic)
- `has_only` regex construction properly sanitizes `]` and `\` characters; pattern structure `^[...]*$` is immune to catastrophic backtracking (confirmed by dedicated ReDoS analysis agent)
- No other dynamic regex patterns exist in evaluation.js or formula/validation.js
- `concat` function uses `Object.assign({}, obj0, obj1)` with fresh target object -- no prototype pollution
- `assignByPath` uses `Object.defineProperty` via `assignField` -- safe from `__proto__` injection
- `number_from_seed` uses SHA-256 based PRNG (deterministic)
- `throw Error` at line 1246 (variable type check) is unreachable -- line 1216 catches the condition with `setFatalError` before RHS evaluation

### AA Balance Accounting (`aa_composer.js`)
- `updateInitialAABalances` properly saves and restores state via savepoints
- `bounce` function correctly restores state vars and balances
- `revert` function properly rolls back to savepoint
- Multi-asset bounce fee behavior is by design (AA configures bounce_fees)
- `MAX_RESPONSES_PER_PRIMARY_TRIGGER = 10` limits chaining depth
- bAir estimation mode intentionally simplifies accounting (documented)
- Historical bugs (pre-aa3UpgradeMci) are properly version-gated

### Signature Verification (`signature.js`)
- Standard ECDSA verification using `secp256k1` library
- PEM key validation in `validateAndFormatPemPubKey` properly checks key structure, algorithm OIDs, and key lengths
- `verifyMessageWithPemPubKey` handles both old and new Node.js API styles

### Input Validation (`validation_utils.js`)
- `hasOwnProperty` uses `Object.prototype.hasOwnProperty.call` (safe from prototype override)
- String length checks, base64 validation, hex validation all appear correct

### JSON Serialization (`string_utils.js`)
- `getJsonSourceString` properly handles all types with JSON quoting
- `toWellFormedJsonStringify` normalizes surrogate code units for cross-version determinism
- `isTooDeeplyNestedOrHasTooManyNodes` limits depth to 1000 and nodes to 10000
- Cross-platform determinism of hashing verified: SHA-256, Number.toString(), Object.keys().sort() are all deterministic per spec

### Object Hashing (`object_hash.js`)
- Modern unit hashing (v2.0+) uses `getJsonSourceString` -- immune to NUL injection
- `cleanNullsDeep` recursion is bounded by input structure depth

### Network Protocol (`network.js`)
- Light client endpoints (`light/get_aa_state_vars`) properly validate parameters with MAX_STATE_VARS limit
- `light/get_aa_responses` order parameter validated against allowlist
- `ignoreBugreportRegexp` is config-controlled, not attacker-controlled
- WebSocket message routing uses explicit command dispatch (not eval/dynamic require)

---

## Out-of-Scope Items Reviewed and Excluded

The following items were identified during analysis but fall outside the bounty program scope:

- **Light client trust model:** Light clients trust hub responses without proof. This is an intentional design choice documented in the architecture.
- **Network-level DoS:** Rate limiting on WebSocket endpoints is a best practice concern, not a specific vulnerability per the program's exclusion of "Network Denial of Service (DDoS/DoS) attacks."
- **51% attack / witness collusion:** Excluded per program rules.
- **Third-party dependency vulnerabilities:** No analysis of lodash, decimal.js, secp256k1, etc. per standard scope rules.
