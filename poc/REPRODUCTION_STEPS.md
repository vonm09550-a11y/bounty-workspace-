# PoC Reproduction Steps: AbortError State Bypass in sei-chain EVM

## Overview

This PoC demonstrates that when `evm.Call()` targets a FailFast precompile with a value transfer, the precompile returns an `AbortError` (which should signal a full revert), but the value transfer (debit from sender, credit to precompile address) **persists in the EVM StateDB** and is not rolled back.

## Prerequisites

- Go 1.21+ installed (the repo uses Go 1.21)
- Git
- ~2 GB disk for dependencies

## Step-by-Step Reproduction

### Step 1: Clone the sei-chain repository

```bash
git clone https://github.com/sei-protocol/sei-chain.git
cd sei-chain
```

Use the same commit the PoC was developed against, or `main`/`master` — the vulnerable code is in the go-ethereum fork's `evm.Call()` method.

### Step 2: Place the test file

Copy the file `abort_error_bypass_test.go` into the keeper test directory:

```bash
cp abort_error_bypass_test.go x/evm/keeper/abort_error_bypass_test.go
```

The file is already in the `package keeper_test` package and imports everything it needs.

### Step 3: Download dependencies

```bash
go mod download
```

If you encounter checksum issues (private forks), use:

```bash
GONOSUMCHECK=* GONOSUMDB=* GOPROXY=direct go mod download
```

### Step 4: Run the test

```bash
cd sei-chain   # make sure you are in the repo root
go test -v -run TestAbortErrorStateBypass ./x/evm/keeper/
```

Or with environment overrides if needed:

```bash
GONOSUMCHECK=* GONOSUMDB=* GOPROXY=direct go test -v -run TestAbortErrorStateBypass ./x/evm/keeper/
```

### Step 5: Interpret the output

#### Expected output (confirming the bug):

```
=== RUN   TestAbortErrorStateBypass
    abort_error_bypass_test.go:84:
            Error Trace:    .../x/evm/keeper/abort_error_bypass_test.go:84
            Error:          Should be true
            Test:           TestAbortErrorStateBypass
--- FAIL: TestAbortErrorStateBypass (0.6Xs)
FAIL
```

**The test reaches line 84 before failing.** This means:

| Line(s)  | Assertion                                       | Result |
|----------|-------------------------------------------------|--------|
| 56       | `callErr` is non-nil (AbortError returned)      | PASS   |
| 57       | Error contains `"invalid precompile call"`       | PASS   |
| 68       | Sender lost funds (EVM StateDB level)            | PASS   |
| 71       | Precompile gained funds (EVM StateDB level)      | PASS   |
| 74       | Sender loss == 1,000,000 (exact value sent)      | PASS   |
| 75       | Precompile gain == 1,000,000 (exact value sent)  | PASS   |
| 79       | `stateDB.Finalize()` succeeds                   | PASS   |
| 84       | Bank module balance positive after Finalize       | FAIL   |

**Lines 56-75 all passing proves the bug:**
- `evm.Call()` returned an `AbortError`
- Despite the error, the EVM StateDB shows the value transfer was NOT reverted
- The sender's balance decreased by exactly the sent amount
- The precompile's balance increased by exactly the sent amount

**Line 84 failing means:**
- `Finalize()` does not propagate the stale EVM balance to the bank module
- The impact is scoped to **within-transaction EVM state** — subsequent EVM opcodes in the same transaction see incorrect balances

## What the bug is

In go-ethereum's `evm.Call()`, when a precompile returns an `AbortError`:

1. The value transfer (sender → precompile) has already been executed via `evm.Context.Transfer()` BEFORE the precompile's `Run()` method is called
2. When `Run()` returns an `AbortError`, the code checks `errors.As(err, &abort)` and returns the error
3. **Crucially, the EVM snapshot is not reverted** — unlike regular errors which trigger `evm.StateDB.RevertToSnapshot(snapshot)`, `AbortError` bypasses the revert logic
4. The value transfer remains in the StateDB

This means any subsequent EVM operations in the same transaction context will see the wrong balances.

## File locations of vulnerable code

The vulnerable code path is in the go-ethereum fork used by sei-chain, specifically in `core/vm/evm.go` in the `Call()` method where `AbortError` handling skips snapshot revert.
