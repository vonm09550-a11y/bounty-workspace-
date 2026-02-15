# PoC Reproduction Steps: AbortError State Bypass in sei-chain EVM

## Overview

This PoC demonstrates that when `evm.Call()` targets a FailFast precompile with a value transfer, the precompile returns an `AbortError` (which should signal a full revert), but the value transfer (debit from sender, credit to precompile address) **persists in the EVM StateDB**, is NOT rolled back, and **survives through `Finalize()` into the underlying store** — permanently locking funds.

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

The file is already in the `package keeper_test` package and imports everything it needs. No other files need to be created or modified.

### Step 3: Download dependencies

```bash
go mod download
```

If you encounter checksum issues (private forks), use:

```bash
GONOSUMCHECK=* GONOSUMDB=* GOPROXY=direct go mod download
```

### Step 4: Run the test

From the sei-chain repo root:

```bash
go test -v -run TestAbortErrorStateBypass ./x/evm/keeper/
```

Or with environment overrides if needed:

```bash
GONOSUMCHECK=* GONOSUMDB=* GOPROXY=direct go test -v -run TestAbortErrorStateBypass ./x/evm/keeper/
```

### Step 5: Interpret the output

#### Expected output (confirming the bug — test PASSES):

```
=== RUN   TestAbortErrorStateBypass
--- PASS: TestAbortErrorStateBypass (0.67s)
PASS
ok      github.com/sei-protocol/sei-chain/x/evm/keeper    1.504s
```

**Every assertion passes**, which proves the bug end-to-end:

| Line(s) | Assertion                                                         | Result |
|---------|-------------------------------------------------------------------|--------|
| 56      | `callErr` is non-nil (AbortError returned)                       | PASS   |
| 57      | Error contains `"invalid precompile call"`                        | PASS   |
| 68      | Sender lost funds (EVM StateDB level)                             | PASS   |
| 71      | Precompile gained funds (EVM StateDB level)                       | PASS   |
| 74      | Sender loss == 1,000,000 (exact value sent)                       | PASS   |
| 75      | Precompile gain == 1,000,000 (exact value sent)                   | PASS   |
| 79      | `stateDB.Finalize()` succeeds                                    | PASS   |
| 88      | Sender permanently lost funds (fresh StateDB after Finalize)      | PASS   |
| 92      | Precompile permanently holds funds (fresh StateDB after Finalize) | PASS   |

### What each phase proves

**Phase 1 — EVM StateDB level (lines 56-75):**
- `evm.Call()` returned an `AbortError`
- Despite the error, the EVM StateDB shows the value transfer was NOT reverted
- The sender's balance decreased by exactly 1,000,000
- The precompile's balance increased by exactly 1,000,000

**Phase 2 — Persistence after Finalize (lines 78-92):**
- `stateDB.Finalize()` commits the dirty state to the underlying store
- A fresh `state.NewDBImpl` reading from the same context confirms the balances persisted
- The sender permanently lost 1,000,000 wei
- The precompile address permanently holds 1,000,000 wei
- Funds are permanently locked / lost

## What the bug is

In go-ethereum's `evm.Call()`, when a precompile returns an `AbortError`:

1. The value transfer (sender -> precompile) has already been executed via `evm.Context.Transfer()` BEFORE the precompile's `Run()` method is called
2. When `Run()` returns an `AbortError`, the code checks `errors.As(err, &abort)` and returns the error
3. **Crucially, the EVM snapshot is not reverted** — unlike regular errors which trigger `evm.StateDB.RevertToSnapshot(snapshot)`, `AbortError` bypasses the revert logic
4. The value transfer remains in the StateDB
5. When `Finalize()` is called, the dirty balance changes are committed to the underlying cosmos store
6. The funds are permanently transferred despite the error

## File locations of vulnerable code

The vulnerable code path is in the go-ethereum fork used by sei-chain, specifically in `core/vm/evm.go` in the `Call()` method where `AbortError` handling skips snapshot revert.
