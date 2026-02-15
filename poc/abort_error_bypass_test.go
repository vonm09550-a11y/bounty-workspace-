package keeper_test

import (
	"testing"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/holiman/uint256"
	"github.com/stretchr/testify/require"

	gigaprecompiles "github.com/sei-protocol/sei-chain/giga/executor/precompiles"
	"github.com/sei-protocol/sei-chain/precompiles/bank"
	testkeeper "github.com/sei-protocol/sei-chain/testutil/keeper"
	"github.com/sei-protocol/sei-chain/x/evm/state"
	"github.com/sei-protocol/sei-chain/x/evm/types"
)

func TestAbortErrorStateBypass(t *testing.T) {
	k, ctx := testkeeper.MockEVMKeeper(t)

	// Setup test account
	privKey := testkeeper.MockPrivateKey()
	seiAddr, evmAddr := testkeeper.PrivateKeyToAddresses(privKey)
	k.SetAddressMapping(ctx, seiAddr, evmAddr)

	// Fund account through bank module
	initialBalance := sdk.NewInt(10000000)
	require.NoError(t, k.BankKeeper().MintCoins(ctx, types.ModuleName, sdk.NewCoins(sdk.NewCoin("usei", initialBalance))))
	require.NoError(t, k.BankKeeper().SendCoinsFromModuleToAccount(ctx, types.ModuleName, seiAddr, sdk.NewCoins(sdk.NewCoin("usei", initialBalance))))

	// Target precompile address (registered as FailFast)
	precompileAddr := common.HexToAddress(bank.BankAddress)

	// Initialize state database
	stateDB := state.NewDBImpl(ctx, k, false)

	// Record balances before execution (EVM level)
	senderBalanceBefore := stateDB.GetBalance(evmAddr)
	precompileBalanceBefore := stateDB.GetBalance(precompileAddr)

	// Configure EVM with FailFast precompiles
	gp := core.GasPool(10000000)
	blockCtx, err := k.GetVMBlockContext(ctx, gp)
	require.NoError(t, err)

	chainCfg := types.DefaultChainConfig().EthereumConfig(k.ChainID(ctx))
	evm := vm.NewEVM(*blockCtx, stateDB, chainCfg, vm.Config{}, gigaprecompiles.AllCustomPrecompilesFailFast)

	// Execute call with value transfer to FailFast precompile
	valueToSend := uint256.NewInt(1000000)
	_, _, callErr := evm.Call(evmAddr, precompileAddr, []byte{}, 100000, valueToSend)

	// Verify AbortError was returned
	require.Error(t, callErr)
	require.Contains(t, callErr.Error(), "invalid precompile call")

	// Check balances after call (before finalize)
	senderBalanceAfter := stateDB.GetBalance(evmAddr)
	precompileBalanceAfter := stateDB.GetBalance(precompileAddr)

	// Calculate changes
	senderLoss := new(uint256.Int).Sub(senderBalanceBefore, senderBalanceAfter)
	precompileGain := new(uint256.Int).Sub(precompileBalanceAfter, precompileBalanceBefore)

	// Sender balance decreased
	require.True(t, senderLoss.Gt(uint256.NewInt(0)))

	// Precompile balance increased (funds locked)
	require.True(t, precompileGain.Gt(uint256.NewInt(0)))

	// Verify transferred amount matches
	require.True(t, senderLoss.Eq(valueToSend))
	require.True(t, precompileGain.Eq(valueToSend))

	// Finalize state (simulating tx completion)
	_, err = stateDB.Finalize()
	require.NoError(t, err)

	// Verify funds permanently locked after finalization via fresh StateDB
	freshStateDB := state.NewDBImpl(ctx, k, false)
	finalSenderBalance := freshStateDB.GetBalance(evmAddr)
	finalPrecompileBalance := freshStateDB.GetBalance(precompileAddr)

	// Confirm sender permanently lost funds
	permanentSenderLoss := new(uint256.Int).Sub(senderBalanceBefore, finalSenderBalance)
	require.True(t, permanentSenderLoss.Gt(uint256.NewInt(0)))

	// Confirm precompile permanently holds funds
	permanentPrecompileGain := new(uint256.Int).Sub(finalPrecompileBalance, precompileBalanceBefore)
	require.True(t, permanentPrecompileGain.Gt(uint256.NewInt(0)))
}
