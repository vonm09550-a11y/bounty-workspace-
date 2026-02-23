using System.Numerics;
using Neo;
using Neo.Assertions;
using Neo.BlockchainToolkit;
using Neo.BlockchainToolkit.SmartContract;
using Neo.SmartContract;
using Neo.VM;
using Xunit;

namespace ProxyTemplate.Tests;

[CheckpointPath("test/bin/checkpoints/contract-deployed.neoxp-checkpoint")]
public class ProxySwapBalanceCheckTests : IClassFixture<CheckpointFixture<ProxySwapBalanceCheckTests>>
{
    readonly CheckpointFixture<ProxySwapBalanceCheckTests> fixture;
    readonly ExpressChain chain;

    // Storage prefixes from ProxyTemplateContract.Admin.cs lines 31-35
    const byte PREFIX_DEPOSIT_BALANCE0 = 0x03;
    const byte PREFIX_DEPOSIT_BALANCE1 = 0x04;
    const byte PREFIX_BALANCE_LPTOKEN = 0x05;

    public ProxySwapBalanceCheckTests(CheckpointFixture<ProxySwapBalanceCheckTests> fixture)
    {
        this.fixture = fixture;
        this.chain = fixture.FindChain("ProxyTemplate.Tests.neo-express");
    }

    [Fact]
    public void Test_ProxySwapTokenInForTokenOut_Fails_WithToken0Deposit_NoPair01()
    {
        // User has 1000 Token0, 0 Pair01
        // Bug: function checks Pair01 balance instead of Token0
        // Expected: FAULT with "Insufficient Balance"

        using var snapshot = fixture.GetSnapshot();

        var alice = chain.GetDefaultAccount("alice");
        var settings = chain.GetProtocolSettings();
        var proxyHash = snapshot.GetContractHash("ProxyTemplate");

        // Set storage: Alice has 1000 Token0
        var storageKey = new byte[] { PREFIX_DEPOSIT_BALANCE0 }
            .Concat(alice.ToScriptHash(settings.AddressVersion).ToArray())
            .ToArray();
        snapshot.SetStorage(proxyHash, storageKey, new BigInteger(1000));

        using var engine = new TestApplicationEngine(snapshot, settings, alice);

        // Invoke: ProxySwapTokenInForTokenOut(sender, amountIn, amountOutMin, isToken0to1, deadline)
        using var sb = new ScriptBuilder();
        sb.EmitDynamicCall(proxyHash, "proxySwapTokenInForTokenOut",
            alice.ToScriptHash(settings.AddressVersion),
            500,
            0,
            true,
            long.MaxValue);

        engine.LoadScript(sb.ToArray());
        engine.Execute();

        // Should FAULT because function checks Pair01 (0) not Token0 (1000)
        Assert.Equal(VMState.FAULT, engine.State);
        Assert.Contains("Insufficient Balance", engine.FaultException?.Message ?? "");
    }

    [Fact]
    public void Test_ProxySwapTokenOutForTokenIn_Passes_WithToken0Deposit_NoPair01()
    {
        // Same setup: 1000 Token0, 0 Pair01
        // Sibling function correctly checks path[0]
        // Expected: Does NOT fault on "Insufficient Balance"

        using var snapshot = fixture.GetSnapshot();

        var alice = chain.GetDefaultAccount("alice");
        var settings = chain.GetProtocolSettings();
        var proxyHash = snapshot.GetContractHash("ProxyTemplate");

        // Set storage: Alice has 1000 Token0
        var storageKey = new byte[] { PREFIX_DEPOSIT_BALANCE0 }
            .Concat(alice.ToScriptHash(settings.AddressVersion).ToArray())
            .ToArray();
        snapshot.SetStorage(proxyHash, storageKey, new BigInteger(1000));

        using var engine = new TestApplicationEngine(snapshot, settings, alice);

        using var sb = new ScriptBuilder();
        sb.EmitDynamicCall(proxyHash, "proxySwapTokenOutForTokenIn",
            alice.ToScriptHash(settings.AddressVersion),
            100,
            500,
            true,
            long.MaxValue);

        engine.LoadScript(sb.ToArray());
        engine.Execute();

        // Should NOT fault on "Insufficient Balance"
        if (engine.State == VMState.FAULT)
        {
            Assert.DoesNotContain("Insufficient Balance", engine.FaultException?.Message ?? "");
        }
    }

    [Fact]
    public void Test_ProxySwapTokenInForTokenOut_WronglyPasses_WithPair01Only()
    {
        // User has 0 Token0, 1000 Pair01
        // Bug: function checks Pair01 so it passes despite no input token
        // Expected: Does NOT fault on "Insufficient Balance" (proves bug)

        using var snapshot = fixture.GetSnapshot();

        var alice = chain.GetDefaultAccount("alice");
        var settings = chain.GetProtocolSettings();
        var proxyHash = snapshot.GetContractHash("ProxyTemplate");

        // Set storage: Alice has 1000 Pair01 (LP token)
        var storageKey = new byte[] { PREFIX_BALANCE_LPTOKEN }
            .Concat(alice.ToScriptHash(settings.AddressVersion).ToArray())
            .ToArray();
        snapshot.SetStorage(proxyHash, storageKey, new BigInteger(1000));

        using var engine = new TestApplicationEngine(snapshot, settings, alice);

        using var sb = new ScriptBuilder();
        sb.EmitDynamicCall(proxyHash, "proxySwapTokenInForTokenOut",
            alice.ToScriptHash(settings.AddressVersion),
            500,
            0,
            true,
            long.MaxValue);

        engine.LoadScript(sb.ToArray());
        engine.Execute();

        // Should NOT fault on "Insufficient Balance" - proves wrong token checked
        if (engine.State == VMState.FAULT)
        {
            Assert.DoesNotContain("Insufficient Balance", engine.FaultException?.Message ?? "");
        }
    }
}
