using System;
using System.Numerics;
using Neo;
using Neo.SmartContract.Testing;
using Neo.SmartContract.Testing.TestingStandards;
using Neo.VM;
using Xunit;

namespace ProxyTemplate.Tests
{
    /// <summary>
    /// PoC: ProxySwapTokenInForTokenOut checks wrong token balance
    /// Demonstrates that function checks Pair01 (LP) deposit instead of path[0] (input token)
    /// </summary>
    public class ProxySwapBalanceCheckPoC : TestBase<ProxyTemplateContract>
    {
        // Contract addresses from ProxyTemplateContract.Admin.cs
        private static readonly UInt160 Token0 = UInt160.Parse("0xd02b79be5918eeeb065c427ade7fa629d6a50f93");
        private static readonly UInt160 Token1 = UInt160.Parse("0x0db9f60de6684be8a6a5528692a1bd6b1ddbe944");
        private static readonly UInt160 Pair01 = UInt160.Parse("0xef9003443351ee3179a3f3ad9f1bef8273c83ecc");

        // Storage prefixes from ProxyTemplateContract.Admin.cs
        private const byte Prefix_Deposit_Balance0 = 0x03;
        private const byte Prefix_Deposit_Balance1 = 0x04;
        private const byte Prefix_Balance_LPToken = 0x05;

        private readonly UInt160 _user;

        public ProxySwapBalanceCheckPoC() : base(ProxyTemplateContract.Nef, ProxyTemplateContract.Manifest)
        {
            _user = TestEngine.GetNewSigner().Account;
        }

        /// <summary>
        /// Setup: User has 1000 Token0 deposited, zero Pair01 deposited
        /// Action: Call ProxySwapTokenInForTokenOut with amountIn=500
        /// Expected: FAULT - function checks DepositOf(Pair01) which is 0
        /// </summary>
        [Fact]
        public void Test_ProxySwapTokenInForTokenOut_FailsWithWrongBalanceCheck()
        {
            // Arrange: Set user Token0 deposit to 1000 (sufficient for swap)
            SetDeposit(Prefix_Deposit_Balance0, _user, 1000);

            // Verify user has Token0 deposit but no Pair01 deposit
            var token0Balance = GetDeposit(Prefix_Deposit_Balance0, _user);
            var pair01Balance = GetDeposit(Prefix_Balance_LPToken, _user);
            Assert.Equal(1000, token0Balance);
            Assert.Equal(0, pair01Balance);

            // Act: Call ProxySwapTokenInForTokenOut
            // isToken0to1=true means path[0]=Token0, user should have Token0 balance
            // But function checks Pair01 balance instead
            var result = Contract.ProxySwapTokenInForTokenOut(
                _user,
                amountIn: 500,
                amountOutMin: 0,
                isToken0to1: true,
                deadLine: long.MaxValue
            );

            // Assert: Transaction faults due to wrong balance check
            Assert.Equal(VMState.FAULT, Engine.State);
        }

        /// <summary>
        /// Setup: User has 1000 Token0 deposited, zero Pair01 deposited
        /// Action: Call ProxySwapTokenOutForTokenIn with amountInMax=500
        /// Expected: HALT - function correctly checks DepositOf(path[0])
        /// Note: Will fault later on Router call but passes balance check
        /// </summary>
        [Fact]
        public void Test_ProxySwapTokenOutForTokenIn_PassesBalanceCheck()
        {
            // Arrange: Same setup - user has Token0 but no Pair01
            SetDeposit(Prefix_Deposit_Balance0, _user, 1000);

            // Act: Call sibling function - checks path[0] correctly
            try
            {
                Contract.ProxySwapTokenOutForTokenIn(
                    _user,
                    amountOut: 100,
                    amountInMax: 500,
                    isToken0to1: true,
                    deadLine: long.MaxValue
                );
            }
            catch
            {
                // May fault on Router call but that's after balance check passes
            }

            // Assert: If faulted, check it was NOT due to "Insufficient Balance"
            if (Engine.State == VMState.FAULT)
            {
                Assert.DoesNotContain("Insufficient Balance", Engine.FaultException?.Message ?? "");
            }
        }

        /// <summary>
        /// Proves the fix: If user has Pair01 deposit, ProxySwapTokenInForTokenOut passes
        /// This confirms the function checks Pair01 instead of input token
        /// </summary>
        [Fact]
        public void Test_ProxySwapTokenInForTokenOut_PassesWithPair01Deposit()
        {
            // Arrange: User has NO Token0 but HAS Pair01 deposit
            SetDeposit(Prefix_Deposit_Balance0, _user, 0);
            SetDeposit(Prefix_Balance_LPToken, _user, 1000);

            // Act: Should pass balance check despite having no input token
            try
            {
                Contract.ProxySwapTokenInForTokenOut(
                    _user,
                    amountIn: 500,
                    amountOutMin: 0,
                    isToken0to1: true,
                    deadLine: long.MaxValue
                );
            }
            catch
            {
                // Will fault later on actual swap but balance check passes
            }

            // Assert: Did not fault on "Insufficient Balance"
            if (Engine.State == VMState.FAULT)
            {
                Assert.DoesNotContain("Insufficient Balance", Engine.FaultException?.Message ?? "");
            }
        }

        #region Storage Helpers

        private void SetDeposit(byte prefix, UInt160 owner, BigInteger amount)
        {
            var key = new byte[] { prefix }.Concat(owner.ToArray()).ToArray();
            if (amount > 0)
                Engine.Storage.Put(Contract.Hash, key, amount);
            else
                Engine.Storage.Delete(Contract.Hash, key);
        }

        private BigInteger GetDeposit(byte prefix, UInt160 owner)
        {
            var key = new byte[] { prefix }.Concat(owner.ToArray()).ToArray();
            var value = Engine.Storage.Find(Contract.Hash, key);
            return value.Any() ? (BigInteger)value.First().Value : 0;
        }

        #endregion
    }
}
