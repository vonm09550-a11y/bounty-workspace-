// SPDX-License-Identifier: MIT
pragma solidity ^0.8.3;

interface IGovernance {
    function deposit(uint amount) external payable;
    function withdraw(uint amount) external;
}

/// @notice Mimics a Gnosis Safe or other contract wallet whose receive() costs > 2300 gas.
///         The storage write makes it incompatible with Solidity's .transfer() stipend.
contract ContractWallet {
    uint private dummy;

    receive() external payable {
        dummy += 1; // storage write: ~20000 gas, far exceeds 2300 stipend
    }

    function doDeposit(address governance, uint amount) external {
        IGovernance(governance).deposit{value: amount}(amount);
    }

    function doWithdraw(address governance, uint amount) external {
        IGovernance(governance).withdraw(amount);
    }
}
