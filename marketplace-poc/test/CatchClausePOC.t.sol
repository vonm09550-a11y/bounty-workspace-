// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

interface IMarketplaceV2 {
    function atomicMatch(
        bytes32 transactionType,
        bytes memory _order,
        address seller,
        bytes memory _sellerMetadata,
        bytes memory sellerSig,
        address buyer,
        bytes memory _buyerMetadata,
        bytes memory buyerSig
    ) external payable;

    function TRANSACT_ERC721() external view returns (bytes32);
}

/// @notice Mock ERC721 using custom error (OpenZeppelin v5, ERC721A, Solady pattern)
contract MockERC721CustomError {
    error TokenDoesNotExist();

    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function ownerOf(uint256) external pure {
        revert TokenDoesNotExist();
    }

    function supportsInterface(bytes4) external pure returns (bool) {
        return true;
    }
}

contract CatchClausePOC is Test {
    IMarketplaceV2 constant MARKETPLACE = IMarketplaceV2(0xFC1759E75180aeE982DC08D0d6D365ebFA0296a7);

    uint256 constant SELLER_PK = 0xA11CE;
    uint256 constant BUYER_PK = 0xB0B;

    address seller;
    address buyer;
    MockERC721CustomError mockNFT;

    function setUp() public {
        vm.createSelectFork("https://eth.llamarpc.com");

        seller = vm.addr(SELLER_PK);
        buyer = vm.addr(BUYER_PK);

        // Deploy mock with seller as owner (Gateway.nftManager fallback returns owner)
        mockNFT = new MockERC721CustomError(seller);

        vm.deal(buyer, 10 ether);
    }

    function test_LazyMintRevertsOnCustomError() public {
        bytes32 txType = MARKETPLACE.TRANSACT_ERC721();

        // Order: allowMint = true triggers _checkMinted path
        bytes memory order = abi.encode(
            address(MARKETPLACE),
            address(mockNFT),
            1,
            address(0),
            1 ether,
            0,
            0,
            address(0),
            true
        );

        bytes memory sellerMeta = abi.encode(true, seller, 0, 0, 1, false, 1);
        bytes memory buyerMeta = abi.encode(false, buyer, 0, 0, 1, false, 2);

        bytes memory sellerSig = _sign(SELLER_PK, txType, order, sellerMeta);
        bytes memory buyerSig = _sign(BUYER_PK, txType, order, buyerMeta);

        // Reverts with custom error instead of returning mintedAmount = 0
        vm.prank(buyer);
        vm.expectRevert(MockERC721CustomError.TokenDoesNotExist.selector);
        MARKETPLACE.atomicMatch{value: 1 ether}(
            txType,
            order,
            seller,
            sellerMeta,
            sellerSig,
            buyer,
            buyerMeta,
            buyerSig
        );
    }

    function _sign(
        uint256 pk,
        bytes32 txType,
        bytes memory order,
        bytes memory meta
    ) internal view returns (bytes memory) {
        bytes32 hash = keccak256(abi.encodePacked(txType, order, meta, block.chainid));
        bytes32 ethHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, ethHash);
        return abi.encodePacked(r, s, v);
    }
}
