// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Poseidon} from "poseidon-sol/contracts/Poseidon.sol";
import {IdentityRegistry} from "../src/IdentityRegistry.sol";
import {
    ConnectionManager,
    CallerNotRegistered,
    TargetNotRegistered,
    InvalidTargetEmbedding,
    InvalidROFLSignature,
    CCMismatch,
    AlreadyConnected,
    ConnectionInitialized,
    ConnectionEstablished
} from "../src/ConnectionManager.sol";

contract ConnectionManagerTest is Test {
    IdentityRegistry registry;
    ConnectionManager manager;
    Poseidon         poseidonContract;

    // Anvil account #0 - used as the ROFL mock signer in tests.
    uint256 constant ROFL_PRIV_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    address roflMockAddr;

    address userA;
    address userB;
    bytes32 embHashA;
    bytes32 embHashB;

    function setUp() public {
        roflMockAddr     = vm.addr(ROFL_PRIV_KEY);
        poseidonContract = new Poseidon();
        registry         = new IdentityRegistry(roflMockAddr);
        manager          = new ConnectionManager(roflMockAddr, address(registry), address(poseidonContract));

        userA    = makeAddr("alice");
        userB    = makeAddr("bob");
        embHashA = keccak256("alice_emb");
        embHashB = keccak256("bob_emb");

        _registerUser(userA, embHashA, false);
        _registerUser(userB, embHashB, false);
    }

    // --- helpers ------------------------------------------------------------

    function _bytes32ToHex(bytes32 value) internal pure returns (string memory) {
        bytes16 hexChars = "0123456789abcdef";
        bytes memory result = new bytes(66);
        result[0] = "0";
        result[1] = "x";
        for (uint256 i = 0; i < 32; i++) {
            uint8 b = uint8(value[i]);
            result[2 + i * 2] = hexChars[b >> 4];
            result[3 + i * 2] = hexChars[b & 0x0f];
        }
        return string(result);
    }

    function _uint256ToHex(uint256 value) internal pure returns (string memory) {
        return _bytes32ToHex(bytes32(value));
    }

    function _signRegistration(address user, bytes32 embHash, bool matchResult)
        internal pure returns (bytes memory)
    {
        bytes32 payloadHash = keccak256(abi.encodePacked(
            '{"ID":"', Strings.toChecksumHexString(user),
            '","embedding_hash":"', _bytes32ToHex(embHash),
            '","match_result":', matchResult ? 'true' : 'false', '}'
        ));
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(payloadHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ROFL_PRIV_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _registerUser(address user, bytes32 embHash, bool matchResult) internal {
        registry.registerProfile(user, embHash, matchResult, _signRegistration(user, embHash, matchResult));
    }

    /// @dev Replicates the contract's keccak CC computation (20-byte address packing).
    function _computeKeccakCC(address a, address b) internal pure returns (uint256) {
        uint160 minId = uint160(a) < uint160(b) ? uint160(a) : uint160(b);
        uint160 maxId = uint160(a) < uint160(b) ? uint160(b) : uint160(a);
        return uint256(keccak256(abi.encodePacked(minId, maxId)));
    }

    function _signConnection(uint256 roflCC, bytes32 embHash, bool matchResult)
        internal pure returns (bytes memory)
    {
        bytes32 payloadHash = keccak256(abi.encodePacked(
            '{"CC_AB":"', _uint256ToHex(roflCC),
            '","hash_received_B":"', _bytes32ToHex(embHash),
            '","match_result":', matchResult ? 'true' : 'false', '}'
        ));
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(payloadHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ROFL_PRIV_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    // --- unit tests ---------------------------------------------------------

    function test_fullHandshake() public {
        uint256 minId = uint160(userA) < uint160(userB) ? uint160(userA) : uint160(userB);
        uint256 maxId = uint160(userA) < uint160(userB) ? uint160(userB) : uint160(userA);
        uint256 expectedCC  = poseidonContract.hash([minId, maxId]);
        uint256 roflCC      = _computeKeccakCC(userA, userB);

        // Pre-compute S (SapphireMock.randomBytes called with userA as caller)
        // and the final ccS before the calls so we can use expectEmit.
        uint256 S           = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao, userA)));
        uint256 expectedCcS = poseidonContract.hash([expectedCC, S]);

        bytes memory sigA = _signConnection(roflCC, embHashB, true);
        bytes memory sigB = _signConnection(roflCC, embHashA, true);

        // First caller (userA to userB): INITIALIZED, emits ConnectionInitialized(expectedCC)
        vm.prank(userA);
        vm.expectEmit(true, false, false, false);
        emit ConnectionInitialized(expectedCC);
        manager.establishConnection(roflCC, embHashB, true, sigA, userB);

        // Second caller (userB to userA): COMPLETED, emits ConnectionEstablished(ccS) unsigned
        vm.prank(userB);
        vm.expectEmit(true, false, false, false);
        emit ConnectionEstablished(expectedCcS);
        manager.establishConnection(roflCC, embHashA, true, sigB, userA);
    }

    function test_revert_callerNotRegistered() public {
        address stranger = makeAddr("stranger");
        uint256 roflCC   = _computeKeccakCC(stranger, userB);
        bytes memory sig = _signConnection(roflCC, embHashB, true);

        vm.prank(stranger);
        vm.expectRevert(CallerNotRegistered.selector);
        manager.establishConnection(roflCC, embHashB, true, sig, userB);
    }

    function test_revert_targetNotRegistered() public {
        address stranger    = makeAddr("stranger");
        bytes32 strangerEmb = keccak256("stranger_emb");
        uint256 roflCC      = _computeKeccakCC(userA, stranger);
        bytes memory sig    = _signConnection(roflCC, strangerEmb, true);

        vm.prank(userA);
        vm.expectRevert(TargetNotRegistered.selector);
        manager.establishConnection(roflCC, strangerEmb, true, sig, stranger);
    }

    function test_revert_alreadyConnected() public {
        uint256 roflCC    = _computeKeccakCC(userA, userB);
        bytes memory sigA = _signConnection(roflCC, embHashB, true);
        bytes memory sigB = _signConnection(roflCC, embHashA, true);

        vm.prank(userA);
        manager.establishConnection(roflCC, embHashB, true, sigA, userB);
        vm.prank(userB);
        manager.establishConnection(roflCC, embHashA, true, sigB, userA);

        // Third call - connection already COMPLETED
        vm.prank(userA);
        vm.expectRevert(AlreadyConnected.selector);
        manager.establishConnection(roflCC, embHashB, true, _signConnection(roflCC, embHashB, true), userB);
    }

    function test_revert_ccMismatch() public {
        uint256 correctCC = _computeKeccakCC(userA, userB);
        uint256 wrongCC   = correctCC ^ 1; // bit-flip - same identity pair, wrong CC value
        // Sign the payload with wrongCC so signature verification passes.
        bytes memory sig  = _signConnection(wrongCC, embHashB, true);

        vm.prank(userA);
        vm.expectRevert(CCMismatch.selector);
        manager.establishConnection(wrongCC, embHashB, true, sig, userB);
    }

    function test_revert_invalidEmbedding() public {
        uint256 roflCC       = _computeKeccakCC(userA, userB);
        bytes32 wrongEmbHash = keccak256("not_registered_emb");
        // Embedding check fires before signature verification - stub sig is fine.
        bytes memory stubSig = new bytes(65);

        vm.prank(userA);
        vm.expectRevert(InvalidTargetEmbedding.selector);
        manager.establishConnection(roflCC, wrongEmbHash, true, stubSig, userB);
    }
}
