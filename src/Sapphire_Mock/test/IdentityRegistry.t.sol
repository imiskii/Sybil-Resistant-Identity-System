// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {
    IdentityRegistry,
    FullRegistration,
    LimitedRegistration,
    InvalidROFLSignature,
    AlreadyRegistered,
    EmbeddingAlreadyExists
} from "../src/IdentityRegistry.sol";

contract IdentityRegistryTest is Test {
    IdentityRegistry registry;

    // Anvil account #9 - used as the ROFL mock signer in tests.
    uint256 constant ROFL_PRIV_KEY = 0x2a871d0798f97d79848a013d4936a73bf4cc922c825d33c1cf7073dff6d409c6;
    address roflMockAddr;

    function setUp() public {
        roflMockAddr = vm.addr(ROFL_PRIV_KEY);
        registry = new IdentityRegistry(roflMockAddr);
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

    function _signRegistration(address user, bytes32 embHash, bool matchResult) internal pure returns (bytes memory) {
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

    // --- hardcoded test vector ----------------------------------------------
    // Verifies that the on-chain JSON reconstruction is byte-perfect.
    // Expected JSON:
    //   {"ID":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    //    "embedding_hash":"0x0000000000000000000000000000000000000000000000000000000000000001",
    //    "match_result":false}
    function test_knownVector_jsonDigest() public pure {
        address knownUser = 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;
        bytes32 knownEmb  = bytes32(uint256(1));

        bytes32 expected = keccak256(bytes(
            '{"ID":"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",'
            '"embedding_hash":"0x0000000000000000000000000000000000000000000000000000000000000001",'
            '"match_result":false}'
        ));
        bytes32 got = keccak256(abi.encodePacked(
            '{"ID":"', Strings.toChecksumHexString(knownUser),
            '","embedding_hash":"', _bytes32ToHex(knownEmb),
            '","match_result":false}'
        ));
        assertEq(got, expected, "JSON digest mismatch: encoding not byte-perfect");
    }

    // --- unit tests ----------------------------------------------------------

    function test_registerFull() public {
        address user    = makeAddr("alice");
        bytes32 embHash = keccak256("alice_emb");

        vm.expectEmit(true, false, false, false);
        emit FullRegistration(user);

        _registerUser(user, embHash, false);

        assertEq(
            uint8(registry.registrationState(user)),
            uint8(IdentityRegistry.RegistrationState.FULL)
        );
        assertEq(registry.embeddingToAddress(embHash), user);
        assertEq(registry.reputation(user), 0);
    }

    function test_registerLimited() public {
        address user    = makeAddr("bob");
        bytes32 embHash = keccak256("bob_emb");

        vm.expectEmit(true, false, false, false);
        emit LimitedRegistration(user);

        _registerUser(user, embHash, true);

        assertEq(
            uint8(registry.registrationState(user)),
            uint8(IdentityRegistry.RegistrationState.LIMITED)
        );
    }

    function test_revert_alreadyRegistered() public {
        address user = makeAddr("alice");
        _registerUser(user, keccak256("emb1"), false);

        vm.expectRevert(AlreadyRegistered.selector);
        _registerUser(user, keccak256("emb2"), false);
    }

    function test_revert_embeddingExists() public {
        bytes32 sharedEmb = keccak256("shared_embedding");
        _registerUser(makeAddr("alice"), sharedEmb, false);

        vm.expectRevert(EmbeddingAlreadyExists.selector);
        _registerUser(makeAddr("bob"), sharedEmb, false);
    }

    function test_revert_invalidSignature() public {
        address user    = makeAddr("alice");
        bytes32 embHash = keccak256("alice_emb");

        // Sign with a different private key - recovered signer != roflMockAddr.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ROFL_PRIV_KEY + 1, keccak256("wrong_payload"));
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.expectRevert(InvalidROFLSignature.selector);
        registry.registerProfile(user, embHash, false, badSig);
    }

    function testFuzz_register(address user, bytes32 embeddingHash, bool matchResult) public {
        vm.assume(user != address(0));

        _registerUser(user, embeddingHash, matchResult);

        assertNotEq(
            uint8(registry.registrationState(user)),
            uint8(IdentityRegistry.RegistrationState.NONE)
        );
        assertEq(registry.embeddingToAddress(embeddingHash), user);
    }
}
