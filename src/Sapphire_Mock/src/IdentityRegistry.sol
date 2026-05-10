// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";

error InvalidROFLSignature();
error AlreadyRegistered();
error EmbeddingAlreadyExists();

event FullRegistration(address indexed user);
event LimitedRegistration(address indexed user);

contract IdentityRegistry {
    address public immutable ROFL_MOCK_ADDRESS;

    enum RegistrationState { NONE, FULL, LIMITED }

    mapping(address => RegistrationState) public registrationState;
    mapping(address => uint256) public reputation;
    mapping(bytes32 => address) public embeddingToAddress;

    constructor(address roflMockAddress) {
        ROFL_MOCK_ADDRESS = roflMockAddress;
    }

    // --- private functions --------------------------------------------------

    /// @dev Produces a lowercase 0x-prefixed 66-char hex string from a bytes32 value.
    /// Must match Python's hex() output byte-for-byte for signature verification.
    function _bytes32ToHexString(bytes32 value) private pure returns (string memory) {
        bytes16 hexChars = "0123456789abcdef";
        bytes memory result = new bytes(66); // '0x' + 64 hex chars
        result[0] = "0";
        result[1] = "x";
        for (uint256 i = 0; i < 32; i++) {
            uint8 b = uint8(value[i]);
            result[2 + i * 2] = hexChars[b >> 4];
            result[3 + i * 2] = hexChars[b & 0x0f];
        }
        return string(result);
    }

    // --- public/external functions ------------------------------------------

    /// @dev Verifies the ROFL Mock signature and registers the user with their embedding hash
    /// and based on match result make FULL or LIMITED registration.
    function registerProfile(
        address user,
        bytes32 embeddingHash,
        bool matchResult,
        bytes calldata roflSignature
    ) external {
        // Reconstruct the exact JSON payload that the ROFL Mock signed (see Python ROFL_Mock implementation).
        bytes32 payloadHash = keccak256(abi.encodePacked(
            '{"ID":"', Strings.toChecksumHexString(user),
            '","embedding_hash":"', _bytes32ToHexString(embeddingHash),
            '","match_result":', matchResult ? 'true' : 'false', '}'
        ));
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(payloadHash);

        if (ECDSA.recoverCalldata(digest, roflSignature) != ROFL_MOCK_ADDRESS) revert InvalidROFLSignature();

        if (registrationState[user] != RegistrationState.NONE) revert AlreadyRegistered();
        if (embeddingToAddress[embeddingHash] != address(0)) revert EmbeddingAlreadyExists();

        reputation[user] = 0;
        embeddingToAddress[embeddingHash] = user;
        registrationState[user] = matchResult ? RegistrationState.LIMITED : RegistrationState.FULL;

        if (matchResult) emit LimitedRegistration(user);
        else emit FullRegistration(user);
    }
}
