// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {Poseidon} from "poseidon-sol/contracts/Poseidon.sol";
import {IdentityRegistry} from "./IdentityRegistry.sol";
import {SapphireMock} from "./SapphireMock.sol";

error CallerNotRegistered();
error TargetNotRegistered();
error InvalidTargetEmbedding();
error InvalidROFLSignature();
error CCMismatch();
error AlreadyConnected();

event ConnectionInitialized(uint256 indexed cc);
event ConnectionEstablished(uint256 indexed ccS);

contract ConnectionManager {
    address public immutable ROFL_MOCK_ADDRESS;
    IdentityRegistry public immutable registry;
    Poseidon public immutable poseidon;

    enum ConnectionState { NONE, INITIALIZED, COMPLETED }

    struct Connection {
        ConnectionState state;
        uint256 secret;
    }

    // --- private functions --------------------------------------------------

    // Keyed by Poseidon CC
    mapping(uint256 => Connection) public connections;

    constructor(address roflMockAddress, address registryAddress, address poseidonAddress) {
        ROFL_MOCK_ADDRESS = roflMockAddress;
        registry = IdentityRegistry(registryAddress);
        poseidon = Poseidon(poseidonAddress);
    }

    /// @dev Produces a lowercase 0x-prefixed 66-char hex string from a bytes32 value.
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

    /// @dev Produces a lowercase 0x-prefixed 66-char hex string from a uint256 value.
    /// Matches Python's "0x" + keccak(...).hex() output.
    function _uint256ToHexString(uint256 value) private pure returns (string memory) {
        return _bytes32ToHexString(bytes32(value));
    }

    // --- public/external functions ------------------------------------------

    /// @dev Establishes a connection between msg.sender and idB, based on the ROFL Mock signature and embedding hash. 
    /// The ROFL Mock signature proves that the off-chain ROFL verified the biometrics between 
    /// the two parties with the given match result.
    /// The embedding hash is used to verify the identity of the target party (idB).
    /// The function performs a two-step handshake to establish the connection, emitting events at each step.
    function establishConnection(
        uint256 roflCC, // Keccak-based CC from ROFL - used only for signature verification
        bytes32 embeddingHashB,
        bool matchResult,
        bytes calldata roflSignature,
        address idB
    ) external {
        // Check registration
        if (registry.registrationState(msg.sender) == IdentityRegistry.RegistrationState.NONE)
            revert CallerNotRegistered();
        if (registry.registrationState(idB) == IdentityRegistry.RegistrationState.NONE)
            revert TargetNotRegistered();

        // Check embedding
        if (registry.embeddingToAddress(embeddingHashB) != idB) revert InvalidTargetEmbedding();

        // Reconstruct ROFL signature digest.
        bytes32 payloadHash = keccak256(abi.encodePacked(
            '{"CC_AB":"', _uint256ToHexString(roflCC),
            '","hash_received_B":"', _bytes32ToHexString(embeddingHashB),
            '","match_result":', matchResult ? 'true' : 'false', '}'
        ));
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(payloadHash);
        if (ECDSA.recoverCalldata(digest, roflSignature) != ROFL_MOCK_ADDRESS) revert InvalidROFLSignature();

        // Compute Poseidon CC on-chain.
        // CC duality: ROFL uses Keccak; contract uses Poseidon.
        uint256 minId = uint160(msg.sender) < uint160(idB) ? uint160(msg.sender) : uint160(idB);
        uint256 maxId = uint160(msg.sender) < uint160(idB) ? uint160(idB) : uint160(msg.sender);
        uint256 expectedCC = poseidon.hash([minId, maxId]);

        // Verify roflCC (Keccak) encodes the same identity pair as (msg.sender, idB).
        bytes32 keccakCC = keccak256(abi.encodePacked(uint160(minId), uint160(maxId)));
        if (bytes32(roflCC) != keccakCC) revert CCMismatch();

        // Guard against completed connections
        if (connections[expectedCC].state == ConnectionState.COMPLETED) revert AlreadyConnected();

        // Two-step handshake
        if (connections[expectedCC].state == ConnectionState.NONE) {
            // First caller: generate the shared secret and store it.
            uint256 S = uint256(SapphireMock.randomBytes(msg.sender));
            connections[expectedCC] = Connection({state: ConnectionState.INITIALIZED, secret: S});
            emit ConnectionInitialized(expectedCC);
        } else {
            // Second caller: derive the final commitment and complete the connection.
            uint256 S = connections[expectedCC].secret;
            uint256 ccS = poseidon.hash([expectedCC, S]);
            connections[expectedCC].state = ConnectionState.COMPLETED;
            // SAPPHIRE LIMITATION: On real Oasis Sapphire, ccS would be signed here using the
            // contract-level signing precompile (Sapphire.sign). That precompile does not exist
            // on standard EVM - ccS is emitted unsigned.
            emit ConnectionEstablished(ccS);
        }
    }
}
