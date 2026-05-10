// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SapphireMock
/// @notice Simulates the Oasis Sapphire precompiles that are expressible in standard Solidity.
/// Saphire libraries also support digital signing, since the key is used within the TEE and is not public. 
/// This is not possible in standard Solidity, so signing will not be performed even though 
/// it is part of the original design.
library SapphireMock {
    /// @notice Simulates Sapphire's secure on-chain randomness precompile.
    /// @dev NOT cryptographically secure on a public EVM - do not use in production.
    /// @param caller The address of the transaction sender, used as entropy.
    /// @return A pseudo-random bytes32 value.
    function randomBytes(address caller) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(block.timestamp, block.prevrandao, caller));
    }
}
