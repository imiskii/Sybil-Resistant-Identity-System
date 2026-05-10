// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Poseidon} from "poseidon-sol/contracts/Poseidon.sol";

contract IncrementalMerkleTree {
    uint32 public constant DEPTH = 4;

    uint32 public nextLeafIndex;
    uint256[DEPTH] public filledSubtrees;
    uint256[DEPTH] public zeros;
    uint256 public root;

    Poseidon private immutable poseidon;

    error TreeFull();

    event LeafInserted(uint256 indexed leaf, uint256 indexed leafIndex, uint256 root);

    constructor() {
        poseidon = new Poseidon();
        _initZeros();
    }

    function _initZeros() private {
        uint256 currentZero = 0;
        zeros[0] = currentZero;

        for (uint32 i = 1; i < DEPTH; i++) {
            currentZero = poseidon.hash([currentZero, currentZero]);
            zeros[i] = currentZero;
        }

        for (uint32 i = 0; i < DEPTH; i++) {
            filledSubtrees[i] = zeros[i];
        }

        root = poseidon.hash([currentZero, currentZero]);
    }

    function insert(uint256 leaf) external returns (uint32 leafIndex) {
        /// NOTE: On this place the contract should check the Sapphire smart contract signature
        /// to verify that the newly inserted connection commitment was validated. This prevents 
        /// malicious actors from inserting invalid commitments into the tree. Therefore there is 
        /// no control of who can insert a commitment into the tree. In the case of Relayer failure 
        /// user can insert the commitment themselves.

        if (nextLeafIndex >= uint32(2) ** DEPTH) revert TreeFull();

        leafIndex = nextLeafIndex;
        nextLeafIndex++;

        uint256 currentLevelHash = leaf;
        uint32 currentIndex = leafIndex;

        for (uint32 i = 0; i < DEPTH; i++) {
            if (currentIndex % 2 == 1) {
                currentLevelHash = poseidon.hash([filledSubtrees[i], currentLevelHash]);
            } else {
                filledSubtrees[i] = currentLevelHash;
                currentLevelHash = poseidon.hash([currentLevelHash, zeros[i]]);
            }
            currentIndex /= 2;
        }

        root = currentLevelHash;
        emit LeafInserted(leaf, leafIndex, root);
    }
}
