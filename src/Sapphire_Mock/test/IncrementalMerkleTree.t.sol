// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IncrementalMerkleTree} from "../src/IncrementalMerkleTree.sol";

contract IncrementalMerkleTreeTest is Test {
    IncrementalMerkleTree tree;

    function setUp() public {
        tree = new IncrementalMerkleTree();
    }

    function test_initialRoot() public view {
        assertNotEq(tree.root(), 0);
        assertEq(tree.nextLeafIndex(), 0);
    }

    function test_insertOne() public {
        uint256 leaf = 42;
        uint256 rootBefore = tree.root();

        vm.expectEmit(true, true, false, false);
        emit IncrementalMerkleTree.LeafInserted(leaf, 0, 0);

        uint32 idx = tree.insert(leaf);

        assertEq(idx, 0);
        assertEq(tree.nextLeafIndex(), 1);
        assertNotEq(tree.root(), rootBefore);
    }

    function test_insertAll() public {
        for (uint256 i = 0; i < 16; i++) {
            tree.insert(i + 1);
        }
        assertEq(tree.nextLeafIndex(), 16);
    }

    function test_revert_treeFull() public {
        for (uint256 i = 0; i < 16; i++) {
            tree.insert(i + 1);
        }
        vm.expectRevert(IncrementalMerkleTree.TreeFull.selector);
        tree.insert(999);
    }

    function test_deterministicRoot() public {
        uint256 leaf = 0xdeadbeef;

        IncrementalMerkleTree treeA = new IncrementalMerkleTree();
        IncrementalMerkleTree treeB = new IncrementalMerkleTree();

        treeA.insert(leaf);
        treeB.insert(leaf);

        assertEq(treeA.root(), treeB.root());
    }

    function testFuzz_insert(uint256 leaf) public {
        tree.insert(leaf);
        assertEq(tree.nextLeafIndex(), 1);
        assertNotEq(tree.root(), 0);
    }
}
