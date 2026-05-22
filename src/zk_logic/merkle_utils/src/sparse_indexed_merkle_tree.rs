// FOR BENCHMARKING/EXAMPLES ONLY.
//
// This module provides a sparse indexed Merkle tree intended solely for
// constructing realistic-sized proofs in benchmark examples. In production,
// the Merkle trees are maintained by off-chain indexers and only individual
// inclusion proofs are handed to the prover — this data structure is never
// needed at proof time.
//
// Design: a binary Merkle tree of fixed depth `d` with 2^d leaf positions.
// Only explicitly inserted leaves are materialised; all absent positions use
// a precomputed "empty-subtree" hash for their level. This means a depth-20
// tree with a single real entry costs O(d) memory and O(d) time to build and
// prove, identical to how a real off-chain indexer would behave.
//
// Sibling ordering matches `MerkleTree::inclusion_proof` (leaf→root, LSB-first
// index decomposition), so the returned `SparseIndexedInclusionProof` can be
// fed directly into `StepInputs::connection_mip_siblings` and
// `StepInputs::reputation_mip_siblings`.

use std::collections::HashMap;

use crate::poseidon_hash::poseidon_hash;

/// Build the empty-subtree hash table.
/// `empty_hashes[0]` = zero leaf `[0u64; 4]`.
/// `empty_hashes[k]` = hash of a completely empty subtree of height k.
fn build_empty_hashes(depth: usize) -> Vec<[u64; 4]> {
    let mut h = Vec::with_capacity(depth + 1);
    h.push([0u64; 4]);
    for _ in 0..depth {
        let top = *h.last().unwrap();
        h.push(poseidon_hash(&[top, top]));
    }
    h
}

/// Sparse indexed Merkle tree of fixed depth for benchmarking examples.
///
/// Stores only the nodes on explicitly inserted leaf paths; all other nodes
/// default to the precomputed empty-subtree hash for their level.
/// Supports any depth up to 63 (depth=20 → 2^20 leaf slots, etc.).
pub struct SparseIndexedMerkleTree {
    depth: usize,
    /// Nodes keyed by (level, position). Level 0 = leaf layer, level `depth` = root.
    nodes: HashMap<(usize, usize), [u64; 4]>,
    /// Precomputed empty-subtree hashes; `empty_hashes[k]` covers height k.
    empty_hashes: Vec<[u64; 4]>,
}

/// Merkle inclusion proof produced by `SparseIndexedMerkleTree`.
///
/// Drop-in replacement for `MerkleInclusionProof`: same field names, same
/// sibling ordering (leaf→root, LSB-first index bits), compatible with all
/// circuit gadgets and `StepInputs`.
pub struct SparseIndexedInclusionProof {
    pub leaf_index: usize,
    pub leaf: [u64; 4],
    /// One sibling hash per tree level, ordered from the leaf level up to
    /// (but not including) the root. `siblings[0]` is the sibling of the
    /// leaf itself; `siblings[depth-1]` is the sibling of the root's child.
    pub siblings: Vec<[u64; 4]>,
}

impl SparseIndexedMerkleTree {
    /// Create an empty tree. Depth must be 1..=63.
    pub fn new(depth: usize) -> Self {
        assert!(depth > 0 && depth <= 63, "depth must be 1..=63");
        SparseIndexedMerkleTree {
            depth,
            nodes: HashMap::new(),
            empty_hashes: build_empty_hashes(depth),
        }
    }

    /// Insert `value` at leaf position `index` and recompute all ancestors.
    pub fn insert(&mut self, index: usize, value: [u64; 4]) {
        assert!(index < (1usize << self.depth), "index out of range for depth {}", self.depth);
        self.nodes.insert((0, index), value);
        let mut pos = index;
        for l in 1..=self.depth {
            pos >>= 1;
            let left  = self.nodes.get(&(l - 1, pos * 2    )).copied().unwrap_or(self.empty_hashes[l - 1]);
            let right = self.nodes.get(&(l - 1, pos * 2 + 1)).copied().unwrap_or(self.empty_hashes[l - 1]);
            self.nodes.insert((l, pos), poseidon_hash(&[left, right]));
        }
    }

    /// Return the current root hash.
    pub fn root(&self) -> [u64; 4] {
        self.nodes.get(&(self.depth, 0)).copied().unwrap_or(self.empty_hashes[self.depth])
    }

    /// Generate an inclusion proof for the leaf at `index`.
    ///
    /// The proof has exactly `depth` siblings. Siblings for absent neighbours
    /// are the precomputed empty-subtree hash for their level, which is what a
    /// real off-chain indexer would supply.
    pub fn inclusion_proof(&self, index: usize) -> SparseIndexedInclusionProof {
        assert!(index < (1usize << self.depth), "index out of range for depth {}", self.depth);
        let leaf = self.nodes.get(&(0, index)).copied().unwrap_or(self.empty_hashes[0]);
        let mut siblings = Vec::with_capacity(self.depth);
        let mut pos = index;
        for l in 0..self.depth {
            let sibling_pos = pos ^ 1;
            let sibling = self.nodes.get(&(l, sibling_pos)).copied().unwrap_or(self.empty_hashes[l]);
            siblings.push(sibling);
            pos >>= 1;
        }
        SparseIndexedInclusionProof { leaf_index: index, leaf, siblings }
    }
}
