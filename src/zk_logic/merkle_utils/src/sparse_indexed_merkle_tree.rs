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

/// Sparse indexed Merkle tree of fixed depth.
/// Stores only the nodes on explicitly inserted leaf paths.
/// Other nodes default to the precomputed empty-subtree hash for their level.
pub struct SparseIndexedMerkleTree {
    depth: usize,
    /// Nodes keyed by (level, position). Level 0 = leaf layer, level `depth` = root.
    nodes: HashMap<(usize, usize), [u64; 4]>,
    /// Precomputed empty-subtree hashes; `empty_hashes[k]` covers height k.
    empty_hashes: Vec<[u64; 4]>,
}

/// Merkle inclusion proof produced by `SparseIndexedMerkleTree`.
pub struct SparseIndexedInclusionProof {
    pub leaf_index: usize,
    pub leaf: [u64; 4],
    /// One sibling hash per tree level, ordered from the leaf to root.
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
