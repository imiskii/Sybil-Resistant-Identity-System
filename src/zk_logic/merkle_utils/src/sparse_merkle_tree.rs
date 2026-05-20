use std::collections::HashMap;
use crate::poseidon_hash::poseidon_hash;

/// The null/empty leaf hash..
fn zero_hash() -> [u64; 4] {
    poseidon_hash(&[[0u64; 4], [0u64; 4]])
}

/// Precompute the default (all-empty) hash for each tree level.
fn build_empty_hashes(depth: usize) -> Vec<[u64; 4]> {
    let mut h = Vec::with_capacity(depth + 1);
    h.push(zero_hash());
    for _ in 0..depth {
        let top = *h.last().unwrap();
        h.push(poseidon_hash(&[top, top]));
    }
    h
}

/// Derive the `depth`-bit path for `key` by hashing it and extracting bits.
fn key_to_path(key: &[u64; 4], depth: usize) -> Vec<bool> {
    let hash = poseidon_hash(&[*key]);
    let mut bits = Vec::with_capacity(depth);
    'outer: for elem in &hash {
        for bit_idx in 0..64u32 {
            bits.push((elem >> bit_idx) & 1 == 1);
            if bits.len() >= depth {
                break 'outer;
            }
        }
    }
    bits
}

/// A sparse Merkle tree with a fixed depth, keyed by 256-bit keys.
pub struct SparseMerkleTree {
    depth: usize,
    /// Maps a path prefix (length 0..=depth) to the hash of that node.
    nodes: HashMap<Vec<bool>, [u64; 4]>,
    /// Precomputed empty-subtree hashes.
    empty_hashes: Vec<[u64; 4]>,
}

/// Non-inclusion proof: proves that `key` maps to the null leaf.
pub struct SparseMerkleNonInclusionProof {
    /// The key whose non-inclusion is being proven.
    pub key: [u64; 4],
    /// `depth` path bits derived from `Poseidon(key)`.
    pub path_bits: Vec<bool>,
    /// Sibling hashes ordered from the leaf level to root.
    pub siblings: Vec<[u64; 4]>,
}

impl SparseMerkleTree {
    /// Create an empty sparse Merkle tree of the given depth.
    /// A depth-32 tree has 2^32 possible leaf positions.
    pub fn new(depth: usize) -> Self {
        assert!(depth > 0, "depth must be at least 1");
        let empty_hashes = build_empty_hashes(depth);
        SparseMerkleTree {
            depth,
            nodes: HashMap::new(),
            empty_hashes,
        }
    }

    /// Insert a key-value pair into the tree.
    pub fn insert(&mut self, key: [u64; 4], value: [u64; 4]) {
        let path = key_to_path(&key, self.depth);

        // Store the leaf.
        self.nodes.insert(path.clone(), value);

        // Recompute all ancestors from just above the leaf up to the root.
        for p in (0..self.depth).rev() {
            // p is the path-prefix length of the parent being updated.
            // Its children are at path length p+1 and are subtrees of height
            // depth-(p+1) above the leaves.
            let child_empty = self.empty_hashes[self.depth - p - 1];

            let mut left_path = path[..p].to_vec();
            left_path.push(false);
            let mut right_path = path[..p].to_vec();
            right_path.push(true);

            let left = self.nodes.get(&left_path).copied().unwrap_or(child_empty);
            let right = self.nodes.get(&right_path).copied().unwrap_or(child_empty);

            let parent = poseidon_hash(&[left, right]);
            self.nodes.insert(path[..p].to_vec(), parent);
        }
    }

    /// Return the current Merkle root.
    pub fn root(&self) -> [u64; 4] {
        self.nodes
            .get(&vec![])
            .copied()
            .unwrap_or(self.empty_hashes[self.depth])
    }

    /// Generate a non-inclusion proof for `key`.
    pub fn non_inclusion_proof(&self, key: [u64; 4]) -> SparseMerkleNonInclusionProof {
        let path = key_to_path(&key, self.depth);
        let mut siblings = Vec::with_capacity(self.depth);

        // Collect siblings from the leaf level up to just below the root.
        for i in 0..self.depth {
            // The bit that leads from the ancestor at depth-(i+1) levels
            // from root down to the current node.
            let bit_idx = self.depth - 1 - i;
            let bit = path[bit_idx];

            // Build the sibling's path: same prefix, opposite bit.
            let mut sibling_path = path[..bit_idx].to_vec();
            sibling_path.push(!bit);

            // The sibling is a subtree of height i (i levels above the leaf).
            let sibling_empty = self.empty_hashes[i];
            let sibling = self
                .nodes
                .get(&sibling_path)
                .copied()
                .unwrap_or(sibling_empty);

            siblings.push(sibling);
        }

        SparseMerkleNonInclusionProof {
            key,
            path_bits: path,
            siblings,
        }
    }

    /// Verify a non-inclusion proof off-circuit.
    pub fn verify_non_inclusion(
        root: [u64; 4],
        proof: &SparseMerkleNonInclusionProof,
        key: [u64; 4],
    ) -> bool {
        let depth = proof.path_bits.len();
        if proof.siblings.len() != depth {
            return false;
        }

        // Confirm the path was derived consistently.
        let expected_path = key_to_path(&key, depth);
        if expected_path != proof.path_bits {
            return false;
        }

        // Recompute the root starting from the null leaf.
        let null = zero_hash();
        let mut current = null;

        for i in 0..depth {
            let bit_idx = depth - 1 - i;
            let bit = proof.path_bits[bit_idx];
            let sibling = proof.siblings[i];

            let (left, right) = if !bit {
                (current, sibling)
            } else {
                (sibling, current)
            };
            current = poseidon_hash(&[left, right]);
        }

        current == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEPTH: usize = 16;

    fn key(n: u64) -> [u64; 4] {
        [n, 0, 0, 0]
    }

    fn value(n: u64) -> [u64; 4] {
        [n, n, n, n]
    }

    #[test]
    fn empty_smt_non_inclusion() {
        let smt = SparseMerkleTree::new(DEPTH);
        let root = smt.root();
        let proof = smt.non_inclusion_proof(key(42));
        assert!(
            SparseMerkleTree::verify_non_inclusion(root, &proof, key(42)),
            "non-inclusion proof must hold on empty SMT"
        );
    }

    #[test]
    fn non_inclusion_fails_after_insert() {
        let mut smt = SparseMerkleTree::new(DEPTH);
        smt.insert(key(42), value(1));
        let root = smt.root();
        let proof = smt.non_inclusion_proof(key(42));
        // The leaf is no longer null, so non-inclusion must NOT verify.
        assert!(
            !SparseMerkleTree::verify_non_inclusion(root, &proof, key(42)),
            "non-inclusion must fail once the key has been inserted"
        );
    }

    #[test]
    fn different_key_still_not_included() {
        let mut smt = SparseMerkleTree::new(DEPTH);
        smt.insert(key(1), value(1));
        let root = smt.root();
        // key(2) was never inserted.
        let proof = smt.non_inclusion_proof(key(2));
        assert!(
            SparseMerkleTree::verify_non_inclusion(root, &proof, key(2)),
            "non-inclusion proof must hold for a key that was never inserted"
        );
    }

    #[test]
    fn root_changes_after_insert() {
        let mut smt = SparseMerkleTree::new(DEPTH);
        let root_before = smt.root();
        smt.insert(key(7), value(99));
        let root_after = smt.root();
        assert_ne!(root_before, root_after);
    }

    #[test]
    fn multiple_inserts_consistent() {
        let mut smt = SparseMerkleTree::new(DEPTH);
        smt.insert(key(10), value(10));
        smt.insert(key(20), value(20));
        let root = smt.root();

        // key(10) is inserted → non-inclusion fails.
        let p10 = smt.non_inclusion_proof(key(10));
        assert!(!SparseMerkleTree::verify_non_inclusion(root, &p10, key(10)));

        // key(30) is absent → non-inclusion holds.
        let p30 = smt.non_inclusion_proof(key(30));
        assert!(SparseMerkleTree::verify_non_inclusion(root, &p30, key(30)));
    }
}
