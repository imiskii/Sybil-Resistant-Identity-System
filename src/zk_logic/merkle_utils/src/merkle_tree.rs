use crate::poseidon_hash::poseidon_hash;

/// A standard Merkle tree over the Goldilocks field using Poseidon hashing.
///
/// Leaves must be provided as Poseidon HashOuts (`[u64; 4]`). The leaf layer
/// is padded to the next power of two with zero leaves (`[0u64; 4]`) before
/// building the tree. Parent nodes are computed as
/// `parent = Poseidon(left_child || right_child)` (8 field-element input).
pub struct MerkleTree {
    /// Original (unpadded) leaves, as provided by the caller.
    pub leaves: Vec<[u64; 4]>,
    /// All tree layers from the padded leaf layer (index 0) up to the root
    /// layer (last index, always length 1). Each layer is half the length of
    /// the previous one.
    layers: Vec<Vec<[u64; 4]>>,
}

/// Merkle inclusion proof for a single leaf.
pub struct MerkleInclusionProof {
    /// Index of the proven leaf in the original (unpadded) leaf list.
    pub leaf_index: usize,
    /// The leaf value that is being proven.
    pub leaf: [u64; 4],
    /// Sibling hashes ordered from the leaf layer up to (but not including)
    /// the root layer. `siblings[0]` is the sibling of the leaf itself;
    /// `siblings.last()` is the sibling of the root's child.
    pub siblings: Vec<[u64; 4]>,
}

impl MerkleTree {
    /// Build a Merkle tree from a list of already-hashed leaf values.
    ///
    /// `leaves` must be non-empty. The leaf layer is padded to the next power
    /// of two using the zero leaf `[0u64; 4]`.
    pub fn new(leaves: Vec<[u64; 4]>) -> Self {
        assert!(!leaves.is_empty(), "MerkleTree requires at least one leaf");

        // Always pad to at least 2 so the root is always a Poseidon hash, not
        // the leaf itself.
        let n = leaves.len().next_power_of_two().max(2);
        let mut padded = leaves.clone();
        padded.resize(n, [0u64; 4]);

        let mut layers: Vec<Vec<[u64; 4]>> = Vec::new();
        layers.push(padded);

        while layers.last().unwrap().len() > 1 {
            let prev = layers.last().unwrap();
            let next: Vec<[u64; 4]> = prev
                .chunks(2)
                .map(|pair| poseidon_hash(&[pair[0], pair[1]]))
                .collect();
            layers.push(next);
        }

        MerkleTree { leaves, layers }
    }

    /// Return the Merkle root (the single hash at the top of the tree).
    pub fn root(&self) -> [u64; 4] {
        self.layers.last().unwrap()[0]
    }

    /// Generate a Merkle inclusion proof for the leaf at `index` in the
    /// original (unpadded) leaf list.
    ///
    /// # Panics
    /// Panics if `index >= self.leaves.len()`.
    pub fn inclusion_proof(&self, index: usize) -> MerkleInclusionProof {
        assert!(index < self.leaves.len(), "leaf index out of range");

        let mut siblings = Vec::new();
        let mut idx = index;

        // Walk from the leaf layer up, stopping before the root layer.
        for layer in &self.layers[..self.layers.len() - 1] {
            let sibling_idx = idx ^ 1; // flip the last bit
            siblings.push(layer[sibling_idx]);
            idx >>= 1;
        }

        MerkleInclusionProof {
            leaf_index: index,
            leaf: self.leaves[index],
            siblings,
        }
    }

    /// Verify a Merkle inclusion proof off-circuit.
    ///
    /// Returns `true` iff recomputing the root from `leaf` and
    /// `proof.siblings` yields `root`.
    pub fn verify_inclusion(
        root: [u64; 4],
        proof: &MerkleInclusionProof,
        leaf: [u64; 4],
    ) -> bool {
        let mut current = leaf;
        let mut idx = proof.leaf_index;

        for sibling in &proof.siblings {
            let (left, right) = if idx % 2 == 0 {
                (current, *sibling)
            } else {
                (*sibling, current)
            };
            current = poseidon_hash(&[left, right]);
            idx >>= 1;
        }

        current == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_leaf(n: u64) -> [u64; 4] {
        [n, 0, 0, 0]
    }

    #[test]
    fn single_leaf_root_equals_hash() {
        let leaf = make_leaf(42);
        let tree = MerkleTree::new(vec![leaf]);
        // With one leaf padded to two, root = poseidon(leaf, zero)
        let expected = poseidon_hash(&[leaf, [0u64; 4]]);
        assert_eq!(tree.root(), expected);
    }

    #[test]
    fn inclusion_proof_roundtrip_power_of_two() {
        let leaves: Vec<_> = (1u64..=4).map(make_leaf).collect();
        let tree = MerkleTree::new(leaves.clone());
        let root = tree.root();

        for i in 0..leaves.len() {
            let proof = tree.inclusion_proof(i);
            assert!(MerkleTree::verify_inclusion(root, &proof, leaves[i]));
        }
    }

    #[test]
    fn inclusion_proof_roundtrip_non_power_of_two() {
        let leaves: Vec<_> = (1u64..=5).map(make_leaf).collect();
        let tree = MerkleTree::new(leaves.clone());
        let root = tree.root();

        for i in 0..leaves.len() {
            let proof = tree.inclusion_proof(i);
            assert!(MerkleTree::verify_inclusion(root, &proof, leaves[i]));
        }
    }

    #[test]
    fn wrong_leaf_fails_verification() {
        let leaves: Vec<_> = (1u64..=4).map(make_leaf).collect();
        let tree = MerkleTree::new(leaves.clone());
        let root = tree.root();
        let proof = tree.inclusion_proof(0);
        // Pass a different leaf value — must fail.
        assert!(!MerkleTree::verify_inclusion(root, &proof, make_leaf(99)));
    }
}
