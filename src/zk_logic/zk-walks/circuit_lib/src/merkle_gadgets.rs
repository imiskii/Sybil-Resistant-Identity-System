//! In-circuit Merkle inclusion and sparse Merkle non-inclusion verification gadgets.
//!
//! Both gadgets use `builder.hash_n_to_hash_no_pad::<PoseidonHash>` for all hashing,
//! which uses the same Poseidon constants as `merkle_utils::poseidon_hash`. Off-circuit
//! and in-circuit hashes are therefore identical.
//!
//! Bit-ordering convention (shared with `merkle_utils`):
//! - Merkle inclusion: `index_bits[i]` is the bit at level i starting from the leaf
//!   (bit 0 = LSB of the leaf index). 0 → current node is left child; 1 → right child.
//! - Sparse Merkle non-inclusion: `key_bits` are in LE order (bit 0 = root-level branch
//!   bit = LSB of Poseidon(key)), matching `builder.split_le` and `key_to_path` in
//!   `merkle_utils`. `siblings[0]` is the leaf-level sibling; `siblings[depth-1]` is
//!   the sibling of the root's child.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::BoolTarget;
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// Verify a Merkle inclusion proof in-circuit.
///
/// Recomputes the Merkle root by walking from `leaf` up to the root using
/// `siblings` and `index_bits`, then checks whether the result equals
/// `expected_root`.
///
/// # Parameters
/// - `leaf`: the leaf `HashOutTarget` being proven.
/// - `siblings`: sibling hashes ordered from the leaf level up (not including
///   the root); `siblings[0]` is the leaf's sibling.
/// - `index_bits`: the leaf index bits in LE order (`index_bits[0]` = LSB).
///   0 means the current node is the left child; 1 means it is the right child.
/// - `expected_root`: the root `HashOutTarget` to compare against.
///
/// # Returns
/// A `BoolTarget` that is `true` if the recomputed root equals `expected_root`.
/// Use `builder.assert_one(result.target)` at the call site to enforce the constraint.
///
/// # Panics
/// Panics if `siblings.len() != index_bits.len()`.
pub fn verify_merkle_inclusion<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: HashOutTarget,
    siblings: &[HashOutTarget],
    index_bits: &[BoolTarget],
    expected_root: HashOutTarget,
) -> BoolTarget {
    assert_eq!(
        siblings.len(),
        index_bits.len(),
        "siblings and index_bits must have the same length (tree height)"
    );

    let mut current = leaf;
    for (sibling, &bit) in siblings.iter().zip(index_bits.iter()) {
        // bit=0 → current is left child, sibling is right.
        // bit=1 → current is right child, sibling is left.
        let left = select_hash(builder, bit, *sibling, current);
        let right = select_hash(builder, bit, current, *sibling);
        let inputs: Vec<_> = left
            .elements
            .iter()
            .chain(right.elements.iter())
            .copied()
            .collect();
        current = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    }

    hash_out_eq(builder, current, expected_root)
}

/// Verify a sparse Merkle non-inclusion proof in-circuit.
///
/// Proves that the leaf at the path described by `key_bits` is the null hash
/// (`Poseidon([0; 8])`), and that the root recomputed from `siblings` equals
/// `expected_root`.
///
/// The traversal mirrors `SparseMerkleTree::verify_non_inclusion` exactly:
/// starting from the null leaf, at step `i` the path bit is `key_bits[depth-1-i]`,
/// so the deepest (leaf-level) bit is used first.
///
/// # Parameters
/// - `key_bits`: `depth` path bits in LE order (bit 0 = root-level branch bit),
///   matching the output of `builder.split_le` applied to `Poseidon(key)`.
/// - `siblings`: sibling hashes; `siblings[0]` is the leaf-level sibling,
///   `siblings[depth-1]` is the sibling of the root's child.
/// - `expected_root`: the root `HashOutTarget` to compare against.
///
/// # Returns
/// A `BoolTarget` that is `true` iff the proof is valid (null leaf + root match).
/// Use `builder.assert_one(result.target)` at the call site to enforce the constraint.
///
/// # Panics
/// Panics if `key_bits.len() != siblings.len()`.
pub fn verify_sparse_merkle_non_inclusion<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    key_bits: &[BoolTarget],
    siblings: &[HashOutTarget],
    expected_root: HashOutTarget,
) -> BoolTarget {
    assert_eq!(
        key_bits.len(),
        siblings.len(),
        "key_bits and siblings must have the same length (tree depth)"
    );

    let depth = key_bits.len();

    // Null leaf: Poseidon([0; 8]) — the empty-leaf hash of the sparse Merkle tree.
    let zero_targets: Vec<_> = (0..8).map(|_| builder.zero()).collect();
    let null_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(zero_targets);

    // Walk from the leaf level up to the root.
    // At step i=0 (leaf level), the relevant path bit is key_bits[depth-1].
    // At step i=depth-1 (root level), the relevant path bit is key_bits[0].
    let mut current = null_hash;
    for i in 0..depth {
        let bit = key_bits[depth - 1 - i];
        let sibling = siblings[i];

        // bit=0 → current is left child; bit=1 → current is right child.
        let left = select_hash(builder, bit, sibling, current);
        let right = select_hash(builder, bit, current, sibling);
        let inputs: Vec<_> = left
            .elements
            .iter()
            .chain(right.elements.iter())
            .copied()
            .collect();
        current = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    }

    hash_out_eq(builder, current, expected_root)
}

/// Select between two `HashOutTarget`s based on a `BoolTarget`.
///
/// Returns `x` when `cond = 1`, `y` when `cond = 0`.
pub fn select_hash<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    cond: BoolTarget,
    x: HashOutTarget,
    y: HashOutTarget,
) -> HashOutTarget {
    HashOutTarget {
        elements: core::array::from_fn(|i| builder.select(cond, x.elements[i], y.elements[i])),
    }
}

/// Return a `BoolTarget` that is 1 if all four elements of `a` equal those of `b`.
pub fn hash_out_eq<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: HashOutTarget,
    b: HashOutTarget,
) -> BoolTarget {
    let eq: Vec<BoolTarget> = a
        .elements
        .iter()
        .zip(b.elements.iter())
        .map(|(&x, &y)| builder.is_equal(x, y))
        .collect();
    let eq01 = builder.and(eq[0], eq[1]);
    let eq23 = builder.and(eq[2], eq[3]);
    builder.and(eq01, eq23)
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_utils::merkle_tree::MerkleTree;
    use merkle_utils::sparse_merkle_tree::SparseMerkleTree;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::hash::hash_types::HashOut;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    fn to_hash(h: [u64; 4]) -> HashOut<F> {
        HashOut {
            elements: h.map(F::from_canonical_u64),
        }
    }

    /// Build a tiny circuit that calls `verify_merkle_inclusion` on a 4-leaf tree,
    /// generate a valid proof, and assert it verifies.
    #[test]
    fn test_merkle_inclusion_proof() -> anyhow::Result<()> {
        let leaves: Vec<[u64; 4]> = (1u64..=4).map(|i| [i, 0, 0, 0]).collect();
        let tree = MerkleTree::new(leaves);
        let root = tree.root();
        let mip = tree.inclusion_proof(0);
        let depth = mip.siblings.len();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let leaf_t = builder.add_virtual_hash();
        let root_t = builder.add_virtual_hash();
        let siblings_t: Vec<_> = (0..depth).map(|_| builder.add_virtual_hash()).collect();
        let bits_t: Vec<_> = (0..depth)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect();

        let ok = verify_merkle_inclusion(&mut builder, leaf_t, &siblings_t, &bits_t, root_t);
        builder.assert_one(ok.target);

        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_hash_target(leaf_t, to_hash(mip.leaf))?;
        pw.set_hash_target(root_t, to_hash(root))?;
        for (i, sib) in mip.siblings.iter().enumerate() {
            pw.set_hash_target(siblings_t[i], to_hash(*sib))?;
        }
        let mut idx = mip.leaf_index;
        for i in 0..depth {
            pw.set_bool_target(bits_t[i], idx % 2 == 1)?;
            idx >>= 1;
        }

        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    /// Test inclusion proof for a non-zero leaf index to exercise the right-child path.
    #[test]
    fn test_merkle_inclusion_right_child() -> anyhow::Result<()> {
        let leaves: Vec<[u64; 4]> = (10u64..=13).map(|i| [i, 0, 0, 0]).collect();
        let tree = MerkleTree::new(leaves.clone());
        let root = tree.root();

        for leaf_idx in 0..leaves.len() {
            let mip = tree.inclusion_proof(leaf_idx);
            let depth = mip.siblings.len();

            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let leaf_t = builder.add_virtual_hash();
            let root_t = builder.add_virtual_hash();
            let siblings_t: Vec<_> = (0..depth).map(|_| builder.add_virtual_hash()).collect();
            let bits_t: Vec<_> = (0..depth)
                .map(|_| builder.add_virtual_bool_target_safe())
                .collect();

            let ok = verify_merkle_inclusion(&mut builder, leaf_t, &siblings_t, &bits_t, root_t);
            builder.assert_one(ok.target);

            let data = builder.build::<C>();

            let mut pw = PartialWitness::new();
            pw.set_hash_target(leaf_t, to_hash(mip.leaf))?;
            pw.set_hash_target(root_t, to_hash(root))?;
            for (i, sib) in mip.siblings.iter().enumerate() {
                pw.set_hash_target(siblings_t[i], to_hash(*sib))?;
            }
            let mut idx = mip.leaf_index;
            for i in 0..depth {
                pw.set_bool_target(bits_t[i], idx % 2 == 1)?;
                idx >>= 1;
            }

            let proof = data.prove(pw)?;
            data.verify(proof)?;
        }
        Ok(())
    }

    /// Build a tiny circuit that calls `verify_sparse_merkle_non_inclusion` on an empty
    /// SMT, generate a valid proof, and assert it verifies.
    #[test]
    fn test_sparse_merkle_non_inclusion_empty_tree() -> anyhow::Result<()> {
        let depth = 8usize;
        let smt = SparseMerkleTree::new(depth);
        let root = smt.root();
        let key = [42u64, 0, 0, 0];
        let ni = smt.non_inclusion_proof(key);

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let root_t = builder.add_virtual_hash();
        let siblings_t: Vec<_> = (0..depth).map(|_| builder.add_virtual_hash()).collect();
        let bits_t: Vec<_> = (0..depth)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect();

        let ok =
            verify_sparse_merkle_non_inclusion(&mut builder, &bits_t, &siblings_t, root_t);
        builder.assert_one(ok.target);

        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_hash_target(root_t, to_hash(root))?;
        for (i, sib) in ni.siblings.iter().enumerate() {
            pw.set_hash_target(siblings_t[i], to_hash(*sib))?;
        }
        // key_bits_t[j] ← path_bits[j] (both in LE order).
        for (j, &bit) in ni.path_bits.iter().enumerate() {
            pw.set_bool_target(bits_t[j], bit)?;
        }

        let proof = data.prove(pw)?;
        data.verify(proof)
    }

    /// Non-inclusion proof for a key that shares some path prefix with an inserted key —
    /// confirms the gadget correctly handles partially-filled SMTs.
    #[test]
    fn test_sparse_merkle_non_inclusion_after_other_insert() -> anyhow::Result<()> {
        let depth = 8usize;
        let mut smt = SparseMerkleTree::new(depth);
        // Insert key(1) but prove non-inclusion of key(99).
        smt.insert([1u64, 0, 0, 0], [7u64, 7, 7, 7]);
        let root = smt.root();
        let key = [99u64, 0, 0, 0];
        let ni = smt.non_inclusion_proof(key);

        // Sanity-check: off-circuit proof must hold.
        assert!(
            SparseMerkleTree::verify_non_inclusion(root, &ni, key),
            "off-circuit non-inclusion sanity check failed"
        );

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let root_t = builder.add_virtual_hash();
        let siblings_t: Vec<_> = (0..depth).map(|_| builder.add_virtual_hash()).collect();
        let bits_t: Vec<_> = (0..depth)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect();

        let ok =
            verify_sparse_merkle_non_inclusion(&mut builder, &bits_t, &siblings_t, root_t);
        builder.assert_one(ok.target);

        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_hash_target(root_t, to_hash(root))?;
        for (i, sib) in ni.siblings.iter().enumerate() {
            pw.set_hash_target(siblings_t[i], to_hash(*sib))?;
        }
        for (j, &bit) in ni.path_bits.iter().enumerate() {
            pw.set_bool_target(bits_t[j], bit)?;
        }

        let proof = data.prove(pw)?;
        data.verify(proof)
    }
}
