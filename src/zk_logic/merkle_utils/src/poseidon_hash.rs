use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::hashing::hash_n_to_hash_no_pad;
use plonky2::hash::poseidon::PoseidonPermutation;

/// Off-circuit Poseidon hash over the Goldilocks field (width 12, rate 8).
///
/// Flattens each `[u64; 4]` HashOut into a contiguous slice of `GoldilocksField`
/// elements, runs the Poseidon permutation (no padding), and returns the first
/// four output elements as a `[u64; 4]` HashOut.
///
/// This uses the same constants as Plonky2's in-circuit `hash_n_to_hash_no_pad`,
/// so off-circuit and in-circuit hashes are identical.
pub fn poseidon_hash(inputs: &[[u64; 4]]) -> [u64; 4] {
    let flat: Vec<GoldilocksField> = inputs
        .iter()
        .flat_map(|chunk| {
            chunk
                .iter()
                .map(|&x| GoldilocksField::from_canonical_u64(x))
        })
        .collect();

    let out: HashOut<GoldilocksField> =
        hash_n_to_hash_no_pad::<GoldilocksField, PoseidonPermutation<GoldilocksField>>(&flat);

    [
        out.elements[0].to_canonical_u64(),
        out.elements[1].to_canonical_u64(),
        out.elements[2].to_canonical_u64(),
        out.elements[3].to_canonical_u64(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_same_input() {
        let a = poseidon_hash(&[[1, 2, 3, 4], [5, 6, 7, 8]]);
        let b = poseidon_hash(&[[1, 2, 3, 4], [5, 6, 7, 8]]);
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_differ() {
        let a = poseidon_hash(&[[0; 4], [0; 4]]);
        let b = poseidon_hash(&[[1; 4], [0; 4]]);
        assert_ne!(a, b);
    }
}
