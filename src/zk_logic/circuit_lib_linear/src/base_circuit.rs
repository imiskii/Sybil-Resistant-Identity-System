use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::MAX_PATH_LEN;

/// Targets for the variable public inputs of the base circuit.
pub struct BaseCircuitTargets {
    pub epoch: HashOutTarget,
    pub connection_mt_root: HashOutTarget,
    pub reputation_mt_root: HashOutTarget,
    pub revocation_smt_root: HashOutTarget,
    pub dest: HashOutTarget,
}

/// Base proof circuit.
pub struct BaseCircuit<F: RichField + Extendable<D>, const D: usize> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> BaseCircuit<F, D> {
    /// Build the base circuit and return compiled circuit data plus target handles.
    ///
    /// Public-input layout (field-element indices):
    ///     [0..4]                epoch
    ///     [4..8]                connection_mt_root
    ///     [8..12]               reputation_mt_root
    ///     [12..16]              revocation_smt_root
    ///     [16]                  path_length  (constant 0)
    ///     [17]                  path_reputation (constant 0)
    ///     [18 .. 18+N*4)        nullifiers   (all zero, N = MAX_PATH_LEN)
    ///     [18+N*4 .. 22+N*4)   dest         (prover-supplied)
    ///
    /// This layout must stay in sync with `RecursiveWalkCircuit`'s public-input extraction in constraint (global-state consistency).
    pub fn build<C>(config: &CircuitConfig) -> (CircuitData<F, C, D>, BaseCircuitTargets)
    where
        C: GenericConfig<D, F = F>,
        C::Hasher: AlgebraicHasher<F>,
    {
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        // Variable public inputs: global-state roots supplied by the prover.
        let epoch = builder.add_virtual_hash();
        builder.register_public_inputs(&epoch.elements);

        let connection_mt_root = builder.add_virtual_hash();
        builder.register_public_inputs(&connection_mt_root.elements);

        let reputation_mt_root = builder.add_virtual_hash();
        builder.register_public_inputs(&reputation_mt_root.elements);

        let revocation_smt_root = builder.add_virtual_hash();
        builder.register_public_inputs(&revocation_smt_root.elements);

        // Constant public inputs: walk scalars are zero at base.
        let zero = builder.zero();

        builder.register_public_input(zero); // path_length = 0
        builder.register_public_input(zero); // path_reputation = 0

        for _ in 0..MAX_PATH_LEN * 4 {
            builder.register_public_input(zero); // nullifiers[i][j] = 0
        }

        // dest is prover-supplied: the first user sets it to Poseidon(id_x, id_a, s_xa_cc, epoch) so the first recursive step can satisfy the anti-replay destination lock.
        let dest = builder.add_virtual_hash();
        builder.register_public_inputs(&dest.elements);

        let circuit_data = builder.build::<C>();
        let targets = BaseCircuitTargets {
            epoch,
            connection_mt_root,
            reputation_mt_root,
            revocation_smt_root,
            dest,
        };

        (circuit_data, targets)
    }

    /// Generate a base proof.
    pub fn generate_proof<C>(
        data: &CircuitData<F, C, D>,
        targets: &BaseCircuitTargets,
        epoch: HashOut<F>,
        connection_mt_root: HashOut<F>,
        reputation_mt_root: HashOut<F>,
        revocation_smt_root: HashOut<F>,
        dest: HashOut<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>>
    where
        C: GenericConfig<D, F = F>,
        C::Hasher: AlgebraicHasher<F>,
    {
        let mut pw = PartialWitness::new();
        pw.set_hash_target(targets.epoch, epoch)?;
        pw.set_hash_target(targets.connection_mt_root, connection_mt_root)?;
        pw.set_hash_target(targets.reputation_mt_root, reputation_mt_root)?;
        pw.set_hash_target(targets.revocation_smt_root, revocation_smt_root)?;
        pw.set_hash_target(targets.dest, dest)?;

        data.prove(pw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_base_circuit_proves_and_verifies() {
        let config = CircuitConfig::standard_recursion_config();
        let (circuit_data, targets) = BaseCircuit::<F, D>::build::<C>(&config);

        let epoch = HashOut::from_vec(vec![
            F::from_canonical_u64(1),
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ]);
        let connection_mt_root = HashOut::from_vec(vec![
            F::from_canonical_u64(2),
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ]);
        let reputation_mt_root = HashOut::from_vec(vec![
            F::from_canonical_u64(3),
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ]);
        let revocation_smt_root = HashOut::from_vec(vec![
            F::from_canonical_u64(4),
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ]);

        // dest = zero for this test (base with no intended next step)
        let dest = HashOut::ZERO;

        let proof = BaseCircuit::<F, D>::generate_proof::<C>(
            &circuit_data,
            &targets,
            epoch,
            connection_mt_root,
            reputation_mt_root,
            revocation_smt_root,
            dest,
        )
        .expect("proving failed");

        circuit_data.verify(proof.clone()).expect("verification failed");

        println!("Public inputs ({} field elements):", proof.public_inputs.len());
        for (i, pi) in proof.public_inputs.iter().enumerate() {
            println!("  [{}] = {}", i, pi);
        }

        let pi = &proof.public_inputs;

        // epoch — matches what we supplied
        assert_eq!(pi[0], F::from_canonical_u64(1), "epoch[0]");
        assert_eq!(pi[1], F::ZERO, "epoch[1]");
        assert_eq!(pi[2], F::ZERO, "epoch[2]");
        assert_eq!(pi[3], F::ZERO, "epoch[3]");

        // path_length = 0 at index 16
        assert_eq!(pi[16], F::ZERO, "path_length must be 0");
        // path_reputation = 0 at index 17
        assert_eq!(pi[17], F::ZERO, "path_reputation must be 0");

        // nullifiers: indices [18 .. 18 + MAX_PATH_LEN*4)
        for i in 0..MAX_PATH_LEN * 4 {
            assert_eq!(pi[18 + i], F::ZERO, "nullifier element {} must be 0", i);
        }

        // dest: indices [18 + MAX_PATH_LEN*4 .. 22 + MAX_PATH_LEN*4) — we supplied zero
        let dest_start = 18 + MAX_PATH_LEN * 4;
        for i in 0..4 {
            assert_eq!(pi[dest_start + i], F::ZERO, "dest element {} must be 0", i);
        }
    }
}
