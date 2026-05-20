use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;

use crate::{inner_pi, MAX_PATH_LEN};

pub struct AggregatorCircuitTargets<const D: usize, const N: usize> {
    // Public input targets (registered with builder.register_public_input)
    pub id_aggregator:         HashOutTarget,
    pub epoch:                 HashOutTarget,
    pub connection_mt_root:    HashOutTarget,
    pub reputation_mt_root:    HashOutTarget,
    pub revocation_smt_root:   HashOutTarget,
    pub path_length_req:       Target,
    pub total_path_reputation: Target,

    // Private input targets
    pub inner_proofs:    [ProofWithPublicInputsTarget<D>; N],
    pub s_aggregator_cc: HashOutTarget,
}

pub struct AggregatorCircuit;

impl AggregatorCircuit {
    /// Build the aggregator circuit.
    pub fn build<F, C, const D: usize, const N: usize>(
        config: &CircuitConfig,
        inner_circuit_data: &CircuitData<F, C, D>,
        path_length_req: u64,
    ) -> (CircuitData<F, C, D>, AggregatorCircuitTargets<D, N>)
    where
        F: RichField + Extendable<D>,
        C: GenericConfig<D, F = F>,
        C::Hasher: AlgebraicHasher<F>,
    {
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        // --- Private inputs: inner proofs ---
        let inner_vd = builder.constant_verifier_data(&inner_circuit_data.verifier_only);
        let inner_proofs: [_; N] = core::array::from_fn(|_| {
            builder.add_virtual_proof_with_pis(&inner_circuit_data.common)
        });

        // Private input: aggregator salt used in Dest computation (Constraint 3).
        let s_aggregator_cc = builder.add_virtual_hash();

        // --- Verify all inner proofs ---
        for proof in &inner_proofs {
            builder.verify_proof::<C>(proof, &inner_vd, &inner_circuit_data.common);
        }

        // --- Public inputs (stable order - verifier decodes by index position) ---
        let id_aggregator = builder.add_virtual_hash();
        builder.register_public_inputs(&id_aggregator.elements);
        let epoch = builder.add_virtual_hash();
        builder.register_public_inputs(&epoch.elements);
        let connection_mt_root = builder.add_virtual_hash();
        builder.register_public_inputs(&connection_mt_root.elements);
        let reputation_mt_root = builder.add_virtual_hash();
        builder.register_public_inputs(&reputation_mt_root.elements);
        let revocation_smt_root = builder.add_virtual_hash();
        builder.register_public_inputs(&revocation_smt_root.elements);
        let path_length_req_t = builder.add_virtual_target();
        builder.register_public_input(path_length_req_t);
        let total_rep_t = builder.add_virtual_target();
        builder.register_public_input(total_rep_t);

        // --- Extract public inputs from each inner proof by index ---
        let epochs: [HashOutTarget; N] = core::array::from_fn(|i| HashOutTarget {
            elements: core::array::from_fn(|j| {
                inner_proofs[i].public_inputs[inner_pi::EPOCH.start + j]
            }),
        });
        let conn_roots: [HashOutTarget; N] = core::array::from_fn(|i| HashOutTarget {
            elements: core::array::from_fn(|j| {
                inner_proofs[i].public_inputs[inner_pi::CONNECTION_MT_ROOT.start + j]
            }),
        });
        let rep_roots: [HashOutTarget; N] = core::array::from_fn(|i| HashOutTarget {
            elements: core::array::from_fn(|j| {
                inner_proofs[i].public_inputs[inner_pi::REPUTATION_MT_ROOT.start + j]
            }),
        });
        let revoc_roots: [HashOutTarget; N] = core::array::from_fn(|i| HashOutTarget {
            elements: core::array::from_fn(|j| {
                inner_proofs[i].public_inputs[inner_pi::REVOCATION_SMT_ROOT.start + j]
            }),
        });
        let path_lengths: [Target; N] =
            core::array::from_fn(|i| inner_proofs[i].public_inputs[inner_pi::PATH_LENGTH]);
        let path_reps: [Target; N] =
            core::array::from_fn(|i| inner_proofs[i].public_inputs[inner_pi::PATH_REPUTATION]);
        let nullifiers: [[HashOutTarget; MAX_PATH_LEN]; N] =
            core::array::from_fn(|i| {
                core::array::from_fn(|k| HashOutTarget {
                    elements: core::array::from_fn(|j| {
                        inner_proofs[i].public_inputs[inner_pi::NULLIFIERS_START + k * 4 + j]
                    }),
                })
            });
        let dests: [HashOutTarget; N] = core::array::from_fn(|i| HashOutTarget {
            elements: core::array::from_fn(|j| {
                inner_proofs[i].public_inputs[inner_pi::DEST_START + j]
            }),
        });

        // --- Global consistency ---
        // Bind the aggregator's public epoch/roots to proof[0]'s values, then
        // assert every other proof agrees with proof[0] on all four fields.
        for j in 0..4 {
            builder.connect(epoch.elements[j], epochs[0].elements[j]);
            builder.connect(connection_mt_root.elements[j], conn_roots[0].elements[j]);
            builder.connect(reputation_mt_root.elements[j], rep_roots[0].elements[j]);
            builder.connect(revocation_smt_root.elements[j], revoc_roots[0].elements[j]);
        }
        for i in 1..N {
            for j in 0..4 {
                builder.connect(epochs[i].elements[j], epochs[0].elements[j]);
                builder.connect(conn_roots[i].elements[j], conn_roots[0].elements[j]);
                builder.connect(rep_roots[i].elements[j], rep_roots[0].elements[j]);
                builder.connect(revoc_roots[i].elements[j], revoc_roots[0].elements[j]);
            }
        }

        // --- Path length ---
        let path_length_req_const =
            builder.constant(F::from_canonical_u64(path_length_req));
        builder.connect(path_length_req_t, path_length_req_const);
        for i in 0..N {
            builder.connect(path_lengths[i], path_length_req_t);
        }

        // --- Destination binding ---
        let dest_inputs: Vec<_> = id_aggregator
            .elements
            .iter()
            .chain(id_aggregator.elements.iter())
            .chain(s_aggregator_cc.elements.iter())
            .chain(epoch.elements.iter())
            .copied()
            .collect();
        let expected_dest = builder.hash_n_to_hash_no_pad::<PoseidonHash>(dest_inputs);
        for i in 0..N {
            builder.connect_hashes(dests[i], expected_dest);
        }

        // --- Nullifier pairwise distinctness ---
        let active_slots = (path_length_req as usize).saturating_sub(1);
        let mut active: Vec<HashOutTarget> =
            Vec::with_capacity(N * active_slots);
        for i in 0..N {
            for j in 0..active_slots {
                active.push(nullifiers[i][j]);
            }
        }

        // Pairwise check: assert no two active nullifiers are equal.
        let n = active.len();
        for a_idx in 0..n {
            for b_idx in (a_idx + 1)..n {
                let a = active[a_idx];
                let b = active[b_idx];
                let eq0 = builder.is_equal(a.elements[0], b.elements[0]);
                let eq1 = builder.is_equal(a.elements[1], b.elements[1]);
                let eq2 = builder.is_equal(a.elements[2], b.elements[2]);
                let eq3 = builder.is_equal(a.elements[3], b.elements[3]);
                let eq01 = builder.and(eq0, eq1);
                let eq23 = builder.and(eq2, eq3);
                let all_eq = builder.and(eq01, eq23);
                builder.assert_zero(all_eq.target);
            }
        }

        // --- Total reputation sum ---
        let mut rep_sum = path_reps[0];
        for i in 1..N {
            rep_sum = builder.add(rep_sum, path_reps[i]);
        }
        builder.connect(total_rep_t, rep_sum);

        let circuit_data = builder.build::<C>();
        (
            circuit_data,
            AggregatorCircuitTargets {
                id_aggregator,
                epoch,
                connection_mt_root,
                reputation_mt_root,
                revocation_smt_root,
                path_length_req: path_length_req_t,
                total_path_reputation: total_rep_t,
                inner_proofs,
                s_aggregator_cc,
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_utils::poseidon_hash::poseidon_hash;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::field::types::PrimeField64;
    use plonky2::hash::hash_types::HashOut;
    use plonky2::iop::target::Target;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::plonk::proof::ProofWithPublicInputs;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    fn h(v: u64) -> HashOut<F> {
        HashOut { elements: [F::from_canonical_u64(v), F::ZERO, F::ZERO, F::ZERO] }
    }

    fn ha(v: u64) -> [u64; 4] { [v, 0, 0, 0] }

    /// Build nullifiers where slot k = h(seed + k + 1) for k < path_len, else zero.
    fn make_nullifiers(seed: u64, path_len: u64) -> [HashOut<F>; MAX_PATH_LEN] {
        core::array::from_fn(|k| {
            if (k as u64) < path_len { h(seed + k as u64 + 1) } else { HashOut::ZERO }
        })
    }

    /// Dummy inner circuit
    struct DummyInnerTargets {
        epoch:                HashOutTarget,
        connection_mt_root:   HashOutTarget,
        reputation_mt_root:   HashOutTarget,
        revocation_smt_root:  HashOutTarget,
        path_length:          Target,
        path_reputation:      Target,
        nullifiers:           [HashOutTarget; MAX_PATH_LEN],
        dest:                 HashOutTarget,
    }

    fn build_dummy_inner() -> (CircuitData<F, C, D>, DummyInnerTargets) {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let epoch = builder.add_virtual_hash();
        builder.register_public_inputs(&epoch.elements);
        let connection_mt_root = builder.add_virtual_hash();
        builder.register_public_inputs(&connection_mt_root.elements);
        let reputation_mt_root = builder.add_virtual_hash();
        builder.register_public_inputs(&reputation_mt_root.elements);
        let revocation_smt_root = builder.add_virtual_hash();
        builder.register_public_inputs(&revocation_smt_root.elements);
        let path_length = builder.add_virtual_target();
        builder.register_public_input(path_length);
        let path_reputation = builder.add_virtual_target();
        builder.register_public_input(path_reputation);
        let nullifiers: [HashOutTarget; MAX_PATH_LEN] = core::array::from_fn(|_| {
            let nh = builder.add_virtual_hash();
            builder.register_public_inputs(&nh.elements);
            nh
        });
        let dest = builder.add_virtual_hash();
        builder.register_public_inputs(&dest.elements);

        let data = builder.build::<C>();
        (data, DummyInnerTargets {
            epoch, connection_mt_root, reputation_mt_root, revocation_smt_root,
            path_length, path_reputation, nullifiers, dest,
        })
    }

    /// Prove the dummy inner circuit with the given public inputs.
    fn make_inner_proof(
        data: &CircuitData<F, C, D>,
        tgts: &DummyInnerTargets,
        epoch: HashOut<F>,
        path_len: u64,
        nullifiers: [HashOut<F>; MAX_PATH_LEN],
        dest: HashOut<F>,
    ) -> anyhow::Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::new();
        pw.set_hash_target(tgts.epoch, epoch)?;
        pw.set_hash_target(tgts.connection_mt_root, HashOut::ZERO)?;
        pw.set_hash_target(tgts.reputation_mt_root, HashOut::ZERO)?;
        pw.set_hash_target(tgts.revocation_smt_root, HashOut::ZERO)?;
        pw.set_target(tgts.path_length, F::from_canonical_u64(path_len))?;
        pw.set_target(tgts.path_reputation, F::from_canonical_u64(100))?;
        for (k, nh) in tgts.nullifiers.iter().enumerate() {
            pw.set_hash_target(*nh, nullifiers[k])?;
        }
        pw.set_hash_target(tgts.dest, dest)?;
        data.prove(pw)
    }

    /// Compute the correct Dest for a given (id_agg, s_cc, epoch) triple.
    fn correct_dest(id_agg: [u64; 4], s_cc: [u64; 4], epoch: [u64; 4]) -> HashOut<F> {
        let arr = poseidon_hash(&[id_agg, id_agg, s_cc, epoch]);
        HashOut { elements: arr.map(F::from_canonical_u64) }
    }

    /// Assemble a partial witness for the aggregator given three inner proofs.
    fn agg_witness(
        tgts: &AggregatorCircuitTargets<D, 3>,
        proofs: [&ProofWithPublicInputs<F, C, D>; 3],
        id_agg: HashOut<F>,
        s_cc: HashOut<F>,
        path_length_req: u64,
    ) -> anyhow::Result<PartialWitness<F>> {
        let mut pw = PartialWitness::new();
        for (i, p) in proofs.iter().enumerate() {
            pw.set_proof_with_pis_target(&tgts.inner_proofs[i], p)?;
        }
        pw.set_hash_target(tgts.id_aggregator, id_agg)?;
        pw.set_hash_target(tgts.s_aggregator_cc, s_cc)?;
        pw.set_target(tgts.path_length_req, F::from_canonical_u64(path_length_req))?;
        Ok(pw)
    }

    /// Test 1: all constraints satisfied - proves successfully and total_path_reputation == 300.
    #[test]
    fn test_happy_path() -> anyhow::Result<()> {
        let (inner_data, inner_tgts) = build_dummy_inner();

        let id_agg   = ha(42);
        let s_cc     = ha(99);
        let epoch_v  = ha(1);
        let good_dest = correct_dest(id_agg, s_cc, epoch_v);

        let agg_nullifier = h(9999);
        let z = HashOut::ZERO;
        let nulls0: [HashOut<F>; MAX_PATH_LEN] = [h(1),   h(2),   agg_nullifier, z, z, z];
        let nulls1: [HashOut<F>; MAX_PATH_LEN] = [h(101), h(102), agg_nullifier, z, z, z];
        let nulls2: [HashOut<F>; MAX_PATH_LEN] = [h(201), h(202), agg_nullifier, z, z, z];

        let proof0 = make_inner_proof(&inner_data, &inner_tgts, h(1), 3, nulls0, good_dest)?;
        let proof1 = make_inner_proof(&inner_data, &inner_tgts, h(1), 3, nulls1, good_dest)?;
        let proof2 = make_inner_proof(&inner_data, &inner_tgts, h(1), 3, nulls2, good_dest)?;

        let config = CircuitConfig::standard_recursion_config();
        let (agg_data, agg_tgts) =
            AggregatorCircuit::build::<F, C, D, 3>(&config, &inner_data, 3);

        let pw = agg_witness(&agg_tgts, [&proof0, &proof1, &proof2], h(42), h(99), 3)?;
        let proof = agg_data.prove(pw)?;

        // PI[21] = total_path_reputation; each inner proof contributes 100, so sum = 300.
        let total_rep = proof.public_inputs[21].to_canonical_u64();
        assert_eq!(total_rep, 300, "expected total_path_reputation == 300");

        agg_data.verify(proof)?;
        Ok(())
    }

    /// Test 2: two proofs with epoch=1 and one with epoch=2 must cause prove() to fail.
    #[test]
    fn test_consistency_epoch_mismatch_fails() -> anyhow::Result<()> {
        let (inner_data, inner_tgts) = build_dummy_inner();

        let id_agg = ha(42);
        let s_cc   = ha(99);

        let dest1 = correct_dest(id_agg, s_cc, ha(1));
        let dest2 = correct_dest(id_agg, s_cc, ha(2));

        let proof0 = make_inner_proof(&inner_data, &inner_tgts, h(1), 3, make_nullifiers(0,   3), dest1)?;
        let proof1 = make_inner_proof(&inner_data, &inner_tgts, h(1), 3, make_nullifiers(100, 3), dest1)?;
        let proof2 = make_inner_proof(&inner_data, &inner_tgts, h(2), 3, make_nullifiers(200, 3), dest2)?;

        let config = CircuitConfig::standard_recursion_config();
        let (agg_data, agg_tgts) =
            AggregatorCircuit::build::<F, C, D, 3>(&config, &inner_data, 3);

        let pw = agg_witness(&agg_tgts, [&proof0, &proof1, &proof2], h(42), h(99), 3)?;
        let result = agg_data.prove(pw);
        assert!(result.is_err(), "expected prove to fail due to epoch mismatch");
        Ok(())
    }

    /// Test 3: two proofs sharing the same nullifier at slot 0 must cause prove() to fail.
    #[test]
    fn test_nullifier_duplicate_fails() -> anyhow::Result<()> {
        let (inner_data, inner_tgts) = build_dummy_inner();

        let id_agg  = ha(42);
        let s_cc    = ha(99);
        let epoch_v = ha(1);
        let good_dest = correct_dest(id_agg, s_cc, epoch_v);

        // proof0 and proof1 share nullifier h(1) at slot 0 - triggers Constraint 4.
        let z = HashOut::ZERO;
        let nulls0: [HashOut<F>; MAX_PATH_LEN] = [h(1),   h(2),   h(3),   z, z, z];
        let nulls1: [HashOut<F>; MAX_PATH_LEN] = [h(1),   h(102), h(103), z, z, z];
        let nulls2: [HashOut<F>; MAX_PATH_LEN] = [h(201), h(202), h(203), z, z, z];

        let proof0 = make_inner_proof(&inner_data, &inner_tgts, h(1), 3, nulls0, good_dest)?;
        let proof1 = make_inner_proof(&inner_data, &inner_tgts, h(1), 3, nulls1, good_dest)?;
        let proof2 = make_inner_proof(&inner_data, &inner_tgts, h(1), 3, nulls2, good_dest)?;

        let config = CircuitConfig::standard_recursion_config();
        let (agg_data, agg_tgts) =
            AggregatorCircuit::build::<F, C, D, 3>(&config, &inner_data, 3);

        let pw = agg_witness(&agg_tgts, [&proof0, &proof1, &proof2], h(42), h(99), 3)?;
        let result = agg_data.prove(pw);
        assert!(result.is_err(), "expected prove to fail due to duplicate nullifier");
        Ok(())
    }

    /// Test 4: one inner proof with wrong dest must cause prove() to fail.
    #[test]
    fn test_dest_wrong_binding_fails() -> anyhow::Result<()> {
        let (inner_data, inner_tgts) = build_dummy_inner();

        let id_agg  = ha(42);
        let s_cc    = ha(99);
        let epoch_v = ha(1);
        let good_dest = correct_dest(id_agg, s_cc, epoch_v);

        let proof0 = make_inner_proof(&inner_data, &inner_tgts, h(1), 3, make_nullifiers(0,   3), good_dest)?;
        let proof1 = make_inner_proof(&inner_data, &inner_tgts, h(1), 3, make_nullifiers(100, 3), good_dest)?;
        // proof2 uses an incorrect dest (zero hash).
        let proof2 = make_inner_proof(&inner_data, &inner_tgts, h(1), 3, make_nullifiers(200, 3), HashOut::ZERO)?;

        let config = CircuitConfig::standard_recursion_config();
        let (agg_data, agg_tgts) =
            AggregatorCircuit::build::<F, C, D, 3>(&config, &inner_data, 3);

        let pw = agg_witness(&agg_tgts, [&proof0, &proof1, &proof2], h(42), h(99), 3)?;
        let result = agg_data.prove(pw);
        assert!(result.is_err(), "expected prove to fail due to wrong dest binding");
        Ok(())
    }
}
