// ZK Random Walk Circuit - cyclic variant

use plonky2::field::extension::Extendable;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;

use merkle_circuit::merkle_gadgets::{
    hash_out_eq, select_hash, verify_merkle_inclusion, verify_sparse_merkle_non_inclusion,
};
use crate::{MAX_PATH_LEN, SCALE};

const RECURSION_DEGREE_BITS: usize = 12;

// Public-input index offsets (same for both this circuit's outputs and inner proof inputs).
//      [0..4]              epoch
//      [4..8]              connection_mt_root
//      [8..12]             reputation_mt_root
//      [12..16]            revocation_smt_root
//      [16]                path_length
//      [17]                path_reputation
//      [18..18+N*4)        nullifiers  (N = MAX_PATH_LEN)
//      [18+N*4..22+N*4)    dest
//      [34..102]           VK (circuit_digest + Merkle cap)
const PI_EPOCH: usize = 0;
const PI_CONN_ROOT: usize = 4;
const PI_REP_ROOT: usize = 8;
const PI_REVOC_ROOT: usize = 12;
const PI_PATH_LEN: usize = 16;
const PI_PATH_REP: usize = 17;
const PI_NULLIFIERS: usize = 18;
const PI_DEST: usize = 18 + MAX_PATH_LEN * 4; // = 30 for MAX_PATH_LEN = 3

// Bits needed for range-check of (MAX_PATH_LEN - 1 - path_length_old).
const PATH_LEN_BITS: usize = 2;

/// All circuit targets for the unified cyclic walk step.
/// Public-input targets are `*_out` hashes/scalars and the `inner_verifier_data` VK.
/// Private-input targets are set by the prover for each hop; `*_base` targets are only meaningful when `is_base_case = true.
pub struct RecursiveWalkTargets<const D: usize> {
    // --- Public-input output targets ---
    pub epoch: HashOutTarget,
    pub connection_mt_root: HashOutTarget,
    pub reputation_mt_root: HashOutTarget,
    pub revocation_smt_root: HashOutTarget,
    pub path_length: Target,
    pub path_reputation: Target,
    pub nullifiers: [HashOutTarget; MAX_PATH_LEN],
    pub dest: HashOutTarget,

    // --- Cyclic recursion targets ---
    pub inner_proof: ProofWithPublicInputsTarget<D>,
    pub inner_verifier_data: VerifierCircuitTarget,

    // --- Base-case selector and fresh inputs ---
    /// True for base proof; false for all recursive hops.
    pub is_base_case: BoolTarget,
    /// Fresh epoch for base (ignored when is_base_case = false).
    pub epoch_base: HashOutTarget,
    pub connection_mt_root_base: HashOutTarget,
    pub reputation_mt_root_base: HashOutTarget,
    pub revocation_smt_root_base: HashOutTarget,
    pub dest_base: HashOutTarget,

    // --- Private walk witnesses (prover sets; ignored by circuit for genesis) ---
    pub id_x: HashOutTarget,
    pub id_a: HashOutTarget,
    /// min(id_x, id_a) by element[0] ordering - prover provides; circuit checks the set.
    pub min_id: HashOutTarget,
    /// max(id_x, id_a) by element[0] ordering - prover provides; circuit checks the set.
    pub max_id: HashOutTarget,
    pub id_b: HashOutTarget,
    pub s_xa_cc: HashOutTarget,
    pub s_ab_cc: HashOutTarget,
    pub r_a: Target,
    pub s_a_r: HashOutTarget,
    pub alpha_scaled: Target,
    pub w_a_b: Target,
    pub connection_mip_siblings: Vec<HashOutTarget>,
    pub connection_mip_index_bits: Vec<BoolTarget>,
    pub revocation_mnip_siblings: Vec<HashOutTarget>,
    /// Derived from split_le(n_xa); included for inspection, not set by prover.
    pub revocation_mnip_key_bits: Vec<BoolTarget>,
    pub reputation_mip_siblings: Vec<HashOutTarget>,
    pub reputation_mip_index_bits: Vec<BoolTarget>,
}

/// Unified cyclic walk circuit - one circuit for base and all recursive hops.
pub struct RecursiveWalkCircuit<F: RichField + Extendable<D>, const D: usize> {
    _phantom: std::marker::PhantomData<F>,
}

/// Three-pass bootstrap that produces a CommonCircuitData whose gate budget matches the real step circuit at RECURSION_DEGREE_BITS. Required by conditionally_verify_cyclic_proof_or_dummy before the circuit is built.
fn common_data_for_recursion<F, C, const D: usize>(
    config: &CircuitConfig,
) -> CommonCircuitData<F, D>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    let builder = CircuitBuilder::<F, D>::new(config.clone());
    let data = builder.build::<C>();

    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let vd = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &vd, &data.common);
    let data = builder.build::<C>();

    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let vd = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &vd, &data.common);
    while builder.num_gates() < (1 << RECURSION_DEGREE_BITS) {
        builder.add_gate(NoopGate, vec![]);
    }
    builder.build::<C>().common
}

impl<F: RichField + Extendable<D>, const D: usize> RecursiveWalkCircuit<F, D> {
    /// Build the unified cyclic walk circuit.
    pub fn build<C>(
        config: &CircuitConfig,
        conn_depth: usize,
        smt_depth: usize,
        rep_depth: usize,
    ) -> anyhow::Result<(CircuitData<F, C, D>, RecursiveWalkTargets<D>)>
    where
        C: GenericConfig<D, F = F> + 'static,
        C::Hasher: AlgebraicHasher<F>,
    {
        let mut common_data = common_data_for_recursion::<F, C, D>(config);
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        let is_base_case = builder.add_virtual_bool_target_safe();

        // --- Register public outputs ---
        let epoch_out = builder.add_virtual_hash();
        builder.register_public_inputs(&epoch_out.elements); // [0..4]
        let conn_root_out = builder.add_virtual_hash();
        builder.register_public_inputs(&conn_root_out.elements); // [4..8]
        let rep_root_out = builder.add_virtual_hash();
        builder.register_public_inputs(&rep_root_out.elements); // [8..12]
        let revoc_root_out = builder.add_virtual_hash();
        builder.register_public_inputs(&revoc_root_out.elements); // [12..16]
        let path_length_out = builder.add_virtual_target();
        builder.register_public_input(path_length_out); // [16]
        let path_rep_out = builder.add_virtual_target();
        builder.register_public_input(path_rep_out); // [17]
        let nullifiers_out: [HashOutTarget; MAX_PATH_LEN] = core::array::from_fn(|_| {
            let nh = builder.add_virtual_hash();
            builder.register_public_inputs(&nh.elements);
            nh
        }); // [18..30]
        let dest_out = builder.add_virtual_hash();
        builder.register_public_inputs(&dest_out.elements); // [30..34]

        // --- VK as public inputs (self-referential cyclic recursion) ---
        let inner_verifier_data = builder.add_verifier_data_public_inputs(); // [34..102]
        common_data.num_public_inputs = builder.num_public_inputs();

        // --- Inner proof - shape determined by common_data above ---
        let inner_proof = builder.add_virtual_proof_with_pis(&common_data);

        // --- Base-case fresh private inputs ---
        let epoch_base = builder.add_virtual_hash();
        let conn_root_base = builder.add_virtual_hash();
        let rep_root_base = builder.add_virtual_hash();
        let revoc_root_base = builder.add_virtual_hash();
        let dest_base = builder.add_virtual_hash();

        // --- Extract [0..34] from inner proof public inputs ---
        let epoch_inner = HashOutTarget {
            elements: core::array::from_fn(|i| inner_proof.public_inputs[PI_EPOCH + i]),
        };
        let conn_root_inner = HashOutTarget {
            elements: core::array::from_fn(|i| inner_proof.public_inputs[PI_CONN_ROOT + i]),
        };
        let rep_root_inner = HashOutTarget {
            elements: core::array::from_fn(|i| inner_proof.public_inputs[PI_REP_ROOT + i]),
        };
        let revoc_root_inner = HashOutTarget {
            elements: core::array::from_fn(|i| inner_proof.public_inputs[PI_REVOC_ROOT + i]),
        };
        let path_length_inner = inner_proof.public_inputs[PI_PATH_LEN];
        let path_rep_inner = inner_proof.public_inputs[PI_PATH_REP];
        let nullifiers_inner: [HashOutTarget; MAX_PATH_LEN] =
            core::array::from_fn(|i| HashOutTarget {
                elements: core::array::from_fn(|j| {
                    inner_proof.public_inputs[PI_NULLIFIERS + i * 4 + j]
                }),
            });
        let dest_old_inner = HashOutTarget {
            elements: core::array::from_fn(|i| inner_proof.public_inputs[PI_DEST + i]),
        };

        // --- Mux between base-case inputs and inner proof values ---
        let epoch_eff = select_hash(&mut builder, is_base_case, epoch_base, epoch_inner);
        let conn_root_eff =
            select_hash(&mut builder, is_base_case, conn_root_base, conn_root_inner);
        let rep_root_eff =
            select_hash(&mut builder, is_base_case, rep_root_base, rep_root_inner);
        let revoc_root_eff =
            select_hash(&mut builder, is_base_case, revoc_root_base, revoc_root_inner);

        builder.connect_hashes(epoch_out, epoch_eff);
        builder.connect_hashes(conn_root_out, conn_root_eff);
        builder.connect_hashes(rep_root_out, rep_root_eff);
        builder.connect_hashes(revoc_root_out, revoc_root_eff);

        let zero = builder.zero();
        let path_length_old = builder.select(is_base_case, zero, path_length_inner);
        let path_rep_old = builder.select(is_base_case, zero, path_rep_inner);

        let zero_hash = HashOutTarget {
            elements: core::array::from_fn(|_| zero),
        };
        let nullifiers_old: [HashOutTarget; MAX_PATH_LEN] = core::array::from_fn(|i| {
            select_hash(&mut builder, is_base_case, zero_hash, nullifiers_inner[i])
        });

        // --- Cyclic proof verification ---
        let not_base = builder.not(is_base_case);
        builder
            .conditionally_verify_cyclic_proof_or_dummy::<C>(not_base, &inner_proof, &common_data)?;

        // --- Private walk witness targets ---
        let id_x = builder.add_virtual_hash();
        let id_a = builder.add_virtual_hash();
        let min_id = builder.add_virtual_hash();
        let max_id = builder.add_virtual_hash();
        let id_b = builder.add_virtual_hash();
        let s_xa_cc = builder.add_virtual_hash();
        let s_ab_cc = builder.add_virtual_hash();
        let r_a = builder.add_virtual_target();
        let s_a_r = builder.add_virtual_hash();
        let alpha_scaled_t = builder.add_virtual_target();
        let w_a_b = builder.add_virtual_target();

        let connection_mip_siblings: Vec<_> =
            (0..conn_depth).map(|_| builder.add_virtual_hash()).collect();
        let connection_mip_index_bits: Vec<_> = (0..conn_depth)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect();
        let revocation_mnip_siblings: Vec<_> =
            (0..smt_depth).map(|_| builder.add_virtual_hash()).collect();
        let reputation_mip_siblings: Vec<_> =
            (0..rep_depth).map(|_| builder.add_virtual_hash()).collect();
        let reputation_mip_index_bits: Vec<_> = (0..rep_depth)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect();

        let one = builder.one();

        // --- Anti-replay destination lock ---
        let dest_inputs: Vec<_> = id_x
            .elements
            .iter()
            .chain(id_a.elements.iter())
            .chain(s_xa_cc.elements.iter())
            .chain(epoch_eff.elements.iter())
            .copied()
            .collect();
        let dest_expected = builder.hash_n_to_hash_no_pad::<PoseidonHash>(dest_inputs);
        let effective_dest_old =
            select_hash(&mut builder, is_base_case, dest_expected, dest_old_inner);
        builder.connect_hashes(effective_dest_old, dest_expected);

        // --- Connection Merkle inclusion proof (bypassed for base case) ---
        let min_is_x = hash_out_eq(&mut builder, min_id, id_x);
        let max_is_a = hash_out_eq(&mut builder, max_id, id_a);
        let is_xa = builder.and(min_is_x, max_is_a);

        let min_is_a = hash_out_eq(&mut builder, min_id, id_a);
        let max_is_x = hash_out_eq(&mut builder, max_id, id_x);
        let is_ax = builder.and(min_is_a, max_is_x);

        let not_xa = builder.not(is_xa);
        let not_ax = builder.not(is_ax);
        let neither = builder.and(not_xa, not_ax);
        let valid_order = builder.not(neither);
        let valid_order_eff = builder.select(is_base_case, one, valid_order.target);
        builder.assert_one(valid_order_eff);

        let cc_xa_base_inputs: Vec<_> = min_id
            .elements
            .iter()
            .chain(max_id.elements.iter())
            .copied()
            .collect();
        let cc_xa_base = builder.hash_n_to_hash_no_pad::<PoseidonHash>(cc_xa_base_inputs);

        let cc_xa_salted_inputs: Vec<_> = cc_xa_base
            .elements
            .iter()
            .chain(s_xa_cc.elements.iter())
            .copied()
            .collect();
        let cc_xa_salted = builder.hash_n_to_hash_no_pad::<PoseidonHash>(cc_xa_salted_inputs);

        let mip_conn_ok = verify_merkle_inclusion(
            &mut builder,
            cc_xa_salted,
            &connection_mip_siblings,
            &connection_mip_index_bits,
            conn_root_eff,
        );
        let mip_conn_ok_eff = builder.select(is_base_case, one, mip_conn_ok.target);
        builder.assert_one(mip_conn_ok_eff);

        // --- Revocation sparse Merkle non-inclusion proof ---
        let n_xa_inputs: Vec<_> = cc_xa_base
            .elements
            .iter()
            .chain(s_xa_cc.elements.iter())
            .chain(s_xa_cc.elements.iter())
            .copied()
            .collect();
        let n_xa = builder.hash_n_to_hash_no_pad::<PoseidonHash>(n_xa_inputs);
        let n_xa_bits = builder.low_bits(n_xa.elements[0], smt_depth, 64);
        let mnip_ok = verify_sparse_merkle_non_inclusion(
            &mut builder,
            &n_xa_bits,
            &revocation_mnip_siblings,
            revoc_root_eff,
        );
        let mnip_ok_eff = builder.select(is_base_case, one, mnip_ok.target);
        builder.assert_one(mnip_ok_eff);

        // --- Reputation Merkle inclusion proof ---
        let r_a_as_hashout = HashOutTarget {
            elements: [r_a, zero, zero, zero],
        };
        let rc_a_inputs: Vec<_> = id_a
            .elements
            .iter()
            .chain(r_a_as_hashout.elements.iter())
            .chain(s_a_r.elements.iter())
            .copied()
            .collect();
        let rc_a = builder.hash_n_to_hash_no_pad::<PoseidonHash>(rc_a_inputs);
        let mip_rep_ok = verify_merkle_inclusion(
            &mut builder,
            rc_a,
            &reputation_mip_siblings,
            &reputation_mip_index_bits,
            rep_root_eff,
        );
        let mip_rep_ok_eff = builder.select(is_base_case, one, mip_rep_ok.target);
        builder.assert_one(mip_rep_ok_eff);

        // --- Nullifier distinctness + array update ---
        let n_a_inputs: Vec<_> = id_a
            .elements
            .iter()
            .chain(epoch_eff.elements.iter())
            .copied()
            .collect();
        let n_a = builder.hash_n_to_hash_no_pad::<PoseidonHash>(n_a_inputs);

        for i in 0..MAX_PATH_LEN {
            let eq = hash_out_eq(&mut builder, n_a, nullifiers_old[i]);
            let neq = builder.not(eq);
            let neq_eff = builder.select(is_base_case, one, neq.target);
            builder.assert_one(neq_eff);
        }

        let max_minus_1 = builder.constant(F::from_canonical_usize(MAX_PATH_LEN - 1));
        let diff = builder.sub(max_minus_1, path_length_old);
        builder.range_check(diff, PATH_LEN_BITS);

        let nullifiers_new: [HashOutTarget; MAX_PATH_LEN] = core::array::from_fn(|i| {
            let i_const = builder.constant(F::from_canonical_usize(i));
            let is_slot = builder.is_equal(path_length_old, i_const);
            select_hash(&mut builder, is_slot, n_a, nullifiers_old[i])
        });

        let nullifiers_final: [HashOutTarget; MAX_PATH_LEN] = core::array::from_fn(|i| {
            select_hash(&mut builder, is_base_case, zero_hash, nullifiers_new[i])
        });

        let path_length_new = builder.add(path_length_old, one);
        let path_length_final = builder.select(is_base_case, zero, path_length_new);

        // --- Path reputation update ---
        let scale_inv = builder.constant(F::from_canonical_u64(SCALE).inverse());
        let pr_times_alpha = builder.mul(path_rep_old, alpha_scaled_t);
        let ra_times_wab = builder.mul(r_a, w_a_b);
        let rep_sum = builder.add(pr_times_alpha, ra_times_wab);
        let path_rep_new = builder.mul(rep_sum, scale_inv);
        let path_rep_final = builder.select(is_base_case, zero, path_rep_new);

        // --- Compute dest_new = Poseidon(id_a, id_b, s_ab_cc, epoch_eff) ---
        let dest_new_inputs: Vec<_> = id_a
            .elements
            .iter()
            .chain(id_b.elements.iter())
            .chain(s_ab_cc.elements.iter())
            .chain(epoch_eff.elements.iter())
            .copied()
            .collect();
        let dest_computed = builder.hash_n_to_hash_no_pad::<PoseidonHash>(dest_new_inputs);
        let dest_final = select_hash(&mut builder, is_base_case, dest_base, dest_computed);

        // --- Connect computed values to public-output targets ---
        builder.connect(path_length_out, path_length_final);
        builder.connect(path_rep_out, path_rep_final);
        for i in 0..MAX_PATH_LEN {
            builder.connect_hashes(nullifiers_out[i], nullifiers_final[i]);
        }
        builder.connect_hashes(dest_out, dest_final);

        let data = builder.build::<C>();
        let targets = RecursiveWalkTargets {
            epoch: epoch_out,
            connection_mt_root: conn_root_out,
            reputation_mt_root: rep_root_out,
            revocation_smt_root: revoc_root_out,
            path_length: path_length_out,
            path_reputation: path_rep_out,
            nullifiers: nullifiers_out,
            dest: dest_out,
            inner_proof,
            inner_verifier_data,
            is_base_case,
            epoch_base,
            connection_mt_root_base: conn_root_base,
            reputation_mt_root_base: rep_root_base,
            revocation_smt_root_base: revoc_root_base,
            dest_base,
            id_x,
            id_a,
            min_id,
            max_id,
            id_b,
            s_xa_cc,
            s_ab_cc,
            r_a,
            s_a_r,
            alpha_scaled: alpha_scaled_t,
            w_a_b,
            connection_mip_siblings,
            connection_mip_index_bits,
            revocation_mnip_siblings,
            revocation_mnip_key_bits: n_xa_bits,
            reputation_mip_siblings,
            reputation_mip_index_bits,
        };

        Ok((data, targets))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_utils::merkle_tree::MerkleTree;
    use merkle_utils::poseidon_hash::poseidon_hash;
    use merkle_utils::sparse_merkle_tree::SparseMerkleTree;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::hash::hash_types::HashOut;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
    use plonky2::recursion::dummy_circuit::cyclic_base_proof;

    use crate::MAX_PATH_LEN;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    fn h(v: u64) -> [u64; 4] {
        [v, 0, 0, 0]
    }
    fn to_hash(arr: [u64; 4]) -> HashOut<F> {
        HashOut {
            elements: arr.map(F::from_canonical_u64),
        }
    }

    fn set_neutral_walk_witnesses(
        pw: &mut PartialWitness<F>,
        tgts: &RecursiveWalkTargets<D>,
    ) -> anyhow::Result<()> {
        pw.set_hash_target(tgts.id_x, HashOut::ZERO)?;
        pw.set_hash_target(tgts.id_a, HashOut::ZERO)?;
        pw.set_hash_target(tgts.min_id, HashOut::ZERO)?;
        pw.set_hash_target(tgts.max_id, HashOut::ZERO)?;
        pw.set_hash_target(tgts.id_b, HashOut::ZERO)?;
        pw.set_hash_target(tgts.s_xa_cc, HashOut::ZERO)?;
        pw.set_hash_target(tgts.s_ab_cc, HashOut::ZERO)?;
        pw.set_target(tgts.r_a, F::ZERO)?;
        pw.set_hash_target(tgts.s_a_r, HashOut::ZERO)?;
        pw.set_target(tgts.alpha_scaled, F::ZERO)?;
        pw.set_target(tgts.w_a_b, F::ZERO)?;
        for &sib in &tgts.connection_mip_siblings {
            pw.set_hash_target(sib, HashOut::ZERO)?;
        }
        for &bit in &tgts.connection_mip_index_bits {
            pw.set_bool_target(bit, false)?;
        }
        for &sib in &tgts.revocation_mnip_siblings {
            pw.set_hash_target(sib, HashOut::ZERO)?;
        }
        for &sib in &tgts.reputation_mip_siblings {
            pw.set_hash_target(sib, HashOut::ZERO)?;
        }
        for &bit in &tgts.reputation_mip_index_bits {
            pw.set_bool_target(bit, false)?;
        }
        Ok(())
    }

    fn set_neutral_base_inputs(
        pw: &mut PartialWitness<F>,
        tgts: &RecursiveWalkTargets<D>,
    ) -> anyhow::Result<()> {
        pw.set_hash_target(tgts.epoch_base, HashOut::ZERO)?;
        pw.set_hash_target(tgts.connection_mt_root_base, HashOut::ZERO)?;
        pw.set_hash_target(tgts.reputation_mt_root_base, HashOut::ZERO)?;
        pw.set_hash_target(tgts.revocation_smt_root_base, HashOut::ZERO)?;
        pw.set_hash_target(tgts.dest_base, HashOut::ZERO)?;
        Ok(())
    }

    /// Prove the base step (is_base_case=true) using a dummy inner proof.
    #[test]
    fn test_base_cyclic_proof() -> anyhow::Result<()> {
        let config = CircuitConfig::standard_recursion_config();
        let (circuit_data, tgts) = RecursiveWalkCircuit::<F, D>::build::<C>(
            &config,
            1, // conn_depth
            8, // smt_depth
            1, // rep_depth
        )?;

        let epoch_v = h(7);
        let conn_root_v = h(42);
        let rep_root_v = h(43);
        let revoc_root_v = h(44);
        let dest_v = h(99);

        let dummy_proof = cyclic_base_proof(
            &circuit_data.common,
            &circuit_data.verifier_only,
            Default::default(),
        );

        let mut pw = PartialWitness::new();
        pw.set_bool_target(tgts.is_base_case, true)?;
        pw.set_proof_with_pis_target(&tgts.inner_proof, &dummy_proof)?;
        pw.set_verifier_data_target(&tgts.inner_verifier_data, &circuit_data.verifier_only)?;
        pw.set_hash_target(tgts.epoch_base, to_hash(epoch_v))?;
        pw.set_hash_target(tgts.connection_mt_root_base, to_hash(conn_root_v))?;
        pw.set_hash_target(tgts.reputation_mt_root_base, to_hash(rep_root_v))?;
        pw.set_hash_target(tgts.revocation_smt_root_base, to_hash(revoc_root_v))?;
        pw.set_hash_target(tgts.dest_base, to_hash(dest_v))?;
        set_neutral_walk_witnesses(&mut pw, &tgts)?;

        let proof = circuit_data.prove(pw)?;
        circuit_data.verify(proof.clone())?;
        check_cyclic_proof_verifier_data(
            &proof,
            &circuit_data.verifier_only,
            &circuit_data.common,
        )?;

        let pi = &proof.public_inputs;
        assert_eq!(pi[0], F::from_canonical_u64(epoch_v[0]), "epoch[0]");
        assert_eq!(pi[16], F::ZERO, "path_length must be 0 for genesis");
        assert_eq!(pi[17], F::ZERO, "path_reputation must be 0 for genesis");
        for k in 0..MAX_PATH_LEN {
            for j in 0..4 {
                assert_eq!(pi[18 + k * 4 + j], F::ZERO, "nullifier[{k}][{j}] must be 0");
            }
        }
        let dest_start = 18 + MAX_PATH_LEN * 4;
        assert_eq!(pi[dest_start], F::from_canonical_u64(dest_v[0]), "dest[0]");

        println!("Genesis proof verified; path_length=0, all nullifiers=0");
        Ok(())
    }

    /// Prove Base then hop 1 using the same unified circuit.
    #[test]
    fn test_base_then_hop_cyclic_proof() -> anyhow::Result<()> {
        // --- Test identities and salts ---
        let id_x_v = h(1);
        let id_a_v = h(2);
        let id_b_v = h(3);
        let s_xa_cc_v = h(5);
        let s_ab_cc_v = h(6);
        let epoch_v = h(7);
        let s_a_r_v = h(8);
        let r_a_val: u64 = 80;
        let w_a_b_val: u64 = 100;
        let alpha_val: u64 = 90;

        // --- Off-circuit hash computations ---
        let dest_genesis_v = poseidon_hash(&[id_x_v, id_a_v, s_xa_cc_v, epoch_v]);

        let (min_id_v, max_id_v) = if id_x_v[0] < id_a_v[0] {
            (id_x_v, id_a_v)
        } else {
            (id_a_v, id_x_v)
        };
        let cc_xa_base_v = poseidon_hash(&[min_id_v, max_id_v]);
        let cc_xa_salted_v = poseidon_hash(&[cc_xa_base_v, s_xa_cc_v]);

        let r_a_hashout_v = [r_a_val, 0u64, 0u64, 0u64];
        let rc_a_v = poseidon_hash(&[id_a_v, r_a_hashout_v, s_a_r_v]);

        let n_a_v = poseidon_hash(&[id_a_v, epoch_v]);
        let dest_new_v = poseidon_hash(&[id_a_v, id_b_v, s_ab_cc_v, epoch_v]);

        // --- Merkle trees ---
        const CONN_DEPTH: usize = 1;
        const REP_DEPTH: usize = 1;
        const SMT_DEPTH: usize = 8;

        let conn_tree = MerkleTree::new(vec![cc_xa_salted_v]);
        let conn_root = conn_tree.root();
        let conn_mip = conn_tree.inclusion_proof(0);

        let rep_tree = MerkleTree::new(vec![rc_a_v]);
        let rep_root = rep_tree.root();
        let rep_mip = rep_tree.inclusion_proof(0);

        let revoc_smt = SparseMerkleTree::new(SMT_DEPTH);
        let revoc_root = revoc_smt.root();
        let dummy_ni = revoc_smt.non_inclusion_proof(h(0));

        // --- Build unified circuit ---
        let config = CircuitConfig::standard_recursion_config();
        let (circuit_data, tgts) = RecursiveWalkCircuit::<F, D>::build::<C>(
            &config, CONN_DEPTH, SMT_DEPTH, REP_DEPTH,
        )?;

        // --- Genesis proof (is_base_case=true) ---
        let dummy_proof = cyclic_base_proof(
            &circuit_data.common,
            &circuit_data.verifier_only,
            Default::default(),
        );

        let mut pw_genesis = PartialWitness::new();
        pw_genesis.set_bool_target(tgts.is_base_case, true)?;
        pw_genesis.set_proof_with_pis_target(&tgts.inner_proof, &dummy_proof)?;
        pw_genesis.set_verifier_data_target(
            &tgts.inner_verifier_data,
            &circuit_data.verifier_only,
        )?;
        pw_genesis.set_hash_target(tgts.epoch_base, to_hash(epoch_v))?;
        pw_genesis.set_hash_target(tgts.connection_mt_root_base, to_hash(conn_root))?;
        pw_genesis.set_hash_target(tgts.reputation_mt_root_base, to_hash(rep_root))?;
        pw_genesis.set_hash_target(tgts.revocation_smt_root_base, to_hash(revoc_root))?;
        pw_genesis.set_hash_target(tgts.dest_base, to_hash(dest_genesis_v))?;
        set_neutral_walk_witnesses(&mut pw_genesis, &tgts)?;

        let genesis_proof = circuit_data.prove(pw_genesis)?;
        circuit_data.verify(genesis_proof.clone())?;
        check_cyclic_proof_verifier_data(
            &genesis_proof,
            &circuit_data.verifier_only,
            &circuit_data.common,
        )?;
        assert_eq!(genesis_proof.public_inputs[16], F::ZERO, "genesis path_length must be 0");

        // --- Hop 1 proof (is_base_case=false) ---
        let mut pw = PartialWitness::new();
        pw.set_bool_target(tgts.is_base_case, false)?;
        pw.set_proof_with_pis_target(&tgts.inner_proof, &genesis_proof)?;
        pw.set_verifier_data_target(&tgts.inner_verifier_data, &circuit_data.verifier_only)?;
        // *_base targets must be set even when is_base_case=false because select_hash()
        // requires all three inputs to be present for its multiplication gate generator.
        set_neutral_base_inputs(&mut pw, &tgts)?;

        pw.set_hash_target(tgts.id_x, to_hash(id_x_v))?;
        pw.set_hash_target(tgts.id_a, to_hash(id_a_v))?;
        pw.set_hash_target(tgts.min_id, to_hash(min_id_v))?;
        pw.set_hash_target(tgts.max_id, to_hash(max_id_v))?;
        pw.set_hash_target(tgts.id_b, to_hash(id_b_v))?;
        pw.set_hash_target(tgts.s_xa_cc, to_hash(s_xa_cc_v))?;
        pw.set_hash_target(tgts.s_ab_cc, to_hash(s_ab_cc_v))?;
        pw.set_target(tgts.r_a, F::from_canonical_u64(r_a_val))?;
        pw.set_hash_target(tgts.s_a_r, to_hash(s_a_r_v))?;
        pw.set_target(tgts.alpha_scaled, F::from_canonical_u64(alpha_val))?;
        pw.set_target(tgts.w_a_b, F::from_canonical_u64(w_a_b_val))?;

        for (i, sib) in conn_mip.siblings.iter().enumerate() {
            pw.set_hash_target(tgts.connection_mip_siblings[i], to_hash(*sib))?;
        }
        let mut idx = conn_mip.leaf_index;
        for i in 0..CONN_DEPTH {
            pw.set_bool_target(tgts.connection_mip_index_bits[i], idx % 2 == 1)?;
            idx >>= 1;
        }

        for (i, sib) in dummy_ni.siblings.iter().enumerate() {
            pw.set_hash_target(tgts.revocation_mnip_siblings[i], to_hash(*sib))?;
        }

        for (i, sib) in rep_mip.siblings.iter().enumerate() {
            pw.set_hash_target(tgts.reputation_mip_siblings[i], to_hash(*sib))?;
        }
        let mut idx = rep_mip.leaf_index;
        for i in 0..REP_DEPTH {
            pw.set_bool_target(tgts.reputation_mip_index_bits[i], idx % 2 == 1)?;
            idx >>= 1;
        }

        let hop1_proof = circuit_data.prove(pw)?;
        circuit_data.verify(hop1_proof.clone())?;
        check_cyclic_proof_verifier_data(
            &hop1_proof,
            &circuit_data.verifier_only,
            &circuit_data.common,
        )?;

        let pi = &hop1_proof.public_inputs;
        assert_eq!(pi[0], F::from_canonical_u64(epoch_v[0]), "epoch[0]");
        assert_eq!(pi[16], F::ONE, "path_length_new must be 1");
        // path_rep_new = (0*90 + 80*100)/100 = 80
        assert_eq!(pi[17], F::from_canonical_u64(80), "path_reputation_new");
        for j in 0..4 {
            assert_eq!(
                pi[18 + j],
                F::from_canonical_u64(n_a_v[j]),
                "nullifiers[0][{j}]"
            );
        }
        for k in 1..MAX_PATH_LEN {
            for j in 0..4 {
                assert_eq!(pi[18 + k * 4 + j], F::ZERO, "nullifiers[{k}][{j}]");
            }
        }
        let dest_start = 18 + MAX_PATH_LEN * 4;
        for j in 0..4 {
            assert_eq!(
                pi[dest_start + j],
                F::from_canonical_u64(dest_new_v[j]),
                "dest_new[{j}]"
            );
        }

        println!("genesis → hop-1 cyclic chain verified; path_length=1, path_rep=80");
        Ok(())
    }
}
