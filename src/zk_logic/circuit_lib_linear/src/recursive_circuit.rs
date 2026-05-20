// ZK Random Walk Circuit - linear variant

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;

use merkle_circuit::merkle_gadgets::{hash_out_eq, select_hash, verify_merkle_inclusion,
    verify_sparse_merkle_non_inclusion};
use crate::{MAX_PATH_LEN, SCALE};

// Public-input index offsets into the inner proof's `public_inputs` slice.
// Must stay in sync with `base_circuit.rs` (and with this circuit's own PI registration).
//      [0..4]                epoch
//      [4..8]                connection_mt_root
//      [8..12]               reputation_mt_root
//      [12..16]              revocation_smt_root
//      [16]                  path_length
//      [17]                  path_reputation
//      [18 .. 18+N*4)        nullifiers  (N = MAX_PATH_LEN)
//      [18+N*4 .. 22+N*4)   dest
const PI_EPOCH: usize = 0;
const PI_CONN_ROOT: usize = 4;
const PI_REP_ROOT: usize = 8;
const PI_REVOC_ROOT: usize = 12;
const PI_PATH_LEN: usize = 16;
const PI_PATH_REP: usize = 17;
const PI_NULLIFIERS: usize = 18;
const PI_DEST: usize = 18 + MAX_PATH_LEN * 4;

// Bits needed to range-check diff = (MAX_PATH_LEN - 1) - path_length_old in [0, MAX_PATH_LEN-1].
// Must satisfy 2^PATH_LEN_BITS >= MAX_PATH_LEN.
const PATH_LEN_BITS: usize = MAX_PATH_LEN.next_power_of_two().ilog2() as usize;

/// All circuit targets for a single recursive walk step.
pub struct RecursiveWalkTargets<const D: usize> {
    // --- Public-input targets ---
    pub epoch: HashOutTarget,
    pub connection_mt_root: HashOutTarget,
    pub reputation_mt_root: HashOutTarget,
    pub revocation_smt_root: HashOutTarget,
    pub path_length: Target,
    pub path_reputation: Target,
    pub nullifiers: [HashOutTarget; MAX_PATH_LEN],
    pub dest: HashOutTarget,

    // --- Private-input targets (prover sets) ---
    pub inner_proof: ProofWithPublicInputsTarget<D>,
    pub inner_verifier_data: VerifierCircuitTarget,
    pub id_x: HashOutTarget,
    pub id_a: HashOutTarget,
    /// min(id_x, id_a) by element[0] ordering - prover provides; circuit checks the set
    pub min_id: HashOutTarget,
    /// max(id_x, id_a) by element[0] ordering - prover provides; circuit checks the set
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

/// Recursive walk step circuit.
pub struct RecursiveWalkCircuit<F: RichField + Extendable<D>, const D: usize> {
    _phantom: std::marker::PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> RecursiveWalkCircuit<F, D> {
    /// Build the recursive circuit.
    ///
    /// # Parameters
    /// - `inner_circuit_data`: compiled data of the circuit whose proof is verified.
    /// - `conn_depth`: height of the connection Merkle tree (siblings count).
    /// - `smt_depth`: depth of the revocation sparse Merkle tree.
    /// - `rep_depth`: height of the reputation Merkle tree.
    pub fn build<C>(
        config: &CircuitConfig,
        inner_circuit_data: &CircuitData<F, C, D>,
        conn_depth: usize,
        smt_depth: usize,
        rep_depth: usize,
    ) -> (CircuitData<F, C, D>, RecursiveWalkTargets<D>)
    where
        C: GenericConfig<D, F = F>,
        C::Hasher: AlgebraicHasher<F>,
    {
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        // --- Inner proof verification ---
        let inner_proof =
            builder.add_virtual_proof_with_pis(&inner_circuit_data.common);
        let inner_verifier_data = builder.add_virtual_verifier_data(
            inner_circuit_data.common.config.fri_config.cap_height,
        );
        builder.verify_proof::<C>(
            &inner_proof,
            &inner_verifier_data,
            &inner_circuit_data.common,
        );

        // --- Extract inner proof public input fields ---
        let epoch = HashOutTarget {
            elements: core::array::from_fn(|i| inner_proof.public_inputs[PI_EPOCH + i]),
        };
        let connection_mt_root = HashOutTarget {
            elements: core::array::from_fn(|i| inner_proof.public_inputs[PI_CONN_ROOT + i]),
        };
        let reputation_mt_root = HashOutTarget {
            elements: core::array::from_fn(|i| inner_proof.public_inputs[PI_REP_ROOT + i]),
        };
        let revocation_smt_root = HashOutTarget {
            elements: core::array::from_fn(|i| inner_proof.public_inputs[PI_REVOC_ROOT + i]),
        };
        let path_length_old = inner_proof.public_inputs[PI_PATH_LEN];
        let path_reputation_old = inner_proof.public_inputs[PI_PATH_REP];
        let nullifiers_old: [HashOutTarget; MAX_PATH_LEN] =
            core::array::from_fn(|i| HashOutTarget {
                elements: core::array::from_fn(|j| {
                    inner_proof.public_inputs[PI_NULLIFIERS + i * 4 + j]
                }),
            });
        let dest_old = HashOutTarget {
            elements: core::array::from_fn(|i| inner_proof.public_inputs[PI_DEST + i]),
        };

        // --- Private witness targets ---
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

        let connection_mip_siblings: Vec<_> = (0..conn_depth)
            .map(|_| builder.add_virtual_hash())
            .collect();
        let connection_mip_index_bits: Vec<_> = (0..conn_depth)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect();
        let revocation_mnip_siblings: Vec<_> = (0..smt_depth)
            .map(|_| builder.add_virtual_hash())
            .collect();
        let reputation_mip_siblings: Vec<_> = (0..rep_depth)
            .map(|_| builder.add_virtual_hash())
            .collect();
        let reputation_mip_index_bits: Vec<_> = (0..rep_depth)
            .map(|_| builder.add_virtual_bool_target_safe())
            .collect();

        // --- Anti-replay dest lock ---
        let dest_inputs: Vec<_> = id_x
            .elements
            .iter()
            .chain(id_a.elements.iter())
            .chain(s_xa_cc.elements.iter())
            .chain(epoch.elements.iter())
            .copied()
            .collect();
        let dest_expected =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(dest_inputs);
        builder.connect_hashes(dest_old, dest_expected);

        // --- Connection Merkle inclusion proof ---
        let min_is_x = hash_out_eq(&mut builder, min_id, id_x);
        let max_is_a = hash_out_eq(&mut builder, max_id, id_a);
        let is_xa = builder.and(min_is_x, max_is_a);

        let min_is_a = hash_out_eq(&mut builder, min_id, id_a);
        let max_is_x = hash_out_eq(&mut builder, max_id, id_x);
        let is_ax = builder.and(min_is_a, max_is_x);

        // Assert at least one ordering is correct
        let not_xa = builder.not(is_xa);
        let not_ax = builder.not(is_ax);
        let neither = builder.and(not_xa, not_ax);
        let valid_order = builder.not(neither);
        builder.assert_one(valid_order.target);

        // cc_xa_base = Poseidon(min_id, max_id)
        let cc_xa_base_inputs: Vec<_> = min_id
            .elements
            .iter()
            .chain(max_id.elements.iter())
            .copied()
            .collect();
        let cc_xa_base =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(cc_xa_base_inputs);

        // cc_xa_salted = Poseidon(cc_xa_base, s_xa_cc)
        let cc_xa_salted_inputs: Vec<_> = cc_xa_base
            .elements
            .iter()
            .chain(s_xa_cc.elements.iter())
            .copied()
            .collect();
        let cc_xa_salted =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(cc_xa_salted_inputs);

        let mip_conn_ok = verify_merkle_inclusion(
            &mut builder,
            cc_xa_salted,
            &connection_mip_siblings,
            &connection_mip_index_bits,
            connection_mt_root,
        );
        builder.assert_one(mip_conn_ok.target);

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
            revocation_smt_root,
        );
        builder.assert_one(mnip_ok.target);

        // --- Reputation Merkle inclusion proof ---
        let zero = builder.zero();
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
            reputation_mt_root,
        );
        builder.assert_one(mip_rep_ok.target);

        // --- Nullifier distinctness + array update ---
        let n_a_inputs: Vec<_> = id_a
            .elements
            .iter()
            .chain(epoch.elements.iter())
            .copied()
            .collect();
        let n_a = builder.hash_n_to_hash_no_pad::<PoseidonHash>(n_a_inputs);

        // Assert n_a is distinct from every existing nullifier.
        for i in 0..MAX_PATH_LEN {
            let eq = hash_out_eq(&mut builder, n_a, nullifiers_old[i]);
            let neq = builder.not(eq);
            builder.assert_one(neq.target);
        }

        // Assert path_length_old < MAX_PATH_LEN by range-checking the difference.
        let max_minus_1 = builder.constant(F::from_canonical_usize(MAX_PATH_LEN - 1));
        let diff = builder.sub(max_minus_1, path_length_old);
        builder.range_check(diff, PATH_LEN_BITS);

        // Build new array of nullifiers
        let nullifiers_new: [HashOutTarget; MAX_PATH_LEN] =
            core::array::from_fn(|i| {
                let i_const = builder.constant(F::from_canonical_usize(i));
                let is_slot = builder.is_equal(path_length_old, i_const);
                select_hash(&mut builder, is_slot, n_a, nullifiers_old[i])
            });

        let one = builder.one();
        let path_length_new = builder.add(path_length_old, one);

        // --- Path reputation update ---
        let scale_inv =
            builder.constant(F::from_canonical_u64(SCALE).inverse());
        let pr_times_alpha = builder.mul(path_reputation_old, alpha_scaled_t);
        let ra_times_wab = builder.mul(r_a, w_a_b);
        let rep_sum = builder.add(pr_times_alpha, ra_times_wab);
        let path_rep_new = builder.mul(rep_sum, scale_inv);

        // --- Compute dest_new = Poseidon(id_a, id_b, s_ab_cc, epoch) ---
        let dest_new_inputs: Vec<_> = id_a
            .elements
            .iter()
            .chain(id_b.elements.iter())
            .chain(s_ab_cc.elements.iter())
            .chain(epoch.elements.iter())
            .copied()
            .collect();
        let dest_new =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(dest_new_inputs);

        // --- Register public inputs (same layout as BaseCircuit) ---
        builder.register_public_inputs(&epoch.elements); // [0..4]
        builder.register_public_inputs(&connection_mt_root.elements); // [4..8]
        builder.register_public_inputs(&reputation_mt_root.elements); // [8..12]
        builder.register_public_inputs(&revocation_smt_root.elements); // [12..16]
        builder.register_public_input(path_length_new); // [16]
        builder.register_public_input(path_rep_new); // [17]
        for nh in &nullifiers_new {
            builder.register_public_inputs(&nh.elements); // [18..30]
        }
        builder.register_public_inputs(&dest_new.elements); // [30..34]

        let data = builder.build::<C>();
        let targets = RecursiveWalkTargets {
            epoch,
            connection_mt_root,
            reputation_mt_root,
            revocation_smt_root,
            path_length: path_length_new,
            path_reputation: path_rep_new,
            nullifiers: nullifiers_new,
            dest: dest_new,
            inner_proof,
            inner_verifier_data,
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

        (data, targets)
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

    use crate::base_circuit::BaseCircuit;
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

    /// Dummy inner circuit: all public inputs are free variables.
    struct DummyInnerTargets {
        epoch: HashOutTarget,
        connection_mt_root: HashOutTarget,
        reputation_mt_root: HashOutTarget,
        revocation_smt_root: HashOutTarget,
        path_length: Target,
        path_reputation: Target,
        nullifiers: [HashOutTarget; MAX_PATH_LEN],
        dest: HashOutTarget,
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

    /// One-hop integration test: dummy inner proof → recursive step → verify.
    ///
    /// All 8 constraints are exercised.  Witness data is derived from off-circuit
    /// Poseidon computations using the same constants as the in-circuit hashes.
    #[test]
    fn test_one_hop_recursive_proof() -> anyhow::Result<()> {
        // --- Test identities and salts ---
        let id_x_v = h(1);
        let id_a_v = h(2);
        let id_b_v = h(3);
        let s_xa_cc_v = h(5);
        let s_ab_cc_v = h(6);
        let epoch_v = h(7);
        let s_a_r_v = h(8);
        let r_a_val: u64 = 80;   // 0.80 × SCALE
        let w_a_b_val: u64 = 100; // 1.00 × SCALE
        let alpha_val: u64 = 90;  // ALPHA_SCALED

        // --- Off-circuit hash computations ---

        // dest_old = Poseidon(id_x, id_a, s_xa_cc, epoch)
        let dest_old_v = poseidon_hash(&[id_x_v, id_a_v, s_xa_cc_v, epoch_v]);

        // canonically-ordered connection commitment
        let (min_id_v, max_id_v) = if id_x_v[0] < id_a_v[0] {
            (id_x_v, id_a_v)
        } else {
            (id_a_v, id_x_v)
        };
        let cc_xa_base_v = poseidon_hash(&[min_id_v, max_id_v]);
        let cc_xa_salted_v = poseidon_hash(&[cc_xa_base_v, s_xa_cc_v]);

        // nullifier (12-element Poseidon)
        let _n_xa_v = poseidon_hash(&[cc_xa_base_v, s_xa_cc_v, s_xa_cc_v]);

        // reputation commitment (12-element Poseidon)
        let r_a_hashout_v = [r_a_val, 0u64, 0u64, 0u64];
        let rc_a_v = poseidon_hash(&[id_a_v, r_a_hashout_v, s_a_r_v]);

        // step nullifier
        let n_a_v = poseidon_hash(&[id_a_v, epoch_v]);

        // dest_new
        let dest_new_v = poseidon_hash(&[id_a_v, id_b_v, s_ab_cc_v, epoch_v]);

        // --- Build Merkle trees ---
        const CONN_DEPTH: usize = 1;  // 1 leaf padded to 2 → height 1
        const REP_DEPTH: usize = 1;
        const SMT_DEPTH: usize = 8;

        let conn_tree = MerkleTree::new(vec![cc_xa_salted_v]);
        let conn_root = conn_tree.root();
        let conn_mip = conn_tree.inclusion_proof(0);
        assert_eq!(conn_mip.siblings.len(), CONN_DEPTH);

        let rep_tree = MerkleTree::new(vec![rc_a_v]);
        let rep_root = rep_tree.root();
        let rep_mip = rep_tree.inclusion_proof(0);
        assert_eq!(rep_mip.siblings.len(), REP_DEPTH);

        // Empty revocation SMT.
        let revoc_smt = SparseMerkleTree::new(SMT_DEPTH);
        let revoc_root = revoc_smt.root();
        let dummy_ni = revoc_smt.non_inclusion_proof(h(0));

        // --- Build dummy inner circuit and prove ---
        let (inner_data, inner_tgts) = build_dummy_inner();

        let mut pw_inner = PartialWitness::new();
        pw_inner.set_hash_target(inner_tgts.epoch, to_hash(epoch_v))?;
        pw_inner.set_hash_target(inner_tgts.connection_mt_root, to_hash(conn_root))?;
        pw_inner.set_hash_target(inner_tgts.reputation_mt_root, to_hash(rep_root))?;
        pw_inner.set_hash_target(inner_tgts.revocation_smt_root, to_hash(revoc_root))?;
        pw_inner.set_target(inner_tgts.path_length, F::ZERO)?;
        pw_inner.set_target(inner_tgts.path_reputation, F::ZERO)?;
        for i in 0..MAX_PATH_LEN {
            pw_inner.set_hash_target(inner_tgts.nullifiers[i], HashOut::ZERO)?;
        }
        pw_inner.set_hash_target(inner_tgts.dest, to_hash(dest_old_v))?;

        let inner_proof = inner_data.prove(pw_inner)?;
        inner_data.verify(inner_proof.clone())?;

        // --- Build recursive circuit ---
        let config = CircuitConfig::standard_recursion_config();
        let (rec_data, rec_tgts) = RecursiveWalkCircuit::<F, D>::build::<C>(
            &config, &inner_data, CONN_DEPTH, SMT_DEPTH, REP_DEPTH,
        );

        // --- Assemble recursive witness ---
        let mut pw = PartialWitness::new();

        pw.set_proof_with_pis_target(&rec_tgts.inner_proof, &inner_proof)?;
        pw.set_verifier_data_target(
            &rec_tgts.inner_verifier_data,
            &inner_data.verifier_only,
        )?;

        pw.set_hash_target(rec_tgts.id_x, to_hash(id_x_v))?;
        pw.set_hash_target(rec_tgts.id_a, to_hash(id_a_v))?;
        pw.set_hash_target(rec_tgts.min_id, to_hash(min_id_v))?;
        pw.set_hash_target(rec_tgts.max_id, to_hash(max_id_v))?;
        pw.set_hash_target(rec_tgts.id_b, to_hash(id_b_v))?;
        pw.set_hash_target(rec_tgts.s_xa_cc, to_hash(s_xa_cc_v))?;
        pw.set_hash_target(rec_tgts.s_ab_cc, to_hash(s_ab_cc_v))?;
        pw.set_target(rec_tgts.r_a, F::from_canonical_u64(r_a_val))?;
        pw.set_hash_target(rec_tgts.s_a_r, to_hash(s_a_r_v))?;
        pw.set_target(rec_tgts.alpha_scaled, F::from_canonical_u64(alpha_val))?;
        pw.set_target(rec_tgts.w_a_b, F::from_canonical_u64(w_a_b_val))?;

        // Connection MIP
        for (i, sib) in conn_mip.siblings.iter().enumerate() {
            pw.set_hash_target(rec_tgts.connection_mip_siblings[i], to_hash(*sib))?;
        }
        let mut idx = conn_mip.leaf_index;
        for i in 0..CONN_DEPTH {
            pw.set_bool_target(rec_tgts.connection_mip_index_bits[i], idx % 2 == 1)?;
            idx >>= 1;
        }

        // Revocation MNIP
        for (i, sib) in dummy_ni.siblings.iter().enumerate() {
            pw.set_hash_target(rec_tgts.revocation_mnip_siblings[i], to_hash(*sib))?;
        }

        // Reputation MIP
        for (i, sib) in rep_mip.siblings.iter().enumerate() {
            pw.set_hash_target(rec_tgts.reputation_mip_siblings[i], to_hash(*sib))?;
        }
        let mut idx = rep_mip.leaf_index;
        for i in 0..REP_DEPTH {
            pw.set_bool_target(rec_tgts.reputation_mip_index_bits[i], idx % 2 == 1)?;
            idx >>= 1;
        }

        // --- Prove and verify ---
        let rec_proof = rec_data.prove(pw)?;
        rec_data.verify(rec_proof.clone())?;

        // --- Inspect public outputs ---
        let pi = &rec_proof.public_inputs;
        println!("Recursive proof public inputs ({} elements):", pi.len());
        for (i, x) in pi.iter().enumerate() {
            println!("  [{}] = {}", i, x);
        }

        // epoch unchanged
        assert_eq!(pi[0], F::from_canonical_u64(epoch_v[0]), "epoch[0]");

        // path_length_new = 0 + 1 = 1
        assert_eq!(pi[16], F::ONE, "path_length_new");

        // path_rep_new = (0 * 90 + 80 * 100) / 100 = 80
        assert_eq!(pi[17], F::from_canonical_u64(80), "path_reputation_new");

        // nullifiers_new[0] = n_a_v, rest = 0
        for j in 0..4 {
            assert_eq!(
                pi[18 + j],
                F::from_canonical_u64(n_a_v[j]),
                "nullifiers[0][{}]",
                j
            );
        }
        for k in 1..MAX_PATH_LEN {
            for j in 0..4 {
                assert_eq!(pi[18 + k * 4 + j], F::ZERO, "nullifiers[{}][{}]", k, j);
            }
        }

        // dest_new
        let dest_start = 18 + MAX_PATH_LEN * 4;
        for j in 0..4 {
            assert_eq!(
                pi[dest_start + j],
                F::from_canonical_u64(dest_new_v[j]),
                "dest_new[{}]",
                j
            );
        }

        Ok(())
    }

    /// End-to-end test: real BaseCircuit genesis proof → first recursive walk step.
    ///
    /// The first user (prover of the genesis) supplies:
    ///   - epoch and all three Merkle roots
    ///   - dest = Poseidon(id_x, pk_a, s_xa_cc, epoch)
    #[test]
    fn test_base_circuit_then_recursive_hop() -> anyhow::Result<()> {
        // --- Test identities and salts ---
        let id_x_v = h(10);
        let id_a_v = h(20);
        let id_b_v = h(30);
        let s_xa_cc_v = h(50);
        let s_ab_cc_v = h(60);
        let epoch_v = h(70);
        let s_a_r_v = h(80);
        let r_a_val: u64 = 60;   // 0.60 × SCALE
        let w_a_b_val: u64 = 50; // 0.50 × SCALE → r_a * w_a_b = 3000, /100 = 30
        let alpha_val: u64 = 90; // ALPHA_SCALED

        // --- Off-circuit hash computations ---

        // Genesis dest = Poseidon(id_x, id_a, s_xa_cc, epoch)
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

        // --- Build and prove the BaseCircuit genesis ---
        let config = CircuitConfig::standard_recursion_config();
        let (base_data, base_tgts) = BaseCircuit::<F, D>::build::<C>(&config);

        let base_proof = BaseCircuit::<F, D>::generate_proof::<C>(
            &base_data,
            &base_tgts,
            to_hash(epoch_v),
            to_hash(conn_root),
            to_hash(rep_root),
            to_hash(revoc_root),
            to_hash(dest_genesis_v), // dest committed by first user
        )?;
        base_data.verify(base_proof.clone())?;

        // Sanity: dest is in the genesis proof at PI[30..34].
        let dest_start = 18 + MAX_PATH_LEN * 4; // = 30
        for j in 0..4 {
            assert_eq!(
                base_proof.public_inputs[dest_start + j],
                F::from_canonical_u64(dest_genesis_v[j]),
                "base proof dest[{}]",
                j
            );
        }

        // --- Build recursive circuit with BaseCircuit as inner ---
        let (rec_data, rec_tgts) = RecursiveWalkCircuit::<F, D>::build::<C>(
            &config, &base_data, CONN_DEPTH, SMT_DEPTH, REP_DEPTH,
        );

        // --- Assemble recursive witness ---
        let mut pw = PartialWitness::new();

        pw.set_proof_with_pis_target(&rec_tgts.inner_proof, &base_proof)?;
        pw.set_verifier_data_target(
            &rec_tgts.inner_verifier_data,
            &base_data.verifier_only,
        )?;

        pw.set_hash_target(rec_tgts.id_x, to_hash(id_x_v))?;
        pw.set_hash_target(rec_tgts.id_a, to_hash(id_a_v))?;
        pw.set_hash_target(rec_tgts.min_id, to_hash(min_id_v))?;
        pw.set_hash_target(rec_tgts.max_id, to_hash(max_id_v))?;
        pw.set_hash_target(rec_tgts.id_b, to_hash(id_b_v))?;
        pw.set_hash_target(rec_tgts.s_xa_cc, to_hash(s_xa_cc_v))?;
        pw.set_hash_target(rec_tgts.s_ab_cc, to_hash(s_ab_cc_v))?;
        pw.set_target(rec_tgts.r_a, F::from_canonical_u64(r_a_val))?;
        pw.set_hash_target(rec_tgts.s_a_r, to_hash(s_a_r_v))?;
        pw.set_target(rec_tgts.alpha_scaled, F::from_canonical_u64(alpha_val))?;
        pw.set_target(rec_tgts.w_a_b, F::from_canonical_u64(w_a_b_val))?;

        for (i, sib) in conn_mip.siblings.iter().enumerate() {
            pw.set_hash_target(rec_tgts.connection_mip_siblings[i], to_hash(*sib))?;
        }
        let mut idx = conn_mip.leaf_index;
        for i in 0..CONN_DEPTH {
            pw.set_bool_target(rec_tgts.connection_mip_index_bits[i], idx % 2 == 1)?;
            idx >>= 1;
        }

        for (i, sib) in dummy_ni.siblings.iter().enumerate() {
            pw.set_hash_target(rec_tgts.revocation_mnip_siblings[i], to_hash(*sib))?;
        }

        for (i, sib) in rep_mip.siblings.iter().enumerate() {
            pw.set_hash_target(rec_tgts.reputation_mip_siblings[i], to_hash(*sib))?;
        }
        let mut idx = rep_mip.leaf_index;
        for i in 0..REP_DEPTH {
            pw.set_bool_target(rec_tgts.reputation_mip_index_bits[i], idx % 2 == 1)?;
            idx >>= 1;
        }

        // --- Prove and verify ---
        let rec_proof = rec_data.prove(pw)?;
        rec_data.verify(rec_proof.clone())?;

        // --- Assert public outputs ---
        let pi = &rec_proof.public_inputs;

        // epoch preserved
        assert_eq!(pi[0], F::from_canonical_u64(epoch_v[0]), "epoch[0]");

        // path_length 0 → 1
        assert_eq!(pi[16], F::ONE, "path_length_new");

        // path_rep = (0 * 90 + 60 * 50) / 100 = 3000 / 100 = 30
        assert_eq!(pi[17], F::from_canonical_u64(30), "path_reputation_new");

        // nullifiers[0] = n_a
        for j in 0..4 {
            assert_eq!(
                pi[18 + j],
                F::from_canonical_u64(n_a_v[j]),
                "nullifiers[0][{}]",
                j
            );
        }
        for k in 1..MAX_PATH_LEN {
            for j in 0..4 {
                assert_eq!(pi[18 + k * 4 + j], F::ZERO, "nullifiers[{}][{}]", k, j);
            }
        }

        // dest_new
        let dest_out_start = 18 + MAX_PATH_LEN * 4;
        for j in 0..4 {
            assert_eq!(
                pi[dest_out_start + j],
                F::from_canonical_u64(dest_new_v[j]),
                "dest_new[{}]",
                j
            );
        }

        println!("base → recursive hop verified; path_length=1, path_rep=30");
        Ok(())
    }
}
