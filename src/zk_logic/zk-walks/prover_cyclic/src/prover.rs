//! WalkProver — builds one unified cyclic circuit and generates genesis/step proofs.

use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;

use circuit_lib_cyclic::recursive_circuit::{RecursiveWalkCircuit, RecursiveWalkTargets};
use circuit_lib_cyclic::{ALPHA_SCALED, MAX_PATH_LEN};

/// Field-element index of `path_length` in the public-inputs array.
const PI_PATH_LEN: usize = 16;

/// Inputs needed to generate the genesis (base) proof.
pub struct BaseInputs<F: RichField> {
    pub epoch: HashOut<F>,
    pub connection_mt_root: HashOut<F>,
    pub reputation_mt_root: HashOut<F>,
    pub revocation_smt_root: HashOut<F>,
    /// Anti-replay commitment for the first step: Poseidon(id_x, pk_a, s_xa_cc, epoch).
    pub dest: HashOut<F>,
}

/// Inputs needed to prove one recursive walk step.
#[allow(clippy::too_many_arguments)]
pub struct StepInputs<F: RichField> {
    /// Previous node (unlocks the dest commitment from the inner proof).
    pub id_x: HashOut<F>,
    /// Current node (the prover of this step).
    pub id_a: HashOut<F>,
    /// Current node's public key.
    pub pk_a: HashOut<F>,
    /// Next node's public key (committed in dest_new for the following step).
    pub pk_b: HashOut<F>,
    /// Salt for the X-A connection record.
    pub s_xa_cc: HashOut<F>,
    /// Salt for the A-B connection record (used in dest_new).
    pub s_ab_cc: HashOut<F>,
    /// A's raw reputation value, scaled by SCALE (= 100).
    pub r_a: u64,
    /// Salt for A's reputation record.
    pub s_a_r: HashOut<F>,
    /// Edge weight A→B, scaled by SCALE.
    pub w_a_b: u64,
    /// Sibling hashes for the connection Merkle inclusion proof (leaf→root order).
    pub connection_mip_siblings: Vec<[u64; 4]>,
    /// Leaf index of the connection record in the connection Merkle tree.
    pub connection_mip_leaf_index: usize,
    /// Sibling hashes for the revocation sparse Merkle non-inclusion proof.
    pub revocation_mnip_siblings: Vec<[u64; 4]>,
    /// Sibling hashes for the reputation Merkle inclusion proof (leaf→root order).
    pub reputation_mip_siblings: Vec<[u64; 4]>,
    /// Leaf index of the reputation record in the reputation Merkle tree.
    pub reputation_mip_leaf_index: usize,
}

/// Holds the single pre-compiled cyclic circuit for all hops.
///
/// Call [`WalkProver::setup`] once (expensive), then reuse [`prove_base`] /
/// [`prove_step`] freely.  All proofs — genesis and recursive hops — use the
/// same `circuit_data`.
pub struct WalkProver<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub conn_depth: usize,
    pub smt_depth: usize,
    pub rep_depth: usize,
    circuit_data: CircuitData<F, C, D>,
    targets: RecursiveWalkTargets<D>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>
    WalkProver<F, C, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    /// Build the single unified cyclic circuit.
    ///
    /// `conn_depth` / `rep_depth` are the Merkle tree heights; `smt_depth` is the
    /// sparse Merkle tree depth for revocations.  These must match the actual trees
    /// used when generating proofs.
    pub fn setup(
        config: CircuitConfig,
        conn_depth: usize,
        smt_depth: usize,
        rep_depth: usize,
    ) -> Self {
        let (circuit_data, targets) =
            RecursiveWalkCircuit::<F, D>::build::<C>(&config, conn_depth, smt_depth, rep_depth)
                .unwrap();
        Self {
            conn_depth,
            smt_depth,
            rep_depth,
            circuit_data,
            targets,
        }
    }

    /// Return the circuit data.  All path lengths share the same circuit, so
    /// `_path_length` is ignored; the parameter is kept for API compatibility.
    pub fn circuit_data_for_length(&self, _path_length: usize) -> &CircuitData<F, C, D> {
        &self.circuit_data
    }

    /// Generate the genesis proof (path_length = 0, all walk state zeroed).
    ///
    /// Internally uses a structural dummy inner proof from `cyclic_base_proof` and
    /// sets all walk-witness targets to neutral zero values — their assertions are
    /// bypassed by `is_base_case = true`, but the hash generators still need inputs.
    pub fn prove_base(&self, inputs: BaseInputs<F>) -> Result<ProofWithPublicInputs<F, C, D>> {
        let dummy_proof = cyclic_base_proof(
            &self.circuit_data.common,
            &self.circuit_data.verifier_only,
            Default::default(),
        );

        let tgts = &self.targets;
        let mut pw = PartialWitness::new();

        pw.set_bool_target(tgts.is_base_case, true)?;
        pw.set_proof_with_pis_target(&tgts.inner_proof, &dummy_proof)?;
        pw.set_verifier_data_target(&tgts.inner_verifier_data, &self.circuit_data.verifier_only)?;

        // Fresh genesis state.
        pw.set_hash_target(tgts.epoch_base, inputs.epoch)?;
        pw.set_hash_target(tgts.connection_mt_root_base, inputs.connection_mt_root)?;
        pw.set_hash_target(tgts.reputation_mt_root_base, inputs.reputation_mt_root)?;
        pw.set_hash_target(tgts.revocation_smt_root_base, inputs.revocation_smt_root)?;
        pw.set_hash_target(tgts.dest_base, inputs.dest)?;

        // Walk witnesses: constraints are bypassed (is_base_case=true) but hash
        // generators still need all inputs to be set.
        set_neutral_walk_witnesses(&mut pw, tgts, self.conn_depth, self.smt_depth, self.rep_depth)?;

        self.circuit_data.prove(pw)
    }

    /// Extend a walk by one hop.
    ///
    /// Reads `path_length_old` from `prev_proof.public_inputs` for the assertion
    /// guard, fills all witnesses, and returns a proof with `path_length = path_length_old + 1`.
    pub fn prove_step(
        &self,
        prev_proof: ProofWithPublicInputs<F, C, D>,
        inputs: StepInputs<F>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let path_length_old =
            prev_proof.public_inputs[PI_PATH_LEN].to_canonical_u64() as usize;
        assert!(
            path_length_old < MAX_PATH_LEN,
            "cannot extend: path already at max length {MAX_PATH_LEN}"
        );

        let tgts = &self.targets;
        let mut pw = PartialWitness::new();

        pw.set_bool_target(tgts.is_base_case, false)?;
        pw.set_proof_with_pis_target(&tgts.inner_proof, &prev_proof)?;
        pw.set_verifier_data_target(&tgts.inner_verifier_data, &self.circuit_data.verifier_only)?;

        // *_base targets must be set even when is_base_case=false because select_hash()
        // requires all three inputs for its multiplication gate generator.
        pw.set_hash_target(tgts.epoch_base, HashOut::ZERO)?;
        pw.set_hash_target(tgts.connection_mt_root_base, HashOut::ZERO)?;
        pw.set_hash_target(tgts.reputation_mt_root_base, HashOut::ZERO)?;
        pw.set_hash_target(tgts.revocation_smt_root_base, HashOut::ZERO)?;
        pw.set_hash_target(tgts.dest_base, HashOut::ZERO)?;

        // Canonical ordering of (id_x, id_a) for the connection commitment.
        let (min_id, max_id) =
            if inputs.id_x.elements[0].to_canonical_u64()
                <= inputs.id_a.elements[0].to_canonical_u64()
            {
                (inputs.id_x, inputs.id_a)
            } else {
                (inputs.id_a, inputs.id_x)
            };

        pw.set_hash_target(tgts.id_x, inputs.id_x)?;
        pw.set_hash_target(tgts.id_a, inputs.id_a)?;
        pw.set_hash_target(tgts.min_id, min_id)?;
        pw.set_hash_target(tgts.max_id, max_id)?;
        pw.set_hash_target(tgts.pk_a, inputs.pk_a)?;
        pw.set_hash_target(tgts.pk_b, inputs.pk_b)?;
        pw.set_hash_target(tgts.s_xa_cc, inputs.s_xa_cc)?;
        pw.set_hash_target(tgts.s_ab_cc, inputs.s_ab_cc)?;
        pw.set_target(tgts.r_a, F::from_canonical_u64(inputs.r_a))?;
        pw.set_hash_target(tgts.s_a_r, inputs.s_a_r)?;
        pw.set_target(tgts.alpha_scaled, F::from_canonical_u64(ALPHA_SCALED))?;
        pw.set_target(tgts.w_a_b, F::from_canonical_u64(inputs.w_a_b))?;

        // Connection Merkle inclusion proof.
        for (i, sib) in inputs.connection_mip_siblings.iter().enumerate() {
            pw.set_hash_target(tgts.connection_mip_siblings[i], to_hash(*sib))?;
        }
        let mut idx = inputs.connection_mip_leaf_index;
        for i in 0..self.conn_depth {
            pw.set_bool_target(tgts.connection_mip_index_bits[i], idx % 2 == 1)?;
            idx >>= 1;
        }

        // Revocation sparse Merkle non-inclusion proof (key bits derived in-circuit).
        for (i, sib) in inputs.revocation_mnip_siblings.iter().enumerate() {
            pw.set_hash_target(tgts.revocation_mnip_siblings[i], to_hash(*sib))?;
        }

        // Reputation Merkle inclusion proof.
        for (i, sib) in inputs.reputation_mip_siblings.iter().enumerate() {
            pw.set_hash_target(tgts.reputation_mip_siblings[i], to_hash(*sib))?;
        }
        let mut idx = inputs.reputation_mip_leaf_index;
        for i in 0..self.rep_depth {
            pw.set_bool_target(tgts.reputation_mip_index_bits[i], idx % 2 == 1)?;
            idx >>= 1;
        }

        self.circuit_data.prove(pw)
    }
}

/// Set all walk-witness targets to neutral zero values.
///
/// Required for `prove_base` (is_base_case=true): even though every walk
/// constraint is bypassed by the mux, every hash generator still needs its
/// input targets to be present in the partial witness.
fn set_neutral_walk_witnesses<F, const D: usize>(
    pw: &mut PartialWitness<F>,
    tgts: &RecursiveWalkTargets<D>,
    conn_depth: usize,
    smt_depth: usize,
    rep_depth: usize,
) -> Result<()>
where
    F: RichField + Extendable<D>,
{
    pw.set_hash_target(tgts.id_x, HashOut::ZERO)?;
    pw.set_hash_target(tgts.id_a, HashOut::ZERO)?;
    pw.set_hash_target(tgts.min_id, HashOut::ZERO)?;
    pw.set_hash_target(tgts.max_id, HashOut::ZERO)?;
    pw.set_hash_target(tgts.pk_a, HashOut::ZERO)?;
    pw.set_hash_target(tgts.pk_b, HashOut::ZERO)?;
    pw.set_hash_target(tgts.s_xa_cc, HashOut::ZERO)?;
    pw.set_hash_target(tgts.s_ab_cc, HashOut::ZERO)?;
    pw.set_target(tgts.r_a, F::ZERO)?;
    pw.set_hash_target(tgts.s_a_r, HashOut::ZERO)?;
    pw.set_target(tgts.alpha_scaled, F::ZERO)?;
    pw.set_target(tgts.w_a_b, F::ZERO)?;
    for i in 0..conn_depth {
        pw.set_hash_target(tgts.connection_mip_siblings[i], HashOut::ZERO)?;
        pw.set_bool_target(tgts.connection_mip_index_bits[i], false)?;
    }
    for i in 0..smt_depth {
        pw.set_hash_target(tgts.revocation_mnip_siblings[i], HashOut::ZERO)?;
    }
    for i in 0..rep_depth {
        pw.set_hash_target(tgts.reputation_mip_siblings[i], HashOut::ZERO)?;
        pw.set_bool_target(tgts.reputation_mip_index_bits[i], false)?;
    }
    Ok(())
}

fn to_hash<F: RichField>(arr: [u64; 4]) -> HashOut<F> {
    HashOut {
        elements: arr.map(F::from_canonical_u64),
    }
}
