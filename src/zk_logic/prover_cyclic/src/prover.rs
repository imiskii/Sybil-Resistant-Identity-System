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
    pub dest: HashOut<F>,
}

/// Inputs needed to prove one recursive walk step.
#[allow(clippy::too_many_arguments)]
pub struct StepInputs<F: RichField> {
    pub id_x: HashOut<F>,
    pub id_a: HashOut<F>,
    pub id_b: HashOut<F>,
    pub s_xa_cc: HashOut<F>,
    pub s_ab_cc: HashOut<F>,
    pub r_a: u64,
    pub s_a_r: HashOut<F>,
    pub w_a_b: u64,
    pub connection_mip_siblings: Vec<[u64; 4]>,
    pub connection_mip_leaf_index: usize,
    pub revocation_mnip_siblings: Vec<[u64; 4]>,
    pub reputation_mip_siblings: Vec<[u64; 4]>,
    pub reputation_mip_leaf_index: usize,
}

/// Holds the single pre-compiled cyclic circuit for all hops.
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
    /// `conn_depth` / `rep_depth` are the Merkle tree heights; `smt_depth` is the
    /// sparse Merkle tree depth for revocations.
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

    /// Return the circuit data.
    /// `_path_length` is ignored; the parameter is kept for API compatibility.
    pub fn circuit_data_for_length(&self, _path_length: usize) -> &CircuitData<F, C, D> {
        &self.circuit_data
    }

    /// Generate the genesis proof (path_length = 0).
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

        pw.set_hash_target(tgts.epoch_base, inputs.epoch)?;
        pw.set_hash_target(tgts.connection_mt_root_base, inputs.connection_mt_root)?;
        pw.set_hash_target(tgts.reputation_mt_root_base, inputs.reputation_mt_root)?;
        pw.set_hash_target(tgts.revocation_smt_root_base, inputs.revocation_smt_root)?;
        pw.set_hash_target(tgts.dest_base, inputs.dest)?;

        set_neutral_walk_witnesses(&mut pw, tgts, self.conn_depth, self.smt_depth, self.rep_depth)?;
        self.circuit_data.prove(pw)
    }

    /// Extend a walk by one hop.
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

        pw.set_hash_target(tgts.epoch_base, HashOut::ZERO)?;
        pw.set_hash_target(tgts.connection_mt_root_base, HashOut::ZERO)?;
        pw.set_hash_target(tgts.reputation_mt_root_base, HashOut::ZERO)?;
        pw.set_hash_target(tgts.revocation_smt_root_base, HashOut::ZERO)?;
        pw.set_hash_target(tgts.dest_base, HashOut::ZERO)?;

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
        pw.set_hash_target(tgts.id_b, inputs.id_b)?;
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
    pw.set_hash_target(tgts.id_b, HashOut::ZERO)?;
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
