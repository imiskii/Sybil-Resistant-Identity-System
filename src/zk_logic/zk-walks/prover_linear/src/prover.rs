//! WalkProver — builds circuit data once and generates base/step proofs.

use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;

use circuit_lib_linear::base_circuit::{BaseCircuit, BaseCircuitTargets};
use circuit_lib_linear::recursive_circuit::{RecursiveWalkCircuit, RecursiveWalkTargets};
use circuit_lib_linear::{ALPHA_SCALED, MAX_PATH_LEN};

/// Field-element index of `path_length` in the public-inputs array.
/// Must stay in sync with base_circuit.rs and recursive_circuit.rs.
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
///
/// Naming convention follows the circuit: id_x is the previous node, id_a is
/// the current prover, and pk_b / s_ab_cc are used to commit the next hop.
#[allow(clippy::too_many_arguments)]
pub struct StepInputs<F: RichField> {
    /// Previous node (its id_a from the last step, unlocks the dest commitment).
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

struct StepCircuit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    data: CircuitData<F, C, D>,
    targets: RecursiveWalkTargets<D>,
}

/// Holds pre-compiled circuit data for all hop depths.
///
/// Call [`WalkProver::setup`] once (expensive), then reuse [`prove_base`] /
/// [`prove_step`] freely. The prover builds:
/// - one base circuit (genesis, no inner proof),
/// - one recursive circuit per possible hop, up to [`MAX_PATH_LEN`].
///
/// [`step_circuits[i]`] verifies proofs produced at depth i:
/// - `step_circuits[0]` verifies base proofs,
/// - `step_circuits[k]` verifies `step_circuits[k-1]` proofs.
pub struct WalkProver<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    pub conn_depth: usize,
    pub smt_depth: usize,
    pub rep_depth: usize,
    base_data: CircuitData<F, C, D>,
    base_targets: BaseCircuitTargets,
    step_circuits: Vec<StepCircuit<F, C, D>>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>
    WalkProver<F, C, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    /// Build all circuit data for up to `MAX_PATH_LEN` hops.
    ///
    /// `conn_depth` / `rep_depth` are the Merkle tree heights used in every step;
    /// `smt_depth` is the sparse Merkle tree depth for revocations.
    /// These must match the actual trees used when generating proofs.
    pub fn setup(
        config: CircuitConfig,
        conn_depth: usize,
        smt_depth: usize,
        rep_depth: usize,
    ) -> Self {
        let (base_data, base_targets) = BaseCircuit::<F, D>::build::<C>(&config);

        // Build the chain of recursive circuits.
        // Each circuit[i] verifies proofs produced at depth i (base or step i-1).
        // We build them one at a time so that each circuit can reference the
        // compiled data of its predecessor.
        let mut step_data: Vec<CircuitData<F, C, D>> = Vec::with_capacity(MAX_PATH_LEN);
        let mut step_targets: Vec<RecursiveWalkTargets<D>> = Vec::with_capacity(MAX_PATH_LEN);

        for i in 0..MAX_PATH_LEN {
            let (d, t) = {
                let inner: &CircuitData<F, C, D> =
                    if i == 0 { &base_data } else { &step_data[i - 1] };
                RecursiveWalkCircuit::<F, D>::build::<C>(
                    &config, inner, conn_depth, smt_depth, rep_depth,
                )
            };
            step_data.push(d);
            step_targets.push(t);
        }

        let step_circuits = step_data
            .into_iter()
            .zip(step_targets)
            .map(|(data, targets)| StepCircuit { data, targets })
            .collect();

        Self {
            conn_depth,
            smt_depth,
            rep_depth,
            base_data,
            base_targets,
            step_circuits,
        }
    }

    /// Return the `CircuitData` for proofs that carry `path_length` as their
    /// public `path_length` field. Use this to select the right circuit when
    /// calling [`verify_walk_proof`].
    pub fn circuit_data_for_length(&self, path_length: usize) -> &CircuitData<F, C, D> {
        if path_length == 0 {
            &self.base_data
        } else {
            &self.step_circuits[path_length - 1].data
        }
    }

    /// Generate the genesis proof (path_length = 0, all walk state zeroed).
    pub fn prove_base(&self, inputs: BaseInputs<F>) -> Result<ProofWithPublicInputs<F, C, D>> {
        BaseCircuit::<F, D>::generate_proof::<C>(
            &self.base_data,
            &self.base_targets,
            inputs.epoch,
            inputs.connection_mt_root,
            inputs.reputation_mt_root,
            inputs.revocation_smt_root,
            inputs.dest,
        )
    }

    /// Extend a walk by one hop.
    ///
    /// Determines the correct step circuit from `path_length_old` in
    /// `prev_proof.public_inputs`, fills all witnesses, and returns the new proof.
    /// The resulting proof has `path_length = path_length_old + 1`.
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

        let step = &self.step_circuits[path_length_old];
        let inner_verifier = if path_length_old == 0 {
            &self.base_data.verifier_only
        } else {
            &self.step_circuits[path_length_old - 1].data.verifier_only
        };

        let tgts = &step.targets;
        let mut pw = PartialWitness::new();

        // Inner proof and its verifier data.
        pw.set_proof_with_pis_target(&tgts.inner_proof, &prev_proof)?;
        pw.set_verifier_data_target(&tgts.inner_verifier_data, inner_verifier)?;

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

        step.data.prove(pw)
    }
}

fn to_hash<F: RichField>(arr: [u64; 4]) -> HashOut<F> {
    HashOut {
        elements: arr.map(F::from_canonical_u64),
    }
}
