//! Shared helpers for aggregator examples.
//!
//! Import with:  `#[path = "common.rs"] mod common;`

use anyhow::Result;
use merkle_utils::merkle_tree::MerkleInclusionProof;
use merkle_utils::poseidon_hash::poseidon_hash;
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use prover_linear::prover::{BaseInputs, StepInputs, WalkProver};

// ─── Hash helpers ─────────────────────────────────────────────────────────────

pub fn h(v: u64) -> [u64; 4] {
    [v, 0, 0, 0]
}

pub fn to_hash<F: Field>(arr: [u64; 4]) -> HashOut<F> {
    HashOut { elements: arr.map(F::from_canonical_u64) }
}

/// Salted connection commitment: Poseidon(Poseidon(min(a,b), max(a,b)), salt).
pub fn cc(id_a: [u64; 4], id_b: [u64; 4], salt: [u64; 4]) -> [u64; 4] {
    let (mn, mx) = if id_a[0] <= id_b[0] { (id_a, id_b) } else { (id_b, id_a) };
    poseidon_hash(&[poseidon_hash(&[mn, mx]), salt])
}

/// Reputation commitment: Poseidon(id, h(rep_value), salt).
pub fn rc(id: [u64; 4], rep: u64, salt: [u64; 4]) -> [u64; 4] {
    poseidon_hash(&[id, h(rep), salt])
}

// ─── Circuit stats ────────────────────────────────────────────────────────────

pub fn fmt_proof_size<F, C, const D: usize>(proof: &ProofWithPublicInputs<F, C, D>) -> String
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    let bytes = proof.to_bytes().len();
    if bytes >= 1 << 20 {
        format!("{:.1} MB", bytes as f64 / (1u64 << 20) as f64)
    } else {
        format!("{} KB", bytes / 1024)
    }
}

pub fn print_circuit_stats<F, C, const D: usize>(label: &str, data: &CircuitData<F, C, D>)
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    let degree_bits = data.common.degree_bits();
    let rows = 1usize << degree_bits;
    let num_wires = data.common.config.num_wires;
    let trace_bytes = rows * num_wires * 8; // GoldilocksField = u64 = 8 bytes
    let size_str = if trace_bytes >= 1 << 20 {
        format!("{:.1} MB", trace_bytes as f64 / (1u64 << 20) as f64)
    } else {
        format!("{} KB", trace_bytes / 1024)
    };
    let num_pis = data.common.num_public_inputs;
    println!("  [{label}]");
    println!("    degree_bits   : {degree_bits}");
    println!("    circuit_size  : {rows} rows × {num_wires} wires, trace={size_str}");
    println!("    public_inputs : {num_pis}");
}

// ─── Generic walk proving ──────────────────────────────────────────────────────

/// Inputs for a single hop.
pub struct WalkHop {
    /// ID of the participant who proved the previous hop (the "x" in StepInputs).
    pub id_prev:     [u64; 4],
    /// ID of the participant proving this hop ("a").
    pub id_curr:     [u64; 4],
    /// ID of the next destination ("b").
    pub id_next:     [u64; 4],
    /// Connection salt for the (prev, curr) edge — used to verify the incoming dest.
    pub s_conn_in:   [u64; 4],
    /// Connection salt for the (curr, next) edge — used to compute the next dest.
    pub s_conn_out:  [u64; 4],
    pub r_curr:      u64,
    pub s_rep_curr:  [u64; 4],
    pub w_curr_next: u64,
    /// Merkle inclusion proof for the (prev, curr) connection.
    pub conn_mip:    MerkleInclusionProof,
    /// Merkle inclusion proof for curr's reputation entry.
    pub rep_mip:     MerkleInclusionProof,
}

/// Prove a multi-hop walk.
///
/// `genesis_dest`: the initial dest committed by the genesis participant X.
///   Computed as `poseidon_hash(&[id_x, id_first_prover, s_conn_first, epoch])`.
///
/// `hops`: one entry per hop (hop 1 through hop N = the last hop by AGG).
///
/// `revoc_sibs`: non-inclusion siblings from the revocation SMT, shared across hops.
pub fn prove_walk<F, C, const D: usize>(
    walk_prover: &WalkProver<F, C, D>,
    epoch:        [u64; 4],
    conn_root:    [u64; 4],
    rep_root:     [u64; 4],
    revoc_root:   [u64; 4],
    genesis_dest: [u64; 4],
    hops:         &[WalkHop],
    revoc_sibs:   &[[u64; 4]],
) -> Result<ProofWithPublicInputs<F, C, D>>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    let base = walk_prover.prove_base(BaseInputs {
        epoch:               to_hash(epoch),
        connection_mt_root:  to_hash(conn_root),
        reputation_mt_root:  to_hash(rep_root),
        revocation_smt_root: to_hash(revoc_root),
        dest:                to_hash(genesis_dest),
    })?;

    let mut proof = base;
    for hop in hops {
        proof = walk_prover.prove_step(proof, StepInputs {
            id_x:     to_hash(hop.id_prev),
            id_a:     to_hash(hop.id_curr),
            id_b:     to_hash(hop.id_next),
            s_xa_cc:  to_hash(hop.s_conn_in),
            s_ab_cc:  to_hash(hop.s_conn_out),
            r_a:      hop.r_curr,
            s_a_r:    to_hash(hop.s_rep_curr),
            w_a_b:    hop.w_curr_next,
            connection_mip_siblings:   hop.conn_mip.siblings.clone(),
            connection_mip_leaf_index: hop.conn_mip.leaf_index,
            revocation_mnip_siblings:  revoc_sibs.to_vec(),
            reputation_mip_siblings:   hop.rep_mip.siblings.clone(),
            reputation_mip_leaf_index: hop.rep_mip.leaf_index,
        })?;
    }
    Ok(proof)
}
