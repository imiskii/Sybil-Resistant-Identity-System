//! Large-trie benchmark — cyclic prover, 1-hop walk.
//!
//! Purpose: measure circuit compilation time and proof generation time when
//! the Merkle trees have realistic depths, as they would in a deployed system.
//! The walk itself is the simplest possible (one hop), so all overhead comes
//! from the Merkle proof verification inside the circuit.
//!
//! Tree parameters (chosen to reflect a large-scale deployment):
//!   conn_depth  = 20  →  up to 2^20 ≈ 1 M connection records per epoch
//!   rep_depth   = 20  →  up to 2^20 ≈ 1 M reputation records per epoch
//!   smt_depth   = 32  →  up to 2^32 ≈ 4 B revocation entries
//!
//! How the large tries are simulated:
//!   The `SparseIndexedMerkleTree` (merkle_utils) stores only the nodes on
//!   explicitly inserted leaf paths. All absent positions use a precomputed
//!   empty-subtree hash for their level — exactly what a real off-chain
//!   indexer returns. The circuit receives proofs with the correct number of
//!   siblings (depth = 20 or 32) regardless of how many real leaves exist.

use std::time::Instant;

use merkle_utils::poseidon_hash::poseidon_hash;
use merkle_utils::sparse_indexed_merkle_tree::SparseIndexedMerkleTree; // for examples only
use merkle_utils::sparse_merkle_tree::SparseMerkleTree;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use prover_cyclic::prover::{BaseInputs, StepInputs, WalkProver};
use prover_cyclic::verifier::verify_walk_proof;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

// Tree depth parameters — the only thing the circuit cares about.
const CONN_DEPTH: usize = 20;
const REP_DEPTH: usize = 20;
const SMT_DEPTH: usize = 32;

fn h(v: u64) -> [u64; 4] {
    [v, 0, 0, 0]
}
fn to_hash(arr: [u64; 4]) -> HashOut<F> {
    HashOut { elements: arr.map(F::from_canonical_u64) }
}

fn main() {
    // ── Identities ────────────────────────────────────────────────────────────
    let id_x = h(0); // genesis anchor (dummy)
    let id_a = h(1); // user A

    // Salts
    let s_xa  = h(20); // X-A connection salt
    let s_aa  = h(21); // A-A (final dest: A points to herself)
    let s_a_rep = h(30); // A's reputation salt

    let epoch = h(100);

    let r_a: u64  = 80;  // A's reputation × SCALE=100  (0.80)
    let w_xa: u64 = 100; // edge weight X→A × SCALE=100 (1.00)

    // ── Connection tree (depth=20, sparse) ───────────────────────────────────
    // Canonical ordering: min(id0, id1) ∥ max(id0, id1) by elements[0].
    let canon = |a: [u64; 4], b: [u64; 4]| -> ([u64; 4], [u64; 4]) {
        if a[0] <= b[0] { (a, b) } else { (b, a) }
    };
    let (mn_xa, mx_xa) = canon(id_x, id_a);
    let cc_xa = poseidon_hash(&[poseidon_hash(&[mn_xa, mx_xa]), s_xa]);

    // Insert the single real connection at leaf index 0; all 2^20-1 other
    // positions are implicitly empty (precomputed empty-subtree hashes).
    let mut conn_tree = SparseIndexedMerkleTree::new(CONN_DEPTH);
    conn_tree.insert(0, cc_xa);
    let conn_root = conn_tree.root();
    let conn_mip_xa = conn_tree.inclusion_proof(0);
    // conn_mip_xa.siblings has exactly CONN_DEPTH=20 entries.

    // ── Reputation tree (depth=20, sparse) ───────────────────────────────────
    let rc_a = poseidon_hash(&[id_a, h(r_a), s_a_rep]);
    let mut rep_tree = SparseIndexedMerkleTree::new(REP_DEPTH);
    rep_tree.insert(0, rc_a);
    let rep_root = rep_tree.root();
    let rep_mip_a = rep_tree.inclusion_proof(0);
    // rep_mip_a.siblings has exactly REP_DEPTH=20 entries.

    // ── Revocation SMT (depth=32, empty) ─────────────────────────────────────
    // No revocations; all siblings in the non-inclusion proof are precomputed
    // empty-subtree hashes — the same as in the sparse indexed trees above.
    let revoc_smt = SparseMerkleTree::new(SMT_DEPTH);
    let revoc_root = revoc_smt.root();
    let revoc_ni = revoc_smt.non_inclusion_proof(h(0));
    // revoc_ni.siblings has exactly SMT_DEPTH=32 entries.

    println!("=== Tree parameters ===");
    println!("conn_depth={CONN_DEPTH}  rep_depth={REP_DEPTH}  smt_depth={SMT_DEPTH}");
    println!("conn siblings:  {}", conn_mip_xa.siblings.len());
    println!("rep  siblings:  {}", rep_mip_a.siblings.len());
    println!("revoc siblings: {}", revoc_ni.siblings.len());
    println!("conn_root  = {:?}", conn_root);
    println!("rep_root   = {:?}", rep_root);
    println!("revoc_root = {:?}", revoc_root);

    // ── Build prover (compiles the unified circuit once) ──────────────────────
    println!("\n=== Circuit compilation ===");
    let t_setup = Instant::now();
    let config = CircuitConfig::standard_recursion_config();
    let walk_prover = WalkProver::<F, C, D>::setup(config, CONN_DEPTH, SMT_DEPTH, REP_DEPTH);
    let setup_time = t_setup.elapsed();

    print_circuit_stats("Unified walk circuit", walk_prover.circuit_data_for_length(0));
    println!("Total setup time: {:.2?}", setup_time);

    // ── Genesis proof (X bootstraps the walk, dest points to A) ──────────────
    let dest_genesis = poseidon_hash(&[id_x, id_a, s_xa, epoch]);

    println!("\n=== Proving ===");
    let t0 = Instant::now();
    let base_proof = walk_prover
        .prove_base(BaseInputs {
            epoch: to_hash(epoch),
            connection_mt_root: to_hash(conn_root),
            reputation_mt_root: to_hash(rep_root),
            revocation_smt_root: to_hash(revoc_root),
            dest: to_hash(dest_genesis),
        })
        .expect("genesis proof failed");
    println!("[X]  Genesis proof  — path_length={}  time={:.2?}", base_proof.public_inputs[16], t0.elapsed());

    // ── Hop 1: A proves X-A connection; dest_new points to A (final) ─────────
    let t1 = Instant::now();
    let hop1_proof = walk_prover
        .prove_step(
            base_proof,
            StepInputs {
                id_x: to_hash(id_x),
                id_a: to_hash(id_a),
                id_b: to_hash(id_a), // A is the final node; she points to herself
                s_xa_cc: to_hash(s_xa),
                s_ab_cc: to_hash(s_aa),
                r_a,
                s_a_r: to_hash(s_a_rep),
                w_a_b: w_xa,
                connection_mip_siblings: conn_mip_xa.siblings.to_vec(),
                connection_mip_leaf_index: conn_mip_xa.leaf_index,
                revocation_mnip_siblings: revoc_ni.siblings.to_vec(),
                reputation_mip_siblings: rep_mip_a.siblings.to_vec(),
                reputation_mip_leaf_index: rep_mip_a.leaf_index,
            },
        )
        .expect("hop-1 proof (A) failed");
    println!(
        "[A]  Hop 1 proof    — path_length={}  path_rep={}  time={:.2?}",
        hop1_proof.public_inputs[16], hop1_proof.public_inputs[17], t1.elapsed()
    );

    // ── Verify ────────────────────────────────────────────────────────────────
    let t_ver = Instant::now();
    let circuit_data = walk_prover.circuit_data_for_length(0);
    let state = verify_walk_proof(circuit_data, &hop1_proof).expect("verification failed");
    println!("[V]  Verification   — time={:.2?}", t_ver.elapsed());

    // ── Public state ──────────────────────────────────────────────────────────
    println!("\n=== Walk public state ===");
    println!("epoch:            {:?}", state.epoch);
    println!("conn_root:        {:?}", state.connection_mt_root);
    println!("rep_root:         {:?}", state.reputation_mt_root);
    println!("revoc_root:       {:?}", state.revocation_smt_root);
    println!("path_length:      {}", state.path_length);
    println!("path_reputation:  {} (raw × SCALE=100)", state.path_reputation);
    println!("dest:             {:?}", state.dest);

    // path_rep after hop 1: (0*90 + 80*100)/100 = 80
    assert_eq!(state.path_length, 1, "expected 1 hop");
    assert_eq!(state.path_reputation, 80, "expected path_reputation = 80");

    println!("\nAll assertions passed.");
}

fn print_circuit_stats(
    label: &str,
    data: &plonky2::plonk::circuit_data::CircuitData<F, C, D>,
) {
    let d = data.common.degree_bits();
    let rows = 1usize << d;
    let gate_constraints = data.common.num_gate_constraints;
    let public_inputs = data.common.num_public_inputs;
    println!(
        "  {label}: degree_bits={d} ({rows} rows)  gate_constraints={gate_constraints}  public_inputs={public_inputs}"
    );
}
