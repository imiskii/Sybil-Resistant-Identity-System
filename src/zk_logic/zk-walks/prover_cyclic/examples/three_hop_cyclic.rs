//! End-to-end 3-hop ZK walk demo.
//!
//! Walk structure:
//!   X (genesis anchor) ──s_xa──> A ──s_ab──> B ──s_bc──> C
//!
//! Roles:
//!   - X:  dummy genesis node. Creates the base proof that hands the walk to A.
//!   - A:  receives genesis proof, proves X-A connection, adds herself to path.
//!   - B:  receives A's proof, proves A-B connection, adds himself to path.
//!   - C:  receives B's proof, proves B-C connection, adds herself to path (final).
//!
//! Expected outcome:
//!   path_length = 3
//!   path_reputation = (0*90+80*100)/100 = 80 after hop 1
//!                   = (80*90+60*80)/100  = 120 after hop 2
//!                   = (120*90+70*90)/100 = 171 after hop 3

use std::time::Instant;

use merkle_utils::merkle_tree::MerkleTree;
use merkle_utils::poseidon_hash::poseidon_hash;
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

fn h(v: u64) -> [u64; 4] {
    [v, 0, 0, 0]
}
fn to_hash(arr: [u64; 4]) -> HashOut<F> {
    HashOut { elements: arr.map(F::from_canonical_u64) }
}

fn main() {
    // ── Identities ────────────────────────────────────────────────────────────
    let id_x = h(0);   // genesis anchor (dummy)
    let id_a = h(1);   // user A
    let id_b = h(2);   // user B
    let id_c = h(3);   // user C

    // Connection salts
    let s_xa = h(20); // X-A
    let s_ab = h(21); // A-B
    let s_bc = h(22); // B-C
    let s_cc = h(23); // C-C (final dest: C points to herself)

    // Reputation salts
    let s_a_rep = h(30);
    let s_b_rep = h(31);
    let s_c_rep = h(32);

    let epoch = h(100);

    // Reputation values (× SCALE=100)
    let r_a: u64 = 80; // 0.80
    let r_b: u64 = 60; // 0.60
    let r_c: u64 = 70; // 0.70

    // Edge weights (× SCALE=100)
    let w_ab: u64 = 100; // A→B: 1.00
    let w_bc: u64 = 80;  // B→C: 0.80
    let w_cc: u64 = 90;  // C→C: 0.90 (final, arbitrary)

    // ── Connection Merkle tree ────────────────────────────────────────────────
    // Three undirected connection records: X-A, A-B, B-C.
    // Canonical ordering: min(id0, id1) || max(id0, id1) by elements[0].
    let canon = |a: [u64; 4], b: [u64; 4]| -> ([u64; 4], [u64; 4]) {
        if a[0] <= b[0] { (a, b) } else { (b, a) }
    };
    let (mn_xa, mx_xa) = canon(id_x, id_a);
    let (mn_ab, mx_ab) = canon(id_a, id_b);
    let (mn_bc, mx_bc) = canon(id_b, id_c);

    let cc_xa_base = poseidon_hash(&[mn_xa, mx_xa]);
    let cc_ab_base = poseidon_hash(&[mn_ab, mx_ab]);
    let cc_bc_base = poseidon_hash(&[mn_bc, mx_bc]);

    let cc_xa_salted = poseidon_hash(&[cc_xa_base, s_xa]);
    let cc_ab_salted = poseidon_hash(&[cc_ab_base, s_ab]);
    let cc_bc_salted = poseidon_hash(&[cc_bc_base, s_bc]);

    // 3 leaves → padded to 4 → tree height = 2  ⟹  conn_depth = 2
    let conn_tree = MerkleTree::new(vec![cc_xa_salted, cc_ab_salted, cc_bc_salted]);
    let conn_root = conn_tree.root();
    let conn_mip_xa = conn_tree.inclusion_proof(0);
    let conn_mip_ab = conn_tree.inclusion_proof(1);
    let conn_mip_bc = conn_tree.inclusion_proof(2);
    let conn_depth = conn_mip_xa.siblings.len(); // 2

    // ── Reputation Merkle tree ────────────────────────────────────────────────
    let rc_a = poseidon_hash(&[id_a, h(r_a), s_a_rep]);
    let rc_b = poseidon_hash(&[id_b, h(r_b), s_b_rep]);
    let rc_c = poseidon_hash(&[id_c, h(r_c), s_c_rep]);

    // 3 leaves → padded to 4 → rep_depth = 2
    let rep_tree = MerkleTree::new(vec![rc_a, rc_b, rc_c]);
    let rep_root = rep_tree.root();
    let rep_mip_a = rep_tree.inclusion_proof(0);
    let rep_mip_b = rep_tree.inclusion_proof(1);
    let rep_mip_c = rep_tree.inclusion_proof(2);
    let rep_depth = rep_mip_a.siblings.len(); // 2

    // ── Revocation SMT (empty) ────────────────────────────────────────────────
    let smt_depth = 8usize;
    let revoc_smt = SparseMerkleTree::new(smt_depth);
    let revoc_root = revoc_smt.root();
    // Empty SMT: all siblings are depth-level empty hashes, path-independent.
    let revoc_ni = revoc_smt.non_inclusion_proof(h(0));

    println!("=== Tree parameters ===");
    println!("conn_depth={conn_depth}  rep_depth={rep_depth}  smt_depth={smt_depth}");
    println!("conn_root  = {:?}", conn_root);
    println!("rep_root   = {:?}", rep_root);
    println!("revoc_root = {:?}", revoc_root);

    // ── Build prover (compiles all circuits) ──────────────────────────────────
    println!("\n=== Circuit compilation ===");
    let t_setup = Instant::now();
    let config = CircuitConfig::standard_recursion_config();
    let walk_prover = WalkProver::<F, C, D>::setup(config, conn_depth, smt_depth, rep_depth);
    let setup_time = t_setup.elapsed();

    // Single unified circuit covers genesis and all hops.
    print_circuit_stats("Unified walk circuit", walk_prover.circuit_data_for_length(0));
    println!("Total setup time: {:.2?}", setup_time);

    // ── Genesis proof (X bootstraps the walk, pointing dest to A) ────────────
    // X sets dest = Poseidon(id_x, id_a, s_xa, epoch) so that constraint ①
    // in hop 1 is satisfied: A unlocks this commitment using (id_x, id_a, s_xa).
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

    // ── Hop 1: User A extends the walk (proves X-A connection) ───────────────
    // id_x=X, id_a=A; unlocks dest from genesis; commits dest_new=Poseidon(A,id_B,s_ab,epoch).
    let t1 = Instant::now();
    let hop1_proof = walk_prover
        .prove_step(
            base_proof,
            StepInputs {
                id_x: to_hash(id_x),
                id_a: to_hash(id_a),
                id_b: to_hash(id_b),
                s_xa_cc: to_hash(s_xa),
                s_ab_cc: to_hash(s_ab),
                r_a,
                s_a_r: to_hash(s_a_rep),
                w_a_b: w_ab,
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

    // ── Hop 2: User B extends the walk (proves A-B connection) ───────────────
    // id_x=A, id_a=B; unlocks dest_new from hop 1; commits dest_new=Poseidon(B,id_C,s_bc,epoch).
    let t2 = Instant::now();
    let hop2_proof = walk_prover
        .prove_step(
            hop1_proof,
            StepInputs {
                id_x: to_hash(id_a),
                id_a: to_hash(id_b),
                id_b: to_hash(id_c),
                s_xa_cc: to_hash(s_ab),
                s_ab_cc: to_hash(s_bc),
                r_a: r_b,
                s_a_r: to_hash(s_b_rep),
                w_a_b: w_bc,
                connection_mip_siblings: conn_mip_ab.siblings.to_vec(),
                connection_mip_leaf_index: conn_mip_ab.leaf_index,
                revocation_mnip_siblings: revoc_ni.siblings.to_vec(),
                reputation_mip_siblings: rep_mip_b.siblings.to_vec(),
                reputation_mip_leaf_index: rep_mip_b.leaf_index,
            },
        )
        .expect("hop-2 proof (B) failed");
    println!(
        "[B]  Hop 2 proof    — path_length={}  path_rep={}  time={:.2?}",
        hop2_proof.public_inputs[16], hop2_proof.public_inputs[17], t2.elapsed()
    );

    // ── Hop 3: User C extends the walk (proves B-C connection) ───────────────
    // id_x=B, id_a=C; id_b=id_C (C points to herself as the final node).
    let t3 = Instant::now();
    let hop3_proof = walk_prover
        .prove_step(
            hop2_proof,
            StepInputs {
                id_x: to_hash(id_b),
                id_a: to_hash(id_c),
                id_b: to_hash(id_c), // final node: dest_new = Poseidon(C, id_C, s_cc, epoch)
                s_xa_cc: to_hash(s_bc),
                s_ab_cc: to_hash(s_cc),
                r_a: r_c,
                s_a_r: to_hash(s_c_rep),
                w_a_b: w_cc,
                connection_mip_siblings: conn_mip_bc.siblings.to_vec(),
                connection_mip_leaf_index: conn_mip_bc.leaf_index,
                revocation_mnip_siblings: revoc_ni.siblings.to_vec(),
                reputation_mip_siblings: rep_mip_c.siblings.to_vec(),
                reputation_mip_leaf_index: rep_mip_c.leaf_index,
            },
        )
        .expect("hop-3 proof (C) failed");
    println!(
        "[C]  Hop 3 proof    — path_length={}  path_rep={}  time={:.2?}",
        hop3_proof.public_inputs[16], hop3_proof.public_inputs[17], t3.elapsed()
    );

    // ── Verify final proof ────────────────────────────────────────────────────
    let t_ver = Instant::now();
    let circuit_data = walk_prover.circuit_data_for_length(0);
    let state = verify_walk_proof(circuit_data, &hop3_proof).expect("verification failed");
    println!("[V]  Verification   — time={:.2?}", t_ver.elapsed());

    // ── Print decoded public state ────────────────────────────────────────────
    println!("\n=== Walk public state ===");
    println!("epoch:            {:?}", state.epoch);
    println!("conn_root:        {:?}", state.connection_mt_root);
    println!("rep_root:         {:?}", state.reputation_mt_root);
    println!("revoc_root:       {:?}", state.revocation_smt_root);
    println!("path_length:      {}", state.path_length);
    println!("path_reputation:  {} (raw × SCALE=100; divide by 100 for float)",
        state.path_reputation);
    for (i, n) in state.nullifiers.iter().enumerate() {
        println!("nullifiers[{}]:    {:?}", i, n);
    }
    println!("dest:             {:?}", state.dest);

    // ── Assertions ────────────────────────────────────────────────────────────
    assert_eq!(state.path_length, 3, "expected 3 hops");
    assert!(state.path_reputation > 0, "path_reputation must be > 0");

    // path_rep after hop 1: (0*90 + 80*100)/100 = 80
    // path_rep after hop 2: (80*90 + 60*80)/100  = (7200+4800)/100 = 120
    // path_rep after hop 3: (120*90 + 70*90)/100 = (10800+6300)/100 = 171
    assert_eq!(state.path_reputation, 171, "expected path_reputation = 171");

    println!("\nAll assertions passed. path_length={}, path_reputation={}",
        state.path_length, state.path_reputation);
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
