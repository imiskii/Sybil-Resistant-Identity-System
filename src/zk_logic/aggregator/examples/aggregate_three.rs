//! End-to-end aggregation demo: three real 3-hop walk proofs aggregated into one.
//!
//! Walk structure (three independent paths, all ending at the same aggregator):
//!
//!   Walk 1:  h(10) ──► h(11) ──► h(12) ──► AGG
//!   Walk 2:  h(20) ──► h(21) ──► h(22) ──► AGG
//!   Walk 3:  h(30) ──► h(31) ──► h(32) ──► AGG
//!
//!   AGG = h(0),  s_agg_cc = h(888),  epoch = h(42)
//!
//! Each walk has path_length = 3. AGG proves the final hop in every walk,
//! so nullifier[2] = Poseidon(AGG, epoch) is the same for all three proofs.
//! The aggregator's Constraint 4 checks only slots 0..path_length_req-1 = {0,1},
//! so this shared last-slot nullifier does not cause a collision.
//!
//! Run with:
//!   cargo run -p aggregator --example aggregate_three --release

#[path = "helpers/common.rs"] mod common;

use std::time::Instant;

use aggregator::prover::{AggregatorInputs, AggregatorProver};
use aggregator::verifier::verify_aggregated_proof;
use common::{cc, fmt_proof_size, h, print_circuit_stats, prove_walk, rc, to_hash, WalkHop};
use merkle_utils::merkle_tree::MerkleTree;
use merkle_utils::poseidon_hash::poseidon_hash;
use merkle_utils::sparse_merkle_tree::SparseMerkleTree;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::PrimeField64;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use prover_linear::prover::WalkProver;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

fn main() -> anyhow::Result<()> {
    // ── Identities ────────────────────────────────────────────────────────────
    let id_agg   = h(0);
    let s_agg_cc = h(888);
    let epoch    = h(42);

    // Walk 1: genesis=h(10), hop-1 prover=h(11), hop-2 prover=h(12)
    let id_x1 = h(10); let id_a1 = h(11); let id_b1 = h(12);
    // Walk 2: genesis=h(20), hop-1 prover=h(21), hop-2 prover=h(22)
    let id_x2 = h(20); let id_a2 = h(21); let id_b2 = h(22);
    // Walk 3: genesis=h(30), hop-1 prover=h(31), hop-2 prover=h(32)
    let id_x3 = h(30); let id_a3 = h(31); let id_b3 = h(32);

    // ── Connection salts ──────────────────────────────────────────────────────
    let s_x1a1 = h(110); let s_a1b1 = h(111); let s_b1agg = h(112);
    let s_x2a2 = h(120); let s_a2b2 = h(121); let s_b2agg = h(122);
    let s_x3a3 = h(130); let s_a3b3 = h(131); let s_b3agg = h(132);

    // ── Reputation values (× SCALE=100) and salts ────────────────────────────
    // IMPORTANT: The reputation formula uses field division (multiply by SCALE⁻¹),
    // not integer truncation.  Every intermediate product
    //   path_rep_old × 90 + r_a × w_a_b
    // must be exactly divisible by 100 to produce a small integer result.
    //
    // Walk 1: rep after hop1=80, hop2=120, hop3=171
    //   (0×90 + 80×100)/100=80  (80×90+60×80)/100=120  (120×90+70×90)/100=171
    // Walk 2: rep after hop1=50, hop2=120, hop3=171
    //   (0×90 + 50×100)/100=50  (50×90+75×100)/100=120  (120×90+70×90)/100=171
    // Walk 3: rep after hop1=90, hop2=100, hop3=153
    //   (0×90 + 90×100)/100=90  (90×90+95×20)/100=100  (100×90+70×90)/100=153
    // Total: 171 + 171 + 153 = 495
    let r_a1: u64 = 80; let s_a1r = h(210);
    let r_b1: u64 = 60; let s_b1r = h(211);
    let r_a2: u64 = 50; let s_a2r = h(220);
    let r_b2: u64 = 75; let s_b2r = h(221);
    let r_a3: u64 = 90; let s_a3r = h(230);
    let r_b3: u64 = 95; let s_b3r = h(231);
    let r_agg: u64 = 70; let s_aggr = h(299);

    // ── Edge weights (× SCALE=100) ────────────────────────────────────────────
    let w_a1b1: u64 = 100; let w_b1agg: u64 = 80;  // walk 1
    let w_a2b2: u64 = 100; let w_b2agg: u64 = 100; // walk 2
    let w_a3b3: u64 = 100; let w_b3agg: u64 = 20;  // walk 3
    let w_agg_self: u64 = 90; // AGG self-weight (same for all walks)

    // ── Connection Merkle tree ────────────────────────────────────────────────
    // 9 records: one per hop across all three walks.
    // Layout: [x1a1, a1b1, b1agg, x2a2, a2b2, b2agg, x3a3, a3b3, b3agg]
    let conn_leaves = vec![
        cc(id_x1, id_a1, s_x1a1),   // idx 0 — walk 1 hop 1
        cc(id_a1, id_b1, s_a1b1),   // idx 1 — walk 1 hop 2
        cc(id_b1, id_agg, s_b1agg), // idx 2 — walk 1 hop 3
        cc(id_x2, id_a2, s_x2a2),   // idx 3 — walk 2 hop 1
        cc(id_a2, id_b2, s_a2b2),   // idx 4 — walk 2 hop 2
        cc(id_b2, id_agg, s_b2agg), // idx 5 — walk 2 hop 3
        cc(id_x3, id_a3, s_x3a3),   // idx 6 — walk 3 hop 1
        cc(id_a3, id_b3, s_a3b3),   // idx 7 — walk 3 hop 2
        cc(id_b3, id_agg, s_b3agg), // idx 8 — walk 3 hop 3
    ];
    let conn_tree  = MerkleTree::new(conn_leaves);
    let conn_root  = conn_tree.root();
    let conn_depth = conn_tree.inclusion_proof(0).siblings.len();

    // ── Reputation Merkle tree ────────────────────────────────────────────────
    // 7 entries: A1, B1, A2, B2, A3, B3, AGG.
    // AGG's entry is reused by all three walks (same reputation proof for hop 3).
    let rep_leaves = vec![
        rc(id_a1, r_a1, s_a1r), // idx 0
        rc(id_b1, r_b1, s_b1r), // idx 1
        rc(id_a2, r_a2, s_a2r), // idx 2
        rc(id_b2, r_b2, s_b2r), // idx 3
        rc(id_a3, r_a3, s_a3r), // idx 4
        rc(id_b3, r_b3, s_b3r), // idx 5
        rc(id_agg, r_agg, s_aggr), // idx 6 — shared by all three walks
    ];
    let rep_tree  = MerkleTree::new(rep_leaves);
    let rep_root  = rep_tree.root();
    let rep_depth = rep_tree.inclusion_proof(0).siblings.len();

    // ── Revocation SMT (empty — no one is revoked) ────────────────────────────
    let smt_depth  = 8usize;
    let revoc_smt  = SparseMerkleTree::new(smt_depth);
    let revoc_root = revoc_smt.root();
    let revoc_sibs = revoc_smt.non_inclusion_proof(h(0)).siblings;

    println!("=== Tree parameters ===");
    println!("conn_depth={conn_depth}  rep_depth={rep_depth}  smt_depth={smt_depth}");
    println!("conn_root  = {:?}", conn_root);
    println!("rep_root   = {:?}", rep_root);
    println!("revoc_root = {:?}", revoc_root);

    // ── Build walk prover (compiles all inner circuits) ───────────────────────
    println!("\n=== Circuit compilation ===");
    let t = Instant::now();
    let config      = CircuitConfig::standard_recursion_config();
    let walk_prover = WalkProver::<F, C, D>::setup(config, conn_depth, smt_depth, rep_depth);
    println!("  Walk prover (all hop depths) : {:.2?}", t.elapsed());

    let inner_circuit_data = walk_prover.circuit_data_for_length(3);
    print_circuit_stats("inner walk circuit (len=3)", inner_circuit_data);

    let t = Instant::now();
    let agg_prover = AggregatorProver::<F, C, D, 3>::setup(inner_circuit_data, 3);
    println!("  Aggregator circuit (N=3)     : {:.2?}", t.elapsed());
    print_circuit_stats("aggregator circuit (N=3, len=3)", &agg_prover.circuit_data);

    // ── Prove three walks ─────────────────────────────────────────────────────
    println!("\n=== Proving walks ===");

    let genesis1 = poseidon_hash(&[id_x1, id_a1, s_x1a1, epoch]);
    let t = Instant::now();
    let proof1 = prove_walk::<F, C, D>(
        &walk_prover, epoch, conn_root, rep_root, revoc_root, genesis1,
        &[
            WalkHop { id_prev: id_x1, id_curr: id_a1, id_next: id_b1,
                      s_conn_in: s_x1a1, s_conn_out: s_a1b1,
                      r_curr: r_a1, s_rep_curr: s_a1r, w_curr_next: w_a1b1,
                      conn_mip: conn_tree.inclusion_proof(0), rep_mip: rep_tree.inclusion_proof(0) },
            WalkHop { id_prev: id_a1, id_curr: id_b1, id_next: id_agg,
                      s_conn_in: s_a1b1, s_conn_out: s_b1agg,
                      r_curr: r_b1, s_rep_curr: s_b1r, w_curr_next: w_b1agg,
                      conn_mip: conn_tree.inclusion_proof(1), rep_mip: rep_tree.inclusion_proof(1) },
            WalkHop { id_prev: id_b1, id_curr: id_agg, id_next: id_agg,
                      s_conn_in: s_b1agg, s_conn_out: s_agg_cc,
                      r_curr: r_agg, s_rep_curr: s_aggr, w_curr_next: w_agg_self,
                      conn_mip: conn_tree.inclusion_proof(2), rep_mip: rep_tree.inclusion_proof(6) },
        ],
        &revoc_sibs,
    )?;
    println!("  Walk 1  path_rep={}  proof={}  time={:.2?}", proof1.public_inputs[17].to_canonical_u64(), fmt_proof_size(&proof1), t.elapsed());

    let genesis2 = poseidon_hash(&[id_x2, id_a2, s_x2a2, epoch]);
    let t = Instant::now();
    let proof2 = prove_walk::<F, C, D>(
        &walk_prover, epoch, conn_root, rep_root, revoc_root, genesis2,
        &[
            WalkHop { id_prev: id_x2, id_curr: id_a2, id_next: id_b2,
                      s_conn_in: s_x2a2, s_conn_out: s_a2b2,
                      r_curr: r_a2, s_rep_curr: s_a2r, w_curr_next: w_a2b2,
                      conn_mip: conn_tree.inclusion_proof(3), rep_mip: rep_tree.inclusion_proof(2) },
            WalkHop { id_prev: id_a2, id_curr: id_b2, id_next: id_agg,
                      s_conn_in: s_a2b2, s_conn_out: s_b2agg,
                      r_curr: r_b2, s_rep_curr: s_b2r, w_curr_next: w_b2agg,
                      conn_mip: conn_tree.inclusion_proof(4), rep_mip: rep_tree.inclusion_proof(3) },
            WalkHop { id_prev: id_b2, id_curr: id_agg, id_next: id_agg,
                      s_conn_in: s_b2agg, s_conn_out: s_agg_cc,
                      r_curr: r_agg, s_rep_curr: s_aggr, w_curr_next: w_agg_self,
                      conn_mip: conn_tree.inclusion_proof(5), rep_mip: rep_tree.inclusion_proof(6) },
        ],
        &revoc_sibs,
    )?;
    println!("  Walk 2  path_rep={}  proof={}  time={:.2?}", proof2.public_inputs[17].to_canonical_u64(), fmt_proof_size(&proof2), t.elapsed());

    let genesis3 = poseidon_hash(&[id_x3, id_a3, s_x3a3, epoch]);
    let t = Instant::now();
    let proof3 = prove_walk::<F, C, D>(
        &walk_prover, epoch, conn_root, rep_root, revoc_root, genesis3,
        &[
            WalkHop { id_prev: id_x3, id_curr: id_a3, id_next: id_b3,
                      s_conn_in: s_x3a3, s_conn_out: s_a3b3,
                      r_curr: r_a3, s_rep_curr: s_a3r, w_curr_next: w_a3b3,
                      conn_mip: conn_tree.inclusion_proof(6), rep_mip: rep_tree.inclusion_proof(4) },
            WalkHop { id_prev: id_a3, id_curr: id_b3, id_next: id_agg,
                      s_conn_in: s_a3b3, s_conn_out: s_b3agg,
                      r_curr: r_b3, s_rep_curr: s_b3r, w_curr_next: w_b3agg,
                      conn_mip: conn_tree.inclusion_proof(7), rep_mip: rep_tree.inclusion_proof(5) },
            WalkHop { id_prev: id_b3, id_curr: id_agg, id_next: id_agg,
                      s_conn_in: s_b3agg, s_conn_out: s_agg_cc,
                      r_curr: r_agg, s_rep_curr: s_aggr, w_curr_next: w_agg_self,
                      conn_mip: conn_tree.inclusion_proof(8), rep_mip: rep_tree.inclusion_proof(6) },
        ],
        &revoc_sibs,
    )?;
    println!("  Walk 3  path_rep={}  proof={}  time={:.2?}", proof3.public_inputs[17].to_canonical_u64(), fmt_proof_size(&proof3), t.elapsed());

    // ── Aggregate ─────────────────────────────────────────────────────────────
    println!("\n=== Aggregation ===");
    let t = Instant::now();
    let agg_proof = agg_prover.prove(AggregatorInputs {
        inner_proofs:    [proof1, proof2, proof3],
        id_aggregator:   to_hash(id_agg),
        s_aggregator_cc: to_hash(s_agg_cc),
        path_length_req: 3,
    })?;
    println!("  Aggregated proof generated : proof={}  time={:.2?}", fmt_proof_size(&agg_proof), t.elapsed());

    // ── Verify ────────────────────────────────────────────────────────────────
    let t = Instant::now();
    let state = verify_aggregated_proof(&agg_prover.circuit_data, &agg_proof)?;
    println!("  Verification               : {:.2?}", t.elapsed());

    // ── Public state ──────────────────────────────────────────────────────────
    println!("\n=== Aggregated public state ===");
    println!("  id_aggregator:          {:?}", state.id_aggregator);
    println!("  epoch:                  {:?}", state.epoch);
    println!("  connection_mt_root:     {:?}", state.connection_mt_root);
    println!("  reputation_mt_root:     {:?}", state.reputation_mt_root);
    println!("  revocation_smt_root:    {:?}", state.revocation_smt_root);
    println!("  path_length_req:        {}", state.path_length_req);
    println!("  total_path_reputation:  {}", state.total_path_reputation);

    // ── Assertions ────────────────────────────────────────────────────────────
    assert_eq!(state.path_length_req, 3,   "expected path_length_req == 3");
    assert_eq!(state.id_aggregator,   id_agg, "id_aggregator mismatch");
    // Walk 1: 171, Walk 2: 171, Walk 3: 153  →  total = 495
    assert_eq!(state.total_path_reputation, 495,
        "expected total_path_reputation == 495 (171+171+153)");

    println!("\nAll assertions passed.");
    Ok(())
}
