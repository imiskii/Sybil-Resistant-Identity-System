//! End-to-end aggregation demo: six real 6-hop walk proofs aggregated into one.
//!
//! Walk structure (six independent paths, all ending at the same aggregator):
//!
//!   Walk i:  X_i ──► A_i ──► B_i ──► C_i ──► D_i ──► E_i ──► AGG
//!   for i = 1..6
//!
//!   AGG = h(0),  s_agg_cc = h(888),  epoch = h(42)
//!   Walk i identities: X=h(i*100), A=h(i*100+1), B=h(i*100+2), C=h(i*100+3),
//!                      D=h(i*100+4), E=h(i*100+5)
//!
//! All walks share:
//!   - Edge weights: all w = 100
//!   - Rep values: A=50, B=45, C=69, D=75, E=81, AGG=70
//!   - Rep formula (path_rep_old*90 + r*100)/100 must be integer at every step:
//!       hop1=50  hop2=90  hop3=150  hop4=210  hop5=270  hop6=313
//!   - path_rep per walk = 313
//!   - total_path_reputation = 6 × 313 = 1878
//!
//! AGG proves the final hop (hop 6) in every walk, so nullifier[5] is identical
//! across all walks. Constraint 4 checks only slots 0..4 (active_slots = 5).
//!
//! Run with:
//!   cargo run -p aggregator --example aggregate_six --release

#[path = "helpers/common.rs"] mod common;

use std::time::Instant;

use aggregator::prover::{AggregatorInputs, AggregatorProver};
use aggregator::verifier::verify_aggregated_proof;
use common::{cc, h, print_circuit_stats, prove_walk, rc, to_hash, WalkHop};
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

// Number of walks and hops (must match AggregatorProver generic params).
const N: usize = 6;
const L: u64   = 6;

fn main() -> anyhow::Result<()> {
    // ── Shared identities ─────────────────────────────────────────────────────
    let id_agg   = h(0);
    let s_agg_cc = h(888);
    let epoch    = h(42);
    let s_aggr   = h(9999); // AGG reputation salt (shared across all walks)
    let r_agg: u64 = 70;

    // ── Per-walk identities ───────────────────────────────────────────────────
    // Walk i (1-indexed): participants h(i*100 + 0..5), AGG = h(0).
    // id_x[i-1] = genesis, id_a..id_e[i-1] = hop provers 1-5, AGG proves hop 6.
    let id_x: [[u64; 4]; N] = core::array::from_fn(|i| h((i as u64 + 1) * 100));
    let id_a: [[u64; 4]; N] = core::array::from_fn(|i| h((i as u64 + 1) * 100 + 1));
    let id_b: [[u64; 4]; N] = core::array::from_fn(|i| h((i as u64 + 1) * 100 + 2));
    let id_c: [[u64; 4]; N] = core::array::from_fn(|i| h((i as u64 + 1) * 100 + 3));
    let id_d: [[u64; 4]; N] = core::array::from_fn(|i| h((i as u64 + 1) * 100 + 4));
    let id_e: [[u64; 4]; N] = core::array::from_fn(|i| h((i as u64 + 1) * 100 + 5));

    // ── Connection salts: s[walk][hop] = h((walk+1)*1000 + hop*10) ───────────
    // hop indices 0=XA, 1=AB, 2=BC, 3=CD, 4=DE, 5=E-AGG
    let s_conn: [[[u64; 4]; 6]; N] =
        core::array::from_fn(|w| core::array::from_fn(|hop| h((w as u64 + 1) * 1000 + hop as u64 * 10)));

    // ── Reputation values (all walks share same rep structure) ────────────────
    // All edge weights = 100.
    // Rep formula: path_rep_new = (path_rep_old*90 + r_curr*100) / 100
    // Values chosen so every intermediate product is divisible by 100:
    //   hop1: (0*90 + 50*100)/100 = 50
    //   hop2: (50*90 + 45*100)/100 = 90
    //   hop3: (90*90 + 69*100)/100 = 150
    //   hop4: (150*90 + 75*100)/100 = 210
    //   hop5: (210*90 + 81*100)/100 = 270
    //   hop6: (270*90 + 70*100)/100 = 313
    let r_hops:  [u64; 5] = [50, 45, 69, 75, 81]; // reps for A, B, C, D, E
    let w_all: u64 = 100;

    // Reputation salts: s_rep[walk][hop] = h((walk+1)*1000 + hop*10 + 5)
    let s_rep: [[[u64; 4]; 5]; N] =
        core::array::from_fn(|w| core::array::from_fn(|hop| h((w as u64 + 1) * 1000 + hop as u64 * 10 + 5)));

    // ── Connection Merkle tree ────────────────────────────────────────────────
    // 6 walks × 6 hops = 36 leaves.
    // Walk w, hop k → leaf index w*6 + k.
    let mut conn_leaves = Vec::with_capacity(N * 6);
    for w in 0..N {
        let ids = [id_x[w], id_a[w], id_b[w], id_c[w], id_d[w], id_e[w], id_agg];
        for k in 0..6usize {
            conn_leaves.push(cc(ids[k], ids[k + 1], s_conn[w][k]));
        }
    }
    let conn_num_leaves = conn_leaves.len();
    let conn_tree  = MerkleTree::new(conn_leaves);
    let conn_root  = conn_tree.root();
    let conn_depth = conn_tree.inclusion_proof(0).siblings.len();

    // ── Reputation Merkle tree ────────────────────────────────────────────────
    // 6 walks × 5 intermediate provers (A..E) = 30 entries + 1 for AGG = 31.
    // Walk w, prover k (0=A,1=B,2=C,3=D,4=E) → leaf index w*5 + k.
    // AGG → leaf index 30.
    let mut rep_leaves = Vec::with_capacity(N * 5 + 1);
    let id_mid: [[[u64; 4]; 5]; N] =
        core::array::from_fn(|w| [id_a[w], id_b[w], id_c[w], id_d[w], id_e[w]]);
    for w in 0..N {
        for k in 0..5usize {
            rep_leaves.push(rc(id_mid[w][k], r_hops[k], s_rep[w][k]));
        }
    }
    rep_leaves.push(rc(id_agg, r_agg, s_aggr)); // AGG at index 30
    let rep_num_leaves = rep_leaves.len();
    let rep_tree  = MerkleTree::new(rep_leaves);
    let rep_root  = rep_tree.root();
    let rep_depth = rep_tree.inclusion_proof(0).siblings.len();

    // ── Revocation SMT (empty — no one is revoked) ────────────────────────────
    let smt_depth  = 8usize;
    let revoc_smt  = SparseMerkleTree::new(smt_depth);
    let revoc_root = revoc_smt.root();
    let revoc_sibs = revoc_smt.non_inclusion_proof(h(0)).siblings;

    println!("=== Tree parameters ===");
    println!("conn_leaves={conn_num_leaves}  conn_depth={conn_depth}");
    println!("rep_leaves={rep_num_leaves}   rep_depth={rep_depth}  smt_depth={smt_depth}");
    println!("conn_root  = {:?}", conn_root);
    println!("rep_root   = {:?}", rep_root);
    println!("revoc_root = {:?}", revoc_root);

    // ── Build walk prover ─────────────────────────────────────────────────────
    println!("\n=== Circuit compilation ===");
    let t = Instant::now();
    let config      = CircuitConfig::standard_recursion_config();
    let walk_prover = WalkProver::<F, C, D>::setup(config, conn_depth, smt_depth, rep_depth);
    println!("  Walk prover (all hop depths) : {:.2?}", t.elapsed());

    let inner_circuit_data = walk_prover.circuit_data_for_length(L as usize);
    print_circuit_stats("inner walk circuit (len=6)", inner_circuit_data);

    let t = Instant::now();
    let agg_prover = AggregatorProver::<F, C, D, N>::setup(inner_circuit_data, L);
    println!("  Aggregator circuit (N=6)     : {:.2?}", t.elapsed());
    print_circuit_stats("aggregator circuit (N=6, len=6)", &agg_prover.circuit_data);

    // ── Prove six walks ───────────────────────────────────────────────────────
    println!("\n=== Proving walks ===");

    let mut proofs = Vec::with_capacity(N);
    for w in 0..N {
        let ids = [id_x[w], id_a[w], id_b[w], id_c[w], id_d[w], id_e[w], id_agg];
        let genesis_dest = poseidon_hash(&[ids[0], ids[1], s_conn[w][0], epoch]);
        let t = Instant::now();

        let hops: Vec<WalkHop> = (0..6usize).map(|k| WalkHop {
            id_prev:     ids[k],
            id_curr:     ids[k + 1],
            id_next:     ids[(k + 2).min(6)],
            s_conn_in:   s_conn[w][k],
            s_conn_out:  if k + 1 < 6 { s_conn[w][k + 1] } else { s_agg_cc },
            r_curr:      if k < 5 { r_hops[k] } else { r_agg },
            s_rep_curr:  if k < 5 { s_rep[w][k] } else { s_aggr },
            w_curr_next: w_all,
            conn_mip:    conn_tree.inclusion_proof(w * 6 + k),
            rep_mip:     if k < 5 {
                             rep_tree.inclusion_proof(w * 5 + k)
                         } else {
                             rep_tree.inclusion_proof(N * 5) // AGG at index 30
                         },
        }).collect();

        let proof = prove_walk::<F, C, D>(
            &walk_prover, epoch, conn_root, rep_root, revoc_root,
            genesis_dest, &hops, &revoc_sibs,
        )?;
        println!("  Walk {}  path_rep={}  time={:.2?}",
            w + 1, proof.public_inputs[17].to_canonical_u64(), t.elapsed());
        proofs.push(proof);
    }

    // ── Aggregate ─────────────────────────────────────────────────────────────
    println!("\n=== Aggregation ===");
    let t = Instant::now();
    let inner_proofs: [_; N] = proofs.try_into().expect("exactly N proofs");
    let agg_proof = agg_prover.prove(AggregatorInputs {
        inner_proofs,
        id_aggregator:   to_hash(id_agg),
        s_aggregator_cc: to_hash(s_agg_cc),
        path_length_req: L,
    })?;
    println!("  Aggregated proof generated : {:.2?}", t.elapsed());

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
    assert_eq!(state.path_length_req, L,     "expected path_length_req == 6");
    assert_eq!(state.id_aggregator,   id_agg, "id_aggregator mismatch");
    // Each walk: path_rep = 313  →  total = 6 × 313 = 1878
    assert_eq!(state.total_path_reputation, 1878,
        "expected total_path_reputation == 1878 (6 × 313)");

    println!("\nAll assertions passed.");
    Ok(())
}
