//! Walk proof verifier — decodes public inputs into WalkPublicState.

use anyhow::{bail, Result};
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;

use circuit_lib_linear::MAX_PATH_LEN;

// Public-input layout (must match base_circuit.rs and recursive_circuit.rs):
//   [0..4]             epoch
//   [4..8]             connection_mt_root
//   [8..12]            reputation_mt_root
//   [12..16]           revocation_smt_root
//   [16]               path_length
//   [17]               path_reputation
//   [18..18+N*4)       nullifiers  (N = MAX_PATH_LEN)
//   [18+N*4..22+N*4)   dest
const EXPECTED_PI_LEN: usize = 4 + 4 + 4 + 4 + 1 + 1 + MAX_PATH_LEN * 4 + 4;

/// Decoded public state extracted from a verified walk proof.
#[derive(Debug, Clone)]
pub struct WalkPublicState {
    pub epoch: [u64; 4],
    pub connection_mt_root: [u64; 4],
    pub reputation_mt_root: [u64; 4],
    pub revocation_smt_root: [u64; 4],
    /// Number of hops completed (0 = genesis proof).
    pub path_length: u64,
    /// Accumulated path reputation (scaled by SCALE = 100).
    pub path_reputation: u64,
    /// Nullifiers for each hop slot; unused slots are `[0; 4]`.
    pub nullifiers: [[u64; 4]; MAX_PATH_LEN],
    /// Anti-replay commitment for the next step.
    pub dest: [u64; 4],
}

/// Verify a walk proof and decode its public state.
///
/// Calls `circuit_data.verify(proof)` to check the ZK proof, then decodes
/// the public-input array into a [`WalkPublicState`].
///
/// # Errors
/// Returns an error if:
/// - ZK proof verification fails, or
/// - the public-input array has an unexpected length.
pub fn verify_walk_proof<F, C, const D: usize>(
    circuit_data: &CircuitData<F, C, D>,
    proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<WalkPublicState>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    circuit_data.verify(proof.clone())?;

    let pi = &proof.public_inputs;
    if pi.len() != EXPECTED_PI_LEN {
        bail!(
            "unexpected public-input count: got {}, expected {}",
            pi.len(),
            EXPECTED_PI_LEN
        );
    }

    let read4 = |start: usize| -> [u64; 4] {
        core::array::from_fn(|i| pi[start + i].to_canonical_u64())
    };

    let epoch = read4(0);
    let connection_mt_root = read4(4);
    let reputation_mt_root = read4(8);
    let revocation_smt_root = read4(12);
    let path_length = pi[16].to_canonical_u64();
    let path_reputation = pi[17].to_canonical_u64();
    let nullifiers: [[u64; 4]; MAX_PATH_LEN] =
        core::array::from_fn(|i| read4(18 + i * 4));
    let dest = read4(18 + MAX_PATH_LEN * 4);

    Ok(WalkPublicState {
        epoch,
        connection_mt_root,
        reputation_mt_root,
        revocation_smt_root,
        path_length,
        path_reputation,
        nullifiers,
        dest,
    })
}
