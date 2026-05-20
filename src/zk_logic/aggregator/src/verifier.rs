use anyhow::{anyhow, Result};
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;

// Aggregated proof public input layout (22 field elements total):
//  [0..4]   id_aggregator
//  [4..8]   epoch
//  [8..12]  connection_mt_root
//  [12..16] reputation_mt_root
//  [16..20] revocation_smt_root
//  [20]     path_length_req
//  [21]     total_path_reputation
const AGG_PI_LEN: usize = 22;

#[derive(Debug, Clone)]
pub struct AggregatedPublicState {
    pub id_aggregator:         [u64; 4],
    pub epoch:                 [u64; 4],
    pub connection_mt_root:    [u64; 4],
    pub reputation_mt_root:    [u64; 4],
    pub revocation_smt_root:   [u64; 4],
    pub path_length_req:       u64,
    pub total_path_reputation: u64,
}

/// Verify an aggregated proof and decode its public state.
pub fn verify_aggregated_proof<F, C, const D: usize>(
    circuit_data: &CircuitData<F, C, D>,
    proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<AggregatedPublicState>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
    C::Hasher: AlgebraicHasher<F>,
{
    circuit_data.verify(proof.clone())?;

    let pi = &proof.public_inputs;
    if pi.len() != AGG_PI_LEN {
        return Err(anyhow!(
            "aggregated proof has {} public inputs, expected {}",
            pi.len(),
            AGG_PI_LEN
        ));
    }

    let read4 = |start: usize| -> [u64; 4] {
        core::array::from_fn(|i| pi[start + i].to_canonical_u64())
    };

    Ok(AggregatedPublicState {
        id_aggregator:         read4(0),
        epoch:                 read4(4),
        connection_mt_root:    read4(8),
        reputation_mt_root:    read4(12),
        revocation_smt_root:   read4(16),
        path_length_req:       pi[20].to_canonical_u64(),
        total_path_reputation: pi[21].to_canonical_u64(),
    })
}
