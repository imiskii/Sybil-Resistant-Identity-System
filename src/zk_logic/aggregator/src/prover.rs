use anyhow::Result;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::circuit::{AggregatorCircuit, AggregatorCircuitTargets};

pub struct AggregatorInputs<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize, const N: usize> {
    pub inner_proofs:    [ProofWithPublicInputs<F, C, D>; N],
    pub id_aggregator:   HashOut<F>,
    pub s_aggregator_cc: HashOut<F>,
    pub path_length_req: u64,
}

pub struct AggregatorProver<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize, const N: usize>
where
    C::Hasher: AlgebraicHasher<F>,
{
    pub circuit_data: CircuitData<F, C, D>,
    pub targets:      AggregatorCircuitTargets<D, N>,
}

impl<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize, const N: usize>
    AggregatorProver<F, C, D, N>
where
    C::Hasher: AlgebraicHasher<F>,
{
    /// Build the aggregator circuit.
    pub fn setup(
        inner_circuit_data: &CircuitData<F, C, D>,
        path_length_req: u64,
    ) -> Self {
        let config = CircuitConfig::standard_recursion_config();
        let (circuit_data, targets) =
            AggregatorCircuit::build::<F, C, D, N>(&config, inner_circuit_data, path_length_req);
        Self { circuit_data, targets }
    }

    /// Generate an aggregated proof from N path proofs.
    pub fn prove(
        &self,
        inputs: AggregatorInputs<F, C, D, N>,
    ) -> Result<ProofWithPublicInputs<F, C, D>> {
        let mut pw = PartialWitness::new();
        for (i, proof) in inputs.inner_proofs.iter().enumerate() {
            pw.set_proof_with_pis_target(&self.targets.inner_proofs[i], proof)?;
        }
        pw.set_hash_target(self.targets.id_aggregator, inputs.id_aggregator)?;
        pw.set_hash_target(self.targets.s_aggregator_cc, inputs.s_aggregator_cc)?;
        pw.set_target(
            self.targets.path_length_req,
            F::from_canonical_u64(inputs.path_length_req),
        )?;
        self.circuit_data.prove(pw)
    }
}
