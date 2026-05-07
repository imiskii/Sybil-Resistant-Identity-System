use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CommonCircuitData, VerifierCircuitTarget};
use plonky2::plonk::config::{GenericConfig, Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

struct StepTargets {
    is_base_case: BoolTarget,
    state_in: HashOutTarget,
    state_out: HashOutTarget,
    prev_proof: ProofWithPublicInputsTarget<D>,
    verifier_data: VerifierCircuitTarget,
    secret: Target,
}

fn build_step_circuit(
    builder: &mut CircuitBuilder<F, D>,
    common_data: &mut CommonCircuitData<F, D>,
) -> Result<StepTargets> {
    let is_base_case = builder.add_virtual_bool_target_safe();
    builder.register_public_input(is_base_case.target);

    let state_in = builder.add_virtual_hash();
    builder.register_public_inputs(&state_in.elements);

    let state_out = builder.add_virtual_hash();
    builder.register_public_inputs(&state_out.elements);

    let verifier_data = builder.add_verifier_data_public_inputs();
    common_data.num_public_inputs = builder.num_public_inputs();

    let prev_proof = builder.add_virtual_proof_with_pis(common_data);

    let condition = builder.not(is_base_case);
    builder.conditionally_verify_cyclic_proof_or_dummy::<C>(condition, &prev_proof, common_data)?;

    let prev_state_out = HashOutTarget {
        elements: [
            prev_proof.public_inputs[5],
            prev_proof.public_inputs[6],
            prev_proof.public_inputs[7],
            prev_proof.public_inputs[8],
        ],
    };

    for i in 0..4 {
        let expected_in = builder.select(
            is_base_case,
            state_in.elements[i],
            prev_state_out.elements[i],
        );
        builder.connect(state_in.elements[i], expected_in);
    }

    let secret = builder.add_virtual_target();
    let mut inputs = state_in.elements.to_vec();
    inputs.push(secret);

    let computed_new_state = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    builder.connect_hashes(computed_new_state, state_out);

    Ok(StepTargets {
        is_base_case,
        state_in,
        state_out,
        prev_proof,
        verifier_data,
        secret,
    })
}

fn common_data_for_recursion() -> CommonCircuitData<F, D> {
    let config = CircuitConfig::standard_recursion_config();
    let builder = CircuitBuilder::<F, D>::new(config);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    let data = builder.build::<C>();

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    while builder.num_gates() < 1 << 12 {
        builder.add_gate(NoopGate, vec![]);
    }
    builder.build::<C>().common
}

fn print_circuit_stats(common_data: &CommonCircuitData<F, D>) {
    println!("Circuit stats:");
    println!("  Degree / gate rows: {}", common_data.degree());
    println!("  Degree bits: {}", common_data.degree_bits());
    println!("  Public inputs: {}", common_data.num_public_inputs);
    println!("  Gate types: {}", common_data.gates.len());
    println!(
        "  Max constraints in any gate: {}",
        common_data.num_gate_constraints
    );
    println!(
        "  Constraint upper bound (rows * max constraints/gate): {}",
        common_data.degree() * common_data.num_gate_constraints
    );
    println!("  Quotient degree: {}\n", common_data.quotient_degree());
}

fn main() -> Result<()> {
    println!("=== Plonky2 Recursive Chain: cyclic_base_proof Fix ===\n");
    let config = CircuitConfig::standard_recursion_config();

    // 1. BOOTSTRAP
    let mut common_data = common_data_for_recursion();

    // 2. REAL BUILD
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let targets = build_step_circuit(&mut builder, &mut common_data)?;
    let circuit_data = builder.build::<C>();
    print_circuit_stats(&circuit_data.common);

    // 3. Generate placeholder proof data for the unverified base branch.
    println!("Generating placeholder proof for base case...");

    let dummy_proof = cyclic_base_proof::<F, C, D>(
        &common_data,
        &circuit_data.verifier_only,
        Default::default(),
    );

    // 4. NODE A (Base Case)
    println!("Step 1: Proving Node A (Base Case)...");
    let genesis_state =
        HashOut::from_vec(vec![F::from_canonical_u64(123), F::ZERO, F::ZERO, F::ZERO]);
    let secret_a = F::from_canonical_u64(456);
    let mut a_hash_inputs = genesis_state.elements.to_vec();
    a_hash_inputs.push(secret_a);
    let expected_out_a = PoseidonHash::hash_no_pad(&a_hash_inputs);

    let mut pw_a = PartialWitness::new();
    pw_a.set_bool_target(targets.is_base_case, true)?;
    pw_a.set_hash_target(targets.state_in, genesis_state)?;
    pw_a.set_hash_target(targets.state_out, expected_out_a)?;
    pw_a.set_target(targets.secret, secret_a)?;

    pw_a.set_proof_with_pis_target(&targets.prev_proof, &dummy_proof)?;
    pw_a.set_verifier_data_target(&targets.verifier_data, &circuit_data.verifier_only)?;

    let proof_a = circuit_data.prove(pw_a)?;
    check_cyclic_proof_verifier_data(&proof_a, &circuit_data.verifier_only, &circuit_data.common)?;
    println!(
        "  Node A Proved! New state element: {:?}\n",
        proof_a.public_inputs[5]
    );

    // 5. NODE B (Recursive Case)
    println!("Step 2: Proving Node B (Recursive)...");
    let secret_b = F::from_canonical_u64(789);
    let mut b_hash_inputs = expected_out_a.elements.to_vec();
    b_hash_inputs.push(secret_b);
    let expected_out_b = PoseidonHash::hash_no_pad(&b_hash_inputs);

    let mut pw_b = PartialWitness::new();
    pw_b.set_bool_target(targets.is_base_case, false)?;
    pw_b.set_hash_target(targets.state_in, expected_out_a)?;
    pw_b.set_hash_target(targets.state_out, expected_out_b)?;
    pw_b.set_target(targets.secret, secret_b)?;

    // BINDING: Pass Node A's proof into Node B
    pw_b.set_proof_with_pis_target(&targets.prev_proof, &proof_a)?;
    pw_b.set_verifier_data_target(&targets.verifier_data, &circuit_data.verifier_only)?;

    let proof_b = circuit_data.prove(pw_b)?;
    check_cyclic_proof_verifier_data(&proof_b, &circuit_data.verifier_only, &circuit_data.common)?;
    println!(
        "  Node B Proved! New state element: {:?}\n",
        proof_b.public_inputs[5]
    );

    // 6. NODE C (Recursive Case)
    println!("Step 3: Proving Node C (Recursive)...");
    let secret_c = F::from_canonical_u64(101112);
    let mut c_hash_inputs = expected_out_b.elements.to_vec();
    c_hash_inputs.push(secret_c);
    let expected_out_c = PoseidonHash::hash_no_pad(&c_hash_inputs);

    let mut pw_c = PartialWitness::new();
    pw_c.set_bool_target(targets.is_base_case, false)?;
    pw_c.set_hash_target(targets.state_in, expected_out_b)?;
    pw_c.set_hash_target(targets.state_out, expected_out_c)?;
    pw_c.set_target(targets.secret, secret_c)?;

    // BINDING: Pass Node B's proof into Node C
    pw_c.set_proof_with_pis_target(&targets.prev_proof, &proof_b)?;
    pw_c.set_verifier_data_target(&targets.verifier_data, &circuit_data.verifier_only)?;

    let proof_c = circuit_data.prove(pw_c)?;
    check_cyclic_proof_verifier_data(&proof_c, &circuit_data.verifier_only, &circuit_data.common)?;
    println!(
        "  Node C Proved! New state element: {:?}\n",
        proof_c.public_inputs[5]
    );

    // Final Verification
    circuit_data.verify(proof_c)?;
    println!("=== SUCCESS: Recursive chain verified! ===");

    Ok(())
}
