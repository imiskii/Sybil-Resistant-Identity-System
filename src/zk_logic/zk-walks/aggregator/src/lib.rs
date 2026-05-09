// Design decision: VK binding
//
// The aggregator calls builder.verify_proof with a fixed inner CircuitData (VK).
// Linear and cyclic variants produce different VKs. Therefore a single compiled
// aggregator circuit is bound to exactly one variant's VK. However, the aggregator
// Rust code is written generically — it accepts a &CircuitData parameter at build
// time. This means:
//   - One aggregator binary can support both variants
//   - But each aggregator *instance* (each compiled CircuitData) is bound to one variant
//   - You cannot mix linear and cyclic proofs inside the same aggregation call
//
// This is the correct behaviour for our system. The caller picks the variant by
// passing the appropriate inner_circuit_data to AggregatorProver::setup().

/// Must match the MAX_PATH_LEN constant used in the inner path circuit.
/// Import from the inner circuit's crate constants or redeclare and document
/// that they must stay in sync.
pub const MAX_PATH_LEN: usize = 6;

/// Index offsets into the inner proof's public_inputs field array.
/// Each HashOutTarget occupies 4 consecutive field elements.
/// Update these if the inner circuit's public input order ever changes.
pub mod inner_pi {
    pub const EPOCH:               std::ops::Range<usize> = 0..4;
    pub const CONNECTION_MT_ROOT:  std::ops::Range<usize> = 4..8;
    pub const REPUTATION_MT_ROOT:  std::ops::Range<usize> = 8..12;
    pub const REVOCATION_SMT_ROOT: std::ops::Range<usize> = 12..16;
    pub const PATH_LENGTH:         usize = 16;
    pub const PATH_REPUTATION:     usize = 17;
    pub const NULLIFIERS_START:    usize = 18; // MAX_PATH_LEN * 4 elements
    pub const DEST_START:          usize = 18 + super::MAX_PATH_LEN * 4; // = 42
}

pub mod circuit;
pub mod prover;
pub mod verifier;
