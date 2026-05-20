/// Maximum number of hops in a walk.
pub const MAX_PATH_LEN: usize = 6;

/// ALPHA × SCALE — represents ALPHA = 0.90 as a scaled integer.
pub const ALPHA_SCALED: u64 = 90;

/// Fixed-point scale factor. Necessary because the circuit does not support floating point arithmetic.
pub const SCALE: u64 = 100;

pub mod base_circuit;
pub mod recursive_circuit;
