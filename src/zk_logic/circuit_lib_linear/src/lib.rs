/// Maximum number of hops in a walk.
pub const MAX_PATH_LEN: usize = 6;

/// α × SCALE — represents α = 0.90 as a scaled integer (divide by SCALE to recover α).
pub const ALPHA_SCALED: u64 = 90;

/// Fixed-point scale factor. All fractional values (α, w, path_reputation) are stored
/// as integers multiplied by SCALE and all arithmetic is performed before dividing out.
pub const SCALE: u64 = 100;

pub mod base_circuit;
pub mod recursive_circuit;
