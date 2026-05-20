
pub const MAX_PATH_LEN: usize = 6;

/// Index offsets into the inner proof's public_inputs field array.
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
