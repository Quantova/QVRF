//! The hash based construction of the verifiable random function.

use crate::{Output, Proof, Vrf, VrfError};

/// The hash based verifiable random function.
pub struct HashBasedVrf {
    // Public parameters and key material will live here once the construction lands.
}

impl HashBasedVrf {
    /// Create a hash based verifiable random function.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for HashBasedVrf {
    fn default() -> Self {
        Self::new()
    }
}

impl Vrf for HashBasedVrf {
    fn output(&self, _input: &[u8]) -> Result<Output, VrfError> {
        // Pending. This will squeeze SHAKE256 over an SLH-DSA signature of the input followed by
        // the input.
        Err(VrfError::Pending)
    }

    fn prove(&self, _input: &[u8]) -> Result<Proof, VrfError> {
        // Pending. This will return the SLH-DSA signature and its Merkle authentication path.
        Err(VrfError::Pending)
    }

    fn verify(&self, _input: &[u8], _output: &Output, _proof: &Proof) -> Result<(), VrfError> {
        // Pending. This will recompute the output and check the Merkle authentication path.
        Err(VrfError::Pending)
    }
}
