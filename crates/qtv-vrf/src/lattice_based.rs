//! The lattice based construction of the verifiable random function.

use crate::{Output, Proof, Vrf, VrfError};

/// The lattice based verifiable random function.
pub struct LatticeBasedVrf {
    // Public parameters and key material will live here once the construction lands.
}

impl LatticeBasedVrf {
    /// Create a lattice based verifiable random function.
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for LatticeBasedVrf {
    fn default() -> Self {
        Self::new()
    }
}

impl Vrf for LatticeBasedVrf {
    fn output(&self, _input: &[u8]) -> Result<Output, VrfError> {
        // Pending. This will squeeze SHAKE256 over an ML-DSA signature of the input followed by
        // the input.
        Err(VrfError::Pending)
    }

    fn prove(&self, _input: &[u8]) -> Result<Proof, VrfError> {
        // Pending. This will return the ML-DSA signature and the proof of correct derivation.
        Err(VrfError::Pending)
    }

    fn verify(&self, _input: &[u8], _output: &Output, _proof: &Proof) -> Result<(), VrfError> {
        // Pending. This will recompute the output and check the proof of correct derivation.
        Err(VrfError::Pending)
    }
}
