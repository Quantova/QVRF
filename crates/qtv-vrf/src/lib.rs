//! qtv-vrf defines the verifiable random function interface for Quantova and the two

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod error;
pub mod hash_based;
pub mod lattice_based;

pub use error::VrfError;

/// Length in bytes of a function output, squeezed from SHAKE256.
pub const OUTPUT_LEN: usize = 64;

/// The pseudorandom output of the function for a given input.
#[derive(Clone, PartialEq, Eq)]
pub struct Output {
    // A digest here renders through the identifier format helper in the chain, never as 0x hex.
    bytes: [u8; OUTPUT_LEN],
}

impl Output {
    /// Build an output from its raw bytes.
    pub fn from_bytes(bytes: [u8; OUTPUT_LEN]) -> Self {
        Self { bytes }
    }

    /// Borrow the raw output bytes.
    pub fn as_bytes(&self) -> &[u8; OUTPUT_LEN] {
        &self.bytes
    }
}

/// The proof that an output was derived correctly for an input.
#[derive(Clone, PartialEq, Eq)]
pub struct Proof {
    signature: Vec<u8>,
    derivation: Vec<u8>,
}

impl Proof {
    /// Build a proof from the signature bytes and the derivation bytes.
    pub fn new(signature: Vec<u8>, derivation: Vec<u8>) -> Self {
        Self {
            signature,
            derivation,
        }
    }

    /// Borrow the signature bytes.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Borrow the derivation bytes.
    pub fn derivation(&self) -> &[u8] {
        &self.derivation
    }
}

/// A verifiable random function.
pub trait Vrf {
    /// Produce the output for an input.
    fn output(&self, input: &[u8]) -> Result<Output, VrfError>;

    /// Produce the proof that the output for an input was derived correctly.
    fn prove(&self, input: &[u8]) -> Result<Proof, VrfError>;

    /// Check an output and its proof against an input. Return Ok when the pair is valid.
    fn verify(&self, input: &[u8], output: &Output, proof: &Proof) -> Result<(), VrfError>;
}
