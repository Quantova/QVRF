// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod error;
pub mod onetime;
pub mod zk;

pub use error::VrfError;

pub const OUTPUT_LEN: usize = 32;

#[derive(Clone, PartialEq, Eq)]
pub struct Output {
    bytes: [u8; OUTPUT_LEN],
}

impl Output {
    pub fn from_bytes(bytes: [u8; OUTPUT_LEN]) -> Self {
        Self { bytes }
    }

    pub fn as_bytes(&self) -> &[u8; OUTPUT_LEN] {
        &self.bytes
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Proof {
    signature: Vec<u8>,
    derivation: Vec<u8>,
}

impl Proof {
    pub fn new(signature: Vec<u8>, derivation: Vec<u8>) -> Self {
        Self {
            signature,
            derivation,
        }
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn derivation(&self) -> &[u8] {
        &self.derivation
    }
}

pub trait Vrf {
    fn output(&self, position: u64, input: &[u8]) -> Result<Output, VrfError>;

    fn prove(&self, position: u64, input: &[u8]) -> Result<Proof, VrfError>;

    fn verify(
        &self,
        position: u64,
        input: &[u8],
        output: &Output,
        proof: &Proof,
    ) -> Result<(), VrfError>;
}
