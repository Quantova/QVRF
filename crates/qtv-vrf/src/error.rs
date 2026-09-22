// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::fmt;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum VrfError {
    InvalidInput,
    InvalidProof,
    InvalidOutput,
}

impl fmt::Display for VrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            VrfError::InvalidInput => "the input was rejected",
            VrfError::InvalidProof => "the proof did not verify",
            VrfError::InvalidOutput => "the output did not match the input",
        };
        f.write_str(message)
    }
}

impl std::error::Error for VrfError {}
