//! The error type returned by the verifiable random function operations.

use core::fmt;

/// An error returned by a verifiable random function operation.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum VrfError {
    /// The input was rejected because it did not meet the expected shape.
    InvalidInput,
    /// The proof did not match the output and the input.
    InvalidProof,
    /// The output did not match the input under the given key.
    InvalidOutput,
    /// The operation is not yet implemented in this construction.
    Pending,
}

impl fmt::Display for VrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            VrfError::InvalidInput => "the input was rejected",
            VrfError::InvalidProof => "the proof did not verify",
            VrfError::InvalidOutput => "the output did not match the input",
            VrfError::Pending => "this operation is not yet implemented",
        };
        f.write_str(message)
    }
}

impl std::error::Error for VrfError {}
