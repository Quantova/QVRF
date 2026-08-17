// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT


use qtv_crypto::sha3::shake256;
use qtv_stark::field::{Felt, MODULUS};
use qtv_stark::zkvrf::{self, OUT_ELEMS, SK_ELEMS, X_ELEMS};

pub const SEED_LEN: usize = 32;

pub struct ZkDraw {
    pub output: [u8; SEED_LEN],
    pub commitment: [u8; SEED_LEN],
    pub proof: Vec<u8>,
}

fn elems<const N: usize>(domain: &[u8], data: &[u8]) -> [Felt; N] {
    let mut buf = Vec::with_capacity(domain.len() + data.len());
    buf.extend_from_slice(domain);
    buf.extend_from_slice(data);
    let mut bytes = vec![0u8; N * 8];
    shake256(&buf, &mut bytes);
    let mut out = [Felt::ZERO; N];
    for (i, cell) in out.iter_mut().enumerate() {
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        *cell = Felt::new(u64::from_le_bytes(word));
    }
    out
}

fn to_bytes(values: &[Felt; OUT_ELEMS]) -> [u8; SEED_LEN] {
    let mut out = [0u8; SEED_LEN];
    for (i, value) in values.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&value.to_u64().to_le_bytes());
    }
    out
}

fn canonical(bytes: &[u8; SEED_LEN]) -> Option<[Felt; OUT_ELEMS]> {
    let mut out = [Felt::ZERO; OUT_ELEMS];
    for (i, cell) in out.iter_mut().enumerate() {
        let mut word = [0u8; 8];
        word.copy_from_slice(&bytes[i * 8..i * 8 + 8]);
        let value = u64::from_le_bytes(word);
        if value >= MODULUS {
            return None;
        }
        *cell = Felt::new(value);
    }
    Some(out)
}

fn key(seed: &[u8; SEED_LEN]) -> [Felt; SK_ELEMS] {
    elems(b"QVRF/zk/key", seed)
}

fn point(input: &[u8]) -> [Felt; X_ELEMS] {
    elems(b"QVRF/zk/input", input)
}

pub fn commitment(seed: &[u8; SEED_LEN]) -> [u8; SEED_LEN] {
    to_bytes(&zkvrf::vrf_commit(&key(seed)))
}

pub fn output(seed: &[u8; SEED_LEN], input: &[u8]) -> [u8; SEED_LEN] {
    to_bytes(&zkvrf::vrf_output(&key(seed), &point(input)))
}

pub fn prove(seed: &[u8; SEED_LEN], input: &[u8], context: &[u8]) -> ZkDraw {
    let draw = zkvrf::prove(&key(seed), &point(input), context);
    ZkDraw {
        output: to_bytes(&draw.output),
        commitment: to_bytes(&draw.commit),
        proof: draw.proof,
    }
}

pub fn verify(
    commitment: &[u8; SEED_LEN],
    input: &[u8],
    output: &[u8; SEED_LEN],
    proof: &[u8],
    context: &[u8],
) -> bool {
    let y = match canonical(output) {
        Some(y) => y,
        None => return false,
    };
    let pk = match canonical(commitment) {
        Some(pk) => pk,
        None => return false,
    };
    zkvrf::verify(&point(input), &y, &pk, proof, context)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed() -> [u8; SEED_LEN] {
        [9u8; SEED_LEN]
    }

    #[test]
    fn the_output_and_commitment_are_deterministic() {
        assert_eq!(output(&seed(), b"slot-42"), output(&seed(), b"slot-42"));
        assert_eq!(commitment(&seed()), commitment(&seed()));
        assert_ne!(output(&seed(), b"a"), output(&seed(), b"b"));
    }

    #[test]
    fn a_draw_proves_and_verifies() {
        let draw = prove(&seed(), b"slot-42", b"Q-net");
        assert_eq!(draw.output, output(&seed(), b"slot-42"));
        assert_eq!(draw.commitment, commitment(&seed()));
        assert!(verify(&draw.commitment, b"slot-42", &draw.output, &draw.proof, b"Q-net"));
    }

    #[test]
    fn a_wrong_output_or_context_or_input_is_rejected() {
        let draw = prove(&seed(), b"slot-42", b"Q-net");
        let mut wrong = draw.output;
        wrong[0] ^= 1;
        assert!(!verify(&draw.commitment, b"slot-42", &wrong, &draw.proof, b"Q-net"));
        assert!(!verify(&draw.commitment, b"slot-42", &draw.output, &draw.proof, b"Q-other"));
        assert!(!verify(&draw.commitment, b"slot-43", &draw.output, &draw.proof, b"Q-net"));
    }
}
