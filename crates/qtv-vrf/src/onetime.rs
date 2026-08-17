// Copyright 2026 Quantova Inc
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::{Output, Proof, Vrf, VrfError, OUTPUT_LEN};
use qtv_crypto::sha3::shake256;

const SECRET_LEN: usize = 32;
const NODE_LEN: usize = 32;

const DOMAIN_LEAF_SECRET: &[u8] = b"QVRF/v1/leaf-secret";
const DOMAIN_LEAF_COMMIT: &[u8] = b"QVRF/v1/leaf-commit";
const DOMAIN_NODE: &[u8] = b"QVRF/v1/node";
const DOMAIN_OUTPUT: &[u8] = b"QVRF/v1/output";

pub const MAX_HEIGHT: u32 = 24;

fn hash(parts: &[&[u8]], out: &mut [u8]) {
    let mut buf = Vec::new();
    for part in parts {
        buf.extend_from_slice(part);
    }
    shake256(&buf, out);
}

fn leaf_secret(master_seed: &[u8; SECRET_LEN], position: u64) -> [u8; SECRET_LEN] {
    let mut out = [0u8; SECRET_LEN];
    hash(
        &[DOMAIN_LEAF_SECRET, master_seed, &position.to_le_bytes()],
        &mut out,
    );
    out
}

fn leaf_commit(secret: &[u8]) -> [u8; NODE_LEN] {
    let mut out = [0u8; NODE_LEN];
    hash(&[DOMAIN_LEAF_COMMIT, secret], &mut out);
    out
}

fn node_hash(left: &[u8; NODE_LEN], right: &[u8; NODE_LEN]) -> [u8; NODE_LEN] {
    let mut out = [0u8; NODE_LEN];
    hash(&[DOMAIN_NODE, left, right], &mut out);
    out
}

fn output_hash(secret: &[u8], input: &[u8]) -> Output {
    let mut out = [0u8; OUTPUT_LEN];
    hash(&[DOMAIN_OUTPUT, secret, input], &mut out);
    Output::from_bytes(out)
}

pub struct OneTimeVrf {
    master_seed: Option<[u8; SECRET_LEN]>,
    levels: Vec<Vec<[u8; NODE_LEN]>>,
    height: u32,
    root: [u8; NODE_LEN],
}

impl OneTimeVrf {
    pub fn keygen(master_seed: &[u8; SECRET_LEN], height: u32) -> Result<Self, VrfError> {
        if height == 0 || height > MAX_HEIGHT {
            return Err(VrfError::InvalidInput);
        }
        let count = 1usize << height;
        let leaves: Vec<[u8; NODE_LEN]> = (0..count as u64)
            .map(|position| leaf_commit(&leaf_secret(master_seed, position)))
            .collect();
        let mut levels = vec![leaves];
        while levels.last().map(|l| l.len()).unwrap_or(0) > 1 {
            let current = levels.last().expect("a level is present");
            let mut next = Vec::with_capacity(current.len() / 2);
            for pair in current.chunks(2) {
                next.push(node_hash(&pair[0], &pair[1]));
            }
            levels.push(next);
        }
        let root = levels.last().expect("the fold ends at the root")[0];
        Ok(Self {
            master_seed: Some(*master_seed),
            levels,
            height,
            root,
        })
    }

    pub fn from_public(root: [u8; NODE_LEN], height: u32) -> Result<Self, VrfError> {
        if height == 0 || height > MAX_HEIGHT {
            return Err(VrfError::InvalidInput);
        }
        Ok(Self {
            master_seed: None,
            levels: Vec::new(),
            height,
            root,
        })
    }

    pub fn root(&self) -> &[u8; NODE_LEN] {
        &self.root
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn positions(&self) -> u64 {
        1u64 << self.height
    }

    fn path_bytes(&self, position: u64) -> Vec<u8> {
        let mut idx = position as usize;
        let mut path = Vec::with_capacity(self.height as usize * NODE_LEN);
        for level in 0..self.height as usize {
            let nodes = &self.levels[level];
            let sibling = if idx & 1 == 0 {
                nodes[idx + 1]
            } else {
                nodes[idx - 1]
            };
            path.extend_from_slice(&sibling);
            idx >>= 1;
        }
        path
    }
}

impl Vrf for OneTimeVrf {
    fn output(&self, position: u64, input: &[u8]) -> Result<Output, VrfError> {
        let seed = self.master_seed.as_ref().ok_or(VrfError::InvalidInput)?;
        if position >= self.positions() {
            return Err(VrfError::InvalidInput);
        }
        let secret = leaf_secret(seed, position);
        Ok(output_hash(&secret, input))
    }

    fn prove(&self, position: u64, _input: &[u8]) -> Result<Proof, VrfError> {
        let seed = self.master_seed.as_ref().ok_or(VrfError::InvalidInput)?;
        if position >= self.positions() {
            return Err(VrfError::InvalidInput);
        }
        let secret = leaf_secret(seed, position);
        Ok(Proof::new(secret.to_vec(), self.path_bytes(position)))
    }

    fn verify(
        &self,
        position: u64,
        input: &[u8],
        output: &Output,
        proof: &Proof,
    ) -> Result<(), VrfError> {
        if position >= self.positions() {
            return Err(VrfError::InvalidInput);
        }
        let secret = proof.signature();
        if secret.len() != SECRET_LEN {
            return Err(VrfError::InvalidProof);
        }
        let path = proof.derivation();
        if path.len() != self.height as usize * NODE_LEN {
            return Err(VrfError::InvalidProof);
        }
        let mut node = leaf_commit(secret);
        let mut idx = position as usize;
        for level in 0..self.height as usize {
            let start = level * NODE_LEN;
            let mut sibling = [0u8; NODE_LEN];
            sibling.copy_from_slice(&path[start..start + NODE_LEN]);
            node = if idx & 1 == 0 {
                node_hash(&node, &sibling)
            } else {
                node_hash(&sibling, &node)
            };
            idx >>= 1;
        }
        if node != self.root {
            return Err(VrfError::InvalidProof);
        }
        if output_hash(secret, input) != *output {
            return Err(VrfError::InvalidOutput);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> OneTimeVrf {
        OneTimeVrf::keygen(&[7u8; SECRET_LEN], 8).unwrap()
    }

    fn verifier(full: &OneTimeVrf) -> OneTimeVrf {
        OneTimeVrf::from_public(*full.root(), full.height()).unwrap()
    }

    #[test]
    fn a_valid_output_and_proof_verify() {
        let vrf = key();
        let v = verifier(&vrf);
        let out = vrf.output(3, b"beacon").unwrap();
        let proof = vrf.prove(3, b"beacon").unwrap();
        assert_eq!(v.verify(3, b"beacon", &out, &proof), Ok(()));
    }

    #[test]
    fn the_output_is_deterministic_for_one_position_and_input() {
        let vrf = key();
        let first = vrf.output(5, b"m").unwrap();
        let second = vrf.output(5, b"m").unwrap();
        assert_eq!(first.as_bytes(), second.as_bytes());
    }

    #[test]
    fn a_different_position_gives_a_different_output() {
        let vrf = key();
        assert_ne!(
            vrf.output(1, b"m").unwrap().as_bytes(),
            vrf.output(2, b"m").unwrap().as_bytes()
        );
    }

    #[test]
    fn a_different_input_gives_a_different_output() {
        let vrf = key();
        assert_ne!(
            vrf.output(1, b"a").unwrap().as_bytes(),
            vrf.output(1, b"b").unwrap().as_bytes()
        );
    }

    #[test]
    fn a_forged_output_for_the_same_position_and_input_is_rejected() {
        let vrf = key();
        let v = verifier(&vrf);
        let proof = vrf.prove(4, b"beacon").unwrap();
        let mut bytes = *vrf.output(4, b"beacon").unwrap().as_bytes();
        bytes[0] ^= 1;
        let forged = Output::from_bytes(bytes);
        assert_eq!(
            v.verify(4, b"beacon", &forged, &proof),
            Err(VrfError::InvalidOutput)
        );
    }

    #[test]
    fn a_secret_from_another_position_does_not_verify_here() {
        let vrf = key();
        let v = verifier(&vrf);
        let out = vrf.output(4, b"beacon").unwrap();
        let other = vrf.prove(9, b"beacon").unwrap();
        assert_eq!(
            v.verify(4, b"beacon", &out, &other),
            Err(VrfError::InvalidProof)
        );
    }

    #[test]
    fn a_tampered_path_is_rejected() {
        let vrf = key();
        let v = verifier(&vrf);
        let out = vrf.output(6, b"beacon").unwrap();
        let base = vrf.prove(6, b"beacon").unwrap();
        let mut path = base.derivation().to_vec();
        path[0] ^= 1;
        let proof = Proof::new(base.signature().to_vec(), path);
        assert_eq!(
            v.verify(6, b"beacon", &out, &proof),
            Err(VrfError::InvalidProof)
        );
    }

    #[test]
    fn a_position_past_the_tree_is_rejected() {
        let vrf = key();
        assert_eq!(vrf.output(256, b"m").err(), Some(VrfError::InvalidInput));
        assert_eq!(vrf.prove(256, b"m").err(), Some(VrfError::InvalidInput));
    }

    #[test]
    fn a_verify_only_key_cannot_produce() {
        let vrf = key();
        let v = verifier(&vrf);
        assert_eq!(v.output(0, b"m").err(), Some(VrfError::InvalidInput));
        assert_eq!(v.prove(0, b"m").err(), Some(VrfError::InvalidInput));
    }

    #[test]
    fn a_wrong_length_secret_is_rejected() {
        let vrf = key();
        let v = verifier(&vrf);
        let out = vrf.output(1, b"m").unwrap();
        let path = vrf.prove(1, b"m").unwrap().derivation().to_vec();
        let short = Proof::new(vec![0u8; 31], path);
        assert_eq!(v.verify(1, b"m", &out, &short), Err(VrfError::InvalidProof));
    }
}
