//! The hash based construction of the verifiable random function.

use crate::{Output, Proof, Vrf, VrfError, OUTPUT_LEN};
use qtv_crypto::sha3::shake256;
use qtv_crypto::slh_dsa;

/// Length of one SLH-DSA seed. The public key is PK.seed followed by PK.root, each this long.
const SEED_LEN: usize = slh_dsa::PUBLIC_KEY_BYTES / 2;

/// The signing context. The signature binds the input alone, so this stays empty.
const CONTEXT: &[u8] = &[];

/// The hash based verifiable random function, holding one SLH-DSA key pair.
pub struct HashBasedVrf {
    secret_key: [u8; slh_dsa::SECRET_KEY_BYTES],
    public_key: [u8; slh_dsa::PUBLIC_KEY_BYTES],
}

impl HashBasedVrf {
    /// Build the function from the three SLH-DSA seeds, reusing the crypto crate key generation.
    pub fn keygen(
        sk_seed: &[u8; SEED_LEN],
        sk_prf: &[u8; SEED_LEN],
        pk_seed: &[u8; SEED_LEN],
    ) -> Self {
        let (secret_key, public_key) = slh_dsa::keygen(sk_seed, sk_prf, pk_seed);
        Self {
            secret_key,
            public_key,
        }
    }

    /// Borrow the public key that a verifier needs.
    pub fn public_key(&self) -> &[u8; slh_dsa::PUBLIC_KEY_BYTES] {
        &self.public_key
    }

    /// The deterministic SLH-DSA signature over the input.
    fn signature(&self, input: &[u8]) -> [u8; slh_dsa::SIGNATURE_BYTES] {
        let addrnd: &[u8; SEED_LEN] = (&self.public_key[..SEED_LEN])
            .try_into()
            .expect("the public key begins with PK.seed");
        slh_dsa::sign(&self.secret_key, input, CONTEXT, addrnd)
            .expect("the empty context is within the length bound")
    }
}

/// Squeeze the fixed length output from a signature.
fn squeeze(signature: &[u8]) -> Output {
    let mut bytes = [0u8; OUTPUT_LEN];
    shake256(signature, &mut bytes);
    Output::from_bytes(bytes)
}

impl Vrf for HashBasedVrf {
    fn output(&self, input: &[u8]) -> Result<Output, VrfError> {
        Ok(squeeze(&self.signature(input)))
    }

    fn prove(&self, input: &[u8]) -> Result<Proof, VrfError> {
        Ok(Proof::new(self.signature(input).to_vec(), Vec::new()))
    }

    fn verify(&self, input: &[u8], output: &Output, proof: &Proof) -> Result<(), VrfError> {
        if !slh_dsa::verify(&self.public_key, input, proof.signature(), CONTEXT) {
            return Err(VrfError::InvalidProof);
        }
        let recomputed = squeeze(proof.signature());
        if recomputed != *output {
            return Err(VrfError::InvalidOutput);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Public inputs of the reproducibility fixture. A reader who runs keygen on these three seeds
    // and asks for the output over INPUT recovers RECORDED_OUTPUT byte for byte.
    const SK_SEED: [u8; SEED_LEN] = [7u8; SEED_LEN];
    const SK_PRF: [u8; SEED_LEN] = [8u8; SEED_LEN];
    const PK_SEED: [u8; SEED_LEN] = [9u8; SEED_LEN];
    const INPUT: &[u8] = b"quantova hash based vrf vector";

    // The output recorded from the fixture above, written as plain decimal bytes.
    const RECORDED_OUTPUT: [u8; OUTPUT_LEN] = [
        239, 72, 177, 133, 162, 196, 155, 193, 5, 194, 185, 62, 75, 188, 30, 230, 141, 122, 211,
        184, 141, 26, 164, 91, 22, 110, 232, 151, 73, 222, 2, 177,
    ];

    fn fixture() -> HashBasedVrf {
        HashBasedVrf::keygen(&SK_SEED, &SK_PRF, &PK_SEED)
    }

    #[test]
    fn output_matches_recorded_vector() {
        let vrf = fixture();
        let out = vrf.output(INPUT).unwrap();
        assert_eq!(out.as_bytes(), &RECORDED_OUTPUT);
    }

    #[test]
    fn output_is_deterministic() {
        let vrf = fixture();
        let first = vrf.output(INPUT).unwrap();
        let second = vrf.output(INPUT).unwrap();
        assert_eq!(first.as_bytes(), second.as_bytes());
        assert_eq!(first.as_bytes(), &RECORDED_OUTPUT);
    }

    #[test]
    fn verify_accepts_valid_pair() {
        let vrf = fixture();
        let out = vrf.output(INPUT).unwrap();
        let proof = vrf.prove(INPUT).unwrap();
        assert_eq!(vrf.verify(INPUT, &out, &proof), Ok(()));
    }

    #[test]
    fn verify_rejects_wrong_output() {
        let vrf = fixture();
        let proof = vrf.prove(INPUT).unwrap();
        let mut bytes = *vrf.output(INPUT).unwrap().as_bytes();
        bytes[0] ^= 1;
        let wrong = Output::from_bytes(bytes);
        assert_eq!(
            vrf.verify(INPUT, &wrong, &proof),
            Err(VrfError::InvalidOutput)
        );
    }

    #[test]
    fn verify_rejects_wrong_proof() {
        let vrf = fixture();
        let out = vrf.output(INPUT).unwrap();
        let mut signature = vrf.prove(INPUT).unwrap().signature().to_vec();
        signature[0] ^= 1;
        let tampered = Proof::new(signature, Vec::new());
        assert_eq!(
            vrf.verify(INPUT, &out, &tampered),
            Err(VrfError::InvalidProof)
        );
    }

    #[test]
    fn verify_rejects_wrong_input() {
        let vrf = fixture();
        let out = vrf.output(INPUT).unwrap();
        let proof = vrf.prove(INPUT).unwrap();
        assert_eq!(
            vrf.verify(b"a different input", &out, &proof),
            Err(VrfError::InvalidProof)
        );
    }

    #[test]
    fn different_inputs_give_different_outputs() {
        let vrf = fixture();
        let first = vrf.output(b"first input").unwrap();
        let second = vrf.output(b"second input").unwrap();
        assert_ne!(first.as_bytes(), second.as_bytes());
    }
}
