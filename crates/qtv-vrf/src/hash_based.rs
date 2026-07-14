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
