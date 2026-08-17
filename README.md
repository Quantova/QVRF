# QVRF

QVRF is the verifiable random function of Quantova and the first such function built entirely from NIST standardized post quantum primitives. It replaces the elliptic curve construction of the classical standard with one built from the SHA3 family alone, so the randomness that drives sortition survives a quantum attacker.

Quantova is a sovereign post quantum Layer 1 built from scratch, sharing no code, no wire, and no trust assumption with any other chain. It is post quantum end to end and not a classical chain with a post quantum signature bolted on. QVRF supplies the sortition randomness for the QORUS consensus and the name service, and it verifies through a QVM opcode like every other cryptographic operation in the stack.

## The function

The function returns a pseudorandom output for a position and an input together with a proof that the output was derived correctly, and anyone holding the public key can check the pair. The crate qtv-vrf defines this as one interface with three operations, one to produce the output, one to produce the proof, and one to verify an output and proof against a position and an input.

## The construction

A key commits a Merkle root over a set of one time secrets, one secret for each position. The secret at a position comes from the master seed and the position. The leaf at a position is the hash of that secret. The public key is the root and the tree height.

The output at a position and an input is the hash of the secret at that position together with the input. The proof reveals that secret and the Merkle path that ties its leaf to the root. To check a proof a verifier rebuilds the leaf from the secret, folds it up the path to a root, checks that root against the committed one, and then checks that the output is the hash of the secret and the input.

For a fixed position the committed leaf is pinned by the root, so there is exactly one secret that opens there and exactly one output. A second output would need a hash collision, which is out of reach, so a key holder cannot grind the result to a value it prefers. Every step is a SHAKE256 hash, so there is no number theory and no lattice for a quantum computer to break. Proving and verifying each cost work in the height of the tree, so the function stays on the block path.

The crate carries tests that a valid output and proof verify, that the output is fixed for one position and input, that a forged output is rejected, that a secret from another position does not open here, that a tampered path is rejected, and that a hostile proof of the wrong shape is refused without a panic. The SHAKE256 hash arrives from the crypto crate and is never reimplemented here.

## What the caller must hold to

The primitive is sound on its own. A caller keeps three rules so the output also stays unpredictable.

Fix the position from the outside and spend it once. In sortition the position is the slot or the committee index. A prover must never be free to choose its own position, because a free choice hands it one output per position and it would keep the one it likes.

Register the public key before the input is known. The output for a position and an input is fixed once the root is set, and a fresh key gives a fresh output, so a party that could pick a new root after seeing the input would grind. The root goes in first and the input arrives after.

Open each position for one input only. The proof reveals the secret at that position, and once it is out anyone can compute the output for any other input at the same position. One position carries one draw.

## The block beacon and honest bias resistance

Alongside the per position function, the vrf specification defines a per block beacon that seeds each block. The beacon is SHAKE256 over the previous seed, the digest of the block's aggregated certificate, and the block height, and because the certificate is an artifact consensus already produces, the beacon costs the pipeline one hash rather than a new round. The beacon drives leader election.

The bias resistance of the beacon is stated as a reduction and not as a claim of unconditional security. The beacon derives from the aggregated certificate rather than from any single validator value, so no participant can bias the output without controlling the supermajority that forms the certificate, and controlling that supermajority is breaking consensus itself. The named assumption is that an adversary holds less than the consensus threshold. For the committee sortition, uniqueness rests on the one time key construction in this crate, a protocol bound of one draw per account per slot backed by slashing, and not on the uniqueness of a signature.

## Published for cryptanalysis

This work is published early so the wider community can study it and try to break it. Public cryptanalysis is welcome and encouraged. It is the first verifiable random function built entirely from NIST post quantum primitives and it is bias resistant by reduction to consensus security. The cryptography is a from scratch reference implementation validated against the NIST test vectors and has not been independently audited, and Quantova is at the testnet stage. It is not described as provably secure, and it will not be until external cryptanalysis has occurred and is cited.

## Dependency and license

The primitives arrive from the crypto crate qtv-crypto at a pinned revision. Dual licensed under Apache 2.0 and MIT.
