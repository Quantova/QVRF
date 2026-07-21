# QVRF

QVRF is the verifiable random function of Quantova and the first such function composed entirely from NIST standardized post quantum primitives. It replaces the elliptic curve construction of the classical standard with one built from ML DSA, SLH DSA, and SHA3, so the randomness that drives sortition survives a quantum attacker.

Quantova is a sovereign post quantum Layer 1 built from scratch, sharing no code, no wire, and no trust assumption with any other chain. It is post quantum end to end and not a classical chain with a post quantum signature bolted on. QVRF supplies the sortition randomness for the QORUS consensus and the name service, and it verifies through a QVM opcode like every other cryptographic operation in the stack.

## The function

The function returns a pseudorandom output for an input together with a proof that the output was derived correctly, and anyone holding the public parameters can verify the pair. The crate qtv-vrf defines this as one interface with three operations, one to produce the output, one to produce the proof, and one to verify an output and proof against an input. Two constructions stand behind that one interface.

## The hash based construction

The hash based construction is the conservative baseline and it is implemented. The output for an input is the SHAKE256 squeeze taken over the deterministic SLH DSA signature of that input, and the proof is the signature. Verification rechecks the signature under the public key and recomputes the output from it, accepting only when both agree. Uniqueness follows from deterministic signing, where one key and one input map to exactly one signature and therefore one output.

The construction is covered by tests that include a recorded reproducibility vector, so a reader who runs the key generation on the published seeds and asks for the output over the fixed input recovers the recorded bytes exactly, and by tests that a wrong output, a tampered proof, and a wrong input are each rejected. The SLH DSA signature and SHAKE256 arrive from the crypto crate and are never reimplemented here.

## The lattice based construction

The lattice based construction stands behind the same interface and is defined but not yet built. It is specified to squeeze SHAKE256 over an ML DSA signature of the input, with a proof of correct derivation that produces compact proofs. Its operations return a pending error today, and the cryptographic logic is still to land. Neither construction is removed, and a benchmark chooses which one is the default once both exist.

## The block beacon and honest bias resistance

Alongside the per user function, SPEC-vrf defines a per block beacon that seeds each block. The beacon is SHAKE256 over the previous seed, the digest of the block's aggregated certificate, and the block height, and because the certificate is an artifact consensus already produces, the beacon costs the pipeline one hash rather than a new round. The beacon drives leader election.

The bias resistance of the beacon is stated as a reduction and not as a claim of unconditional security. The beacon derives from the aggregated certificate rather than from any single validator value, so no participant can bias the output without controlling the supermajority that forms the certificate, and controlling that supermajority is breaking consensus itself. The named assumption is that an adversary holds less than the consensus threshold. For the committee sortition, uniqueness rests on the one time key construction in SPEC-sortition-onetime, a protocol bound of one draw per account per slot backed by slashing, and not on the uniqueness of a signature, because a verifier cannot tell a derandomized signature from a hedged one. The specifications state this exactly and no stronger.

## Published for cryptanalysis

This work is published early so the wider community can study it and try to break it. Public cryptanalysis is welcome and encouraged. It is the first verifiable random function composed entirely from NIST post quantum primitives and it is bias resistant by reduction to consensus security. The cryptography is a from scratch reference implementation validated against the NIST test vectors and has not been independently audited, and Quantova is at the testnet stage. It is not described as provably secure, and it will not be until external cryptanalysis has occurred and is cited.

## Dependency and license

The primitives arrive from the crypto crate qtv-crypto at the pinned tag v0.1.0. Dual licensed under Apache 2.0 and MIT.
