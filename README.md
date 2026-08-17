# QVRF

QVRF is the verifiable random function of Quantova. It drives the sortition randomness for the QORUS consensus and the name service, and it rests on hashing alone, with no elliptic curve and no number theory that a quantum computer could break. The crate carries two constructions that answer two different needs.

The first is a one time key hash function built entirely from the SHA3 family. It is tiny, it checks itself in the height of a Merkle tree, and it is what belongs on the block path. The second is a zero knowledge function that proves a keyed output was computed correctly without ever revealing the key, for any input, with no per use state. It is heavier and it lives off the block path.

Quantova is a sovereign post quantum Layer 1 built from scratch, sharing no code, no wire, and no trust assumption with any other chain. It is post quantum end to end and not a classical chain with a post quantum signature bolted on.

## The one time key construction

A key commits a Merkle root over a set of one time secrets, one secret for each position. The secret at a position comes from the master seed and the position. The leaf at a position is the hash of that secret. The public key is the root and the tree height.

The output at a position and an input is the hash of the secret at that position together with the input. The proof reveals that secret and the Merkle path that ties its leaf to the root. To check a proof a verifier rebuilds the leaf from the secret, folds it up the path to a root, checks that root against the committed one, and then checks that the output is the hash of the secret and the input.

For a fixed position the committed leaf is pinned by the root, so there is exactly one secret that opens there and exactly one output. A second output would need a hash collision, which is out of reach, so a key holder cannot grind the result to a value it prefers. Every step is a SHAKE256 hash. Proving and verifying each cost work in the height of the tree, so the function stays on the block path and adds no measurable load to finality. This is the construction the running sortition uses.

Its one cost is state. Each position is spent once. A caller keeps three rules so the output also stays unpredictable. Fix the position from the outside and spend it once. Register the public key before the input is known. Open each position for one input only.

## The zero knowledge construction

The second construction removes the state at the price of a heavier proof. The output is a keyed algebraic hash, Rescue Prime over the Goldilocks field, with a round count taken from the Rescue Prime security formula. The proof is a transparent STARK from the q-prover backend that attests two facts at once, that the output is the keyed hash of the input, and that the same key hashes to the public commitment, all without revealing the key. There is no trusted setup and no pairing, the proof is hashes over a prime field, so it stays post quantum.

Grinding is dead by construction here too. For one key and one input the output is a function, and the proof binds it, so there is one and only one output that verifies. The proof is blinded so it leaks nothing about the key. The blinding is a random multiple of the vanishing polynomial added to every committed column, which changes nothing on the evaluation subgroup where the constraints live and randomizes every value a verifier ever opens, with a mask wider than the number of openings so the key stays hidden information theoretically. The blinding randomness is derived from the key inside the prover, so a caller cannot weaken it.

This construction takes any input and holds no state, which is what makes it useful to a light client or an auditor who wants to confirm a draw was honest without trusting the committee, and as the basis for slashing evidence. It does not belong on the block path. The proof takes seconds to make and is over a megabyte, which cannot fit inside a sub second block times a whole committee, so forcing it onto the hot path would stop the chain. It rides off the block path, where its cost never touches finality.

The crate wraps this behind a small byte interface, a key from a seed, a commitment, an output, a prover, and a verifier that rejects a non canonical encoding. The proving engine arrives from q-prover at a pinned revision.

## The block beacon

Alongside the per position function the specification defines a per block beacon that seeds each block. The beacon is SHAKE256 over the previous seed, the digest of the block's aggregated certificate, and the block height, and because the certificate is an artifact consensus already produces, the beacon costs the pipeline one hash rather than a new round. The beacon drives leader election. Its bias resistance is stated as a reduction and not as unconditional security. The beacon derives from the aggregated certificate rather than any single validator value, so no participant can bias it without controlling the supermajority that forms the certificate, which is breaking consensus itself.

## Published for cryptanalysis

This work is published early so the wider community can study it and try to break it. Public cryptanalysis is welcome and encouraged. The one time key function is built entirely from NIST standardized hash primitives. The zero knowledge function uses a STARK friendly hash that is not a NIST standard but rests on the same hash and field hardness with no number theory. Both are from scratch reference implementations. Neither has been independently audited, and Quantova is at the testnet stage. Nothing here is described as provably secure or as a proven world first, and it will not be until external cryptanalysis has occurred and is cited.

## Dependency and license

The hash primitives arrive from the crypto crate qtv-crypto at a pinned revision, and the zero knowledge proving engine from q-prover at a pinned revision. Dual licensed under Apache 2.0 and MIT.
