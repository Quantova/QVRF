# QVRF

This repository holds the verifiable random function for Quantova. It is the first verifiable random function composed entirely from NIST post quantum primitives. It is bias resistant by reduction to the security of consensus, which means an adversary would have to break consensus before it could bias the output.

The function has two layers. A per block beacon hashes an artifact that consensus already produces. A per user function returns SHAKE256 taken over an ML DSA signature of the input followed by the input, together with a proof that carries the signature and a proof of correct derivation. Two constructions sit behind one interface. One is hash based and uses SLH DSA with Merkle authentication. The other is lattice based and uses ML DSA with a proof system. The primitives arrive from the crypto crate by tag and are never reimplemented here.

This work is published early so that the wider community can study it and try to break it. Public cryptanalysis is welcome and encouraged.

This repository is authored by the owner only.

It is dual licensed under Apache 2.0 and MIT, and you may choose either license.
