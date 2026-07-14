# Contributing

This repository is part of the Quantova post quantum stack. Before you contribute, read the crypto policy and the handoff in the Quantova Specs repository. The crypto policy is the highest authority. If anything you are asked to do conflicts with it, stop and report.

Only the NIST post quantum algorithms exist in this stack. These are ML DSA from FIPS 204, SLH DSA from FIPS 205, and SHA 3 and SHAKE from FIPS 202. Classical cryptography cannot be expressed here. The banned crates, including transitive and development dependencies, are held out by the deny file. The primitives come from the crypto crate by tag and are never reimplemented in this repository.

Author every commit as the repository owner only, with no other attribution anywhere. Once the history is open to review, work on a feature branch, open a request, and merge only when the checks are green. Every request names the part of the specification it carries.

Public cryptanalysis of this construction is welcome. If you find a weakness, report it through the repository so that it can be studied in the open.
