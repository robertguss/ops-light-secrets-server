---
id: T05
title: "Crypto at rest: age keyring, AEAD binding, clear-metadata boundary"
label: wayfinder:grilling
status: open
assignee:
blocked-by: [T04]
---

## Question

The core learning subsystem — walk it until explainable, then verdict:

- age-wrapped fixed-purpose keyring (KTD3) vs per-blob age vs anything
  simpler; the no-unseal-ceremony seal boundary (boot-supplied identity, R21).
- XChaCha20-Poly1305 record AEAD with canonical binary AAD binding ciphertext
  to store/type/path/version/key-id; nonce policy; checked-in test vectors.
- The clear-structural-metadata boundary: paths, identity names, grants stored
  clear but MAC-authenticated (R4, R39, KTD15, KTD11) — keep, simplify, or
  accept-and-document differently? KTD15's checkpointed state digest rides
  here too.
- Zeroization scope and its honest limits (R5, KTD7).

Resolution: verdicts per piece, plus explain-back on what `age` does on the
server's behalf and why the boundary holds — this is verbatim the plan's
primary success criterion.
