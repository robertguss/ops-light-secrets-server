---
id: T05
title: "Crypto at rest: age keyring, AEAD binding, clear-metadata boundary"
label: wayfinder:grilling
status: closed
assignee: robertguss
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

## Resolution

Resolved 2026-07-15, grilling session. All four pieces walked; verdict on each.

1. **Keyring architecture (KTD3 + R21): keep.** Not a close call — MAC keys
   force a keyring to exist in every variant (per-blob age still needs one);
   five independent random purpose keys are simpler than master-key+HKDF and
   rotate independently; seal boundary has no state machine (boot-supplied
   identity IS the unseal). Per-blob age strictly worse: full-store re-encrypt
   on recipient rotation.
2. **Record AEAD: keep as written.** XChaCha20-Poly1305 + canonical binary AAD
   + fresh 192-bit random nonce per encryption + checked-in test vectors.
   Every element closes a named failure mode (ciphertext transplant, nonce
   reuse, encoding ambiguity, silent format drift). XChaCha over AES-GCM
   because the extended nonce makes random-per-encryption safe with zero
   collision bookkeeping — already the cheapest safe variant.
3. **Clear-metadata boundary (R4/R39/KTD15/KTD11): keep** — clear structural
   metadata + per-record keyed MAC (fail-closed) + checkpointed state digest.
   Already the simplification vs encrypt-everything; MAC closes offline
   grant-editing, digest closes rollback/deletion of formerly-valid records.
   **Conditional on T08:** the digest anchors to KTD4's external checkpoints —
   if T08 cuts or defers checkpoint machinery, this digest verdict re-opens.
   *(Resolved 2026-07-16: T08 kept external checkpoints — this verdict
   stands unconditionally.)*
4. **Zeroization (R5/KTD7): keep.** Near-zero cost; the bigger win is type
   discipline (`SecretString` has no Debug/Display — closes accidental
   logging disclosure), memory scrubbing second. R5's honest-limits wording
   (allocator/kernel/TLS copies excluded) stays — no overclaim. No deeper
   hardening (mlock etc.) for v0.1.

### Explain-back

**Agent-supplied at Robert's request (session cut short) — NOT Robert's own
words. The plan's primary success criterion (explain from understanding) is
not yet verified for this subsystem; redo in Robert's words at T14 or before
building U2.**

*What age does on the server's behalf:* envelope encryption of the keyring,
nothing else. `init` encrypts the five-purpose-key bundle to the server's age
recipient (plus optional offline recovery recipient) and stores it as one redb
row. At boot the age identity arrives through an approved credential channel,
the server opens the envelope once into `secrecy` memory and verifies the
embedded store id; from then on all record crypto is symmetric under keyring
keys. Recipient rotation rewraps one row. age is the only asymmetric mechanism
and the seal boundary — no unseal ceremony because possession of the
boot-supplied identity is the unseal.

*Why the boundary holds:* a thief with the database file holds only ciphertext
(keyring envelope, secret and audit records) plus readable-but-MAC'd topology.
The one thing not in the file is the age identity — R21's custody rules keep
it off disk, out of shell history, out of argv. Without it there are no
purpose keys: secrets stay ciphertext, credential guesses can't be verified
offline, grants can't be edited (metadata MAC fails closed), and rollback or
deletion of formerly-valid records is caught by the checkpoint-anchored state
digest. Documented residual: topology (paths, identity names, grants) is
readable — the accepted v0.1 offline-theft boundary.
