---
id: T10
title: "Recovery: backup format, restore epochs, key rotation, clock model"
label: wayfinder:grilling
status: closed
assignee: robertguss
blocked-by: [T05, T08]
---

## Question

Walk and verdict the recovery story:

- KTD17 logical backup format (canonical frames, never the redb file) vs
  something simpler with documented caveats — budget test against the named
  failure modes (torn copy, format lock-in, credential resurrection).
- Restore semantics: credential-epoch increment, rollback recovery with
  explicit audit-epoch fork (R32) — keep both, or v0.1 takes normal restore
  only?
- `backup verify --full` rehearsal as a standing gate.
- U8's five different key-rotation semantics (record, metadata-MAC,
  audit-payload, index, verifier keys) — understand why they differ; verdict
  on what ships v0.1 vs documented-manual.
- The clock model: monotonic anchor, persisted high-water mark, readiness
  trip, `clock repair` (R18, Assumptions) — right-sized or simplifiable?
- R27's preallocated `recovery.reserve` file.

Resolution: verdicts plus explain-back on why a restored snapshot can't
resurrect revoked credentials.

## Resolution (2026-07-16)

First ticket resolved under the ask-only-when-it-matters mode (map Notes):
all six pieces are analysis-determined — forced by named failure modes or by
decisions already kept — so **all verdicts recorded as agent-recommended,
unopposed. Everything KEPT**, with one follow-on adjustment from T08's
index defer.

1. **KTD17 logical backup format — KEEP.** The simpler alternative (copy the
   redb file) fails all three named failure modes at once: torn copies
   (R32 requires backup *while the server runs*; a live file copy has no
   consistency story), format lock-in (file-as-format ties every old backup
   to redb's file format — KTD17 is what keeps release fixtures stable
   across redb changes, part of why T04 kept redb), and it forecloses
   verify-before-install restore. Frames from one consistent read
   transaction are modest code; restore-as-rebuild with full verification
   is the DR quality bar.
2. **Restore epochs: both semantics — KEEP.** Normal restore's credential-
   epoch bump is already settled (T06/T08; explain-back below). Rollback
   recovery (restore behind the newest retained checkpoint → explicit
   flag + audited reason + audit-epoch fork, never presented as continuous)
   must ship too: the behind-checkpoint case IS the disaster case — losing
   it means the product can't recover from its worst day. Checkpoints
   (kept, T08) provide detection; the fork is one recorded event plus
   tiered verification reporting.
3. **`backup verify --full` — KEEP.** The restore path reused with
   no-install, so marginal code is flag wiring; an unrehearsed backup is
   not a recovery plan. Standing-gate cadence is operator docs + release
   fixtures (U10/U12 own the CI half).
4. **U8 five rotation semantics — KEEP; understand as forced, not chosen.**
   Each key's rotation shape follows from its data relationship: record key
   → offline whole-store re-encrypt (ciphertext must change); metadata-MAC
   key → offline rewrite (MACs regenerate from clear values); audit-payload
   key → forward-only with decrypt-only predecessors (rewriting ciphertext
   would break chain hashes anchored by checkpoints — forced by T08's
   keep); credential-verifier key → only with epoch increment (verifiers
   are non-recoverable — forced by T06's R41 keep). No generic "rotate all
   keys" command can exist honestly. Record-key rotation must ship (not
   documented-manual): restore preserves ciphertext unchanged, so without
   U8's offline pass the product has NO re-key path at all. The
   no-resumable-cursor design (interrupted pass = delete `.new`, rerun) is
   already the minimal correct shape.
   **Adjustment (T08 follow-on):** the fifth semantic — audit-index key →
   rebuild — leaves v0.1 with the index. The keyring still mints all five
   purpose keys at init (32 random bytes; keeps the T05 keyring format
   stable so the index arrives later without a keyring migration); the
   index key is dormant in v0.1. T14 wording note.
5. **Clock model — KEEP as written.** Each piece closes a named, realistic
   solo-operator failure: the persisted high-water mark (riding
   already-durable transactions, near-free) is the only thing standing
   between a VM restore/NTP rollback and silently extended bearer TTLs
   (Threat Model names this); the implausibly-ahead check plus offline
   `clock repair` (exact old mark + reason + credential-epoch bump) is what
   prevents one NTP spike from bricking the store permanently; runtime
   discontinuity trips readiness rather than silently stretching TTLs.
   Monotonic-only TTLs stay rejected (don't survive restart). Tolerance
   values are build-time constants — deferred to build, documented knob.
6. **`recovery.reserve` — KEPT at T08 Q6;** re-affirmed here unchanged. Its
   job (backup/checkpoint/shutdown remain possible after fail-closed) is
   load-bearing for this ticket's story.

### Why a restored snapshot can't resurrect revoked credentials
(rationale record)

**Agent-drafted, not Robert's words** (explain-back retired — map Notes).

Every credential record carries the `issue_epoch` it was minted under, and
that epoch is inside the keyed verifier's MAC domain (KTD5) — it is not
advisory metadata, it is cryptographically bound. The store separately
persists one `current_credential_epoch`. Verification requires equality.
A backup necessarily contains credential records that were live when it was
taken — including ones revoked afterward, whose revocation events the
backup predates. Restore therefore atomically increments
`current_credential_epoch` as part of installing the rebuilt store: every
restored bearer credential still carries its original issue epoch, so every
one of them — revoked-later or not — fails epoch validation even where its
verifier and TTL would pass. Nothing needs to be found and deleted; the
invalidation is structural. Identities, grants, secrets, and audit history
survive (they are not bearer instruments); tokens and secret_ids are
reissued through normal login. The same primitive backs R41's incident
command and `clock repair`'s distrust of prior TTL math — one mechanism,
three doors.

**Downstream:** nothing invalidated; the dormant-index-key note and
four-semantics-in-v0.1 wording go to T14. No fog graduates. T10 closes the
security/recovery spine: T01–T10 walked, only T11–T13 (deployment, test
weight, meta) and T14 remain.
