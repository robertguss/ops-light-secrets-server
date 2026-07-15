---
id: T10
title: "Recovery: backup format, restore epochs, key rotation, clock model"
label: wayfinder:grilling
status: open
assignee:
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
