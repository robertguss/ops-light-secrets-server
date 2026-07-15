---
id: T07
title: "AuthZ: canonical resource, raw-target guard, grants, capability set"
label: wayfinder:grilling
status: open
assignee:
blocked-by: [T03]
---

## Question

Walk and verdict the authorization boundary:

- KTD9's RawTargetGuard + single canonical `Resource` parse — reject-not-
  normalize posture, one module one corpus. Understand why validation must
  run before framework decoding.
- Grant model: exact-path or segment-prefix subtree, no globs/deny/DSL (R8).
- R22's closed capability set — 7 secret + 9 management capabilities.
  Ruthless-budget question: does v0.1 need this many distinct capabilities,
  or does a smaller set survive the same threat model?
- Capability-thin tokens + per-request grant reload as the R28 linearization
  story.
- R29's delete/destroy/purge ladder and destroy-all being local-only.

Resolution: verdicts plus explain-back on how a request becomes an
authorization decision.
