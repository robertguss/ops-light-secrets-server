---
id: T09
title: "Rotation & consumers: registry, three views, status granularity, closeout"
label: wayfinder:grilling
status: open
assignee:
blocked-by: [T08]
---

## Question

Rotation is the product's wedge — how much ceremony ships in v0.1?

- R40 declared-consumer registry (the fourth-round reversal put it back in
  v0.1) — keep, or trust migration order without it?
- R10's three separately labeled views (declared/authorized/observed) and
  reconciliation states.
- R33 status view: on-current/on-prior/silent-since-write at declared,
  identity, AND consumer-instance granularity, plus the guarded
  `rotation complete` with audited override. Ruthless-budget question: does
  v0.1 need instance granularity and the closeout guard, or is observation
  plus operator judgment enough for a solo operator?
- R11's begin/cutover/complete state machine with CAS protection; R12
  age/interval display.
- Dependency check: which of these survive if T08 deferred the blind index?

**Note (from T08, 2026-07-16):** blind index DEFERRED — v0.1 rotation-status
queries scan primary events over R23's lookback window; R33's index-health/
closeout fail-closed coupling is gone from v0.1 (primary is always
authoritative). Walk R33's granularity question against scan cost, not
index cost. Checkpoints and segmentation verdicts: checkpoints kept,
archive/prune deferred.

Resolution: a chosen v0.1 rotation surface (what's kept, what joins the
post-v0.1 campaign list) plus explain-back on why observed reads — not
grants — are the rotation evidence.
